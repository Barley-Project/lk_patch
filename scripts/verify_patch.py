#!/usr/bin/env python3
"""Verify the exact four-byte LK patch and decode the changed instruction."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import sys

try:
    from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
except ImportError as exc:
    raise SystemExit("Install Capstone first: python -m pip install capstone") from exc

SOURCE_SHA256 = "9a5dde49e87c43def1d5aa86b632508f96b07210eb1df608451e6d3d202d659e"
OUTPUT_SHA256 = "2e448518270f65b91de13d7c77578af9479b53cfe9168509fd60f9ca5396c1d5"
FILE_OFFSET = 0x2782E
VA = 0x4C42762E
BEFORE = bytes.fromhex("08 f0 41 fd")
AFTER = bytes.fromhex("af f3 00 80")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(message: str) -> int:
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="OEM unsigned CN lk.img")
    parser.add_argument("patched", type=Path, help="patched LK to check")
    args = parser.parse_args()
    if not args.source.is_file() or not args.patched.is_file():
        return fail("source or patched image does not exist")

    source, patched = args.source.read_bytes(), args.patched.read_bytes()
    if sha256(source) != SOURCE_SHA256:
        return fail("source SHA-256 is not the analyzed OEM unsigned CN LK")
    if sha256(patched) != OUTPUT_SHA256:
        return fail("patched-image SHA-256 does not match the reference artifact")
    if len(source) != len(patched):
        return fail("image length changed")
    changed = [i for i, (a, b) in enumerate(zip(source, patched)) if a != b]
    if changed != list(range(FILE_OFFSET, FILE_OFFSET + 4)):
        return fail(f"expected exactly four changed bytes at 0x{FILE_OFFSET:x}; got {changed}")
    if source[:FILE_OFFSET] != patched[:FILE_OFFSET] or source[FILE_OFFSET + 4:] != patched[FILE_OFFSET + 4:]:
        return fail("bytes outside the patch differ")
    if source[:0x200] != patched[:0x200]:
        return fail("MediaTek LK header changed")
    payload_size = struct.unpack_from("<I", source, 4)[0]
    trailer = 0x200 + payload_size
    if source[trailer:] != patched[trailer:]:
        return fail("trailing lk_main_dtb or container data changed")

    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    original = list(decoder.disasm(source[FILE_OFFSET - 2:FILE_OFFSET + 8], VA - 2))
    result = list(decoder.disasm(patched[FILE_OFFSET - 2:FILE_OFFSET + 8], VA - 2))
    if len(original) < 3 or original[1].mnemonic != "bl" or original[1].op_str != "#0x4c4300b4":
        return fail("original instruction is not BL region_check_boot")
    if len(result) < 3 or result[1].mnemonic != "nop.w" or result[1].size != 4:
        return fail("replacement is not one four-byte Thumb-2 NOP.W")
    if (original[2].address, original[2].bytes) != (result[2].address, result[2].bytes):
        return fail("instruction following the patch changed")

    print("PASS: exact four-byte diff; header and trailing LK data unchanged")
    print(f"Original: 0x{VA:08x}  {BEFORE.hex()}  bl 0x4c4300b4")
    print(f"Patched:  0x{VA:08x}  {AFTER.hex()}  nop.w")
    print(f"SHA-256: {sha256(patched)}")
    print("Device boot and Preloader acceptance: not tested")
    return 0


if __name__ == "__main__":
    sys.exit(main())
