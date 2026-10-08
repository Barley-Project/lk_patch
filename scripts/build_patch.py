#!/usr/bin/env python3
"""Create the TB330FU CN LK region-call patch in a new output file."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

SOURCE_SHA256 = "9a5dde49e87c43def1d5aa86b632508f96b07210eb1df608451e6d3d202d659e"
FILE_OFFSET = 0x2782E
BEFORE = bytes.fromhex("08 f0 41 fd")
AFTER = bytes.fromhex("af f3 00 80")  # Thumb-2 NOP.W
EXPECTED_OUTPUT_SHA256 = "2e448518270f65b91de13d7c77578af9479b53cfe9168509fd60f9ca5396c1d5"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="OEM unsigned CN image/mtk_unsigned_images/lk.img")
    parser.add_argument("output", type=Path, help="new patched LK output path")
    args = parser.parse_args()

    if not args.source.is_file():
        parser.error(f"input file does not exist: {args.source}")
    if args.output.exists():
        parser.error(f"output already exists; choose a new path: {args.output}")
    image = args.source.read_bytes()
    actual = sha256(image)
    if actual != SOURCE_SHA256:
        parser.error(f"unexpected input SHA-256 {actual}; expected {SOURCE_SHA256}")
    if image[FILE_OFFSET:FILE_OFFSET + len(BEFORE)] != BEFORE:
        parser.error("instruction bytes do not match the analyzed CN LK; refusing to patch")

    patched = image[:FILE_OFFSET] + AFTER + image[FILE_OFFSET + len(AFTER):]
    result = sha256(patched)
    if result != EXPECTED_OUTPUT_SHA256:
        parser.error(f"unexpected output SHA-256 {result}; expected {EXPECTED_OUTPUT_SHA256}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"Wrote: {args.output}")
    print(f"SHA-256: {result}")
    print(f"Changed bytes: file offset 0x{FILE_OFFSET:x}, {BEFORE.hex()} -> {AFTER.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
