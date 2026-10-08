# Lenovo TB330FU LK region-check patch

This repository contains a reproducible, four-byte patch for the CN ZUI 16 LK image of the Lenovo TB330FU (Barley). At the normal Android boot call site, it replaces the call to `region_check_boot` with a Thumb-2 `NOP.W`. The patch skips this LK caller's region-policy check. It does not edit the region helper functions, the `oem unlock-region` fastboot command, AVB routines, or device data.

The static patch artifact is in [`patches/`](patches/). It was made from the OEM **unsigned** CN LK container. Its SHA-256 is `2e448518270f65b91de13d7c77578af9479b53cfe9168509fd60f9ca5396c1d5`. This is an experimental image: static checks pass, but acceptance by the device's Preloader and successful boot have not been verified.

## Rebuild

Use the OEM unsigned CN `lk.img` at `image/mtk_unsigned_images/lk.img` as the input. The script checks its SHA-256 and the original instruction bytes before writing an output file. It never edits the input.

```powershell
python scripts/build_patch.py "C:\firmware\image\mtk_unsigned_images\lk.img" "C:\work\lk_patched.img"
python scripts/verify_patch.py "C:\firmware\image\mtk_unsigned_images\lk.img" "C:\work\lk_patched.img"
```

`verify_patch.py` requires the Python `capstone` package. The expected input SHA-256 is `9a5dde49e87c43def1d5aa86b632508f96b07210eb1df608451e6d3d202d659e`.

## Analysis notes

- `docs/region_check.md` records the CN/ROW disassembly evidence and decision flow.
- `docs/preloader_auth.md` explains the LK authentication policy observed in the supplied CN Preloader and boot logs.
- `docs/patch.md` records the byte-level rationale and static verification limits.

The research workspace used Ghidra 11.3.2 headless and Capstone. Key addresses, file offsets, input hashes, and the region-check evidence are documented so the patch can be reviewed without the original Ghidra project.
