# LK Region Check: CN / ROW static analysis

## Image mapping

Both stock LK images begin with the MediaTek `0x58881688` wrapper and a 512-byte (`0x200`) header. The LK payload is linked at `0x4C400000`; its reset vector begins in ARM mode and enters Thumb code through normal interworking. For payload virtual address `VA`, its container file offset is `0x200 + VA - 0x4C400000`. The signed CN LK file SHA-256 is `0f47a6676d9c173d85413077375338fd2da7034225b2cefd3df1bb83c4ffb794`; ROW is `d8fe632488f40884be1da0e46bb23f1fcbb79f167accefcd64f0e9a41f3c92d6`.

The initial LK payload is followed by separate `cert1`, `cert2`, and `lk_main_dtb` components. The signature components are outside the executable payload. Ghidra headless analysis and Capstone Thumb disassembly were run on both payloads.

## Normal boot control flow

CN's `android_boot_with_fdt` is at `0x4C42741C`. After `boot_linux_fdt` has loaded and opened the Android FDT, its call at `0x4C42762E` enters `region_check_boot` at `0x4C4300B4`, passing the FDT pointer. The caller resumes at `0x4C427632`. The call is before the later `boot_linux_fdt` / kernel hand-off path; it is LK policy code, not Android AVB verification.

| Function | CN entry | ROW entry | Evidence |
|---|---:|---:|---|
| Android FDT boot path | `0x4C42741C` | `0x4C4279C8` | Ghidra function body and call reference |
| Region check on normal boot | `0x4C4300B4` | `0x4C430908` | Caller reference and function body |
| Region mismatch display helper | `0x4C40618C` | `0x4C405F34` | Thumb PC-relative string references and direct calls |
| Product region from FDT | `0x4C42FC54` | `0x4C430424` | `/product_region`, `country`, `city`, `province` strings and FDT calls |
| Read current region from RPMB | `0x4C42FD48` | `0x4C430518` | Function body; RPMB read wrapper |
| Compare current, build, and stored regions | `0x4C42FEDC` | `0x4C4306DC` | Country comparisons and mismatch log xrefs |
| Region state validation | `0x4C42F7F4` | `0x4C43000C` | Magic/version constants and validation branches |
| Fastboot `oem unlock-region` | `0x4C42F4D4` | `0x4C42FA18` | Command string xref; separate caller/command path |

In CN, the primary mismatch path is in `region_check_boot`: when current region state is present, it reads the new/update state from RPMB, then compares the three 64-byte country fields. On mismatch, it reads the update flag. If no update is pending, the function calls `show_region_mismatch_logo` at `0x4C43038A`; after an update candidate fails the country match, it calls the same helper at `0x4C4303AC`. The helper shows the logo, delays about 3000 ms, and calls the platform reset routine. It does not simply continue into Android.

The normal check also has a first-boot-after-flush path which reads build-region data from the FDT, constructs region state, and writes it to RPMB. The scoped call-site patch skips all of `region_check_boot` for this normal Android boot caller. It therefore prevents this function from doing either its checks or its region-state initialization/update. It does not alter the helper code used by fastboot commands.

## Region inputs and CNPX

The `proinfo` country reader is a separate LK path. In CN, `read_proinfo_country_validated` at `0x4C429914` reads 1024 bytes from the configured proinfo area, checks the four-byte code at offset `0x3C`, and accepts alphabetic characters. `get_countrycode` copies the result into country-code command-line state. The supplied boot logs show `code_info=CNPX` and Android init logging `countrycode:CNPX`.

No xref or call path from the CN region-check function to the proinfo country reader was found in the Ghidra exports. The region policy instead consumes an FDT `/product_region` and RPMB region state. Thus CNPX is evidence for the separate country-code path; it is not, on the available binary evidence, the direct value compared by `region_check_boot`.

The CN and ROW boot FDTs in the supplied firmware images both contain `/product_region/{country,province,city} = "ROW"`; the CN and ROW LK main DTBs also contain ROW. Both DTBO overlays contain ROW region nodes. LK code reads the Android boot FDT supplied to `android_boot_with_fdt`. These static files alone do not establish the FDT actually passed on the user's current boot.

The CN LK contains strings for `androidboot.product_region=PRC` and `...=ROW`, with references in a helper which chooses based on the existing command line and otherwise uses a region string. The ROW LK has a ROW setter. These setters are not the `proinfo` read and are not AVB checks. The exact live command line, RPMB contents, and current FDT were not read from the device, so the runtime mismatch tuple is `UNVERIFIED`.

## CN versus ROW

The core policy has a recognizable, cross-referenced counterpart in each LK; matching addresses or strings alone were not used to infer equivalence. The ROW build includes extra logging/helpers for `read_new_product_region_from_rpmb`, `is_new_region_same`, and update-flag checks. In the normal check's steady-state flow, both builds compare current/build/RPMB country fields and take the mismatch helper when update handling does not authorize the new state. See `output/ghidra_cn/focused.c`, `output/ghidra_row/focused.c`, each `focused_disassembly.tsv`, `focused_calls.tsv`, `string_xrefs.tsv`, and `cfg.tsv` in the analysis workspace for the decompiler and cross-reference exports.

The splash text reported by the user was not captured with an LK display ID or log entry. The binary proves that the region mismatch helper exists and when this normal-boot policy calls it; attributing the observed message to that LK helper rather than a later Android component remains `UNVERIFIED` without matching runtime evidence.
