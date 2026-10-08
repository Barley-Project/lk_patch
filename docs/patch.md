# Patch rationale and static verification

The patch changes the normal Android boot call at CN LK runtime VA `0x4C42762E`, payload offset `0x2762E`, container offset `0x2782E`:

```text
before  08 f0 41 fd    bl  0x4C4300B4   ; region_check_boot
after   af f3 00 80    nop.w            ; same four-byte instruction width
```

This call site is inside the Android FDT boot path. The target function is solely the normal boot region policy routine. The following instruction is a call to `0x4C4246D8`, which overwrites `r0`; the region routine is void and the caller does not consume a return value. The same caller saves its link register in its function prologue. The edit leaves all other file bytes alone.

Static verification compared the complete output with its unsigned OEM input: image length is unchanged, the only differences are file offsets `0x2782E` through `0x27831`, the LK wrapper header is unchanged, and the `lk_main_dtb`/trailing data is unchanged. Capstone decodes the original branch target and the replacement as `NOP.W`. The patched SHA-256 is `2e448518270f65b91de13d7c77578af9479b53cfe9168509fd60f9ca5396c1d5`.

These checks establish the intended static control-flow change only. They do not establish Preloader acceptance, successful boot, or that the observed “hardware mismatch” screen comes from this LK path. Do not treat the static pass as a device boot result.
