"""Increase SHARED_REGION_SIZE_ARM64 in the PCC vphone600 kernelcache from 6 GiB
to 8 GiB so the iOS 27.0 (24A437) dyld shared cache can be mapped.

The vphone600 kernel (cloudOS 26.x base) defines both SHARED_REGION_BASE_ARM64
and SHARED_REGION_SIZE_ARM64 as 0x180000000 (6 GiB). iOS 27.0 release (build
24A437) ships a dyld shared cache whose mapped span is 0x1857FC000 (~6.086 GiB),
which exceeds the 6 GiB region by 88 MiB. Even with maxSlide zeroed, the cache
span alone overflows the kernel's vm_shared_region allocation, causing ENOMEM in
_shared_region_map_and_slide -> dyld can't load libSystem -> launchd crash ->
kernel panic.

Fix: patch the two kernel instructions that load SHARED_REGION_SIZE_ARM64:
  1. In vm_shared_region_lookup: MOV X26, #0x180000000 -> MOV X26, #0x200000000
  2. In the shared-region bounds check: MOV X10, #0x180000000 -> MOV X10, #0x200000000

The base address (SHARED_REGION_BASE_ARM64 = 0x180000000) is NOT changed — only
the size grows from 6 GiB to 8 GiB, extending the shared region VA range from
[0x180000000, 0x300000000) to [0x180000000, 0x380000000).

Detection: ARM64 ORR (logical immediate) encoding for 0x180000000, register-
matched. Both BASE and SIZE use the same encoding but different destination
registers. The SIZE sites are identified by register number (X26 in the lookup
function, X10 in the bounds check). Context verification: the X26 site must be
preceded by the X22 (BASE) load.

Self-gating: no-op if the kernelcache doesn't contain the expected 5 instruction
sites (3 non-SIZE + 2 SIZE). Idempotent: no-op if already patched.

Input: raw IM4P kernelcache (uncompressed Mach-O inside an IMG4/IM4P wrapper).
The Mach-O magic (0xFEEDFACF) is located inside the container and patches are
applied at the IM4P file offsets.
"""

import os
import struct

OLD_SIZE_6G = 0x180000000
NEW_SIZE_8G = 0x200000000

# ARM64 ORR (logical immediate) encoding: MOV Xn, #0x180000000
# Base encoding with Rd=0: 0xB26107E0 (verified via keystone assembler)
OLD_ENCODING_BASE = 0xB26107E0
OLD_ENCODING_MASK = 0xFFFFFFE0  # mask out Rd (bits 4:0)

# MOV Xn, #0x200000000 = MOVZ Xn, #2, LSL #32
# Base encoding with Rd=0: 0xD2C00040 (verified via keystone assembler)
NEW_ENCODING_BASE = 0xD2C00040

EXPECTED_TOTAL_SITES = 5
SIZE_REGISTERS = {26, 10}


def patch_kernel_shared_region_size(kc_path, *, dry_run=False):
    """Patch SHARED_REGION_SIZE_ARM64 from 6 GiB to 8 GiB in the kernelcache.

    Returns the number of instructions patched (0 if no-op, 2 on success).
    """
    with open(kc_path, "r+b") as f:
        data = f.read()

    magic = struct.pack("<I", 0xFEEDFACF)
    mach_start = data.find(magic)
    if mach_start < 0:
        raise RuntimeError(f"{kc_path}: no Mach-O magic found")

    print(f"  [.] Mach-O at offset 0x{mach_start:X}")

    # Find all MOV Xn, #0x180000000 instructions
    matches = []
    for off in range(mach_start, len(data) - 3, 4):
        insn_val = struct.unpack_from("<I", data, off)[0]
        if (insn_val & OLD_ENCODING_MASK) == OLD_ENCODING_BASE:
            rd = insn_val & 0x1F
            matches.append((off, rd))

    # Check for already-patched state (MOV Xn, #0x200000000 present)
    new_matches = []
    for off in range(mach_start, len(data) - 3, 4):
        insn_val = struct.unpack_from("<I", data, off)[0]
        if (insn_val & OLD_ENCODING_MASK) == (NEW_ENCODING_BASE & OLD_ENCODING_MASK):
            rd = insn_val & 0x1F
            if rd in SIZE_REGISTERS:
                new_matches.append((off, rd))

    if new_matches:
        regs = {rd for _, rd in new_matches}
        if regs == SIZE_REGISTERS:
            print(f"  [=] already patched: found MOV X{{{','.join(str(r) for r in sorted(regs))}}}, "
                  f"#0x{NEW_SIZE_8G:X}; no change")
            return 0

    print(f"  [.] found {len(matches)} MOV Xn, #0x{OLD_SIZE_6G:X} instructions")
    for off, rd in matches:
        print(f"      offset 0x{off:08X}: X{rd}")

    if len(matches) != EXPECTED_TOTAL_SITES:
        print(f"  [-] expected {EXPECTED_TOTAL_SITES} sites, found {len(matches)}; skipping")
        return 0

    size_sites = [(off, rd) for off, rd in matches if rd in SIZE_REGISTERS]
    if len(size_sites) != 2:
        print(f"  [-] expected 2 SIZE sites (X26, X10), found {len(size_sites)}; skipping")
        return 0

    found_regs = {rd for _, rd in size_sites}
    if found_regs != SIZE_REGISTERS:
        print(f"  [-] expected registers {SIZE_REGISTERS}, found {found_regs}; skipping")
        return 0

    # Context verification: X26 site should be preceded (within 12 bytes) by X22 (BASE)
    x26_site = next((off, rd) for off, rd in size_sites if rd == 26)
    x22_found = False
    for check_off in range(x26_site[0] - 12, x26_site[0], 4):
        if check_off < mach_start:
            continue
        check_val = struct.unpack_from("<I", data, check_off)[0]
        if (check_val & OLD_ENCODING_MASK) == OLD_ENCODING_BASE and (check_val & 0x1F) == 22:
            x22_found = True
            break
    if not x22_found:
        print(f"  [-] X22 (BASE) not found near X26 site; skipping (unexpected layout)")
        return 0

    print(f"  [+] X26 context verified: X22 (BASE) precedes X26 (SIZE)")

    if dry_run:
        for off, rd in size_sites:
            print(f"      would patch 0x{off:08X}: X{rd} 0x{OLD_SIZE_6G:X} -> 0x{NEW_SIZE_8G:X}")
        return 2

    patched = bytearray(data)
    for off, rd in size_sites:
        new_val = NEW_ENCODING_BASE | rd
        new_bytes = struct.pack("<I", new_val)
        old_bytes = data[off:off + 4]
        patched[off:off + 4] = new_bytes
        print(f"  [+] patched 0x{off:08X}: X{rd}  {old_bytes.hex()} -> {new_bytes.hex()}")

    with open(kc_path, "wb") as f:
        f.write(bytes(patched))

    # Verify
    with open(kc_path, "rb") as f:
        verify = f.read()
    for off, rd in size_sites:
        val = struct.unpack_from("<I", verify, off)[0]
        expected = NEW_ENCODING_BASE | rd
        if val != expected:
            raise RuntimeError(f"verify failed at 0x{off:08X}: 0x{val:08X} != 0x{expected:08X}")

    print(f"  [+] kernel shared region size patch complete: "
          f"0x{OLD_SIZE_6G:X} -> 0x{NEW_SIZE_8G:X}")
    return 2


def _self_test():
    """Verify the patch logic on a synthetic kernel stub."""
    import tempfile

    def mk_stub(path, size_val=OLD_SIZE_6G):
        """Create a minimal IM4P-like file with the expected instruction pattern."""
        # IM4P header (0x46 bytes)
        im4p_hdr = bytearray(0x46)
        im4p_hdr[0:4] = b"\x30\x84\x00\x00"
        im4p_hdr[8:12] = b"IMG4"
        # Mach-O starts at 0x46
        macho = bytearray(0x1000)
        macho[0:4] = struct.pack("<I", 0xFEEDFACF)
        # Place 5 MOV Xn, #0x180000000 instructions at known offsets
        regs_base = [8, 22, 11]  # non-SIZE registers
        regs_size = [26, 10]     # SIZE registers to patch
        off = 0x100
        for rd in regs_base:
            struct.pack_into("<I", macho, off, OLD_ENCODING_BASE | rd)
            off += 4
        # X22 (BASE) right before X26 (SIZE) for context check
        struct.pack_into("<I", macho, off, OLD_ENCODING_BASE | 22)
        off += 4  # X22
        off += 4  # DUP (skip)
        off += 4  # STR (skip)
        # SIZE encoding for X26
        if size_val == OLD_SIZE_6G:
            struct.pack_into("<I", macho, off, OLD_ENCODING_BASE | 26)
        else:
            struct.pack_into("<I", macho, off, NEW_ENCODING_BASE | 26)
        off += 0x100
        if size_val == OLD_SIZE_6G:
            struct.pack_into("<I", macho, off, OLD_ENCODING_BASE | 10)
        else:
            struct.pack_into("<I", macho, off, NEW_ENCODING_BASE | 10)

        data = bytes(im4p_hdr) + bytes(macho)
        with open(path, "wb") as f:
            f.write(data)
        return data

    def mk_stub_real(path, size_val=OLD_SIZE_6G):
        """Mimic the real kernel: exactly 5 MOV Xn, #0x180000000 instructions.
        Order: X8, X22 (BASE), X26 (SIZE), X10 (BOUNDS), X11."""
        im4p_hdr = bytearray(0x46)
        im4p_hdr[0:4] = b"\x30\x84\x00\x00"
        im4p_hdr[8:12] = b"IMG4"
        macho = bytearray(0x2000)
        macho[0:4] = struct.pack("<I", 0xFEEDFACF)
        off = 0x100
        # X8 (flag ORR — not patched)
        struct.pack_into("<I", macho, off, OLD_ENCODING_BASE | 8); off += 0x100
        # X22 (BASE — not patched)
        struct.pack_into("<I", macho, off, OLD_ENCODING_BASE | 22); off += 4
        # DUP + STR (filler)
        off += 8
        # X26 (SIZE — patched)
        enc = OLD_ENCODING_BASE | 26 if size_val == OLD_SIZE_6G else NEW_ENCODING_BASE | 26
        struct.pack_into("<I", macho, off, enc); off += 0x200
        # X10 (BOUNDS — patched)
        enc = OLD_ENCODING_BASE | 10 if size_val == OLD_SIZE_6G else NEW_ENCODING_BASE | 10
        struct.pack_into("<I", macho, off, enc); off += 0x100
        # X11 (0x180000001 — not patched)
        struct.pack_into("<I", macho, off, OLD_ENCODING_BASE | 11)
        with open(path, "wb") as f:
            f.write(bytes(im4p_hdr) + bytes(macho))

    with tempfile.NamedTemporaryFile(suffix=".kc", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        # Test 1: patch 6G -> 8G
        mk_stub_real(tmp_path, OLD_SIZE_6G)
        assert patch_kernel_shared_region_size(tmp_path) == 2
        # Test 2: idempotent (already patched)
        assert patch_kernel_shared_region_size(tmp_path) == 0
        # Test 3: already at 8G from the start
        mk_stub_real(tmp_path, NEW_SIZE_8G)
        assert patch_kernel_shared_region_size(tmp_path) == 0
    finally:
        os.unlink(tmp_path)
    print("self-test OK")


if __name__ == "__main__":
    _self_test()
