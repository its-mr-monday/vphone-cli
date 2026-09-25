// KernelJBPatchSharedRegionSize.swift — JB kernel patch: Enlarge SHARED_REGION_SIZE_ARM64.
//
// iOS 27.0 release (build 24A437) ships a 6.086 GiB dyld shared cache, overflowing
// the PCC vphone600 kernel's SHARED_REGION_SIZE_ARM64 = 0x180000000 (6 GiB).
// The maxSlide DSC patch (cfw_patch_dsc_maxslide.py) is insufficient because the
// cache's mapped span itself exceeds the region. This patch increases the arm64
// shared region size from 6 GiB to 8 GiB in vm_shared_region_lookup so the kernel
// allocates enough VA space for the cache to map successfully.

import Foundation

extension KernelJBPatcher {
    /// Patch `SHARED_REGION_SIZE_ARM64` from 0x180000000 (6 GiB) to 0x200000000 (8 GiB)
    /// in the arm64 branch of `vm_shared_region_lookup`.
    ///
    /// The compiler merges BASE and SIZE (both 0x180000000) via `dup v0.2d`:
    /// ```
    ///   mov  x22, #0x180000000       ; SIZE
    ///   dup  v0.2d, x22              ; v0 = {SIZE, SIZE}
    ///   str  q0, [sp, #0x70]         ; store struct {base, size}
    ///   mov  x26, #0x180000000       ; BASE
    ///   b    <common>
    /// ```
    /// We replace with separate stores so BASE stays 6 GiB and SIZE becomes 8 GiB:
    /// ```
    ///   mov  x26, #0x180000000       ; BASE (unchanged)
    ///   mov  x22, #0x200000000       ; SIZE = 8 GiB
    ///   stp  x26, x22, [sp, #0x70]  ; {base, size}
    ///   nop
    ///   b    <common>                ; unchanged
    /// ```
    @discardableResult
    func patchSharedRegionSize() -> Bool {
        log("\n[JB] SHARED_REGION_SIZE_ARM64: 6 GiB -> 8 GiB")

        // ORR Xd, XZR, #0x180000000 has a fixed encoding with only Rd varying.
        let orrBase: UInt32 = 0xB261_07E0 // rd=0 template
        let orrMask: UInt32 = 0xFFFF_FFE0

        // STR q0, [sp, #0x70] (exact encoding, verified from kernel binary)
        let strQ0Sp70: UInt32 = 0x3D80_1FE0

        // Scan __TEXT_EXEC for the 5-instruction pattern
        guard let (codeStart, codeEnd) = kernTextRange else {
            log("  [-] no __TEXT_EXEC range")
            return false
        }

        var patchOff = -1
        var sizeRd: UInt32 = 0
        var baseRd: UInt32 = 0
        var branchInsn: UInt32 = 0

        var off = codeStart
        while off + 20 <= codeEnd {
            let i0 = buffer.readU32(at: off)      // mov xN, #0x180000000 (SIZE)
            let i1 = buffer.readU32(at: off + 4)   // dup v0.2d, xN
            let i2 = buffer.readU32(at: off + 8)   // str q0, [sp, #0x70]
            let i3 = buffer.readU32(at: off + 12)  // mov xM, #0x180000000 (BASE)
            let i4 = buffer.readU32(at: off + 16)  // b <target>

            guard (i0 & orrMask) == orrBase,
                  i2 == strQ0Sp70,
                  (i3 & orrMask) == orrBase,
                  (i4 & 0xFC00_0000) == 0x1400_0000 // unconditional B
            else {
                off += 4
                continue
            }

            // Verify the DUP uses the same Rd as i0
            let rd0 = i0 & 0x1F
            // DUP v0.2d, xN encoding: 0x4E080C00 | (Rn << 5)
            // Actually: dup v0.2d, x<n> = 0x4E08_0C00 | (n << 5) ... but the
            // exact encoding depends on the element size. Let me check:
            // DUP (general) 64-bit: Q=1 [30], imm5=01000 (d lane), Rn, Rd(Vd)
            // = 0x4E08_0C00 | (Rn << 5) | Vd
            let expectedDup = 0x4E08_0C00 | (rd0 << 5) // Vd=0 (v0)
            guard i1 == expectedDup else {
                off += 4
                continue
            }

            sizeRd = rd0
            baseRd = i3 & 0x1F
            branchInsn = i4
            patchOff = off
            break
        }

        guard patchOff >= 0 else {
            log("  [-] shared region dup+str pattern not found in __TEXT_EXEC")
            return false
        }

        log("  [+] found at 0x\(String(format: "%06X", patchOff)): "
            + "sizeRd=x\(sizeRd), baseRd=x\(baseRd)")

        // Build the 5-instruction replacement (20 bytes)
        let movBase = orrBase | baseRd       // mov x<baseRd>, #0x180000000

        // ORR Xd, XZR, #0x200000000: N=1, immr=31, imms=0
        let orr200Base: UInt32 = 0xB25F_03E0
        let movSize = orr200Base | sizeRd    // mov x<sizeRd>, #0x200000000

        // STP x<baseRd>, x<sizeRd>, [sp, #0x70]
        // opc=10, V=0, type=010, L=0, imm7=14(0x70/8), Rt2=sizeRd, Rn=SP(31), Rt1=baseRd
        let stpInsn: UInt32 = (0b10 << 30) | (0b101 << 27) | (0b010 << 23)
            | (14 << 15) | (sizeRd << 10) | (31 << 5) | baseRd

        // Concatenate: movBase + movSize + stp + nop + branch
        var patch = Data()
        patch.append(ARM64.encodeU32(movBase))
        patch.append(ARM64.encodeU32(movSize))
        patch.append(ARM64.encodeU32(stpInsn))
        patch.append(ARM64.nop)
        patch.append(ARM64.encodeU32(branchInsn))

        let va = fileOffsetToVA(patchOff)
        emit(patchOff, Data(patch.prefix(4)),
             patchID: "kernelcache_jb.shared_region_size_0",
             virtualAddress: va,
             description: "mov x\(baseRd), #0x180000000 [BASE]")
        emit(patchOff + 4, Data(patch[4 ..< 8]),
             patchID: "kernelcache_jb.shared_region_size_1",
             virtualAddress: va.map { $0 + 4 },
             description: "mov x\(sizeRd), #0x200000000 [SIZE 8GiB]")
        emit(patchOff + 8, Data(patch[8 ..< 12]),
             patchID: "kernelcache_jb.shared_region_size_2",
             virtualAddress: va.map { $0 + 8 },
             description: "stp x\(baseRd), x\(sizeRd), [sp, #0x70]")
        emit(patchOff + 12, Data(patch[12 ..< 16]),
             patchID: "kernelcache_jb.shared_region_size_3",
             virtualAddress: va.map { $0 + 12 },
             description: "nop [pad]")

        return true
    }
}
