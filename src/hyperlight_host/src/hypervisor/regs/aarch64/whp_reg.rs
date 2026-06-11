/*
Copyright 2026 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! Marshalling between the architecture-neutral [`CommonRegisters`],
//! [`CommonFpu`] and [`CommonSpecialRegisters`] types and the Windows
//! Hypervisor Platform (WHP) register name/value representation for aarch64.
//!
//! The `windows` crate (0.62) does **not** generate the WHP runtime ARM64
//! register-name constants (the `WHvArm64Register*` values of type
//! [`WHV_REGISTER_NAME`]); it only exposes the unrelated `REGISTER_ID`
//! constants used by the saved-state-dump API, which cannot be used with
//! `WHvGet/SetVirtualProcessorRegisters`. We therefore define the constants we
//! need here. The numeric values are taken verbatim from the Windows SDK
//! header `WinHvPlatformDefs.h` and are stable ABI.

use windows::Win32::System::Hypervisor::{WHV_REGISTER_NAME, WHV_REGISTER_VALUE};

use super::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::regs::Align16;

// --- WHP ARM64 register-name constants (from WinHvPlatformDefs.h) ---
// General-purpose registers X0..X30 are contiguous: X0..X28 then Fp (X29) and
// Lr (X30), so `WHV_ARM64_X0.0 + n` is valid for the whole `0..=30` range.
const WHV_ARM64_X0: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0002_0000);
/// Stack pointer for EL0. The guest runs in EL1t (`SPSel == 0`), so the active
/// stack pointer is `SP_EL0`; this matches the KVM/MSHV backends which map the
/// common `sp` to `SP_EL0`.
pub(crate) const WHV_ARM64_SP_EL0: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0002_0020);
const WHV_ARM64_SP_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0002_0021);
pub(crate) const WHV_ARM64_PC: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0002_0022);
const WHV_ARM64_PSTATE: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0002_0023);
const WHV_ARM64_Q0: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0003_0000);
const WHV_ARM64_FPCR: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004_0012);
const WHV_ARM64_FPSR: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004_0013);
const WHV_ARM64_SCTLR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004_0002);
const WHV_ARM64_CPACR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004_0004);
const WHV_ARM64_TTBR0_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004_0005);
const WHV_ARM64_TCR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004_0007);
const WHV_ARM64_MAIR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004_000B);
const WHV_ARM64_VBAR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004_000C);

// --- ARM64 debug registers, cleared on vcpu reset (see `reset_vcpu`). ---
pub(crate) const WHV_ARM64_MDSCR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0005_004D);
pub(crate) const WHV_ARM64_DBGBCR0_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0005_0000);
pub(crate) const WHV_ARM64_DBGBVR0_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0005_0020);
pub(crate) const WHV_ARM64_DBGWCR0_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0005_0010);
pub(crate) const WHV_ARM64_DBGWVR0_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0005_0030);

/// Number of general-purpose registers (X0..=X30).
const NUM_GP_REGS: usize = 31;
/// Number of SIMD/FP vector registers (Q0..=Q31).
const NUM_VEC_REGS: usize = 32;

/// Number of registers in the [`CommonRegisters`] WHP batch
/// (X0..=X30, SP_EL0, PC, PSTATE).
pub(crate) const REGS_LEN: usize = NUM_GP_REGS + 3;
/// Number of registers in the [`CommonFpu`] WHP batch (Q0..=Q31, FPSR, FPCR).
pub(crate) const FPU_LEN: usize = NUM_VEC_REGS + 2;
/// Number of registers in the [`CommonSpecialRegisters`] WHP batch.
pub(crate) const SREGS_LEN: usize = 7;

/// The WHP register name for general-purpose register `n` (`0..=30`).
pub(crate) fn gp_reg_name(n: u8) -> WHV_REGISTER_NAME {
    debug_assert!((n as usize) < NUM_GP_REGS);
    WHV_REGISTER_NAME(WHV_ARM64_X0.0 + n as i32)
}

/// The WHP register name for vector register `n` (`0..=31`).
fn vec_reg_name(n: u8) -> WHV_REGISTER_NAME {
    debug_assert!((n as usize) < NUM_VEC_REGS);
    WHV_REGISTER_NAME(WHV_ARM64_Q0.0 + n as i32)
}

/// Wrap a 64-bit value as an aligned WHP register value.
pub(crate) fn val64(value: u64) -> Align16<WHV_REGISTER_VALUE> {
    Align16(WHV_REGISTER_VALUE { Reg64: value })
}

/// Wrap a 128-bit value as an aligned WHP register value.
fn val128(value: u128) -> Align16<WHV_REGISTER_VALUE> {
    Align16(WHV_REGISTER_VALUE {
        Reg128: windows::Win32::System::Hypervisor::WHV_UINT128 {
            Anonymous: windows::Win32::System::Hypervisor::WHV_UINT128_0 {
                Low64: value as u64,
                High64: (value >> 64) as u64,
            },
        },
    })
}

/// Read a 64-bit value out of an aligned WHP register value.
///
/// # Safety
/// The value must have been written as a 64-bit register (which is the case for
/// every name produced by [`regs_names`]/[`sregs_names`]).
unsafe fn read64(value: &Align16<WHV_REGISTER_VALUE>) -> u64 {
    unsafe { value.0.Reg64 }
}

/// The ordered WHP register names for a [`CommonRegisters`] batch.
pub(crate) fn regs_names() -> [WHV_REGISTER_NAME; REGS_LEN] {
    let mut names = [WHV_ARM64_X0; REGS_LEN];
    for (n, slot) in names.iter_mut().enumerate().take(NUM_GP_REGS) {
        *slot = gp_reg_name(n as u8);
    }
    names[NUM_GP_REGS] = WHV_ARM64_SP_EL0;
    names[NUM_GP_REGS + 1] = WHV_ARM64_PC;
    names[NUM_GP_REGS + 2] = WHV_ARM64_PSTATE;
    names
}

/// The WHP register values for a [`CommonRegisters`], in [`regs_names`] order.
pub(crate) fn regs_values(regs: &CommonRegisters) -> [Align16<WHV_REGISTER_VALUE>; REGS_LEN] {
    let mut values = [val64(0); REGS_LEN];
    for (n, slot) in values.iter_mut().enumerate().take(NUM_GP_REGS) {
        *slot = val64(regs.x[n]);
    }
    values[NUM_GP_REGS] = val64(regs.sp);
    values[NUM_GP_REGS + 1] = val64(regs.pc);
    values[NUM_GP_REGS + 2] = val64(regs.pstate);
    values
}

/// Parse a [`CommonRegisters`] from WHP values returned in [`regs_names`] order.
pub(crate) fn regs_from_values(
    values: &[Align16<WHV_REGISTER_VALUE>; REGS_LEN],
) -> CommonRegisters {
    let mut x = [0u64; NUM_GP_REGS];
    // SAFETY: every register in this batch was requested as a 64-bit value.
    unsafe {
        for (n, slot) in x.iter_mut().enumerate() {
            *slot = read64(&values[n]);
        }
        CommonRegisters {
            x,
            sp: read64(&values[NUM_GP_REGS]),
            pc: read64(&values[NUM_GP_REGS + 1]),
            pstate: read64(&values[NUM_GP_REGS + 2]),
        }
    }
}

/// The ordered WHP register names for a [`CommonFpu`] batch.
pub(crate) fn fpu_names() -> [WHV_REGISTER_NAME; FPU_LEN] {
    let mut names = [WHV_ARM64_Q0; FPU_LEN];
    for (n, slot) in names.iter_mut().enumerate().take(NUM_VEC_REGS) {
        *slot = vec_reg_name(n as u8);
    }
    names[NUM_VEC_REGS] = WHV_ARM64_FPSR;
    names[NUM_VEC_REGS + 1] = WHV_ARM64_FPCR;
    names
}

/// The WHP register values for a [`CommonFpu`], in [`fpu_names`] order.
pub(crate) fn fpu_values(fpu: &CommonFpu) -> [Align16<WHV_REGISTER_VALUE>; FPU_LEN] {
    let mut values = [val64(0); FPU_LEN];
    for (n, slot) in values.iter_mut().enumerate().take(NUM_VEC_REGS) {
        *slot = val128(fpu.v[n]);
    }
    values[NUM_VEC_REGS] = val64(fpu.fpsr as u64);
    values[NUM_VEC_REGS + 1] = val64(fpu.fpcr as u64);
    values
}

/// Parse a [`CommonFpu`] from WHP values returned in [`fpu_names`] order.
pub(crate) fn fpu_from_values(values: &[Align16<WHV_REGISTER_VALUE>; FPU_LEN]) -> CommonFpu {
    let mut v = [0u128; NUM_VEC_REGS];
    // SAFETY: vector registers were requested as 128-bit values and the
    // status/control registers as 64-bit values.
    unsafe {
        for (n, slot) in v.iter_mut().enumerate() {
            let q = values[n].0.Reg128.Anonymous;
            *slot = (q.High64 as u128) << 64 | q.Low64 as u128;
        }
        CommonFpu {
            v,
            fpsr: read64(&values[NUM_VEC_REGS]) as u32,
            fpcr: read64(&values[NUM_VEC_REGS + 1]) as u32,
        }
    }
}

/// The ordered WHP register names for a [`CommonSpecialRegisters`] batch.
pub(crate) fn sregs_names() -> [WHV_REGISTER_NAME; SREGS_LEN] {
    [
        WHV_ARM64_TTBR0_EL1,
        WHV_ARM64_TCR_EL1,
        WHV_ARM64_MAIR_EL1,
        WHV_ARM64_SCTLR_EL1,
        WHV_ARM64_CPACR_EL1,
        WHV_ARM64_VBAR_EL1,
        WHV_ARM64_SP_EL1,
    ]
}

/// The WHP register values for a [`CommonSpecialRegisters`], in
/// [`sregs_names`] order.
pub(crate) fn sregs_values(
    sregs: &CommonSpecialRegisters,
) -> [Align16<WHV_REGISTER_VALUE>; SREGS_LEN] {
    [
        val64(sregs.ttbr0_el1),
        val64(sregs.tcr_el1),
        val64(sregs.mair_el1),
        val64(sregs.sctlr_el1),
        val64(sregs.cpacr_el1),
        val64(sregs.vbar_el1),
        val64(sregs.sp_el1),
    ]
}

/// Parse a [`CommonSpecialRegisters`] from WHP values in [`sregs_names`] order.
pub(crate) fn sregs_from_values(
    values: &[Align16<WHV_REGISTER_VALUE>; SREGS_LEN],
) -> CommonSpecialRegisters {
    // SAFETY: every special register in this batch was requested as 64-bit.
    unsafe {
        CommonSpecialRegisters {
            ttbr0_el1: read64(&values[0]),
            tcr_el1: read64(&values[1]),
            mair_el1: read64(&values[2]),
            sctlr_el1: read64(&values[3]),
            cpacr_el1: read64(&values[4]),
            vbar_el1: read64(&values[5]),
            sp_el1: read64(&values[6]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_regs() {
        let mut original = CommonRegisters {
            sp: 0x1234,
            pc: 0x5678,
            pstate: 0x3c4,
            ..Default::default()
        };
        for (i, slot) in original.x.iter_mut().enumerate() {
            *slot = 0x1000 + i as u64;
        }
        let names = regs_names();
        let values = regs_values(&original);
        assert_eq!(names.len(), values.len());
        let round_tripped = regs_from_values(&values);
        assert_eq!(original, round_tripped);
    }

    #[test]
    fn round_trip_fpu() {
        let mut original = CommonFpu {
            fpsr: 0xaa,
            fpcr: 0xbb,
            ..Default::default()
        };
        for (i, slot) in original.v.iter_mut().enumerate() {
            *slot = ((i as u128) << 64) | (0xdead_0000 + i as u128);
        }
        let values = fpu_values(&original);
        let round_tripped = fpu_from_values(&values);
        assert_eq!(original, round_tripped);
    }

    #[test]
    fn round_trip_sregs() {
        let original = CommonSpecialRegisters {
            ttbr0_el1: 0x1,
            tcr_el1: 0x2,
            mair_el1: 0x3,
            sctlr_el1: 0x4,
            cpacr_el1: 0x5,
            vbar_el1: 0x6,
            sp_el1: 0x7,
        };
        let values = sregs_values(&original);
        let round_tripped = sregs_from_values(&values);
        assert_eq!(original, round_tripped);
    }
}
