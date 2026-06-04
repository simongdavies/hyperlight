/*
Copyright 2025 The Hyperlight Authors.

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

use std::sync::LazyLock;

use hyperlight_common::outb::VmAction;
use mshv_bindings::{
    hv_message_type, hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_register_assoc, hv_register_name, hv_register_name_HV_ARM64_REGISTER_CPACR_EL1,
    hv_register_name_HV_ARM64_REGISTER_DBGBCR0_EL1, hv_register_name_HV_ARM64_REGISTER_DBGBVR0_EL1,
    hv_register_name_HV_ARM64_REGISTER_DBGWCR0_EL1, hv_register_name_HV_ARM64_REGISTER_DBGWVR0_EL1,
    hv_register_name_HV_ARM64_REGISTER_FPCR, hv_register_name_HV_ARM64_REGISTER_FPSR,
    hv_register_name_HV_ARM64_REGISTER_MAIR_EL1, hv_register_name_HV_ARM64_REGISTER_MDSCR_EL1,
    hv_register_name_HV_ARM64_REGISTER_PC, hv_register_name_HV_ARM64_REGISTER_PSTATE,
    hv_register_name_HV_ARM64_REGISTER_Q0, hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1,
    hv_register_name_HV_ARM64_REGISTER_SP_EL0, hv_register_name_HV_ARM64_REGISTER_SP_EL1,
    hv_register_name_HV_ARM64_REGISTER_TCR_EL1, hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1,
    hv_register_name_HV_ARM64_REGISTER_VBAR_EL1, hv_register_name_HV_ARM64_REGISTER_X0,
    hv_register_value, hv_u128, mshv_user_mem_region,
};
use mshv_ioctls::{Mshv, VcpuFd, VmFd, VmType};
use tracing::{Span, instrument};
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
use crate::hypervisor::virtual_machine::{
    CreateVmError, MapMemoryError, RegisterError, ResetVcpuError, RunVcpuError, UnmapMemoryError,
    VirtualMachine, VmExit,
};
use crate::mem::memory_region::MemoryRegion;
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

/// Number of general purpose registers (X0..=X30).
const NUM_GP_REGS: usize = 31;
/// Number of SIMD/FP vector registers (Q0..=Q31).
const NUM_VEC_REGS: usize = 32;

// AArch64 ESR_EL2.ISS field encodings for a Data Abort (see the Arm
// Architecture Reference Manual, "ISS encoding for an exception from a
// Data Abort"). These are used to decode the register and width of an
// MMIO store so that we can recover the value being written, which -
// unlike KVM - MSHV does not hand to us directly.
/// ISS.ISV (bit 24): instruction syndrome valid. When clear, the
/// register/size fields below are not meaningful.
const ESR_ISS_ISV: u64 = 1 << 24;
/// ISS.SAS (bits 23:22): access size (0=byte, 1=halfword, 2=word, 3=doubleword).
const ESR_ISS_SAS_SHIFT: u64 = 22;
const ESR_ISS_SAS_MASK: u64 = 0b11;
/// ISS.SRT (bits 20:16): the GP register number transferred.
const ESR_ISS_SRT_SHIFT: u64 = 16;
const ESR_ISS_SRT_MASK: u64 = 0b1_1111;
/// ISS.WnR (bit 6): write (1) or read (0).
const ESR_ISS_WNR: u64 = 1 << 6;
/// Register number 31 encodes the zero register (XZR), which reads as 0.
const ESR_XZR: u8 = 31;

static MSHV: LazyLock<std::result::Result<Mshv, CreateVmError>> =
    LazyLock::new(|| Mshv::new().map_err(|e| CreateVmError::HypervisorNotAvailable(e.into())));

/// Return `true` if the MSHV API is available
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    MSHV.as_ref().is_ok()
}

/// An MSHV implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct MshvVm {
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
}

/// Build a register association carrying a 64-bit value.
fn assoc64(name: hv_register_name, value: u64) -> hv_register_assoc {
    hv_register_assoc {
        name,
        value: hv_register_value { reg64: value },
        ..Default::default()
    }
}

/// Build a register association carrying a 128-bit value.
fn assoc128(name: hv_register_name, value: u128) -> hv_register_assoc {
    hv_register_assoc {
        name,
        value: hv_register_value {
            reg128: hv_u128 {
                low_part: value as u64,
                high_part: (value >> 64) as u64,
            },
        },
        ..Default::default()
    }
}

/// The hypervisor register name for GP register `n` (`0..=30`).
///
/// The MSHV `X0..=X28`, `FP` (X29) and `LR` (X30) register names are
/// contiguous, so a simple offset from `X0` is valid for the whole
/// `0..=30` range.
fn gp_reg_name(n: u8) -> hv_register_name {
    hv_register_name_HV_ARM64_REGISTER_X0 + n as u32
}

impl MshvVm {
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let mshv = MSHV.as_ref().map_err(|e| e.clone())?;

        // Use the standard partition setup for the host architecture.
        // On AArch64 this configures the processor feature banks
        // correctly (notably leaving GIC v3/v4 enabled, which MSHV
        // requires for ARM64 guests) and sets the synthetic processor
        // features property, which must happen before `initialize`.
        let vm_fd = mshv
            .create_vm_with_type(VmType::Normal)
            .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;

        vm_fd
            .initialize()
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

        let vcpu_fd = vm_fd
            .create_vcpu(0)
            .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;

        Ok(Self { vm_fd, vcpu_fd })
    }

    /// Read a batch of registers, returning their associations.
    fn get_regs_raw(
        &self,
        names: &[hv_register_name],
    ) -> std::result::Result<Vec<hv_register_assoc>, mshv_ioctls::MshvError> {
        let mut assocs: Vec<hv_register_assoc> = names
            .iter()
            .map(|&name| hv_register_assoc {
                name,
                ..Default::default()
            })
            .collect();
        self.vcpu_fd.get_reg(&mut assocs)?;
        Ok(assocs)
    }

    /// Read a single 64-bit register.
    fn get_reg64(
        &self,
        name: hv_register_name,
    ) -> std::result::Result<u64, mshv_ioctls::MshvError> {
        let assocs = self.get_regs_raw(&[name])?;
        // SAFETY: we requested a single register and read it back as a 64-bit value.
        Ok(unsafe { assocs[0].value.reg64 })
    }

    /// Read the value of GP register `n` (`0..=30`), or 0 for XZR (`n == 31`).
    fn get_gp_reg(&self, n: u8) -> std::result::Result<u64, mshv_ioctls::MshvError> {
        if n >= ESR_XZR {
            return Ok(0);
        }
        self.get_reg64(gp_reg_name(n))
    }

    /// Recover the value written by an MMIO store from the data abort syndrome.
    ///
    /// `esr` is the AArch64 ESR_EL2 value reported in the memory
    /// intercept message. Returns the little-endian bytes of the store,
    /// matching the width encoded in `ISS.SAS`.
    fn mmio_write_data(&self, esr: u64) -> std::result::Result<Vec<u8>, RunVcpuError> {
        if esr & ESR_ISS_ISV == 0 {
            // Without a valid instruction syndrome we cannot determine
            // the source register or width of the store.
            return Err(RunVcpuError::ParseGpaAccessInfo);
        }
        let srt = ((esr >> ESR_ISS_SRT_SHIFT) & ESR_ISS_SRT_MASK) as u8;
        let sas = (esr >> ESR_ISS_SAS_SHIFT) & ESR_ISS_SAS_MASK;
        let nbytes = 1usize << sas;
        let value = self
            .get_gp_reg(srt)
            .map_err(|e| RunVcpuError::Unknown(e.into()))?;
        Ok(value.to_le_bytes()[..nbytes].to_vec())
    }
}

impl VirtualMachine for MshvVm {
    unsafe fn map_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd
            .map_user_memory(mshv_region)
            .map_err(|e| MapMemoryError::Hypervisor(e.into()))
    }

    fn unmap_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd
            .unmap_user_memory(mshv_region)
            .map_err(|e| UnmapMemoryError::Hypervisor(e.into()))
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        const UNMAPPED_GPA_MESSAGE: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const GPA_INTERCEPT_MESSAGE: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;

        // setup_guest_trace must be called right before vcpu_fd.run(), because
        // it sets the guest span; no other traces or spans must be set up in
        // between these calls.
        #[cfg(feature = "trace_guest")]
        tc.setup_guest_trace(Span::current().context());

        let exit_reason = self.vcpu_fd.run();
        match exit_reason {
            Ok(m) => {
                let msg_type = m.header.message_type;
                match msg_type {
                    UNMAPPED_GPA_MESSAGE | GPA_INTERCEPT_MESSAGE => {
                        let info = m
                            .to_memory_info()
                            .map_err(|_| RunVcpuError::DecodeIOMessage(msg_type))?;
                        let addr = info.guest_physical_address;
                        let esr = info.syndrome;
                        let is_write = esr & ESR_ISS_WNR != 0;

                        let io_page_gpa = const { hyperlight_common::layout::io_page().unwrap().0 };
                        if is_write
                            && addr > io_page_gpa
                            && let off = (addr - io_page_gpa) as usize
                            && off < hyperlight_common::vmem::PAGE_SIZE
                        {
                            // A write into the I/O page: this is the guest
                            // signalling the host. Unlike KVM, MSHV does not
                            // advance the program counter over the faulting
                            // instruction, so do it here before returning so
                            // that the guest resumes after the store on the
                            // next entry.
                            let pc = info.header.pc;
                            let instruction_length = info.header.instruction_length as u64;
                            self.vcpu_fd
                                .set_reg(&[assoc64(
                                    hv_register_name_HV_ARM64_REGISTER_PC,
                                    pc + instruction_length,
                                )])
                                .map_err(|e| RunVcpuError::IncrementRip(e.into()))?;

                            let port = off / core::mem::size_of::<u64>();
                            if port == VmAction::Halt as usize {
                                Ok(VmExit::Halt())
                            } else {
                                let data = self.mmio_write_data(esr)?;
                                Ok(VmExit::IoOut(port as u16, data))
                            }
                        } else if is_write {
                            Ok(VmExit::MmioWrite(addr))
                        } else {
                            Ok(VmExit::MmioRead(addr))
                        }
                    }
                    other => Ok(VmExit::Unknown(format!(
                        "Unknown MSHV VCPU exit: {:?}",
                        other
                    ))),
                }
            }
            Err(e) => match e.errno() {
                libc::EINTR => Ok(VmExit::Cancelled()),
                libc::EAGAIN => Ok(VmExit::Retry()),
                _ => Err(RunVcpuError::Unknown(e.into())),
            },
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        let mut names = Vec::with_capacity(NUM_GP_REGS + 3);
        for n in 0..NUM_GP_REGS as u8 {
            names.push(gp_reg_name(n));
        }
        // The guest runs in EL1t (SPSel = 0), so the active stack
        // pointer is SP_EL0. KVM's core `SP` register maps to the same
        // SP_EL0, so we use it here too to match guest expectations.
        names.push(hv_register_name_HV_ARM64_REGISTER_SP_EL0);
        names.push(hv_register_name_HV_ARM64_REGISTER_PC);
        names.push(hv_register_name_HV_ARM64_REGISTER_PSTATE);

        let assocs = self
            .get_regs_raw(&names)
            .map_err(|e| RegisterError::GetRegs(e.into()))?;

        let mut x = [0u64; NUM_GP_REGS];
        // SAFETY: every register was requested as a 64-bit value.
        unsafe {
            for (i, slot) in x.iter_mut().enumerate() {
                *slot = assocs[i].value.reg64;
            }
            Ok(CommonRegisters {
                x,
                sp: assocs[NUM_GP_REGS].value.reg64,
                pc: assocs[NUM_GP_REGS + 1].value.reg64,
                pstate: assocs[NUM_GP_REGS + 2].value.reg64,
            })
        }
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        let mut assocs = Vec::with_capacity(NUM_GP_REGS + 3);
        for (n, &value) in regs.x.iter().enumerate() {
            assocs.push(assoc64(gp_reg_name(n as u8), value));
        }
        assocs.push(assoc64(hv_register_name_HV_ARM64_REGISTER_SP_EL0, regs.sp));
        assocs.push(assoc64(hv_register_name_HV_ARM64_REGISTER_PC, regs.pc));
        assocs.push(assoc64(
            hv_register_name_HV_ARM64_REGISTER_PSTATE,
            regs.pstate,
        ));
        self.vcpu_fd
            .set_reg(&assocs)
            .map_err(|e| RegisterError::SetRegs(e.into()))
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        let mut names = Vec::with_capacity(NUM_VEC_REGS + 2);
        for n in 0..NUM_VEC_REGS as u32 {
            names.push(hv_register_name_HV_ARM64_REGISTER_Q0 + n);
        }
        names.push(hv_register_name_HV_ARM64_REGISTER_FPSR);
        names.push(hv_register_name_HV_ARM64_REGISTER_FPCR);

        let assocs = self
            .get_regs_raw(&names)
            .map_err(|e| RegisterError::GetFpu(e.into()))?;

        let mut v = [0u128; NUM_VEC_REGS];
        // SAFETY: vector registers were requested as 128-bit values and the
        // status/control registers as 64-bit values.
        unsafe {
            for (i, slot) in v.iter_mut().enumerate() {
                let q = assocs[i].value.reg128;
                *slot = (q.high_part as u128) << 64 | q.low_part as u128;
            }
            Ok(CommonFpu {
                v,
                fpsr: assocs[NUM_VEC_REGS].value.reg64 as u32,
                fpcr: assocs[NUM_VEC_REGS + 1].value.reg64 as u32,
            })
        }
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        let mut assocs = Vec::with_capacity(NUM_VEC_REGS + 2);
        for (n, &value) in fpu.v.iter().enumerate() {
            assocs.push(assoc128(
                hv_register_name_HV_ARM64_REGISTER_Q0 + n as u32,
                value,
            ));
        }
        assocs.push(assoc64(
            hv_register_name_HV_ARM64_REGISTER_FPSR,
            fpu.fpsr as u64,
        ));
        assocs.push(assoc64(
            hv_register_name_HV_ARM64_REGISTER_FPCR,
            fpu.fpcr as u64,
        ));
        self.vcpu_fd
            .set_reg(&assocs)
            .map_err(|e| RegisterError::SetFpu(e.into()))
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        let names = [
            hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1,
            hv_register_name_HV_ARM64_REGISTER_TCR_EL1,
            hv_register_name_HV_ARM64_REGISTER_MAIR_EL1,
            hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1,
            hv_register_name_HV_ARM64_REGISTER_CPACR_EL1,
            hv_register_name_HV_ARM64_REGISTER_VBAR_EL1,
            hv_register_name_HV_ARM64_REGISTER_SP_EL1,
        ];
        let assocs = self
            .get_regs_raw(&names)
            .map_err(|e| RegisterError::GetSregs(e.into()))?;
        // SAFETY: every special register was requested as a 64-bit value.
        unsafe {
            Ok(CommonSpecialRegisters {
                ttbr0_el1: assocs[0].value.reg64,
                tcr_el1: assocs[1].value.reg64,
                mair_el1: assocs[2].value.reg64,
                sctlr_el1: assocs[3].value.reg64,
                cpacr_el1: assocs[4].value.reg64,
                vbar_el1: assocs[5].value.reg64,
                sp_el1: assocs[6].value.reg64,
            })
        }
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        let assocs = [
            assoc64(
                hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1,
                sregs.ttbr0_el1,
            ),
            assoc64(hv_register_name_HV_ARM64_REGISTER_TCR_EL1, sregs.tcr_el1),
            assoc64(hv_register_name_HV_ARM64_REGISTER_MAIR_EL1, sregs.mair_el1),
            assoc64(
                hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1,
                sregs.sctlr_el1,
            ),
            assoc64(
                hv_register_name_HV_ARM64_REGISTER_CPACR_EL1,
                sregs.cpacr_el1,
            ),
            assoc64(hv_register_name_HV_ARM64_REGISTER_VBAR_EL1, sregs.vbar_el1),
            assoc64(hv_register_name_HV_ARM64_REGISTER_SP_EL1, sregs.sp_el1),
        ];
        self.vcpu_fd
            .set_reg(&assocs)
            .map_err(|e| RegisterError::SetSregs(e.into()))
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        todo!()
    }

    fn set_debug_regs(&self, _drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError> {
        todo!()
    }

    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError> {
        unimplemented!("aarch64 does not support XSAVE operations")
    }

    fn reset_xsave(&self) -> std::result::Result<(), RegisterError> {
        unimplemented!("aarch64 does not support XSAVE operations")
    }

    #[cfg(test)]
    fn set_xsave(&self, _xsave: &[u32]) -> std::result::Result<(), RegisterError> {
        unimplemented!("aarch64 does not support XSAVE operations")
    }

    fn can_reset_vcpu(&self) -> bool {
        true
    }

    fn reset_vcpu(&mut self) -> std::result::Result<(), ResetVcpuError> {
        // Clear the guest-visible debug state on reset, mirroring what KVM
        // does on AArch64 vcpu reset. KVM's table-driven sysreg reset
        // (`reset_dbg_wb_reg`/`reset_val` in `arch/arm64/kvm/sys_regs.c`)
        // zeroes MDSCR_EL1, MDCCINT_EL1 and every implemented breakpoint
        // (DBGBCR<n>/DBGBVR<n>) and watchpoint (DBGWCR<n>/DBGWVR<n>)
        // register. KVM can blindly zero all 16 banks because it only
        // writes an in-memory software shadow; MSHV's `set_reg` instead
        // reaches the hypervisor, which rejects writes to debug-register
        // indices beyond the count the CPU actually implements
        // (`AccessDenied`). KVM derives that count from ID_AA64DFR0_EL1,
        // but MSHV exposes neither that ID register nor a vcpu-reset
        // primitive, so we cannot enumerate the implemented banks.
        //
        // We therefore clear only index 0 of each bank, which the Arm
        // architecture guarantees is always implemented (the BRPs/WRPs
        // fields of ID_AA64DFR0_EL1 are "minus one" encoded, so at least
        // one breakpoint and one watchpoint always exist). This is a
        // strict subset of KVM's reset using the same zero reset value,
        // and issues no rejected hypercalls. The caller
        // (`HyperlightVm::reset_vcpu`) restores the special registers and
        // the next guest dispatch rewrites all GP and FP registers, so no
        // further reset work is required here.
        //
        // Each register is written with its own `set_reg` hypercall:
        // MSHV rejects a single batched `set_reg` carrying all of these
        // debug registers together with `InvalidParameter`, even though
        // every one of them is accepted on its own.
        const RESET_REGS: [hv_register_name; 5] = [
            hv_register_name_HV_ARM64_REGISTER_MDSCR_EL1,
            hv_register_name_HV_ARM64_REGISTER_DBGBCR0_EL1,
            hv_register_name_HV_ARM64_REGISTER_DBGBVR0_EL1,
            hv_register_name_HV_ARM64_REGISTER_DBGWCR0_EL1,
            hv_register_name_HV_ARM64_REGISTER_DBGWVR0_EL1,
        ];
        for name in RESET_REGS {
            self.vcpu_fd
                .set_reg(&[assoc64(name, 0)])
                .map_err(|e| ResetVcpuError::Register(RegisterError::SetRegs(e.into())))?;
        }
        Ok(())
    }
}
