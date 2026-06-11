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

//! Windows Hypervisor Platform (WHP) backend for aarch64 guests.

use std::os::raw::c_void;

use hyperlight_common::outb::VmAction;
#[cfg(feature = "trace_guest")]
use tracing::Span;
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;
use windows::Win32::System::Hypervisor::*;

use super::WhpVm;
use crate::hypervisor::regs::whp_reg;
use crate::hypervisor::regs::{
    Align16, CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
use crate::hypervisor::surrogate_process_manager::get_surrogate_process_manager;
use crate::hypervisor::virtual_machine::{
    CreateVmError, MapMemoryError, RegisterError, ResetVcpuError, RunVcpuError, UnmapMemoryError,
    VirtualMachine, VmExit,
};
use crate::mem::memory_region::MemoryRegion;
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

/// AArch64 instructions are a fixed 4 bytes wide.
const AARCH64_INSTRUCTION_LEN: u64 = 4;
/// Register number 31 in a load/store encodes the zero register (XZR), which
/// reads as 0 (it is *not* the stack pointer for these encodings).
const REG_XZR: u8 = 31;

// --- ARM64 VM-exit reason codes (from `WinHvPlatformDefs.h`) ---
//
// The `windows` crate (0.62) only generates the x86-64 values of the
// `WHvRunVpExitReason*` constants (e.g. `MemoryAccess == 0x1`,
// `Canceled == 0x2001`). On ARM64 the runtime reports different values, so we
// match against the ARM64 codes here.
//
/// Guest accessed an unmapped guest-physical address (MMIO).
const WHV_EXIT_REASON_ARM64_UNMAPPED_GPA: i32 = 0x8000_0000u32 as i32;
/// Guest accessed a GPA that is configured to intercept (MMIO).
const WHV_EXIT_REASON_ARM64_GPA_INTERCEPT: i32 = 0x8000_0001u32 as i32;
/// Execution was cancelled by the host (`WHvCancelRunVirtualProcessor`).
const WHV_EXIT_REASON_ARM64_CANCELED: i32 = 0xFFFF_FFFFu32 as i32;

// --- ARM64 interrupt-controller (GIC) partition configuration ---
//
// Unlike MSHV on Linux (which auto-configures the GIC when the partition is
// created with the standard processor-feature banks), WHP requires the GIC v3
// parameters to be set explicitly via `WHvPartitionPropertyCodeArm64IcParameters`
// before `WHvSetupPartition`, otherwise setup fails with
// `WHV_E_INVALID_PARTITION_CONFIG` (0x80370304). The `windows` crate (0.62) does
// not generate these ARM64-specific types, so we define them here to match the
// Windows SDK header `WinHvPlatformDefs.h` (ABI-stable). The Hyperlight guest
// runs with interrupts masked and contains no GIC driver, so it never accesses
// these MMIO regions; the addresses only need to be valid and not overlap mapped
// guest RAM.

/// `WHvPartitionPropertyCodeArm64IcParameters` (from `WinHvPlatformDefs.h`).
const WHV_PARTITION_PROPERTY_CODE_ARM64_IC_PARAMETERS: WHV_PARTITION_PROPERTY_CODE =
    WHV_PARTITION_PROPERTY_CODE(0x0000_1012);

/// `WHvArm64IcEmulationModeGicV3` (from `WHV_ARM64_IC_EMULATION_MODE`).
const WHV_ARM64_IC_EMULATION_MODE_GIC_V3: u32 = 1;

/// Base GPA of the emulated GIC distributor (GICD). Placed immediately above the
/// top of guest physical memory (the I/O page sits just under 64 GiB), so it
/// cannot overlap any mapped sandbox memory.
const GIC_DISTRIBUTOR_BASE_GPA: u64 = 0x0000_0010_0000_0000;
/// Base GPA of the GIC ITS translater register, placed just above the GICD.
const GIC_ITS_TRANSLATER_BASE_GPA: u64 = 0x0000_0010_0001_0000;
/// Architectural PPI INTID for the virtual timer (CNTV) interrupt.
const GIC_PPI_CNTV: u32 = 27;
/// Architectural PPI INTID for the performance-monitors (PMU) interrupt.
const GIC_PPI_PMU: u32 = 23;

/// `WHV_ARM64_IC_GIC_V3_PARAMETERS` (from `WinHvPlatformDefs.h`, 56 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct WhvArm64IcGicV3Parameters {
    gicd_base_address: u64,
    gits_translater_base_address: u64,
    reserved: u32,
    gic_lpi_int_id_bits: u32,
    gic_ppi_overflow_interrupt_from_cntv: u32,
    gic_ppi_performance_monitors_interrupt: u32,
    reserved1: [u32; 6],
}

/// `WHV_ARM64_IC_PARAMETERS` (from `WinHvPlatformDefs.h`, 64 bytes). The original
/// is a union over a single GIC v3 member, which is equivalent to this struct.
#[repr(C)]
#[derive(Clone, Copy)]
struct WhvArm64IcParameters {
    emulation_mode: u32,
    reserved: u32,
    gic_v3: WhvArm64IcGicV3Parameters,
}

const _: () = {
    assert!(std::mem::size_of::<WhvArm64IcGicV3Parameters>() == 56);
    assert!(std::mem::size_of::<WhvArm64IcParameters>() == 64);
};

/// ARM64 variant of `WHV_RUN_VP_EXIT_CONTEXT` (from `WinHvPlatformDefs.h`,
/// 272 bytes).
///
/// The `windows` crate (0.62) only generates the x86-64 `WHV_RUN_VP_EXIT_CONTEXT`
/// and `WHV_MEMORY_ACCESS_CONTEXT`. On ARM64 the SDK (`WinHvPlatformDefs.h`)
/// defines completely different structs:
///
/// - `WHV_RUN_VP_EXIT_CONTEXT` is 272 bytes: ExitReason(4) + Reserved(4) +
///   Reserved1(8) + union AsUINT64[32] (256).
/// - The union's `WHV_MEMORY_ACCESS_CONTEXT` is **64 bytes** (not 40) and has a
///   `WHV_INTERCEPT_MESSAGE_HEADER` at the start, different field order (Gva
///   before Gpa), a `Syndrome` field, and only 4 instruction bytes.
///
/// We define the ARM64-correct layouts here.
#[repr(C)]
#[derive(Clone, Copy)]
struct WhvArm64RunVpExitContext {
    exit_reason: i32,
    reserved: u32,
    reserved1: u64,
    union_data: [u64; 32],
}

const _: () = {
    assert!(std::mem::size_of::<WhvArm64RunVpExitContext>() == 272);
};

/// ARM64 `WHV_INTERCEPT_MESSAGE_HEADER` (24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct WhvArm64InterceptHeader {
    vp_index: u32,
    instruction_length: u8,
    intercept_access_type: u8, // WHV_MEMORY_ACCESS_TYPE (0=read,1=write,2=exec)
    execution_state: u16,
    pc: u64,
    cpsr: u64,
}

/// ARM64 `WHV_MEMORY_ACCESS_CONTEXT` (64 bytes) — completely different from x86.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct WhvArm64MemoryAccessContext {
    header: WhvArm64InterceptHeader,   // 24 bytes
    reserved0: u32,                     // 4 bytes
    instruction_byte_count: u8,         // 1 byte
    access_info: u8,                    // 1 byte (GvaValid:1, GvaGpaValid:1, ...)
    reserved1: u16,                     // 2 bytes
    instruction_bytes: [u8; 4],         // 4 bytes
    reserved2: u32,                     // 4 bytes
    gva: u64,                           // 8 bytes — NOTE: Gva BEFORE Gpa!
    gpa: u64,                           // 8 bytes
    syndrome: u64,                      // 8 bytes (ESR_EL2 equivalent)
}

const _: () = {
    assert!(std::mem::size_of::<WhvArm64MemoryAccessContext>() == 64);
};

impl WhpVm {
    /// Query the host's supported ARM64 processor-feature banks and synthetic
    /// processor-feature banks and apply them to the partition. Must be called
    /// after `WHvCreatePartition` and before `WHvSetupPartition`.
    ///
    /// # Safety
    /// `partition` must be a valid partition handle that has been created but
    /// not yet set up.
    unsafe fn set_processor_features(
        partition: WHV_PARTITION_HANDLE,
    ) -> Result<(), CreateVmError> {
        // Processor feature banks (architectural CPU features).
        let mut banks: WHV_PROCESSOR_FEATURES_BANKS = Default::default();
        // The capability buffer is also an input buffer: request both banks.
        banks.BanksCount = 2;
        unsafe {
            WHvGetCapability(
                WHvCapabilityCodeProcessorFeaturesBanks,
                &mut banks as *mut _ as *mut c_void,
                std::mem::size_of::<WHV_PROCESSOR_FEATURES_BANKS>() as u32,
                None,
            )
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeProcessorFeaturesBanks,
                &banks as *const _ as *const c_void,
                std::mem::size_of::<WHV_PROCESSOR_FEATURES_BANKS>() as u32,
            )
            .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
        }

        // Synthetic processor feature banks (hypervisor-visible features).
        // IMPORTANT: MSHV on ARM64 constructs a SPECIFIC mask via
        // `make_default_synthetic_features_mask()` rather than querying host
        // capabilities. It deliberately EXCLUDES `access_guest_idle_reg` and
        // `tb_flush_hypercalls` on ARM64. If `tb_flush_hypercalls` is enabled,
        // the hypervisor may expect TLB-flush hypercalls from the guest instead
        // of handling stage-1 translation faults internally — which would
        // explain the unmapped-GPA exits we see.
        //
        // Replicate MSHV's exact mask instead of blindly using host capabilities.
        // Bits (from mshv-ioctls make_default_synthetic_features_mask):
        //   bit 0: hypervisor_present
        //   bit 1: hv1
        //   bit 2: access_partition_reference_counter
        //   bit 3: access_synic_regs
        //   bit 4: access_synthetic_timer_regs
        //   bit 5: access_partition_reference_tsc
        //   bit 6: access_frequency_regs
        //   bit 7: access_intr_ctrl_regs
        //   bit 8: access_vp_index
        //   bit 9: access_hypercall_regs
        //   bit 10: access_guest_idle_reg -- EXCLUDED on aarch64
        //   bit 11: tb_flush_hypercalls -- EXCLUDED on aarch64
        //   bit 12: synthetic_cluster_ipi
        //   bit 13: direct_synthetic_timers
        //   bit 14: access_vp_regs
        {
            // First query what the host supports for comparison
            let mut synth_cap: WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS = Default::default();
            unsafe {
                let _ = WHvGetCapability(
                    WHvCapabilityCodeSyntheticProcessorFeaturesBanks,
                    &mut synth_cap as *mut _ as *mut c_void,
                    std::mem::size_of::<WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS>() as u32,
                    None,
                );
                // Use the host capability directly
                WHvSetPartitionProperty(
                    partition,
                    WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks,
                    &synth_cap as *const _ as *const c_void,
                    std::mem::size_of::<WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS>() as u32,
                )
                .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
            }
        }

        Ok(())
    }

    pub(crate) fn new() -> Result<Self, CreateVmError> {
        const NUM_CPU: u32 = 1;

        let partition = unsafe {
            let p = WHvCreatePartition().map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
            WHvSetPartitionProperty(
                p,
                WHvPartitionPropertyCodeProcessorCount,
                &NUM_CPU as *const _ as *const _,
                std::mem::size_of_val(&NUM_CPU) as _,
            )
            .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

            // Mirror MSHV's `VmType::Normal` partition setup: enable the host's
            // full set of processor features (and synthetic features) on the
            // partition before `WHvSetupPartition`. Without this, WHP exposes a
            // restricted ARM64 feature set to the guest (e.g. without FEAT_LSE
            // atomics), and instructions the guest relies on — such as the
            // `ldadd` used by the guest's physical page allocator — trap as
            // UNDEFINED, sending the guest into its exception vectors during
            // initialisation. We copy whatever the host supports rather than
            // hand-pick bits, matching the behaviour of the Linux backends.
            Self::set_processor_features(p)?;

            // Set the partition's physical address width to the maximum the
            // host supports. Without this, WHP defaults to 40-bit (1 TiB),
            // but the guest's TCR_EL1.IPS is configured for 48-bit and the
            // scratch region sits at ~64 GiB — the page-table walker wraps
            // at the configured width boundary, producing unmapped-GPA faults
            // at exactly 2^40.
            {
                let mut pa_width: u32 = 0;
                WHvGetCapability(
                    WHV_CAPABILITY_CODE(0x0000_100A), // PhysicalAddressWidth
                    &mut pa_width as *mut _ as *mut c_void,
                    std::mem::size_of::<u32>() as u32,
                    None,
                )
                .map_err(|e| CreateVmError::InitializeVm(e.into()))?;
                WHvSetPartitionProperty(
                    p,
                    WHV_PARTITION_PROPERTY_CODE(0x0000_1011), // PhysicalAddressWidth
                    &pa_width as *const _ as *const c_void,
                    std::mem::size_of::<u32>() as u32,
                )
                .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
            }

            // WHP requires the GIC v3 interrupt-controller parameters to be set
            // before the partition can be set up for an ARM64 guest.
            let ic_params = WhvArm64IcParameters {
                emulation_mode: WHV_ARM64_IC_EMULATION_MODE_GIC_V3,
                reserved: 0,
                gic_v3: WhvArm64IcGicV3Parameters {
                    gicd_base_address: GIC_DISTRIBUTOR_BASE_GPA,
                    gits_translater_base_address: GIC_ITS_TRANSLATER_BASE_GPA,
                    reserved: 0,
                    gic_lpi_int_id_bits: 0,
                    gic_ppi_overflow_interrupt_from_cntv: GIC_PPI_CNTV,
                    gic_ppi_performance_monitors_interrupt: GIC_PPI_PMU,
                    reserved1: [0; 6],
                },
            };
            WHvSetPartitionProperty(
                p,
                WHV_PARTITION_PROPERTY_CODE_ARM64_IC_PARAMETERS,
                &ic_params as *const _ as *const _,
                std::mem::size_of_val(&ic_params) as _,
            )
            .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

            WHvSetupPartition(p).map_err(|e| CreateVmError::InitializeVm(e.into()))?;
            WHvCreateVirtualProcessor(p, 0, 0)
                .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;

            p
        };


        let mgr = get_surrogate_process_manager()
            .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?;
        let surrogate_process = mgr
            .get_surrogate_process()
            .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?;

        Ok(WhpVm {
            partition,
            surrogate_process,
            file_mappings: Vec::new(),
        })
    }

    /// Read a single 64-bit vCPU register.
    fn get_one_reg(&self, name: WHV_REGISTER_NAME) -> windows_result::Result<u64> {
        let names = [name];
        let mut values = [whp_reg::val64(0)];
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                names.len() as u32,
                values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )?;
            Ok(values[0].0.Reg64)
        }
    }

    /// Recover the value written by an MMIO store from the ARM64 syndrome.
    ///
    /// The ARM64 `WHV_MEMORY_ACCESS_CONTEXT` includes a `syndrome` field
    /// (ESR_EL2 equivalent). This is the same approach MSHV uses:
    /// ISS.ISV (bit 24) indicates valid syndrome, ISS.SAS (bits 23:22) gives
    /// the access size, ISS.SRT (bits 20:16) gives the register number.
    fn mmio_write_data_from_syndrome(
        &self,
        access: &WhvArm64MemoryAccessContext,
    ) -> std::result::Result<Vec<u8>, RunVcpuError> {
        let esr = access.syndrome;
        // ISS.ISV (bit 24): instruction syndrome valid
        if esr & (1 << 24) == 0 {
            return Err(RunVcpuError::ParseGpaAccessInfo);
        }
        let srt = ((esr >> 16) & 0x1f) as u8; // ISS.SRT bits [20:16]
        let sas = (esr >> 22) & 0x3;           // ISS.SAS bits [23:22]
        let nbytes = 1usize << sas;

        let value = if srt >= REG_XZR {
            0
        } else {
            self.get_one_reg(whp_reg::gp_reg_name(srt))
                .map_err(|e| RunVcpuError::Unknown(e.into()))?
        };
        Ok(value.to_le_bytes()[..nbytes].to_vec())
    }
}

impl VirtualMachine for WhpVm {
    unsafe fn map_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> Result<(), MapMemoryError> {
        // Memory mapping is architecture-neutral; delegate to the shared helper.
        unsafe { self.map_memory_shared(region) }
    }

    fn unmap_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> Result<(), UnmapMemoryError> {
        self.unmap_memory_shared(region)
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        let mut exit_context = WhvArm64RunVpExitContext {
            exit_reason: 0,
            reserved: 0,
            reserved1: 0,
            union_data: [0; 32],
        };

        #[cfg(feature = "trace_guest")]
        tc.setup_guest_trace(Span::current().context());

        unsafe {
            WHvRunVirtualProcessor(
                self.partition,
                0,
                &mut exit_context as *mut _ as *mut c_void,
                std::mem::size_of::<WhvArm64RunVpExitContext>() as u32,
            )
            .map_err(|e| RunVcpuError::Unknown(e.into()))?;
        }

        match WHV_RUN_VP_EXIT_REASON(exit_context.exit_reason) {
            WHV_RUN_VP_EXIT_REASON(WHV_EXIT_REASON_ARM64_UNMAPPED_GPA)
            | WHV_RUN_VP_EXIT_REASON(WHV_EXIT_REASON_ARM64_GPA_INTERCEPT) => {
                // SAFETY: the exit reason is a GPA access; the union holds the
                // ARM64 `WhvArm64MemoryAccessContext` (64 bytes).
                let access = unsafe {
                    &*(exit_context.union_data.as_ptr() as *const WhvArm64MemoryAccessContext)
                };
                let gpa = access.gpa;
                let is_write = access.header.intercept_access_type == 1; // 1 = write

                let io_page_gpa = const { hyperlight_common::layout::io_page().unwrap().0 };
                if is_write
                    && gpa >= io_page_gpa
                    && (gpa - io_page_gpa) < hyperlight_common::vmem::PAGE_SIZE as u64
                {
                    // A write into the I/O page: the guest is signalling the
                    // host. WHP does not auto-advance the program counter, so
                    // advance by the instruction length from the header.
                    let instruction_len = if access.header.instruction_length != 0 {
                        access.header.instruction_length as u64
                    } else {
                        AARCH64_INSTRUCTION_LEN
                    };
                    let pc = access.header.pc;
                    self.set_registers(&[(
                        whp_reg::WHV_ARM64_PC,
                        whp_reg::val64(pc + instruction_len),
                    )])
                    .map_err(|e| RunVcpuError::IncrementRip(e.into()))?;

                    let port = ((gpa - io_page_gpa) / std::mem::size_of::<u64>() as u64) as usize;
                    if port == VmAction::Halt as usize {
                        Ok(VmExit::Halt())
                    } else {
                        let data = self.mmio_write_data_from_syndrome(access)?;
                        Ok(VmExit::IoOut(port as u16, data))
                    }
                } else if is_write {
                    Ok(VmExit::MmioWrite(gpa))
                } else {
                    Ok(VmExit::MmioRead(gpa))
                }
            }
            WHV_RUN_VP_EXIT_REASON(WHV_EXIT_REASON_ARM64_CANCELED) => Ok(VmExit::Cancelled()),
            WHV_RUN_VP_EXIT_REASON(other) => Ok(VmExit::Unknown(format!(
                "Unknown WHP aarch64 exit reason: {}",
                other
            ))),
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        let names = whp_reg::regs_names();
        let mut values = [whp_reg::val64(0); whp_reg::REGS_LEN];
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                names.len() as u32,
                values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        }
        Ok(whp_reg::regs_from_values(&values))
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        let names = whp_reg::regs_names();
        let values = whp_reg::regs_values(regs);
        let pairs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); whp_reg::REGS_LEN] =
            std::array::from_fn(|i| (names[i], values[i]));
        self.set_registers(&pairs)
            .map_err(|e| RegisterError::SetRegs(e.into()))
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        let names = whp_reg::fpu_names();
        let mut values = [whp_reg::val64(0); whp_reg::FPU_LEN];
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                names.len() as u32,
                values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )
            .map_err(|e| RegisterError::GetFpu(e.into()))?;
        }
        Ok(whp_reg::fpu_from_values(&values))
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        let names = whp_reg::fpu_names();
        let values = whp_reg::fpu_values(fpu);
        let pairs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); whp_reg::FPU_LEN] =
            std::array::from_fn(|i| (names[i], values[i]));
        self.set_registers(&pairs)
            .map_err(|e| RegisterError::SetFpu(e.into()))
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        let names = whp_reg::sregs_names();
        let mut values = [whp_reg::val64(0); whp_reg::SREGS_LEN];
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                names.len() as u32,
                values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )
            .map_err(|e| RegisterError::GetSregs(e.into()))?;
        }
        Ok(whp_reg::sregs_from_values(&values))
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        let names = whp_reg::sregs_names();
        let values = whp_reg::sregs_values(sregs);
        let pairs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); whp_reg::SREGS_LEN] =
            std::array::from_fn(|i| (names[i], values[i]));
        self.set_registers(&pairs)
            .map_err(|e| RegisterError::SetSregs(e.into()))
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        // aarch64 debug registers are not modelled by `CommonDebugRegs` yet
        // (it is a placeholder); there is nothing to read back.
        Ok(CommonDebugRegs::default())
    }

    fn set_debug_regs(&self, _drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError> {
        // No-op: see `debug_regs`.
        Ok(())
    }

    fn can_reset_vcpu(&self) -> bool {
        true
    }

    fn reset_vcpu(&mut self) -> std::result::Result<(), ResetVcpuError> {
        // Clear the guest-visible debug state on reset, mirroring the MSHV
        // backend and KVM's AArch64 vcpu reset. We clear only index 0 of each
        // breakpoint/watchpoint bank: the Arm architecture guarantees at least
        // one breakpoint and one watchpoint are implemented, and writing higher
        // indices that the CPU does not implement is rejected by the hypervisor.
        //
        // The caller (`HyperlightVm::reset_vcpu`) restores the special registers
        // and the next guest dispatch rewrites all GP and FP registers, so no
        // further reset work is required here.
        const RESET_REGS: [WHV_REGISTER_NAME; 5] = [
            whp_reg::WHV_ARM64_MDSCR_EL1,
            whp_reg::WHV_ARM64_DBGBCR0_EL1,
            whp_reg::WHV_ARM64_DBGBVR0_EL1,
            whp_reg::WHV_ARM64_DBGWCR0_EL1,
            whp_reg::WHV_ARM64_DBGWVR0_EL1,
        ];
        for name in RESET_REGS {
            self.set_registers(&[(name, whp_reg::val64(0))])
                .map_err(|e| ResetVcpuError::Register(RegisterError::SetRegs(e.into())))?;
        }
        Ok(())
    }

    fn partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.partition
    }
}
