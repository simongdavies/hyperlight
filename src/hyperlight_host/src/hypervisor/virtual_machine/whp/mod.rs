/*
Copyright 2025  The Hyperlight Authors.

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

//! Windows Hypervisor Platform (WHP) backend.
//!
//! This module is split into architecture-specific implementations
//! ([`x86_64`] and [`aarch64`]). The shared, architecture-neutral pieces
//! (the [`WhpVm`] type, guest-memory mapping via the surrogate process, the
//! dynamically-loaded `WHvMapGpaRange2` helper and partition teardown) live
//! here so they are not duplicated between the two backends.

use std::os::raw::c_void;

use windows::Win32::Foundation::{CloseHandle, FreeLibrary, HANDLE};
use windows::Win32::System::Hypervisor::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::{MEMORY_MAPPED_VIEW_ADDRESS, UnmapViewOfFile};
use windows::core::s;
use windows_result::HRESULT;

use crate::hypervisor::regs::Align16;
use crate::hypervisor::surrogate_process::SurrogateProcess;
#[cfg(all(feature = "hw-interrupts", target_arch = "x86_64"))]
use crate::hypervisor::virtual_machine::x86_64::hw_interrupts::TimerThread;
use crate::hypervisor::virtual_machine::{HypervisorError, MapMemoryError, UnmapMemoryError};
use crate::hypervisor::wrappers::HandleWrapper;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

pub(crate) fn is_hypervisor_present() -> bool {
    let mut capability: WHV_CAPABILITY = Default::default();
    let written_size: Option<*mut u32> = None;

    match unsafe {
        WHvGetCapability(
            WHvCapabilityCodeHypervisorPresent,
            &mut capability as *mut _ as *mut c_void,
            std::mem::size_of::<WHV_CAPABILITY>() as u32,
            written_size,
        )
    } {
        Ok(_) => unsafe { capability.HypervisorPresent.as_bool() },
        Err(_) => {
            tracing::info!("Windows Hypervisor Platform is not available on this system");
            false
        }
    }
}

/// Helper: release a host-side file mapping view and its handle.
/// Called from both `unmap_memory` and `WhpVm::drop`.
fn release_file_mapping(view_base: *mut c_void, mapping_handle: HandleWrapper) {
    unsafe {
        if let Err(e) = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: view_base }) {
            tracing::error!("Failed to unmap file view at {:?}: {:?}", view_base, e);
        }
        if let Err(e) = CloseHandle(mapping_handle.into()) {
            tracing::error!(
                "Failed to close file mapping handle {:?}: {:?}",
                mapping_handle,
                e
            );
        }
    }
}

/// A Windows Hypervisor Platform implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct WhpVm {
    partition: WHV_PARTITION_HANDLE,
    // Surrogate process for memory mapping
    surrogate_process: SurrogateProcess,
    /// Tracks host-side file mappings (view_base, mapping_handle) for
    /// cleanup on unmap or drop. Only populated for MappedFile regions.
    file_mappings: Vec<(HandleWrapper, *mut c_void)>,
    /// Handle to the background timer (if started).
    #[cfg(all(feature = "hw-interrupts", target_arch = "x86_64"))]
    timer: Option<TimerThread>,
}

// Safety: `WhpVm` is !Send because it holds `SurrogateProcess` which contains a raw pointer
// `allocated_address` (*mut c_void). This pointer represents a memory mapped view address
// in the surrogate process. It is never dereferenced, only used for address arithmetic and
// resource management (unmapping). This is a system resource that is not bound to the creating
// thread and can be safely transferred between threads.
// `file_mappings` contains raw pointers that are also kernel resource handles,
// safe to use from any thread.
unsafe impl Send for WhpVm {}

impl WhpVm {
    /// Helper for setting arbitrary registers. Makes sure the same number
    /// of names and values are passed (at the expense of some performance).
    fn set_registers(
        &self,
        registers: &[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)],
    ) -> windows_result::Result<()> {
        let (names, values): (Vec<_>, Vec<_>) = registers.iter().copied().unzip();

        unsafe {
            WHvSetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                names.len() as u32,
                values.as_ptr() as *const WHV_REGISTER_VALUE, // Casting Align16 away
            )
        }
    }

    /// Map a guest memory region into the partition.
    ///
    /// This is architecture-neutral: it allocates a view in the surrogate
    /// process and maps it into the guest physical address space via
    /// `WHvMapGpaRange2`.
    ///
    /// # Safety
    /// The caller must uphold the same invariants as
    /// [`VirtualMachine::map_memory`](crate::hypervisor::virtual_machine::VirtualMachine::map_memory):
    /// the region must be valid, page-aligned and remain live for as long as
    /// it is mapped.
    unsafe fn map_memory_shared(
        &mut self,
        region: &MemoryRegion,
    ) -> std::result::Result<(), MapMemoryError> {
        // Calculate the surrogate process address for this region
        let surrogate_base = self
            .surrogate_process
            .map(
                region.host_region.start.from_handle,
                region.host_region.start.handle_base,
                region.host_region.start.handle_size,
                &region.region_type.surrogate_mapping(),
            )
            .map_err(|e| MapMemoryError::SurrogateProcess(e.to_string()))?;
        let surrogate_addr = surrogate_base.wrapping_add(region.host_region.start.offset);

        let flags = region
            .flags
            .iter()
            .map(|flag| match flag {
                MemoryRegionFlags::NONE => Ok(WHvMapGpaRangeFlagNone),
                MemoryRegionFlags::READ => Ok(WHvMapGpaRangeFlagRead),
                MemoryRegionFlags::WRITE => Ok(WHvMapGpaRangeFlagWrite),
                MemoryRegionFlags::EXECUTE => Ok(WHvMapGpaRangeFlagExecute),
                _ => Err(MapMemoryError::InvalidFlags(format!(
                    "Invalid memory region flag: {:?}",
                    flag
                ))),
            })
            .collect::<std::result::Result<Vec<WHV_MAP_GPA_RANGE_FLAGS>, MapMemoryError>>()?
            .iter()
            .fold(WHvMapGpaRangeFlagNone, |acc, flag| acc | *flag);

        let whvmapgparange2_func = unsafe {
            match try_load_whv_map_gpa_range2() {
                Ok(func) => func,
                Err(e) => {
                    return Err(MapMemoryError::LoadApi {
                        api_name: "WHvMapGpaRange2",
                        source: e,
                    });
                }
            }
        };

        let res = unsafe {
            whvmapgparange2_func(
                self.partition,
                self.surrogate_process.process_handle.into(),
                surrogate_addr,
                region.guest_region.start as u64,
                region.guest_region.len() as u64,
                flags,
            )
        };
        if res.is_err() {
            return Err(MapMemoryError::Hypervisor(HypervisorError::WindowsError(
                windows_result::Error::from_hresult(res),
            )));
        }

        // Track host-side file mappings for cleanup on unmap or drop.
        if region.region_type == MemoryRegionType::MappedFile {
            self.file_mappings.push((
                region.host_region.start.from_handle,
                region.host_region.start.handle_base as *mut c_void,
            ));
        }

        Ok(())
    }

    /// Unmap a previously-mapped guest memory region. Architecture-neutral.
    fn unmap_memory_shared(
        &mut self,
        region: &MemoryRegion,
    ) -> std::result::Result<(), UnmapMemoryError> {
        unsafe {
            WHvUnmapGpaRange(
                self.partition,
                region.guest_region.start as u64,
                region.guest_region.len() as u64,
            )
            .map_err(|e| UnmapMemoryError::Hypervisor(HypervisorError::WindowsError(e)))?;
        }
        self.surrogate_process
            .unmap(region.host_region.start.handle_base);

        // Clean up host-side file mapping resources for MappedFile regions.
        if region.region_type == MemoryRegionType::MappedFile {
            let handle_base = region.host_region.start.handle_base as *mut c_void;
            if let Some(pos) = self
                .file_mappings
                .iter()
                .position(|(_, vb)| *vb == handle_base)
            {
                let (handle, view) = self.file_mappings.swap_remove(pos);
                release_file_mapping(view, handle);
            }
        }

        Ok(())
    }
}

impl Drop for WhpVm {
    fn drop(&mut self) {
        // Clean up any remaining file mappings that weren't explicitly unmapped.
        for (handle, view) in self.file_mappings.drain(..) {
            release_file_mapping(view, handle);
        }

        // Stop the software timer thread before tearing down the partition.
        #[cfg(all(feature = "hw-interrupts", target_arch = "x86_64"))]
        if let Some(mut t) = self.timer.take() {
            t.stop();
        }

        // HyperlightVm::drop() calls set_dropped() before this runs.
        // set_dropped() ensures no WHvCancelRunVirtualProcessor calls are in progress
        // or will be made in the future, so it's safe to delete the partition.
        // (HyperlightVm::drop() runs before its fields are dropped, so
        // set_dropped() completes before this Drop impl runs.)
        if let Err(e) = unsafe { WHvDeletePartition(self.partition) } {
            tracing::error!("Failed to delete partition: {}", e);
        }
    }
}

// This function dynamically loads the WHvMapGpaRange2 function from the winhvplatform.dll
// WHvMapGpaRange2 only available on Windows 11 or Windows Server 2022 and later
// we do things this way to allow a user trying to load hyperlight on an older version of windows to
// get an error message saying that hyperlight requires a newer version of windows, rather than just failing
// with an error about a missing entrypoint
// This function should always succeed since before we get here we have already checked that the hypervisor is present and
// that we are on a supported version of windows.
type WHvMapGpaRange2Func = unsafe extern "C" fn(
    WHV_PARTITION_HANDLE,
    HANDLE,
    *const c_void,
    u64,
    u64,
    WHV_MAP_GPA_RANGE_FLAGS,
) -> HRESULT;

unsafe fn try_load_whv_map_gpa_range2() -> windows_result::Result<WHvMapGpaRange2Func> {
    let library = unsafe {
        LoadLibraryExA(
            s!("winhvplatform.dll"),
            None,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    }?;

    let address = unsafe { GetProcAddress(library, s!("WHvMapGpaRange2")) };

    if address.is_none() {
        unsafe { FreeLibrary(library)? };
        return Err(windows_result::Error::new(
            HRESULT::from_win32(127), // ERROR_PROC_NOT_FOUND
            "Failed to find WHvMapGpaRange2 in winhvplatform.dll",
        ));
    }

    unsafe { Ok(std::mem::transmute_copy(&address)) }
}
