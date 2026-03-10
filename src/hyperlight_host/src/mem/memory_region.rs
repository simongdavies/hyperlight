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

use std::ops::Range;

use bitflags::bitflags;
#[cfg(mshv3)]
use hyperlight_common::mem::PAGE_SHIFT;
use hyperlight_common::mem::PAGE_SIZE_USIZE;
#[cfg(kvm)]
use kvm_bindings::{KVM_MEM_READONLY, kvm_userspace_memory_region};
#[cfg(mshv3)]
use mshv_bindings::{
    MSHV_SET_MEM_BIT_EXECUTABLE, MSHV_SET_MEM_BIT_UNMAP, MSHV_SET_MEM_BIT_WRITABLE,
};
#[cfg(mshv3)]
use mshv_bindings::{hv_x64_memory_intercept_message, mshv_user_mem_region};
#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::{self, WHV_MEMORY_ACCESS_TYPE};

#[cfg(target_os = "windows")]
use crate::hypervisor::wrappers::HandleWrapper;

pub(crate) const DEFAULT_GUEST_BLOB_MEM_FLAGS: MemoryRegionFlags = MemoryRegionFlags::READ;

bitflags! {
    /// flags representing memory permission for a memory region
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct MemoryRegionFlags: u32 {
        /// no permissions
        const NONE = 0;
        /// allow guest to read
        const READ = 1;
        /// allow guest to write
        const WRITE = 2;
        /// allow guest to execute
        const EXECUTE = 4;
    }
}

impl std::fmt::Display for MemoryRegionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            write!(f, "NONE")
        } else {
            let mut first = true;
            if self.contains(MemoryRegionFlags::READ) {
                write!(f, "READ")?;
                first = false;
            }
            if self.contains(MemoryRegionFlags::WRITE) {
                if !first {
                    write!(f, " | ")?;
                }
                write!(f, "WRITE")?;
                first = false;
            }
            if self.contains(MemoryRegionFlags::EXECUTE) {
                if !first {
                    write!(f, " | ")?;
                }
                write!(f, "EXECUTE")?;
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
impl TryFrom<WHV_MEMORY_ACCESS_TYPE> for MemoryRegionFlags {
    type Error = crate::HyperlightError;

    fn try_from(flags: WHV_MEMORY_ACCESS_TYPE) -> crate::Result<Self> {
        match flags {
            Hypervisor::WHvMemoryAccessRead => Ok(MemoryRegionFlags::READ),
            Hypervisor::WHvMemoryAccessWrite => Ok(MemoryRegionFlags::WRITE),
            Hypervisor::WHvMemoryAccessExecute => Ok(MemoryRegionFlags::EXECUTE),
            _ => Err(crate::HyperlightError::Error(
                "unknown memory access type".to_string(),
            )),
        }
    }
}

#[cfg(mshv3)]
impl TryFrom<hv_x64_memory_intercept_message> for MemoryRegionFlags {
    type Error = crate::HyperlightError;

    fn try_from(msg: hv_x64_memory_intercept_message) -> crate::Result<Self> {
        let access_type = msg.header.intercept_access_type;
        match access_type {
            0 => Ok(MemoryRegionFlags::READ),
            1 => Ok(MemoryRegionFlags::WRITE),
            2 => Ok(MemoryRegionFlags::EXECUTE),
            _ => Err(crate::HyperlightError::Error(
                "unknown memory access type".to_string(),
            )),
        }
    }
}

// NOTE: In the future, all host-side knowledge about memory region types
// should collapse down to Snapshot vs Scratch (see shared_mem.rs).
// Until then, these variants help distinguish regions for diagnostics
// and crash dumps. Not part of the public API.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
/// The type of memory region
pub(crate) enum MemoryRegionType {
    /// The region contains the guest's code
    Code,
    /// The region contains the guest's init data
    InitData,
    /// The region contains the PEB
    Peb,
    /// The region contains the Heap
    Heap,
    /// The region contains the Guard Page
    Scratch,
    /// The snapshot region
    Snapshot,
    /// An externally-mapped file (via [`MultiUseSandbox::map_file_cow`]).
    /// These regions are backed by file handles (Windows) or mmap
    /// (Linux) and are read-only + executable. They are cleaned up
    /// during restore/drop — not part of the guest's own allocator.
    MappedFile,
}

/// A trait that distinguishes between different kinds of memory region representations.
///
/// This trait is used to parameterize [`MemoryRegion_`]
pub trait MemoryRegionKind {
    /// The type used to represent host memory addresses.
    type HostBaseType: Copy;

    /// Computes an address by adding a size to a base address.
    ///
    /// # Arguments
    /// * `base` - The starting address
    /// * `size` - The size in bytes to add
    ///
    /// # Returns
    /// The computed end address (`base + size` for host-guest regions,
    /// `()` for guest-only regions).
    fn add(base: Self::HostBaseType, size: usize) -> Self::HostBaseType;
}

/// Type for memory regions that track both host and guest addresses.
///
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct HostGuestMemoryRegion {}

#[cfg(not(target_os = "windows"))]
impl MemoryRegionKind for HostGuestMemoryRegion {
    type HostBaseType = usize;

    fn add(base: Self::HostBaseType, size: usize) -> Self::HostBaseType {
        base + size
    }
}
/// Describes how a memory region should be mapped through the surrogate process
/// pipeline on Windows (WHP).
///
/// Different mapping types require different page protections and guard page
/// behaviour when projected into the surrogate process via `MapViewOfFileNuma2`.
#[cfg(target_os = "windows")]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub(crate) enum SurrogateMapping {
    /// Standard sandbox shared memory: mapped with `PAGE_READWRITE` protection
    /// and guard pages (`PAGE_NOACCESS`) set on the first and last pages.
    SandboxMemory,
    /// File-backed read-only mapping: mapped with `PAGE_READONLY` protection
    /// and **no** guard pages.
    ReadOnlyFile,
}

/// A [`HostRegionBase`] keeps track of not just a pointer, but also a
/// file mapping into which it is pointing.  This is used on WHP,
/// where mapping the actual pointer into the VM actually involves
/// first mapping the file into a surrogate process.
#[cfg(target_os = "windows")]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct HostRegionBase {
    /// The file handle from which the file mapping was created
    pub from_handle: HandleWrapper,
    /// The base of the file mapping
    pub handle_base: usize,
    /// The size of the file mapping
    pub handle_size: usize,
    /// The offset into file mapping region where this
    /// [`HostRegionBase`] is pointing.
    pub offset: usize,
    /// How this region should be mapped through the surrogate process.
    /// Controls page protection and guard page behaviour.
    pub(crate) surrogate_mapping: SurrogateMapping,
}
#[cfg(target_os = "windows")]
impl std::hash::Hash for HostRegionBase {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // it's safe not to hash the handle (which is not hashable)
        // since, for any of these in use at the same time, the handle
        // should be uniquely determined by the
        // handle_base/handle_size combination.
        self.handle_base.hash(state);
        self.handle_size.hash(state);
        self.offset.hash(state);
        self.surrogate_mapping.hash(state);
    }
}
#[cfg(target_os = "windows")]
impl From<HostRegionBase> for usize {
    fn from(x: HostRegionBase) -> usize {
        x.handle_base + x.offset
    }
}
#[cfg(target_os = "windows")]
impl TryFrom<HostRegionBase> for isize {
    type Error = <isize as TryFrom<usize>>::Error;
    fn try_from(x: HostRegionBase) -> Result<isize, Self::Error> {
        <isize as TryFrom<usize>>::try_from(x.into())
    }
}
#[cfg(target_os = "windows")]
impl MemoryRegionKind for HostGuestMemoryRegion {
    type HostBaseType = HostRegionBase;

    fn add(base: Self::HostBaseType, size: usize) -> Self::HostBaseType {
        HostRegionBase {
            from_handle: base.from_handle,
            handle_base: base.handle_base,
            handle_size: base.handle_size,
            offset: base.offset + size,
            surrogate_mapping: base.surrogate_mapping,
        }
    }
}

/// Type for memory regions that only track guest addresses.
///
#[cfg_attr(feature = "nanvix-unstable", allow(dead_code))]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub(crate) struct GuestMemoryRegion {}

impl MemoryRegionKind for GuestMemoryRegion {
    type HostBaseType = ();

    fn add(_base: Self::HostBaseType, _size: usize) -> Self::HostBaseType {}
}

/// represents a single memory region inside the guest. All memory within a region has
/// the same memory permissions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryRegion_<K: MemoryRegionKind> {
    /// the range of guest memory addresses
    pub guest_region: Range<usize>,
    /// the range of host memory addresses
    ///
    /// Note that Range<()> = () x () = ().
    pub host_region: Range<K::HostBaseType>,
    /// memory access flags for the given region
    pub flags: MemoryRegionFlags,
    /// the type of memory region
    pub(crate) region_type: MemoryRegionType,
}

/// A memory region that tracks both host and guest addresses.
pub type MemoryRegion = MemoryRegion_<HostGuestMemoryRegion>;

/// A [`MemoryRegionKind`] for crash dump regions that always uses raw
/// `usize` host addresses.  The crash dump path only reads host memory
/// through raw pointers, so it never needs the file-mapping metadata
/// stored in [`HostRegionBase`] on Windows.
#[cfg(crashdump)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub(crate) struct CrashDumpMemoryRegion;

#[cfg(crashdump)]
impl MemoryRegionKind for CrashDumpMemoryRegion {
    type HostBaseType = usize;

    fn add(base: Self::HostBaseType, size: usize) -> Self::HostBaseType {
        base + size
    }
}

/// A memory region used exclusively by the crash dump path.
///
/// Host addresses are always raw `usize` pointers, avoiding the need
/// to construct platform-specific wrappers like [`HostRegionBase`].
#[cfg(crashdump)]
pub(crate) type CrashDumpRegion = MemoryRegion_<CrashDumpMemoryRegion>;

#[cfg(crashdump)]
impl HostGuestMemoryRegion {
    /// Extract the raw `usize` host address from the platform-specific
    /// host base type.
    ///
    /// On Linux this is identity (`HostBaseType` = `usize`).
    /// On Windows it computes `handle_base + offset` via the existing
    /// `From<HostRegionBase> for usize` impl.
    pub(crate) fn to_addr(val: <Self as MemoryRegionKind>::HostBaseType) -> usize {
        #[cfg(not(target_os = "windows"))]
        {
            val
        }
        #[cfg(target_os = "windows")]
        {
            val.into()
        }
    }
}

#[cfg_attr(feature = "nanvix-unstable", allow(unused))]
pub(crate) struct MemoryRegionVecBuilder<K: MemoryRegionKind> {
    guest_base_phys_addr: usize,
    host_base_virt_addr: K::HostBaseType,
    regions: Vec<MemoryRegion_<K>>,
}

impl<K: MemoryRegionKind> MemoryRegionVecBuilder<K> {
    pub(crate) fn new(guest_base_phys_addr: usize, host_base_virt_addr: K::HostBaseType) -> Self {
        Self {
            guest_base_phys_addr,
            host_base_virt_addr,
            regions: Vec::new(),
        }
    }

    fn push(
        &mut self,
        size: usize,
        flags: MemoryRegionFlags,
        region_type: MemoryRegionType,
    ) -> usize {
        if self.regions.is_empty() {
            let guest_end = self.guest_base_phys_addr + size;
            let host_end = <K as MemoryRegionKind>::add(self.host_base_virt_addr, size);
            self.regions.push(MemoryRegion_ {
                guest_region: self.guest_base_phys_addr..guest_end,
                host_region: self.host_base_virt_addr..host_end,
                flags,
                region_type,
            });
            return guest_end - self.guest_base_phys_addr;
        }

        #[allow(clippy::unwrap_used)]
        // we know this is safe because we check if the regions are empty above
        let last_region = self.regions.last().unwrap();
        let host_end = <K as MemoryRegionKind>::add(last_region.host_region.end, size);
        let new_region = MemoryRegion_ {
            guest_region: last_region.guest_region.end..last_region.guest_region.end + size,
            host_region: last_region.host_region.end..host_end,
            flags,
            region_type,
        };
        let ret = new_region.guest_region.end;
        self.regions.push(new_region);
        ret - self.guest_base_phys_addr
    }

    /// Pushes a memory region with the given size. Will round up the size to the nearest page.
    /// Returns the current size of the all memory regions in the builder after adding the given region.
    /// # Note:
    /// Memory regions pushed MUST match the guest's memory layout, in SandboxMemoryLayout::new(..)
    pub(crate) fn push_page_aligned(
        &mut self,
        size: usize,
        flags: MemoryRegionFlags,
        region_type: MemoryRegionType,
    ) -> usize {
        let aligned_size = (size + PAGE_SIZE_USIZE - 1) & !(PAGE_SIZE_USIZE - 1);
        self.push(aligned_size, flags, region_type)
    }

    /// Consumes the builder and returns a vec of memory regions. The regions are guaranteed to be a contiguous chunk
    /// of memory, in other words, there will be any memory gaps between them.
    pub(crate) fn build(self) -> Vec<MemoryRegion_<K>> {
        self.regions
    }
}

#[cfg(mshv3)]
impl From<&MemoryRegion> for mshv_user_mem_region {
    fn from(region: &MemoryRegion) -> Self {
        let size = (region.guest_region.end - region.guest_region.start) as u64;
        let guest_pfn = region.guest_region.start as u64 >> PAGE_SHIFT;
        let userspace_addr = region.host_region.start as u64;

        let flags: u8 = region.flags.iter().fold(0, |acc, flag| {
            let flag_value = match flag {
                MemoryRegionFlags::NONE => 1 << MSHV_SET_MEM_BIT_UNMAP,
                MemoryRegionFlags::READ => 0,
                MemoryRegionFlags::WRITE => 1 << MSHV_SET_MEM_BIT_WRITABLE,
                MemoryRegionFlags::EXECUTE => 1 << MSHV_SET_MEM_BIT_EXECUTABLE,
                _ => 0, // ignore any unknown flags
            };
            acc | flag_value
        });

        mshv_user_mem_region {
            guest_pfn,
            size,
            userspace_addr,
            flags,
            ..Default::default()
        }
    }
}

#[cfg(kvm)]
impl From<&MemoryRegion> for kvm_bindings::kvm_userspace_memory_region {
    fn from(region: &MemoryRegion) -> Self {
        let perm_flags =
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE;

        let perm_flags = perm_flags.intersection(region.flags);

        kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: region.guest_region.start as u64,
            memory_size: (region.guest_region.end - region.guest_region.start) as u64,
            userspace_addr: region.host_region.start as u64,
            flags: if perm_flags.contains(MemoryRegionFlags::WRITE) {
                0 // RWX
            } else {
                // Note: KVM_MEM_READONLY is executable
                KVM_MEM_READONLY // RX 
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_region_flags_display() {
        assert_eq!(format!("{}", MemoryRegionFlags::NONE), "NONE");
        assert_eq!(format!("{}", MemoryRegionFlags::READ), "READ");
        assert_eq!(
            format!("{}", MemoryRegionFlags::READ | MemoryRegionFlags::WRITE),
            "READ | WRITE"
        );
        assert_eq!(
            format!(
                "{}",
                MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE
            ),
            "READ | WRITE | EXECUTE"
        );
    }

    #[cfg(target_os = "windows")]
    mod windows_tests {
        use std::collections::HashSet;
        use std::hash::{DefaultHasher, Hash, Hasher};

        use super::*;

        /// Helper to create a `HostRegionBase` with the given `SurrogateMapping`.
        fn make_host_region_base(mapping: SurrogateMapping) -> HostRegionBase {
            HostRegionBase {
                from_handle: windows::Win32::Foundation::INVALID_HANDLE_VALUE.into(),
                handle_base: 0x1000,
                handle_size: 0x2000,
                offset: 0x100,
                surrogate_mapping: mapping,
            }
        }

        fn hash_of(val: &impl Hash) -> u64 {
            let mut hasher = DefaultHasher::new();
            val.hash(&mut hasher);
            hasher.finish()
        }

        #[test]
        fn surrogate_mapping_equality() {
            assert_eq!(
                SurrogateMapping::SandboxMemory,
                SurrogateMapping::SandboxMemory
            );
            assert_eq!(
                SurrogateMapping::ReadOnlyFile,
                SurrogateMapping::ReadOnlyFile
            );
            assert_ne!(
                SurrogateMapping::SandboxMemory,
                SurrogateMapping::ReadOnlyFile
            );
        }

        #[test]
        fn surrogate_mapping_variants_are_distinct() {
            // Verify the two variants are distinct values that can be
            // used to key different behaviour in the surrogate pipeline
            let sandbox = SurrogateMapping::SandboxMemory;
            let readonly = SurrogateMapping::ReadOnlyFile;
            assert_ne!(sandbox, readonly);

            // Verify Copy semantics work (enum is Copy + Eq)
            let copy = sandbox;
            assert_eq!(sandbox, copy);
        }

        #[test]
        fn host_region_base_different_surrogate_mapping_not_equal() {
            let sandbox = make_host_region_base(SurrogateMapping::SandboxMemory);
            let readonly = make_host_region_base(SurrogateMapping::ReadOnlyFile);
            assert_ne!(sandbox, readonly);
        }

        #[test]
        fn host_region_base_different_surrogate_mapping_different_hash() {
            let sandbox = make_host_region_base(SurrogateMapping::SandboxMemory);
            let readonly = make_host_region_base(SurrogateMapping::ReadOnlyFile);
            assert_ne!(hash_of(&sandbox), hash_of(&readonly));
        }

        #[test]
        fn host_region_base_same_surrogate_mapping_equal_and_same_hash() {
            let a = make_host_region_base(SurrogateMapping::SandboxMemory);
            let b = make_host_region_base(SurrogateMapping::SandboxMemory);
            assert_eq!(a, b);
            assert_eq!(hash_of(&a), hash_of(&b));
        }

        #[test]
        fn host_region_base_into_usize() {
            let hrb = make_host_region_base(SurrogateMapping::SandboxMemory);
            let addr: usize = hrb.into();
            assert_eq!(addr, 0x1000 + 0x100); // handle_base + offset
        }

        #[test]
        fn memory_region_kind_add_preserves_surrogate_mapping() {
            let base = make_host_region_base(SurrogateMapping::ReadOnlyFile);
            let result = <HostGuestMemoryRegion as MemoryRegionKind>::add(base, 0x400);

            assert_eq!(result.from_handle, base.from_handle);
            assert_eq!(result.handle_base, base.handle_base);
            assert_eq!(result.handle_size, base.handle_size);
            assert_eq!(result.offset, base.offset + 0x400);
            assert_eq!(result.surrogate_mapping, SurrogateMapping::ReadOnlyFile);
        }

        #[test]
        fn host_region_base_works_in_hashset() {
            let sandbox = make_host_region_base(SurrogateMapping::SandboxMemory);
            let readonly = make_host_region_base(SurrogateMapping::ReadOnlyFile);

            let mut set = HashSet::new();
            set.insert(sandbox);
            set.insert(readonly);
            // Both should be present since they differ by surrogate_mapping
            assert_eq!(set.len(), 2);

            // Inserting a duplicate should not increase the count
            set.insert(make_host_region_base(SurrogateMapping::SandboxMemory));
            assert_eq!(set.len(), 2);
        }

        #[test]
        fn memory_region_with_surrogate_mapping_equality() {
            let base_sandbox = make_host_region_base(SurrogateMapping::SandboxMemory);
            let base_readonly = make_host_region_base(SurrogateMapping::ReadOnlyFile);

            let region_sandbox = MemoryRegion {
                guest_region: 0x0..0x2000,
                host_region: base_sandbox
                    ..<HostGuestMemoryRegion as MemoryRegionKind>::add(base_sandbox, 0x2000),
                flags: MemoryRegionFlags::READ,
                region_type: MemoryRegionType::Code,
            };

            let region_readonly = MemoryRegion {
                guest_region: 0x0..0x2000,
                host_region: base_readonly
                    ..<HostGuestMemoryRegion as MemoryRegionKind>::add(base_readonly, 0x2000),
                flags: MemoryRegionFlags::READ,
                region_type: MemoryRegionType::Code,
            };

            // Regions with different surrogate_mapping should not be equal
            assert_ne!(region_sandbox, region_readonly);
        }
    }
}
