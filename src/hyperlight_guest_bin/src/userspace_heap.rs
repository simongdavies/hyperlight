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

//! Split kernel / user heap for the `userspace` feature (x86-64).
//!
//! When user code runs in ring 3 it needs to allocate, but it must not be able
//! to corrupt the runtime's heap. This module provides a [`RoutedHeap`] global
//! allocator backed by two independent buddy allocators:
//!
//! * a **kernel heap**, used by the ring 0 runtime, whose control structure
//!   lives in supervisor-only memory (the allocator static itself);
//! * a **user heap**, used by ring 3 code, whose control structure and pool
//!   live in user-accessible memory at [`USER_HEAP_BASE_GVA`], so ring 3 can
//!   allocate directly without a syscall.
//!
//! `alloc` is routed by the current privilege level (ring 3 code gets the user
//! heap); `dealloc` is routed by address range, so a pointer is always returned
//! to the heap that owns it even if it is freed from a different ring. A ring 3
//! bug can therefore corrupt only its own heap, never the runtime's.
//!
//! Note the guest runs without CR4.SMAP, so ring 0 can freely read and write
//! user-accessible pages (needed to initialise the user heap and, later, to
//! marshal data); only ring 3 → supervisor accesses are blocked by hardware.

use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;

use buddy_system_allocator::LockedHeap;
use hyperlight_common::vmem::{BasicMapping, MappingKind, PAGE_SIZE};
use hyperlight_guest::prim_alloc::alloc_phys_pages;

/// Base (lowest address) of the ring 3 user heap region. The buddy-allocator
/// control structure lives at this address and the allocatable pool follows it;
/// both are mapped user-accessible so ring 3 code can allocate directly without
/// a syscall. It sits in its own high-half slot, clear of the user stack
/// (0xffff_fc00_..) and the kernel structures above it.
const USER_HEAP_BASE_GVA: u64 = 0xffff_fb00_0000_0000;

/// Size of the ring 3 user heap (control structure + pool). Mapped eagerly for
/// now from the scratch region (the host enlarges the default scratch size when
/// the userspace feature is enabled to accommodate it); on-demand growth is
/// future work. This bounds how much ring 3 code can allocate, which is
/// sufficient for the self-test and simple guest functions.
const USER_HEAP_SIZE: u64 = 512 * 1024;

/// Buddy-allocator order, matching the kernel heap's historical configuration.
const HEAP_ORDER: usize = 32;

/// The user heap's buddy-allocator control structure is placed at the base of
/// the user heap region (user-accessible memory). The allocatable pool follows
/// it, one page in.
const USER_HEAP_CONTROL: *mut LockedHeap<HEAP_ORDER> =
    USER_HEAP_BASE_GVA as *mut LockedHeap<HEAP_ORDER>;

/// Global allocator that routes between the supervisor-only kernel heap and the
/// user-accessible user heap.
pub(crate) struct RoutedHeap {
    /// Kernel heap, used by ring 0 runtime code. Supervisor-only.
    kernel: LockedHeap<HEAP_ORDER>,
}

impl RoutedHeap {
    /// Create an empty router. The kernel heap is initialised by
    /// `generic_init`; the user heap by [`init_user_heap`].
    pub(crate) const fn new() -> Self {
        Self {
            kernel: LockedHeap::empty(),
        }
    }

    /// The kernel heap, so `generic_init` can initialise it with the guest's
    /// heap region.
    pub(crate) fn kernel(&self) -> &LockedHeap<HEAP_ORDER> {
        &self.kernel
    }
}

/// True if the CPU is currently executing in ring 3 (user mode), determined
/// from the current code segment selector's requested privilege level.
#[inline(always)]
fn in_user_mode() -> bool {
    let cs: u16;
    // Reading CS is unprivileged and cheap; its low two bits are the CPL.
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    (cs & 3) == 3
}

/// True if `ptr` lies within the user heap region.
#[inline(always)]
fn is_user_ptr(ptr: *mut u8) -> bool {
    let addr = ptr as u64;
    addr >= USER_HEAP_BASE_GVA && addr < USER_HEAP_BASE_GVA + USER_HEAP_SIZE
}

/// Reference to the user heap allocator living in user-accessible memory.
///
/// # Safety
/// [`init_user_heap`] must have run first.
#[inline(always)]
unsafe fn user_heap() -> &'static LockedHeap<HEAP_ORDER> {
    unsafe { &*USER_HEAP_CONTROL }
}

/// Allocate `layout` bytes from the **user** heap explicitly, regardless of the
/// current privilege level.
///
/// This is how ring 0 marshalling code stages buffers in user-accessible memory
/// for ring 3 to read or write (the routed [`GlobalAlloc`] would otherwise send
/// a ring 0 allocation to the kernel heap). Returns null on failure.
///
/// # Safety
/// [`init_user_heap`] must have run first. The returned pointer must be freed
/// with [`user_dealloc`] using the same `layout`.
pub(crate) unsafe fn user_alloc(layout: Layout) -> *mut u8 {
    unsafe { user_heap().alloc(layout) }
}

/// Free a pointer previously returned by [`user_alloc`].
///
/// # Safety
/// `ptr`/`layout` must come from a prior [`user_alloc`] call, and `ptr` must lie
/// within the user heap region (see [`is_user_ptr`]).
pub(crate) unsafe fn user_dealloc(ptr: *mut u8, layout: Layout) {
    debug_assert!(is_user_ptr(ptr), "user_dealloc on non-user pointer");
    unsafe { user_heap().dealloc(ptr, layout) }
}

// Only `alloc` and `dealloc` are implemented: `GlobalAlloc`'s default
// `alloc_zeroed` and `realloc` are written in terms of them, so they inherit
// the routing automatically.
unsafe impl GlobalAlloc for RoutedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if in_user_mode() {
            unsafe { user_heap().alloc(layout) }
        } else {
            unsafe { self.kernel.alloc(layout) }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if is_user_ptr(ptr) {
            unsafe { user_heap().dealloc(ptr, layout) }
        } else {
            unsafe { self.kernel.dealloc(ptr, layout) }
        }
    }
}

/// Map the user heap region user-accessible and initialise its allocator.
///
/// Runs once during early initialisation, in ring 0 (so it may write the
/// user-accessible control structure directly).
///
/// # Safety
/// Must be called exactly once, after paging is usable and before any ring 3
/// code allocates.
pub(crate) unsafe fn init_user_heap() {
    unsafe {
        let pages = USER_HEAP_SIZE / PAGE_SIZE as u64;
        let phys = alloc_phys_pages(pages);
        crate::paging::map_region_with_access(
            phys,
            USER_HEAP_BASE_GVA as *mut u8,
            USER_HEAP_SIZE,
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
            true, // user-accessible
        );
        crate::paging::barrier::first_valid_same_ctx();

        // Place the control structure at the base of the region, and give the
        // allocator the rest of the region (after the first page, which holds
        // the control structure) as its pool.
        USER_HEAP_CONTROL.write(LockedHeap::empty());
        let pool_start = (USER_HEAP_BASE_GVA + PAGE_SIZE as u64) as usize;
        let pool_size = (USER_HEAP_SIZE - PAGE_SIZE as u64) as usize;
        (*USER_HEAP_CONTROL).lock().init(pool_start, pool_size);
    }
}
