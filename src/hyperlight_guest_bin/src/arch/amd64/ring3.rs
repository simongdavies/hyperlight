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

//! x86-64 ring 0 / ring 3 privilege transitions for the `userspace` feature.
//!
//! User-provided guest code (`hyperlight_main` and registered guest functions)
//! runs in ring 3, while the Hyperlight runtime stays in ring 0. This module
//! provides the two halves of that boundary:
//!
//! * [`enter_user`] drops into ring 3 via `iretq`, running a user function on
//!   the dedicated user stack.
//! * `hl_syscall_entry` is the `syscall` entry point that user code uses to
//!   return to ring 0 (and, in later phases, to request privileged services).
//!   It is reached because [`init`] points the `IA32_LSTAR` MSR at it.
//!
//! # Stack switching
//!
//! `syscall` does **not** switch the stack pointer, and on a single-vCPU guest
//! we do not need per-CPU state (`swapgs`/`KERNEL_GS_BASE`). Instead
//! [`enter_user`] records the kernel `RSP` at the moment it dropped to ring 3
//! in [`HL_KERNEL_RETURN_RSP`]; the `SYS_RETURN` path restores it to unwind
//! straight back into [`enter_user`]'s caller, and other syscalls switch onto
//! that same kernel stack (growing down, below the saved frame) for the
//! duration of the call.

use core::arch::{asm, global_asm};

use hyperlight_common::vmem::{BasicMapping, MappingKind, PAGE_SIZE};
use hyperlight_guest::prim_alloc::alloc_phys_pages;

use super::layout::{USER_STACK_SIZE, USER_STACK_TOP_GVA};

// ===== Model-specific registers =====
/// Extended Feature Enable Register; bit 0 (SCE) enables `syscall`/`sysret`.
const IA32_EFER: u32 = 0xC000_0080;
/// Segment selectors for `syscall`/`sysret` (see [`STAR_VALUE`]).
const IA32_STAR: u32 = 0xC000_0081;
/// 64-bit `syscall` entry RIP.
const IA32_LSTAR: u32 = 0xC000_0082;
/// RFLAGS bits cleared on `syscall` entry (see [`FMASK_VALUE`]).
const IA32_FMASK: u32 = 0xC000_0084;

/// EFER.SCE (System Call Extensions) - enables `syscall`/`sysret`.
const EFER_SCE: u64 = 1;

// ===== Segment selectors =====
// These must match the GDT layout built in `init::init_gdt`.
/// Ring 3 code selector: GDT offset 0x38 with RPL 3.
const USER_CS: u64 = 0x38 | 3;
/// Ring 3 stack/data selector: GDT offset 0x30 with RPL 3.
const USER_SS: u64 = 0x30 | 3;

/// `IA32_STAR`: bits [63:48] are the `sysret` selector base (0x28, so `sysretq`
/// loads CS=0x28+16=0x38|3 and SS=0x28+8=0x30|3); bits [47:32] are the
/// `syscall` selector base (0x08, so `syscall` loads CS=0x08 and SS=0x10).
const STAR_VALUE: u64 = (0x28u64 << 48) | (0x08u64 << 32);

// RFLAGS bit positions used below.
const RFLAGS_TF: u64 = 1 << 8; // trap flag
const RFLAGS_IF: u64 = 1 << 9; // interrupt enable
const RFLAGS_DF: u64 = 1 << 10; // direction flag
const RFLAGS_NT: u64 = 1 << 14; // nested task
const RFLAGS_AC: u64 = 1 << 18; // alignment check
/// Reserved bit 1 of RFLAGS, which is always set.
const RFLAGS_RESERVED1: u64 = 1 << 1;

/// `IA32_FMASK`: RFLAGS bits cleared by the CPU on `syscall` entry. Clearing IF
/// keeps the entry path from being interrupted before it has switched stacks;
/// the others (TF/DF/NT/AC) are cleared for hygiene so a ring 3 RFLAGS value
/// cannot influence ring 0 execution.
const FMASK_VALUE: u64 = RFLAGS_TF | RFLAGS_IF | RFLAGS_DF | RFLAGS_NT | RFLAGS_AC;

/// RFLAGS value installed for ring 3 execution: only the always-set reserved
/// bit and IF (interrupts enabled). Hyperlight guests normally run without
/// hardware interrupts, but leaving IF set matches ring 0 and is harmless.
const USER_RFLAGS: u64 = RFLAGS_RESERVED1 | RFLAGS_IF;

// ===== Syscall numbers =====
// Passed in RAX by ring 3 code. Only SYS_RETURN exists so far; privileged
// services (host calls, logging, abort, tracing) are added in later phases.
/// Return from a ring 3 user function back into [`enter_user`]'s caller. The
/// 64-bit return value is passed in RDI.
pub(crate) const SYS_RETURN: u64 = 0;

unsafe extern "C" {
    /// Drop into ring 3 and run `entry(arg)` on the user stack. Returns the
    /// value the user code passes to `SYS_RETURN`. Defined in `global_asm!`
    /// below.
    fn enter_user(entry: u64, arg: u64) -> u64;
    /// `syscall` entry point (installed in `IA32_LSTAR`). Defined in
    /// `global_asm!` below.
    fn hl_syscall_entry();
}

/// Kernel `RSP` captured by [`enter_user`] just before dropping to ring 3. The
/// `SYS_RETURN` path restores it to unwind back into [`enter_user`]'s caller,
/// and returning syscalls use it as the base of their (downward-growing)
/// kernel stack. Single-vCPU, single-threaded: one slot is sufficient.
static mut HL_KERNEL_RETURN_RSP: u64 = 0;

/// Read a model-specific register.
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nostack, preserves_flags));
    }
    ((high as u64) << 32) | (low as u64)
}

/// Write a model-specific register.
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high, options(nostack, preserves_flags));
    }
}

/// Map the ring 3 user stack and program the `syscall`/`sysret` MSRs.
///
/// Must be called once during early initialisation, after paging is usable and
/// the GDT (with its user-mode descriptors) has been loaded.
///
/// # Safety
/// Must be called exactly once, before any [`enter_user`] call, with paging
/// initialised.
pub(crate) unsafe fn init() {
    unsafe {
        // Eagerly map a small user stack. On-demand growth via the page-fault
        // handler is a later refinement.
        let pages = USER_STACK_SIZE / PAGE_SIZE as u64;
        let phys = alloc_phys_pages(pages);
        let base = USER_STACK_TOP_GVA - USER_STACK_SIZE;
        crate::paging::map_region_with_access(
            phys,
            base as *mut u8,
            USER_STACK_SIZE,
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
            true, // user-accessible
        );
        crate::paging::barrier::first_valid_same_ctx();

        // Set up the user-accessible heap so ring 3 code can allocate.
        crate::userspace_heap::init_user_heap();

        // Program the syscall MSRs. The host already sets EFER.SCE, but set it
        // defensively in case that ever changes.
        wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_SCE);
        wrmsr(IA32_STAR, STAR_VALUE);
        wrmsr(IA32_LSTAR, hl_syscall_entry as usize as u64);
        wrmsr(IA32_FMASK, FMASK_VALUE);
    }
}

/// Run `f` in ring 3, returning the value it passes to `SYS_RETURN`.
///
/// `f` is an `extern "C"` function that receives `arg` and must not return
/// normally; it terminates by issuing a `SYS_RETURN` syscall (see
/// [`sys_return`]).
///
/// # Safety
/// [`init`] must have been called. `f` must be mapped user-accessible and
/// executable, and must only touch user-accessible memory while in ring 3.
pub(crate) unsafe fn enter_user_fn(f: extern "C" fn(u64) -> !, arg: u64) -> u64 {
    unsafe { enter_user(f as usize as u64, arg) }
}

/// Issue a `SYS_RETURN` syscall from ring 3, returning `value` to the ring 0
/// [`enter_user`] caller. Never returns.
///
/// # Safety
/// Must only be called from ring 3 code entered via [`enter_user_fn`].
pub(crate) unsafe fn sys_return(value: u64) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_RETURN,
            in("rdi") value,
            options(noreturn, nostack),
        )
    }
}

// The `enter_user` / `hl_syscall_entry` pair. See the module documentation for
// the stack-switching contract.
global_asm!(
    // ----- enter_user(entry = rdi, arg = rsi) -> rax -----
    ".global enter_user",
    "enter_user:",
    // Preserve the System V callee-saved registers so SYS_RETURN can return
    // cleanly into our caller.
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    // Record the kernel RSP for the SYS_RETURN unwind / syscall stack base.
    "mov [rip + {kernel_rsp}], rsp",
    // Build the iretq frame (popped as RIP, CS, RFLAGS, RSP, SS), so push in
    // reverse: SS, RSP, RFLAGS, CS, RIP.
    "mov rax, {user_ss}",
    "push rax",
    "mov rax, {user_stack_top}",
    "sub rax, 8", // SysV expects RSP%16==8 at function entry (no call pushed a return address)
    "push rax",
    "mov rax, {user_rflags}",
    "push rax",
    "mov rax, {user_cs}",
    "push rax",
    "push rdi", // entry RIP
    "mov rdi, rsi", // arg -> first parameter of the user function
    // Scrub registers so no ring 0 state leaks into ring 3.
    "xor rax, rax",
    "xor rsi, rsi",
    "xor rdx, rdx",
    "xor rcx, rcx",
    "xor r8, r8",
    "xor r9, r9",
    "xor r10, r10",
    "xor r11, r11",
    "xor rbx, rbx",
    "xor rbp, rbp",
    "xor r12, r12",
    "xor r13, r13",
    "xor r14, r14",
    "xor r15, r15",
    "iretq",
    // ----- hl_syscall_entry: syscall from ring 3 -----
    // On entry: rcx = user return RIP, r11 = user RFLAGS, rsp = user stack
    // (unchanged), rax = syscall number, args in rdi/rsi/rdx. IF is cleared.
    ".global hl_syscall_entry",
    "hl_syscall_entry:",
    "cmp rax, {sys_return}",
    "jne 2f",
    // SYS_RETURN: restore the kernel stack and unwind into enter_user's caller.
    "mov rsp, [rip + {kernel_rsp}]",
    "mov rax, rdi", // return value
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "ret",
    // Any other syscall number is not implemented yet; trap loudly. Replaced
    // with a real dispatcher when privileged services are wired up.
    "2:",
    "ud2",
    kernel_rsp = sym HL_KERNEL_RETURN_RSP,
    user_ss = const USER_SS,
    user_cs = const USER_CS,
    user_rflags = const USER_RFLAGS,
    user_stack_top = const USER_STACK_TOP_GVA,
    sys_return = const SYS_RETURN,
);

/// Self-test the ring 0 -> ring 3 -> ring 0 round-trip.
///
/// Drops into ring 3, runs a trivial user function that transforms its
/// argument and returns it via `SYS_RETURN`, and checks the value survives the
/// round-trip. Aborts the guest if the mechanism is broken, since continuing
/// would be unsafe. Cheap (a single transition) and only ever runs in a
/// `userspace`-enabled guest.
pub(crate) fn selftest() {
    /// Sentinel mixed into the round-trip so a stuck/zero value is detected.
    const SENTINEL: u64 = 0x1234_5678_9abc_def0;
    const TRANSFORM: u64 = 0x0f0f_0f0f_0f0f_0f0f;

    extern "C" fn user_fn(arg: u64) -> ! {
        // Runs in ring 3. Pure register arithmetic plus the syscall; touches
        // only the (user-accessible) stack.
        unsafe { sys_return(arg ^ TRANSFORM) }
    }

    let got = unsafe { enter_user_fn(user_fn, SENTINEL) };
    if got != SENTINEL ^ TRANSFORM {
        panic!("ring 3 round-trip self-test failed: got {got:#x}");
    }
}

/// Self-test the user heap by allocating from ring 3.
///
/// Drops into ring 3, allocates a vector from the user heap, fills and checksums
/// it, frees it, and returns the checksum. This exercises the routed global
/// allocator's ring 3 path end to end. Aborts the guest on mismatch.
pub(crate) fn selftest_user_heap() {
    /// Sentinel mixed into the elements so a stuck/zero result is detected.
    const SENTINEL: u64 = 0xcafe_f00d_dead_beef;
    /// Number of elements to allocate and sum.
    const N: u64 = 128;

    extern "C" fn user_fn(arg: u64) -> ! {
        // Runs in ring 3. Allocations route to the user heap.
        let mut v: alloc::vec::Vec<u64> = alloc::vec::Vec::with_capacity(N as usize);
        for i in 0..N {
            v.push(arg.wrapping_add(i));
        }
        let sum = v.iter().fold(0u64, |acc, &x| acc ^ x);
        drop(v);
        unsafe { sys_return(sum) }
    }

    let expected = (0..N).fold(0u64, |acc, i| acc ^ SENTINEL.wrapping_add(i));
    let got = unsafe { enter_user_fn(user_fn, SENTINEL) };
    if got != expected {
        panic!("ring 3 user-heap self-test failed: got {got:#x}, expected {expected:#x}");
    }
}
