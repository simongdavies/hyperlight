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

use alloc::vec::Vec;
use core::alloc::Layout;
use core::arch::{asm, global_asm};

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::vmem::{BasicMapping, MappingKind, PAGE_SIZE};
use hyperlight_guest::error::Result;
use hyperlight_guest::prim_alloc::alloc_phys_pages;

use super::layout::{USER_STACK_SIZE, USER_STACK_TOP_GVA};
use crate::guest_function::definition::GuestFunc;
use crate::userspace_heap::{user_alloc, user_dealloc};

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
// Passed in RAX by ring 3 code. Two kinds of syscall exist:
//
// * *Non-returning* syscalls unwind the kernel stack back into [`enter_user`]'s
//   caller and never resume the ring 3 code (`SYS_RETURN`).
// * *Returning* syscalls run a ring 0 handler ([`hl_syscall_dispatch`]) and then
//   `sysretq` back into the ring 3 code with a result in RAX.
//
// Privileged services (host calls, logging, abort) are added on top of the
// returning-syscall mechanism in later phases.
/// Return from a ring 3 user function back into [`enter_user`]'s caller. The
/// 64-bit return value is passed in RDI. Non-returning.
pub(crate) const SYS_RETURN: u64 = 0;

/// Self-test syscall used to validate the returning-syscall (`sysretq`) path at
/// boot. Takes two scalar arguments and returns their XOR, computed in ring 0.
/// Pointer-free by design, so it exercises the transition mechanism in
/// isolation from user-pointer handling. Returning.
const SYS_SELFTEST: u64 = 1;

/// Perform a host function call on behalf of ring 3 code. `a0` is a pointer to a
/// [`HostCallDescriptor`] in user memory describing the (already-serialised)
/// request; the ring 0 handler performs the privileged push/`out`/pop and writes
/// the encoded result back into the descriptor. Returning.
const SYS_HOST_CALL: u64 = 2;

/// True if the CPU is currently executing in ring 3 (user mode), determined from
/// the current code segment selector's requested privilege level. Reading CS is
/// unprivileged and cheap.
#[inline(always)]
pub(crate) fn in_ring3() -> bool {
    let cs: u16;
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    (cs & 3) == 3
}

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

/// Scratch slot holding the ring 3 `RSP` while a returning syscall runs on the
/// kernel stack, so it can be restored before `sysretq`. Single-vCPU,
/// single-threaded: one slot is sufficient.
static mut HL_USER_RSP_SCRATCH: u64 = 0;

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

/// Issue a *returning* syscall from ring 3 with two scalar arguments, returning
/// the `u64` the ring 0 handler produced.
///
/// `syscall` clobbers `rcx` and `r11`, and the ring 0 handler is an ordinary C
/// function, so every caller-saved register is treated as clobbered.
///
/// # Safety
/// Must only be called from ring 3 code entered via [`enter_user_fn`].
unsafe fn syscall2(num: u64, a0: u64, a1: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            inout("rax") num => ret,
            inout("rdi") a0 => _,
            inout("rsi") a1 => _,
            out("rdx") _,
            out("rcx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
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
    // Returning syscall: run a ring 0 handler then sysretq back to ring 3.
    "2:",
    // Stash the ring 3 RSP and switch to the kernel stack. The kernel stack
    // grows downward from the parked enter_user frame, so it does not disturb
    // the callee-saved registers SYS_RETURN will later pop.
    "mov [rip + {user_rsp}], rsp",
    "mov rsp, [rip + {kernel_rsp}]",
    // Preserve the user return RIP (rcx) and RFLAGS (r11) across the call; both
    // are needed by sysretq and would be clobbered by a C call.
    "push rcx",
    "push r11",
    "sub rsp, 8", // keep rsp 16-byte aligned for the call
    // Marshal into the System V argument registers: dispatch(num, a0, a1, a2).
    // Cascade so no source register is clobbered before it is read.
    "mov rcx, rdx", // a2 -> 4th arg
    "mov rdx, rsi", // a1 -> 3rd arg
    "mov rsi, rdi", // a0 -> 2nd arg
    "mov rdi, rax", // syscall number -> 1st arg
    "call {dispatch}",
    // rax now holds the result to deliver to ring 3.
    "add rsp, 8",
    "pop r11", // user RFLAGS
    "pop rcx", // user return RIP
    "mov rsp, [rip + {user_rsp}]",
    "sysretq",
    kernel_rsp = sym HL_KERNEL_RETURN_RSP,
    user_rsp = sym HL_USER_RSP_SCRATCH,
    dispatch = sym hl_syscall_dispatch,
    user_ss = const USER_SS,
    user_cs = const USER_CS,
    user_rflags = const USER_RFLAGS,
    user_stack_top = const USER_STACK_TOP_GVA,
    sys_return = const SYS_RETURN,
);

/// Ring 0 handler for *returning* syscalls from ring 3.
///
/// Runs on the kernel stack (set up by `hl_syscall_entry`); the `u64` return
/// value is delivered to ring 3 in RAX after `sysretq`. An unknown syscall
/// number indicates a broken or malicious ring 3, so the guest is aborted.
///
/// Pointer-taking syscalls added in later phases must validate that any
/// user-supplied pointers refer to user-accessible memory before dereferencing
/// them, so ring 3 cannot use the kernel to read or write supervisor memory.
#[unsafe(no_mangle)]
extern "C" fn hl_syscall_dispatch(num: u64, a0: u64, a1: u64, _a2: u64) -> u64 {
    match num {
        SYS_SELFTEST => a0 ^ a1,
        SYS_HOST_CALL => unsafe { sys_host_call_handler(a0) },
        _ => panic!("ring 3 issued an unknown syscall: {num:#x}"),
    }
}

/// Descriptor for a ring 3 host function call, shared between the ring 3 issuer
/// ([`sys_host_call`]) and the ring 0 handler ([`sys_host_call_handler`]). Lives
/// in user memory so both sides can read and write it.
#[repr(C)]
struct HostCallDescriptor {
    /// User buffer holding the encoded host `FunctionCall` request (input).
    request_ptr: u64,
    request_len: u64,
    /// User buffer (a leaked `Vec<u8>`) holding the encoded
    /// `FunctionCallResult`, written by the ring 0 handler (output). A null
    /// `result_ptr` signals the call failed before producing a result.
    result_ptr: u64,
    result_len: u64,
    result_cap: u64,
}

/// Ring 0 handler for [`SYS_HOST_CALL`].
///
/// Reads the request bytes the ring 3 caller staged in user memory, performs the
/// privileged host call (push to the shared output buffer, `out`, pop the result
/// from the shared input buffer) via the supervisor-only guest handle, copies
/// the encoded result into a fresh user buffer, and records it in the
/// descriptor. All access to the PEB, shared buffers, and the `out` instruction
/// stays in ring 0; ring 3 only ever sees its own user buffers.
///
/// # Safety
/// `desc_ptr` must point to a valid [`HostCallDescriptor`] in user memory whose
/// `request_ptr`/`request_len` describe a readable user buffer.
unsafe fn sys_host_call_handler(desc_ptr: u64) -> u64 {
    unsafe {
        let desc = &mut *(desc_ptr as *mut HostCallDescriptor);
        let request =
            core::slice::from_raw_parts(desc.request_ptr as *const u8, desc.request_len as usize);

        let handle = crate::GUEST_HANDLE;
        match handle.dispatch_host_call_raw(request) {
            Ok(result) => {
                // Stage the encoded result in a user buffer for ring 3 to read.
                let layout = layout_for(result.len());
                let buf = user_alloc(layout);
                if buf.is_null() {
                    desc.result_ptr = 0;
                    desc.result_len = 0;
                    desc.result_cap = 0;
                } else {
                    core::ptr::copy_nonoverlapping(result.as_ptr(), buf, result.len());
                    desc.result_ptr = buf as u64;
                    desc.result_len = result.len() as u64;
                    desc.result_cap = layout.size() as u64;
                }
            }
            Err(_) => {
                desc.result_ptr = 0;
                desc.result_len = 0;
                desc.result_cap = 0;
            }
        }
        0
    }
}

/// Issue a [`SYS_HOST_CALL`] from ring 3, returning the encoded
/// `FunctionCallResult` bytes the host produced (in a user-heap `Vec`).
///
/// The request bytes are already in user-accessible memory (the caller
/// serialised them on the user heap); the descriptor lives on the ring 3 stack.
/// Returns `None` if the host call failed to produce a result.
///
/// # Safety
/// Must only be called from ring 3 code entered via [`enter_user`].
pub(crate) unsafe fn sys_host_call(request: &[u8]) -> Option<Vec<u8>> {
    let mut desc = HostCallDescriptor {
        request_ptr: request.as_ptr() as u64,
        request_len: request.len() as u64,
        result_ptr: 0,
        result_len: 0,
        result_cap: 0,
    };
    unsafe {
        syscall2(SYS_HOST_CALL, &raw mut desc as u64, 0);
    }
    if desc.result_ptr == 0 {
        return None;
    }
    // Reconstruct the Vec the ring 0 handler allocated on the user heap so it is
    // owned (and freed) here; the routed allocator sends the free to the user
    // heap by address.
    let v = unsafe {
        Vec::from_raw_parts(
            desc.result_ptr as *mut u8,
            desc.result_len as usize,
            desc.result_cap as usize,
        )
    };
    Some(v)
}

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

/// Self-test the *returning* syscall (`sysretq`) path.
///
/// Drops into ring 3, issues a `SYS_SELFTEST` syscall (handled in ring 0 by
/// [`hl_syscall_dispatch`]), verifies the ring 0 result is delivered back to
/// ring 3, then returns it via `SYS_RETURN`. This exercises the full
/// ring 3 -> ring 0 -> ring 3 -> ring 0 path, including the `sysretq` resume
/// that the non-returning self-tests do not cover. Aborts the guest on
/// mismatch.
pub(crate) fn selftest_returning_syscall() {
    /// Arbitrary operands whose XOR (computed in ring 0) is checked twice: once
    /// in ring 3 after `sysretq`, and once in ring 0 after `SYS_RETURN`.
    const A: u64 = 0xa5a5_a5a5_0000_1111;
    const B: u64 = 0x1234_2222_5a5a_5a5a;

    extern "C" fn user_fn(arg: u64) -> ! {
        // Runs in ring 3. Issue a returning syscall, check the result came back
        // across sysretq, then hand it to SYS_RETURN.
        let got = unsafe { syscall2(SYS_SELFTEST, arg, B) };
        if got != arg ^ B {
            // Resumed in ring 3 but with the wrong value: report a sentinel the
            // ring 0 checker below will reject.
            unsafe { sys_return(0) }
        }
        unsafe { sys_return(got) }
    }

    let got = unsafe { enter_user_fn(user_fn, A) };
    if got != A ^ B {
        panic!(
            "ring 3 returning-syscall self-test failed: got {got:#x}, expected {:#x}",
            A ^ B
        );
    }
}

// ===== Running registered guest functions in ring 3 =====

/// Shared descriptor for a guest-function call marshalled into ring 3.
///
/// Lives in user-accessible memory so both the ring 0 caller and the ring 3
/// trampoline can read and write it. The ring 0 side fills in the inputs
/// (`fn_ptr`, `input_*`); the ring 3 side fills in the outputs (`output_*`)
/// with the bytes to push to the host's shared output buffer.
#[repr(C)]
struct GuestCallDescriptor {
    /// Address of the registered guest function (`GuestFunc`).
    fn_ptr: u64,
    /// User buffer holding the encoded `FunctionCall`.
    input_ptr: u64,
    input_len: u64,
    /// User buffer (a leaked `Vec<u8>`) holding the encoded result to return to
    /// the host. Written by the ring 3 trampoline.
    output_ptr: u64,
    output_len: u64,
    output_cap: u64,
}

/// Run a registered guest function `f` in ring 3 and return the bytes to push
/// to the host's shared output buffer.
///
/// `encoded_call` is the original encoded `FunctionCall` (the bytes the host
/// placed in the shared input buffer). They are copied verbatim into a user
/// buffer - no re-encoding - the function runs in ring 3 (so its allocations
/// land on the user heap and a bug cannot touch the runtime's supervisor
/// state), and the encoded result is copied back. Any error raised by the guest
/// function is encoded into a `FunctionCallResult` in ring 3, exactly as the
/// ring 0 dispatch path would, so the returned bytes are always the final bytes
/// to hand to the host.
///
/// Returned as `Result` only to match the non-userspace call site; it is always
/// `Ok` (guest-function errors are encoded into the returned bytes).
///
/// Note: a guest function that itself calls a host function will fault in
/// ring 3 until the host-call syscall is wired up; pure guest functions work
/// today.
///
/// # Safety
/// [`init`] and the user heap must be initialised, and `f` must be a valid
/// registered guest-function pointer.
pub(crate) unsafe fn run_registered_guest_fn(f: GuestFunc, encoded_call: &[u8]) -> Result<Vec<u8>> {
    // Stage the (already-encoded) call, plus the descriptor, in user-accessible
    // memory for ring 3 to read.
    let input_layout = layout_for(encoded_call.len());
    let desc_layout = Layout::new::<GuestCallDescriptor>();
    unsafe {
        let input_buf = user_alloc(input_layout);
        let desc_buf = user_alloc(desc_layout) as *mut GuestCallDescriptor;
        assert!(
            !input_buf.is_null() && !desc_buf.is_null(),
            "user heap exhausted while marshalling a guest call into ring 3"
        );
        core::ptr::copy_nonoverlapping(encoded_call.as_ptr(), input_buf, encoded_call.len());
        desc_buf.write(GuestCallDescriptor {
            fn_ptr: f as usize as u64,
            input_ptr: input_buf as u64,
            input_len: encoded_call.len() as u64,
            output_ptr: 0,
            output_len: 0,
            output_cap: 0,
        });

        // Run the guest function in ring 3.
        enter_user(guest_call_trampoline as usize as u64, desc_buf as u64);

        // Copy the result out of user memory into a kernel-heap Vec, then free
        // the user buffers.
        let desc = &*desc_buf;
        let out =
            core::slice::from_raw_parts(desc.output_ptr as *const u8, desc.output_len as usize)
                .to_vec();
        if desc.output_cap != 0 {
            user_dealloc(
                desc.output_ptr as *mut u8,
                layout_for(desc.output_cap as usize),
            );
        }
        user_dealloc(input_buf, input_layout);
        user_dealloc(desc_buf as *mut u8, desc_layout);
        Ok(out)
    }
}

/// `Layout` for a `len`-byte, byte-aligned user buffer (matching `Vec<u8>`).
#[inline]
fn layout_for(len: usize) -> Layout {
    // align 1 matches Vec<u8>'s allocation; len is clamped to at least 1 so the
    // allocator never sees a zero-size request.
    Layout::from_size_align(len.max(1), 1).expect("valid byte-buffer layout")
}

/// Ring 3 trampoline: decode the `FunctionCall`, run the guest function, and
/// stage the encoded result back in user memory for ring 0 to collect.
///
/// Runs entirely in ring 3. All allocations (decoding, the result `Vec`, error
/// encoding) land on the user heap. The result `Vec` is leaked into the
/// descriptor; ring 0 copies it out and frees it.
extern "C" fn guest_call_trampoline(desc_ptr: u64) -> ! {
    // SAFETY: ring 0 passed a valid descriptor pointer in user memory.
    let desc = unsafe { &mut *(desc_ptr as *mut GuestCallDescriptor) };
    // SAFETY: fn_ptr is a registered guest function; input_* describe the
    // encoded FunctionCall staged by ring 0.
    let f: GuestFunc = unsafe { core::mem::transmute::<usize, GuestFunc>(desc.fn_ptr as usize) };
    let input = unsafe {
        core::slice::from_raw_parts(desc.input_ptr as *const u8, desc.input_len as usize)
    };

    // Decode, call, and turn the outcome into the final bytes to hand the host.
    // A guest-function error is encoded into a FunctionCallResult here, mirroring
    // the ring 0 dispatch path, so ring 0 can push the bytes unconditionally.
    let result_bytes: Vec<u8> = match FunctionCall::try_from(input) {
        Ok(call) => match f(call) {
            Ok(bytes) => bytes,
            Err(err) => encode_guest_error(err.kind, &err.message),
        },
        // The input was just re-encoded from a valid FunctionCall by ring 0, so
        // this is effectively unreachable; encode a generic error if it ever
        // happens rather than faulting in ring 3.
        Err(err) => encode_guest_error(ErrorCode::GuestError, &alloc::format!("{err}")),
    };

    // Leak the Vec into the descriptor; ring 0 copies it out and frees it.
    let mut v = result_bytes;
    desc.output_ptr = v.as_mut_ptr() as u64;
    desc.output_len = v.len() as u64;
    desc.output_cap = v.capacity() as u64;
    core::mem::forget(v);

    // SAFETY: reached only from enter_user, in ring 3.
    unsafe { sys_return(0) }
}

/// Encode a guest error into the `FunctionCallResult` flatbuffer the host
/// expects, identically to the ring 0 dispatch path.
fn encode_guest_error(kind: ErrorCode, message: &str) -> Vec<u8> {
    let guest_error = Err(GuestError::new(kind, message.into()));
    let fcr = FunctionCallResult::new(guest_error);
    let mut builder = FlatBufferBuilder::new();
    fcr.encode(&mut builder).to_vec()
}
