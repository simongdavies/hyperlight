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

//! Syscall ABI numbers for the `userspace` feature (x86-64).
//!
//! These are the single source of truth shared between the ring 3 *issuers*
//! (here in `hyperlight_guest` and in `hyperlight_guest_bin`) and the ring 0
//! *dispatcher* (`hyperlight_guest_bin::arch::amd64::ring3`). The number is
//! passed in `rax`; see that module for the calling convention and the two
//! kinds of syscall (non-returning vs returning).

/// Return from a ring 3 user function back into the `enter_user` caller
/// (non-returning; the 64-bit value is passed in RDI).
pub const SYS_RETURN: u64 = 0;
/// Boot self-test of the returning-syscall path: XOR two scalars in ring 0.
pub const SYS_SELFTEST: u64 = 1;
/// Perform a host function call on behalf of ring 3 (RDI points to a descriptor
/// in user memory; returning).
pub const SYS_HOST_CALL: u64 = 2;
/// Perform a privileged `out dx, eax` on behalf of ring 3 (RDI = port,
/// RSI = value; returning). Used by the abort/debug-print paths, whose data is
/// carried in the `out` value rather than a shared buffer.
pub const SYS_OUTB: u64 = 3;
