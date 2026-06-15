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

// The addresses in this file should be coordinated with
// src/hyperlight_common/src/arch/amd64/layout.rs and
// src/hyperlight_guest/src/arch/amd64/layout.rs

/// On amd64, since the processor is told the VAs of control
/// structures like the GDT/IDT/TSS, we need to map them somewhere to
/// a VA that will survive the snapshot process. Since we don't have a
/// useful virtual allocator yet, we just put them here...
pub const PROC_CONTROL_GVA: u64 = 0xffff_fd00_0000_0000;

/// Top (exclusive, i.e. one past the highest byte) of the ring 3 user stack,
/// used when the `userspace` feature drops guest code into ring 3. It lives in
/// its own high-half slot, well clear of the kernel main stack
/// (`MAIN_STACK_TOP_GVA`, 0xffff_ff00_..), the processor control structures
/// (`PROC_CONTROL_GVA`, 0xffff_fd00_..) and the snapshot page tables
/// (0xffff_8000_..). The stack grows downward from here.
#[cfg(feature = "userspace")]
pub const USER_STACK_TOP_GVA: u64 = 0xffff_fc00_0000_0000;

/// Size of the ring 3 user stack. A small fixed stack is mapped eagerly when
/// entering ring 3 for the first time; on-demand growth via the page-fault
/// handler is a later refinement.
#[cfg(feature = "userspace")]
pub const USER_STACK_SIZE: u64 = 64 * 1024;
