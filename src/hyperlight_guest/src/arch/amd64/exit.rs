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

use core::arch::asm;

#[cfg(feature = "trace_guest")]
use hyperlight_common::outb::OutBAction;

/// OUT function for sending a 32-bit value to the host.
///
/// With the `userspace` feature, a ring 3 caller cannot execute the privileged
/// `out` instruction, so the call is routed through a `SYS_OUTB` syscall and the
/// real `out` is performed in ring 0 by [`raw_out32`]. Ring 0 callers (including
/// exception handlers, which always run in ring 0) go straight to [`raw_out32`].
///
/// `out32` can be called from an exception context, so we must be careful
/// with the tracing state that might be locked at that time.
/// The tracing state calls `try_lock` internally to avoid deadlocks.
/// Furthermore, the instrument macro is not used here to avoid creating spans
/// in exception contexts. Because if the trace state is already locked, trying to create a span
/// would cause a panic, which is undesirable in exception handling.
pub(crate) unsafe fn out32(port: u16, val: u32) {
    #[cfg(all(feature = "userspace", target_arch = "x86_64"))]
    if in_ring3() {
        // Ring 3 cannot execute `out`; trap into ring 0, which performs the real
        // OUT. (Tracing batches are not forwarded from ring 3 yet.)
        unsafe {
            asm!(
                "syscall",
                in("rax") crate::syscall::SYS_OUTB,
                in("rdi") port as u64,
                in("rsi") val as u64,
                lateout("rax") _,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        return;
    }
    unsafe { raw_out32(port, val) }
}

/// Execute the privileged `out dx, eax` (plus any pending trace batch). Must run
/// in ring 0; the `userspace` ring 0 syscall dispatcher calls this on behalf of
/// ring 3.
///
/// # Safety
/// Issues a privileged I/O instruction; must be called from ring 0.
pub unsafe fn raw_out32(port: u16, val: u32) {
    #[cfg(feature = "trace_guest")]
    {
        if let Some((ptr, len)) = hyperlight_guest_tracing::serialized_data() {
            // If tracing is enabled and there is data to send, send it along with the OUT action
            unsafe {
                asm!("out dx, eax",
                    in("dx") port,
                    in("eax") val,
                    in("r8") OutBAction::TraceBatch as u64,
                    in("r9") ptr,
                    in("r10") len,
                    options(preserves_flags, nomem, nostack)
                )
            };

            // Reset the trace state after sending the batch
            // This clears all existing spans/events ensuring a clean state for the next operations
            // The trace state is expected to be flushed before this call
            hyperlight_guest_tracing::reset();
        } else {
            // If tracing is not enabled, just send the value
            unsafe {
                asm!("out dx, eax", in("dx") port, in("eax") val, options(preserves_flags, nomem, nostack))
            };
        }
    }
    #[cfg(not(feature = "trace_guest"))]
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") val, options(preserves_flags, nomem, nostack));
    }
}

/// True if the CPU is currently executing in ring 3 (user mode), determined from
/// the current code segment selector's requested privilege level. Reading CS is
/// unprivileged and cheap.
#[cfg(all(feature = "userspace", target_arch = "x86_64"))]
#[inline(always)]
fn in_ring3() -> bool {
    let cs: u16;
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    (cs & 3) == 3
}
