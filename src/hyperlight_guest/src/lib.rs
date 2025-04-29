/*
Copyright 2024 The Hyperlight Authors.

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

#![no_std]
// Deps
use alloc::string::ToString;
use core::hint::unreachable_unchecked;
use core::ptr::copy_nonoverlapping;

use buddy_system_allocator::LockedHeap;
use guest_function_register::GuestFunctionRegister;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::mem::{HyperlightPEB, RunMode};

use crate::host_function_call::{outb, OutBAction};
extern crate alloc;

// Modules
pub mod entrypoint;
pub mod shared_input_data;
pub mod shared_output_data;

pub mod guest_error;
pub mod guest_function_call;
pub mod guest_function_definition;
pub mod guest_function_register;

pub mod host_error;
pub mod host_function_call;
pub mod host_functions;

pub(crate) mod guest_logger;
pub mod memory;
pub mod print;
pub(crate) mod security_check;
pub mod setjmp;

pub mod chkstk;
pub mod error;
pub mod gdt;
pub mod idt;
pub mod idtr;
pub mod interrupt_entry;
pub mod interrupt_handlers;
pub mod logging;

// Unresolved symbols
///cbindgen:ignore
#[no_mangle]
pub(crate) extern "C" fn __CxxFrameHandler3() {}
///cbindgen:ignore
#[no_mangle]
pub(crate) static _fltused: i32 = 0;

// It looks like rust-analyzer doesn't correctly manage no_std crates,
// and so it displays an error about a duplicate panic_handler.
// See more here: https://github.com/rust-lang/rust-analyzer/issues/4490

/// Custom panic handler for the no_std guest environment.
///
/// This function is called when a panic occurs in the guest code. It captures the panic 
/// information, writes it to a designated buffer in the `HyperlightPEB` (Process Environment Block),
/// and then signals the host that an abort is requested with an "unknown error" code.
///
/// # Behavior
///
/// 1. Converts the panic information to a string
/// 2. Copies this string into the guest panic context buffer in the PEB
/// 3. Signals the host with an abort request via I/O port
/// 4. Uses `unreachable_unchecked` as the panic is unrecoverable
///
/// # Safety
///
/// This function uses unsafe code to access the PEB and signal the host. It's called
/// automatically by the Rust runtime when a panic occurs and is not meant to be called
/// directly.
///
/// # Note
///
/// The host will observe the abort signal and terminate the guest execution, potentially
/// providing the panic information in diagnostic output.
#[cfg_attr(not(test), panic_handler)]
#[allow(clippy::panic)]
// to satisfy the clippy when cfg == test
#[allow(dead_code)]
fn panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        let peb_ptr = P_PEB.unwrap();
        copy_nonoverlapping(
            info.to_string().as_ptr(),
            (*peb_ptr).guestPanicContextData.guestPanicContextDataBuffer as *mut u8,
            (*peb_ptr).guestPanicContextData.guestPanicContextDataSize as usize,
        );
    }
    outb(OutBAction::Abort as u16, ErrorCode::UnknownError as u8);
    unsafe { unreachable_unchecked() }
}

// Globals
#[global_allocator]
/// Memory allocator for the guest environment.
///
/// This is a buddy system allocator that manages dynamic memory allocation for the guest code.
/// It's initialized as empty and will be configured with the appropriate memory region during
/// the guest initialization process.
///
/// The buddy allocator uses 32 levels to efficiently manage memory blocks of different sizes.
/// It's specifically designed for no_std environments like the Hyperlight guest.
pub(crate) static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::empty();

///cbindgen:ignore
#[no_mangle]
/// Security cookie used for stack buffer overflow protection.
///
/// This value is initialized during guest startup and used by security 
/// mechanisms to detect stack corruption. The host will initialize this
/// with a random value during sandbox setup.
pub(crate) static mut __security_cookie: u64 = 0;

/// Pointer to the Hyperlight Process Environment Block.
///
/// The PEB contains critical information about the guest environment, including
/// memory layout, shared buffers for host-guest communication, and various control
/// structures. It is initialized during guest startup and remains valid for the
/// lifetime of the guest execution.
///
/// # Safety
///
/// This is a mutable static variable containing a pointer, so all access requires
/// unsafe code. The pointer is initialized during guest startup and should never
/// be modified after initialization.
pub(crate) static mut P_PEB: Option<*mut HyperlightPEB> = None;

/// Minimum stack address for the guest environment.
///
/// This value stores the lowest valid address of the guest's stack. It's used for
/// stack validation and security checks to ensure that the guest doesn't access memory
/// below the stack boundary. The value is initialized during guest startup.
pub static mut MIN_STACK_ADDRESS: u64 = 0;

/// Operating system page size.
///
/// This variable stores the memory page size of the underlying operating system.
/// It's used for memory alignment operations and optimization of memory accesses.
/// The value is initialized during guest startup based on host system information.
pub static mut OS_PAGE_SIZE: u32 = 0;

/// Function pointer for basic I/O port operations in in-process mode.
///
/// This variable holds a function pointer to the implementation of the I/O port write 
/// operation when running in in-process mode without a context parameter. It's used
/// by the `outb` function to communicate with the host.
///
/// # Safety
///
/// This is a mutable static variable containing a function pointer, so all access
/// requires unsafe code. It should only be modified during guest initialization.
pub(crate) static mut OUTB_PTR: Option<extern "win64" fn(u16, u8)> = None;

/// Function pointer for context-aware I/O port operations in in-process mode.
///
/// This variable holds a function pointer to the implementation of the I/O port write 
/// operation when running in in-process mode with a context parameter. The context 
/// parameter allows for better isolation when multiple guests are running in the same
/// host process.
///
/// # Safety
///
/// This is a mutable static variable containing a function pointer, so all access
/// requires unsafe code. It should only be modified during guest initialization.
pub(crate) static mut OUTB_PTR_WITH_CONTEXT: Option<
    extern "win64" fn(*mut core::ffi::c_void, u16, u8),
> = None;

/// Current runtime mode of the guest.
///
/// This variable indicates how the guest is being executed - either in hypervisor mode
/// (isolated by hardware virtualization), in-process mode on Linux or Windows, or none
/// if not yet initialized. The runtime mode determines various aspects of guest behavior,
/// particularly how it communicates with the host.
///
/// The mode is set during guest initialization and remains constant throughout execution.
pub static mut RUNNING_MODE: RunMode = RunMode::None;

/// Registry of functions that the guest exposes to the host.
///
/// This global registry maintains all guest functions that can be called by the host.
/// It's populated during guest initialization through calls to the `register_function`
/// function and then used by the guest runtime to dispatch incoming function calls 
/// from the host to the appropriate implementation.
///
/// # Safety
///
/// This is a mutable static variable, so all access requires unsafe code. Currently,
/// it's considered safe because the guest is single-threaded, but this may need
/// to be revisited for multi-threaded guests (see issue #808).
pub(crate) static mut REGISTERED_GUEST_FUNCTIONS: GuestFunctionRegister =
    GuestFunctionRegister::new();
