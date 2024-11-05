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

use core::alloc::Layout;
use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::ptr;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::entrypoint::abort_with_code;

extern crate alloc;

#[no_mangle]
pub extern "C" fn hlmalloc(size: usize) -> *mut c_void {
    alloc_helper(size, false)
}

pub fn alloc_helper(size: usize, zero: bool) -> *mut c_void {
    // Allocate a block that includes space for both layout information and data
    if size == 0 {
        return ptr::null_mut();
    }

    let total_size = size + size_of::<Layout>();
    let layout = Layout::from_size_align(total_size, align_of::<usize>()).unwrap();
    unsafe {
        let raw_ptr = match zero {
            true => alloc::alloc::alloc_zeroed(layout),
            false => alloc::alloc::alloc(layout),
        };
        if raw_ptr.is_null() {
            abort_with_code(ErrorCode::MallocFailed as i32);
        } else {
            let layout_ptr = raw_ptr as *mut Layout;
            layout_ptr.write(layout);
            layout_ptr.add(1) as *mut c_void
        }
    }
}

#[no_mangle]
pub extern "C" fn hlcalloc(n: usize, size: usize) -> *mut c_void {
    let total_size = n * size;
    alloc_helper(total_size, true)
}

#[no_mangle]
pub extern "C" fn hlfree(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            let block_start = (ptr as *const Layout).sub(1);
            let layout = block_start.read();
            alloc::alloc::dealloc(block_start as *mut u8, layout)
        }
    }
}

#[no_mangle]
pub extern "C" fn hlrealloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    if ptr.is_null() {
        // If the pointer is null, treat as a malloc
        return hlmalloc(size);
    }

    unsafe {
        let block_start = (ptr as *const Layout).sub(1);
        let layout = block_start.read();
        let total_new_size = size + size_of::<Layout>();
        let new_block_start =
            alloc::alloc::realloc(block_start as *mut u8, layout, total_new_size) as *mut Layout;

        if new_block_start.is_null() {
            // Realloc failed
            abort_with_code(ErrorCode::MallocFailed as i32);
        } else {
            // Return the pointer just after the layout information
            // since old layout should still as it would have been copied
            new_block_start.add(1) as *mut c_void
        }
    }
}
