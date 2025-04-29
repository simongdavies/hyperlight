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

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::slice::from_raw_parts_mut;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::error::{HyperlightGuestError, Result};
use crate::P_PEB;

/// Adds data to the shared output buffer used for communication between guest and host.
///
/// This function writes data to a shared memory region that can be read by the host. It uses a
/// stack-like structure where each write adds both the data itself and a pointer to that data.
/// The function maintains a stack pointer at the beginning of the buffer that indicates where
/// the next write should occur.
///
/// # Parameters
///
/// * `data` - The byte vector containing the data to write to the shared output buffer
///
/// # Returns
///
/// * `Ok(())` - If the data was successfully written to the shared output buffer
/// * `Err` - If there was an error writing to the buffer, such as insufficient space or invalid state
///
/// # Errors
///
/// This function will return an error in the following situations:
/// * If the output data buffer has zero size
/// * If the stack pointer is out of bounds (less than 8 or greater than the buffer size)
/// * If there is not enough space in the buffer to write the data and its pointer
///
/// # Example
///
/// ```no_run
/// use hyperlight_guest::shared_output_data::push_shared_output_data;
/// use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
///
/// // Serialize and push a result to the shared output buffer
/// let result = 42;
/// let serialized_data = get_flatbuffer_result(result);
/// push_shared_output_data(serialized_data).expect("Failed to write to shared output buffer");
/// ```
///
/// # Memory Layout
///
/// The shared output buffer has the following structure:
/// ```text
/// +----------------+------------------+----------+------------------+
/// | Stack Pointer  | User Data Block 1| Pointer 1| User Data Block 2|
/// | (8 bytes)      | (variable size)  | (8 bytes)| (variable size)  |
/// +----------------+------------------+----------+------------------+
/// ```
///
/// Each time this function is called, it:
/// 1. Writes the user data at the position indicated by the stack pointer
/// 2. Writes a pointer (offset) to that data immediately after the data
/// 3. Updates the stack pointer to point past both the data and its pointer
pub fn push_shared_output_data(data: Vec<u8>) -> Result<()> {
    let peb_ptr = unsafe { P_PEB.unwrap() };
    let shared_buffer_size = unsafe { (*peb_ptr).outputdata.outputDataSize as usize };
    let odb = unsafe {
        from_raw_parts_mut(
            (*peb_ptr).outputdata.outputDataBuffer as *mut u8,
            shared_buffer_size,
        )
    };

    if odb.is_empty() {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "Got a 0-size buffer in push_shared_output_data".to_string(),
        ));
    }

    // get offset to next free address on the stack
    let stack_ptr_rel: usize =
        usize::from_le_bytes(odb[..8].try_into().expect("Shared output buffer too small"));

    // check if the stack pointer is within the bounds of the buffer.
    // It can be equal to the size, but never greater
    // It can never be less than 8. An empty buffer's stack pointer is 8
    if stack_ptr_rel > shared_buffer_size || stack_ptr_rel < 8 {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Invalid stack pointer: {} in push_shared_output_data",
                stack_ptr_rel
            ),
        ));
    }

    // check if there is enough space in the buffer
    let size_required = data.len() + 8; // the data plus the pointer pointing to the data
    let size_available = shared_buffer_size - stack_ptr_rel;
    if size_required > size_available {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Not enough space in shared output buffer. Required: {}, Available: {}",
                size_required, size_available
            ),
        ));
    }

    // write the actual data
    odb[stack_ptr_rel..stack_ptr_rel + data.len()].copy_from_slice(&data);

    // write the offset to the newly written data, to the top of the stack
    let bytes = stack_ptr_rel.to_le_bytes();
    odb[stack_ptr_rel + data.len()..stack_ptr_rel + data.len() + 8].copy_from_slice(&bytes);

    // update stack pointer to point to next free address
    let new_stack_ptr_rel = stack_ptr_rel + data.len() + 8;
    odb[0..8].copy_from_slice(&(new_stack_ptr_rel).to_le_bytes());

    Ok(())
}
