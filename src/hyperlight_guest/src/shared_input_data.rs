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
use core::any::type_name;
use core::slice::from_raw_parts_mut;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::error::{HyperlightGuestError, Result};
use crate::P_PEB;

/// Retrieves and deserializes data from the shared input buffer.
///
/// This function retrieves the top element from the shared input buffer (which is used 
/// for host-to-guest communication), converts it to the specified type, and updates the
/// buffer's state to mark that data as consumed. It works as a stack, where the most 
/// recently pushed data is retrieved first.
///
/// # Type Parameters
///
/// * `T` - The type to deserialize the buffer data into, which must implement
///   `TryFrom<&[u8]>`
///
/// # Returns
///
/// * `Ok(T)` - The successfully deserialized value
/// * `Err` - If there was an error reading from the buffer or converting to type `T`
///
/// # Errors
///
/// This function will return an error in the following situations:
/// * If the input data buffer has zero size
/// * If the stack pointer is out of bounds (less than 16 or greater than the buffer size)
/// * If the buffer data cannot be converted to the requested type `T`
///
/// # Example
///
/// ```no_run
/// use hyperlight_guest::shared_input_data::try_pop_shared_input_data_into;
/// use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
///
/// // After receiving data from the host (e.g., after a host function call)
/// let return_value = try_pop_shared_input_data_into::<ReturnValue>()
///     .expect("Failed to deserialize return value");
///
/// // Process the return value
/// match return_value {
///     ReturnValue::Int(i) => println!("Got integer: {}", i),
///     ReturnValue::String(s) => println!("Got string: {}", s),
///     // Handle other return value types...
///     _ => println!("Got other return type"),
/// }
/// ```
///
/// # Memory Layout
///
/// The shared input buffer has the following structure:
/// ```text
/// +----------------+------------------+--------------------+
/// | Stack Pointer  | Data Block 1     | Pointer to Block 1 |
/// | (8 bytes)      | (variable size)  | (8 bytes)          |
/// +----------------+------------------+--------------------+
/// ```
///
/// This function:
/// 1. Reads the stack pointer to find the last element pointer
/// 2. Reads the data at the position indicated by that pointer
/// 3. Converts the data to the requested type
/// 4. Updates the stack pointer and zeros out the consumed data
pub fn try_pop_shared_input_data_into<T>() -> Result<T>
where
    T: for<'a> TryFrom<&'a [u8]>,
{
    let peb_ptr = unsafe { P_PEB.unwrap() };
    let shared_buffer_size = unsafe { (*peb_ptr).inputdata.inputDataSize as usize };

    let idb = unsafe {
        from_raw_parts_mut(
            (*peb_ptr).inputdata.inputDataBuffer as *mut u8,
            shared_buffer_size,
        )
    };

    if idb.is_empty() {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "Got a 0-size buffer in pop_shared_input_data_into".to_string(),
        ));
    }

    // get relative offset to next free address
    let stack_ptr_rel: usize =
        usize::from_le_bytes(idb[..8].try_into().expect("Shared input buffer too small"));

    if stack_ptr_rel > shared_buffer_size || stack_ptr_rel < 16 {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Invalid stack pointer: {} in pop_shared_input_data_into",
                stack_ptr_rel
            ),
        ));
    }

    // go back 8 bytes and read. This is the offset to the element on top of stack
    let last_element_offset_rel = usize::from_le_bytes(
        idb[stack_ptr_rel - 8..stack_ptr_rel]
            .try_into()
            .expect("Invalid stack pointer in pop_shared_input_data_into"),
    );

    let buffer = &idb[last_element_offset_rel..];

    // convert the buffer to T
    let type_t = match T::try_from(buffer) {
        Ok(t) => Ok(t),
        Err(_e) => {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!("Unable to convert buffer to {}", type_name::<T>()),
            ));
        }
    };

    // update the stack pointer to point to the element we just popped of since that is now free
    idb[..8].copy_from_slice(&last_element_offset_rel.to_le_bytes());

    // zero out popped off buffer
    idb[last_element_offset_rel..stack_ptr_rel].fill(0);

    type_t
}
