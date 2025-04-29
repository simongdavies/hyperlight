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
use core::slice::from_raw_parts;

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::ParameterType;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;

use crate::error::{HyperlightGuestError, Result};
use crate::P_PEB;

/// Validates a host function call before execution.
///
/// This internal function checks that a host function call is valid by:
/// 1. Verifying the host function exists
/// 2. Checking that the provided parameters match the expected parameter types
/// 3. Ensuring parameter counts match what the function expects
///
/// It's used internally by the Hyperlight runtime before dispatching function calls to
/// the host to ensure type safety and prevent errors.
///
/// # Parameters
///
/// * `function_call` - The function call to validate, containing the function name and parameters
///
/// # Returns
///
/// * `Ok(())` - If the function call is valid
/// * `Err` - If the function doesn't exist or the parameters don't match expectations
///
/// # Errors
///
/// This function will return an error in the following situations:
/// * If no host functions are registered
/// * If the specified function name doesn't exist among registered host functions
/// * If the number of parameters doesn't match what the function expects
/// * If any parameter type doesn't match the expected type at that position
pub(crate) fn validate_host_function_call(function_call: &FunctionCall) -> Result<()> {
    // get host function details
    let host_function_details = get_host_function_details();

    // check if there are any host functions
    if host_function_details.host_functions.is_none() {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "No host functions found".to_string(),
        ));
    }

    // check if function w/ given name exists
    let host_function = if let Some(host_function) =
        host_function_details.find_by_function_name(&function_call.function_name)
    {
        host_function
    } else {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Host Function Not Found: {}",
                function_call.function_name.clone()
            ),
        ));
    };

    let function_call_fparameters = if let Some(parameters) = function_call.parameters.clone() {
        parameters
    } else {
        if host_function.parameter_types.is_some() {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!(
                    "Incorrect parameter count for function: {}",
                    function_call.function_name.clone()
                ),
            ));
        }

        Vec::new() // if no parameters (and no mismatches), return empty vector
    };

    let function_call_parameter_types = function_call_fparameters
        .iter()
        .map(|p| p.into())
        .collect::<Vec<ParameterType>>();

    // Verify that the function call has the correct parameter types.
    host_function
        .verify_equal_parameter_types(&function_call_parameter_types)
        .map_err(|_| {
            HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!(
                    "Incorrect parameter type for function: {}",
                    function_call.function_name.clone()
                ),
            )
        })?;

    Ok(())
}

/// Retrieves information about host functions available to the guest.
///
/// This function reads the host function definitions from the shared Process Environment
/// Block (PEB) and deserializes them into a `HostFunctionDetails` object. This object
/// contains metadata about all the functions implemented by the host that can be called
/// by the guest.
///
/// # Returns
///
/// A `HostFunctionDetails` object containing information about all available host functions,
/// including their names, parameter types, and return types.
///
/// # Panics
///
/// This function will panic if:
/// * The PEB pointer is not initialized
/// * The host function details buffer cannot be deserialized
///
/// # Example
///
/// ```no_run
/// use hyperlight_guest::host_functions::get_host_function_details;
///
/// // Get information about available host functions
/// let host_functions = get_host_function_details();
///
/// // Check if a specific host function exists
/// if let Some(print_function) = host_functions.find_by_function_name("HostPrint") {
///     println!("HostPrint function is available with {} parameters",
///              print_function.parameter_types.as_ref().map_or(0, |v| v.len()));
/// }
/// ```
pub fn get_host_function_details() -> HostFunctionDetails {
    let peb_ptr = unsafe { P_PEB.unwrap() };

    let host_function_details_buffer =
        unsafe { (*peb_ptr).hostFunctionDefinitions.fbHostFunctionDetails } as *const u8;
    let host_function_details_size =
        unsafe { (*peb_ptr).hostFunctionDefinitions.fbHostFunctionDetailsSize };

    let host_function_details_slice: &[u8] = unsafe {
        from_raw_parts(
            host_function_details_buffer,
            host_function_details_size as usize,
        )
    };

    host_function_details_slice
        .try_into()
        .expect("Failed to convert buffer to HostFunctionDetails")
}
