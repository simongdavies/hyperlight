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
use core::arch::global_asm;

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_common::mem::RunMode;

use crate::error::{HyperlightGuestError, Result};
use crate::host_error::check_for_host_error;
use crate::host_functions::validate_host_function_call;
use crate::shared_input_data::try_pop_shared_input_data_into;
use crate::shared_output_data::push_shared_output_data;
use crate::{OUTB_PTR, OUTB_PTR_WITH_CONTEXT, P_PEB, RUNNING_MODE};

/// Action codes used for guest-to-host communication via I/O ports.
///
/// These values identify the type of action the guest is requesting when calling
/// the host through the `outb` function. Each action triggers different behavior
/// in the host system.
///
/// # Variants
///
/// * `Log` - Sends a log message from the guest to the host's logging system
/// * `CallFunction` - Requests execution of a host function defined in the shared output buffer
/// * `Abort` - Signals that the guest is aborting execution, with an exit code
///
/// # Usage
///
/// These codes are used internally by the Hyperlight runtime when calling the `outb`
/// function to signal different events to the host. For example:
///
/// ```no_run
/// use hyperlight_guest::host_function_call::{outb, OutBAction};
///
/// // Signal that we're calling a host function
/// outb(OutBAction::CallFunction as u16, 0);
///
/// // Abort execution with exit code 1
/// outb(OutBAction::Abort as u16, 1);
/// ```
///
/// # Note
///
/// Guest code should typically use the higher-level functions like `call_host_function`
/// or `abort_with_code` rather than using these action codes directly.
pub enum OutBAction {
    Log = 99,
    CallFunction = 101,
    Abort = 102,
}

/// Retrieves the return value from a previously executed host function call.
///
/// This function deserializes a return value from the shared input buffer and
/// tries to convert it to the requested type. It's typically called immediately
/// after `call_host_function` to retrieve the result returned by the host.
///
/// # Type Parameters
///
/// * `T` - The expected return type, which must be able to be converted from a `ReturnValue`
///
/// # Returns
///
/// * `Ok(T)` - The successfully deserialized and converted return value
/// * `Err` - If the return value couldn't be deserialized or converted to the requested type
///
/// # Errors
///
/// This function will return an error in the following situations:
/// * If there is no return value in the shared input buffer
/// * If the return value cannot be converted to the requested type `T`
///
/// # Example
///
/// ```no_run
/// use hyperlight_guest::host_function_call::{call_host_function, get_host_return_value};
/// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
/// use alloc::vec::Vec;
///
/// // Call a host function that returns a string
/// call_host_function(
///     "HostGetGreeting",
///     Some(Vec::from(&[ParameterValue::String("world".to_string())])),
///     ReturnType::String
/// ).expect("Failed to call host function");
///
/// // Get the string result
/// let greeting = get_host_return_value::<String>().expect("Failed to get host return value");
/// assert_eq!(greeting, "Hello, world!");
/// ```
///
/// # Note
///
/// The type parameter `T` must match the actual type returned by the host function
/// that was previously called with `call_host_function`. If there's a mismatch,
/// this function will return an error.
pub fn get_host_return_value<T: TryFrom<ReturnValue>>() -> Result<T> {
    let return_value = try_pop_shared_input_data_into::<ReturnValue>()
        .expect("Unable to deserialize a return value from host");
    T::try_from(return_value).map_err(|_| {
        HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Host return value was not a {} as expected",
                core::any::type_name::<T>()
            ),
        )
    })
}

// TODO: Make this generic, return a Result<T, ErrorCode> this should allow callers to call this function and get the result type they expect
// without having to do the conversion themselves

/// Calls a function implemented by the host from the guest.
///
/// This function allows guest code to invoke functions that are implemented and registered by the host.
/// It serializes the function call information (including name, parameters, and expected return type),
/// writes it to the shared output buffer, and notifies the host via a port operation.
///
/// # Parameters
///
/// * `function_name` - The name of the host function to call
/// * `parameters` - Optional vector of parameters to pass to the host function
/// * `return_type` - The expected return type of the host function
///
/// # Returns
///
/// * `Ok(())` - If the function call was successfully dispatched to the host
/// * `Err` - If there was an error during the call setup or execution
///
/// # Errors
///
/// This function will return an error in the following situations:
/// * If the host function name is not found in the registered host functions
/// * If the parameter types don't match what the host function expects
/// * If there was an error writing to the shared output buffer
/// * If the host encountered an error while executing the function
///
/// # Example
///
/// ```no_run
/// use hyperlight_guest::host_function_call::{call_host_function, get_host_return_value};
/// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
/// use alloc::vec::Vec;
///
/// // Call a host function that adds two numbers
/// call_host_function(
///     "HostAdd",
///     Some(Vec::from(&[ParameterValue::Int(5), ParameterValue::Int(10)])),
///     ReturnType::Int
/// ).expect("Failed to call host function");
///
/// // Get the result from the host function
/// let result = get_host_return_value::<i32>().expect("Failed to get host return value");
/// assert_eq!(result, 15);
/// ```
///
/// # Note
///
/// After calling this function, you typically need to call `get_host_return_value<T>()`
/// to retrieve the result returned by the host function. The type parameter `T` should
/// match the `return_type` parameter passed to this function.
pub fn call_host_function(
    function_name: &str,
    parameters: Option<Vec<ParameterValue>>,
    return_type: ReturnType,
) -> Result<()> {
    let host_function_call = FunctionCall::new(
        function_name.to_string(),
        parameters,
        FunctionCallType::Host,
        return_type,
    );

    validate_host_function_call(&host_function_call)?;

    let host_function_call_buffer: Vec<u8> = host_function_call
        .try_into()
        .expect("Unable to serialize host function call");

    push_shared_output_data(host_function_call_buffer)?;

    outb(OutBAction::CallFunction as u16, 0);

    Ok(())
}

/// Performs an I/O port write operation for communication with the host.
///
/// This low-level function is used to signal events from the guest to the host,
/// such as function calls, log messages, or abort requests. The behavior depends
/// on the runtime environment (hypervisor or in-process mode).
///
/// # Parameters
///
/// * `port` - The I/O port number to write to, typically an `OutBAction` value
/// * `value` - The byte value to write to the port
///
/// # Safety
///
/// This function is unsafe because it performs raw I/O operations and accesses
/// global mutable state. It should only be called from controlled contexts within
/// the Hyperlight guest runtime.
///
/// # Panics
///
/// This function will panic if:
/// * Running in in-process mode without proper function pointers set up
/// * Running in an unsupported runtime mode
///
/// # Note
///
/// This is an internal communication mechanism used by higher-level functions like
/// `call_host_function`. Most guest code should not need to call this function directly.
pub fn outb(port: u16, value: u8) {
    unsafe {
        match RUNNING_MODE {
            RunMode::Hypervisor => {
                hloutb(port, value);
            }
            RunMode::InProcessLinux | RunMode::InProcessWindows => {
                if let Some(outb_func) = OUTB_PTR_WITH_CONTEXT {
                    if let Some(peb_ptr) = P_PEB {
                        outb_func((*peb_ptr).pOutbContext, port, value);
                    }
                } else if let Some(outb_func) = OUTB_PTR {
                    outb_func(port, value);
                } else {
                    panic!("Tried to call outb without hypervisor and without outb function ptrs");
                }
            }
            _ => {
                panic!("Tried to call outb in invalid runmode");
            }
        }

        check_for_host_error();
    }
}

// Low-level assembly function for I/O port communication in hypervisor mode.
//
// This function is implemented in assembly to directly use the x86 `out` instruction
// to communicate with the hypervisor by writing a byte to an I/O port. It's called 
// by the higher-level `outb` function when running in hypervisor mode.
//
// # Parameters
//
// * `port` - The I/O port number to write to (passed in RCX register)
// * `value` - The byte value to write to the port (passed in RDX register)
//
// # Safety
//
// This is a raw assembly function that directly manipulates hardware I/O ports.
// It should only be called from the `outb` function, which ensures appropriate
// safety checks and runtime mode validation.
extern "win64" {
    fn hloutb(port: u16, value: u8);
}

/// A pre-defined guest function for sending text output to the host.
///
/// This function is a convenience wrapper that can be registered as a guest function
/// to allow the host to send text to the guest's output. It calls the "HostPrint"
/// host function with the provided string message.
///
/// # Parameters
///
/// * `function_call` - The function call containing parameters from the host.
///   The first parameter must be a string containing the message to print.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Serialized result containing the number of characters printed
/// * `Err` - If the parameter is not a string or there was an error calling the host function
///
/// # Example
///
/// ```no_run
/// use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
/// use hyperlight_guest::guest_function_register::register_function;
/// use hyperlight_guest::host_function_call::print_output_as_guest_function;
/// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
///
/// // Register the print function during guest initialization
/// let print_function = GuestFunctionDefinition::new(
///     "PrintMessage".to_string(),
///     vec![ParameterType::String],
///     ReturnType::Int,
///     print_output_as_guest_function as usize
/// );
///
/// register_function(print_function);
/// ```
///
/// Once registered, the host can call this function to print messages:
///
/// ```no_run
/// // Host code (pseudocode)
/// sandbox.call_guest_function(
///     "PrintMessage",
///     vec![ParameterValue::String("Hello from host!")],
///     ReturnType::Int
/// );
/// ```
pub fn print_output_as_guest_function(function_call: &FunctionCall) -> Result<Vec<u8>> {
    if let ParameterValue::String(message) = function_call.parameters.clone().unwrap()[0].clone() {
        call_host_function(
            "HostPrint",
            Some(Vec::from(&[ParameterValue::String(message.to_string())])),
            ReturnType::Int,
        )?;
        let res_i = get_host_return_value::<i32>()?;
        Ok(get_flatbuffer_result(res_i))
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "Wrong Parameters passed to print_output_as_guest_function".to_string(),
        ))
    }
}

// Assembly implementation of the hloutb function for x86-64 architecture
//
// This assembly code implements the hloutb function declared earlier:
// - xor rax, rax    : Clear RAX register (zero it out)
// - mov al, dl      : Move the value byte (in DL) to AL (lower 8 bits of RAX)
// - mov dx, cx      : Move the port number (in CX) to DX (for the OUT instruction)
// - out dx, al      : Execute OUT instruction to write AL to the port in DX
// - ret             : Return to caller
//
// Register usage follows the Windows x64 calling convention:
// - First parameter (port) is in RCX
// - Second parameter (value) is in RDX
global_asm!(
    ".global hloutb
        hloutb:
            xor rax, rax
            mov al, dl
            mov dx, cx
            out dx, al
            ret"
);
