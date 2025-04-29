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
#![no_main]

extern crate alloc;
extern crate hyperlight_guest;

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterType, ParameterValue, ReturnType,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_guest::error::{HyperlightGuestError, Result};
use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
use hyperlight_guest::guest_function_register::register_function;
use hyperlight_guest::host_function_call::{
    call_host_function, get_host_return_value, print_output_as_guest_function,
};
use hyperlight_guest::logging::log_message;

fn send_message_to_host_method(
    method_name: &str,
    guest_message: &str,
    message: &str,
) -> Result<Vec<u8>> {
    let message = format!("{}{}", guest_message, message);
    call_host_function(
        method_name,
        Some(Vec::from(&[ParameterValue::String(message.to_string())])),
        ReturnType::Int,
    )?;

    let result = get_host_return_value::<i32>()?;

    Ok(get_flatbuffer_result(result))
}

fn guest_function(function_call: &FunctionCall) -> Result<Vec<u8>> {
    if let ParameterValue::String(message) = &function_call.parameters.as_ref().unwrap()[0] {
        send_message_to_host_method("HostMethod", "Hello from GuestFunction, ", message)
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestFunctionParameterTypeMismatch,
            "Invalid parameters passed to guest_function".to_string(),
        ))
    }
}

fn guest_function1(function_call: &FunctionCall) -> Result<Vec<u8>> {
    if let ParameterValue::String(message) = &function_call.parameters.as_ref().unwrap()[0] {
        send_message_to_host_method("HostMethod1", "Hello from GuestFunction1, ", message)
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestFunctionParameterTypeMismatch,
            "Invalid parameters passed to guest_function1".to_string(),
        ))
    }
}

fn guest_function2(function_call: &FunctionCall) -> Result<Vec<u8>> {
    if let ParameterValue::String(message) = &function_call.parameters.as_ref().unwrap()[0] {
        send_message_to_host_method("HostMethod1", "Hello from GuestFunction2, ", message)
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestFunctionParameterTypeMismatch,
            "Invalid parameters passed to guest_function2".to_string(),
        ))
    }
}

fn guest_function3(function_call: &FunctionCall) -> Result<Vec<u8>> {
    if let ParameterValue::String(message) = &function_call.parameters.as_ref().unwrap()[0] {
        send_message_to_host_method("HostMethod1", "Hello from GuestFunction3, ", message)
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestFunctionParameterTypeMismatch,
            "Invalid parameters passed to guest_function3".to_string(),
        ))
    }
}

fn guest_function4(_: &FunctionCall) -> Result<Vec<u8>> {
    call_host_function(
        "HostMethod4",
        Some(Vec::from(&[ParameterValue::String(
            "Hello from GuestFunction4".to_string(),
        )])),
        ReturnType::Void,
    )?;

    Ok(get_flatbuffer_result(()))
}

fn guest_log_message(function_call: &FunctionCall) -> Result<Vec<u8>> {
    if let (
        ParameterValue::String(message),
        ParameterValue::String(source),
        ParameterValue::Int(level),
    ) = (
        &function_call.parameters.as_ref().unwrap()[0],
        &function_call.parameters.as_ref().unwrap()[1],
        &function_call.parameters.as_ref().unwrap()[2],
    ) {
        let mut log_level = *level;
        if !(0..=6).contains(&log_level) {
            log_level = 0;
        }

        log_message(
            LogLevel::from(log_level as u8),
            message,
            source,
            "guest_log_message",
            file!(),
            line!(),
        );

        Ok(get_flatbuffer_result(message.len() as i32))
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestFunctionParameterTypeMismatch,
            "Invalid parameters passed to guest_log_message".to_string(),
        ))
    }
}

fn call_error_method(function_call: &FunctionCall) -> Result<Vec<u8>> {
    if let ParameterValue::String(message) = &function_call.parameters.as_ref().unwrap()[0] {
        send_message_to_host_method("ErrorMethod", "Error From Host: ", message)
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestFunctionParameterTypeMismatch,
            "Invalid parameters passed to call_error_method".to_string(),
        ))
    }
}

fn call_host_spin(_: &FunctionCall) -> Result<Vec<u8>> {
    call_host_function("Spin", None, ReturnType::Void)?;
    Ok(get_flatbuffer_result(()))
}

#[no_mangle]
/// Main entry point for Hyperlight guest binaries.
/// 
/// This function is called when the guest binary is loaded by the Hyperlight host.
/// It's responsible for registering all guest functions that can be called by the host.
/// Each function is registered with its name, parameter types, return type, and a pointer
/// to the implementation function.
/// 
/// In this implementation, we register several guest functions:
/// - `PrintOutput`: Prints a message to the host's output
/// - `GuestMethod`, `GuestMethod1`, etc.: Various functions that can be called from the host
/// - `LogMessage`: Writes messages to the guest log
/// - `CallErrorMethod`: Demonstrates error handling between guest and host
/// - `CallHostSpin`: Calls a host function that spins/blocks
/// 
/// # Note
/// 
/// This function must be named exactly `hyperlight_main` and must have the `#[no_mangle]`
/// attribute to ensure the Hyperlight host can find it when loading the guest binary.
pub extern "C" fn hyperlight_main() {
    let print_output_def = GuestFunctionDefinition::new(
        "PrintOutput".to_string(),
        Vec::from(&[ParameterType::String]),
        ReturnType::Int,
        print_output_as_guest_function as usize,
    );
    register_function(print_output_def);

    let guest_function_def = GuestFunctionDefinition::new(
        "GuestMethod".to_string(),
        Vec::from(&[ParameterType::String]),
        ReturnType::Int,
        guest_function as usize,
    );
    register_function(guest_function_def);

    let guest_function1_def = GuestFunctionDefinition::new(
        "GuestMethod1".to_string(),
        Vec::from(&[ParameterType::String]),
        ReturnType::Int,
        guest_function1 as usize,
    );
    register_function(guest_function1_def);

    let guest_function2_def = GuestFunctionDefinition::new(
        "GuestMethod2".to_string(),
        Vec::from(&[ParameterType::String]),
        ReturnType::Int,
        guest_function2 as usize,
    );
    register_function(guest_function2_def);

    let guest_function3_def = GuestFunctionDefinition::new(
        "GuestMethod3".to_string(),
        Vec::from(&[ParameterType::String]),
        ReturnType::Int,
        guest_function3 as usize,
    );
    register_function(guest_function3_def);

    let guest_function4_def = GuestFunctionDefinition::new(
        "GuestMethod4".to_string(),
        Vec::new(),
        ReturnType::Int,
        guest_function4 as usize,
    );
    register_function(guest_function4_def);

    let guest_log_message_def = GuestFunctionDefinition::new(
        "LogMessage".to_string(),
        Vec::from(&[
            ParameterType::String,
            ParameterType::String,
            ParameterType::Int,
        ]),
        ReturnType::Int,
        guest_log_message as usize,
    );
    register_function(guest_log_message_def);

    let call_error_method_def = GuestFunctionDefinition::new(
        "CallErrorMethod".to_string(),
        Vec::from(&[ParameterType::String]),
        ReturnType::Int,
        call_error_method as usize,
    );
    register_function(call_error_method_def);

    let call_host_spin_def = GuestFunctionDefinition::new(
        "CallHostSpin".to_string(),
        Vec::new(),
        ReturnType::Int,
        call_host_spin as usize,
    );
    register_function(call_host_spin_def);
}

#[no_mangle]
/// Dispatches function calls to the appropriate guest function handler.
/// 
/// This function serves as a fallback dispatcher for any function calls not handled
/// by the explicitly registered functions. In this implementation, it simply returns
/// an error indicating that the requested function was not found.
/// 
/// # Parameters
/// 
/// * `function_call` - The function call information including name and parameters
/// 
/// # Returns
/// 
/// * `Result<Vec<u8>>` - A serialized flatbuffer containing the function result or an error
///
/// # Example
/// 
/// This function is typically called by the hyperlight host runtime when it cannot find
/// a registered function with the specified name. It is not meant to be called directly
/// from guest code.
pub fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>> {
    Err(HyperlightGuestError::new(
        ErrorCode::GuestFunctionNotFound,
        function_call.function_name.clone(),
    ))
}
