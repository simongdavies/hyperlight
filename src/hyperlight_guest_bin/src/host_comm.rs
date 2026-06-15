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

use alloc::string::ToString;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_common::func::{ParameterTuple, SupportedReturnType};
use hyperlight_guest::error::{HyperlightGuestError, Result};

use crate::GUEST_HANDLE;

pub fn call_host_function<T>(
    function_name: &str,
    parameters: Option<Vec<ParameterValue>>,
    return_type: ReturnType,
) -> Result<T>
where
    T: TryFrom<ReturnValue>,
{
    // With the userspace feature, a guest function calling a host function may
    // be running in ring 3, where the PEB, shared I/O buffers and the `out`
    // instruction are all inaccessible. Route the call through a syscall so the
    // privileged work happens in ring 0; the request is serialised and the
    // result deserialised here, in user memory.
    #[cfg(all(feature = "userspace", target_arch = "x86_64"))]
    if crate::arch::ring3::in_ring3() {
        return call_host_function_ring3::<T>(function_name, parameters, return_type);
    }

    let handle = unsafe { GUEST_HANDLE };
    handle.call_host_function::<T>(function_name, parameters, return_type)
}

/// Ring 3 path for [`call_host_function`]: serialise the call, hand it to ring 0
/// via [`SYS_HOST_CALL`](crate::arch::ring3), and deserialise the result. Mirrors
/// the conversion `GuestHandle::get_host_return_value` performs in ring 0.
#[cfg(all(feature = "userspace", target_arch = "x86_64"))]
fn call_host_function_ring3<T>(
    function_name: &str,
    parameters: Option<Vec<ParameterValue>>,
    return_type: ReturnType,
) -> Result<T>
where
    T: TryFrom<ReturnValue>,
{
    use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCallType;
    use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;

    // Serialise the host call into user-heap memory.
    let call = FunctionCall::new(
        function_name.to_string(),
        parameters,
        FunctionCallType::Host,
        return_type,
    );
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let request = call.encode(&mut builder);

    // Ring 0 performs the privileged push/out/pop and returns the encoded result.
    let result_bytes = unsafe { crate::arch::ring3::sys_host_call(request) }.ok_or_else(|| {
        HyperlightGuestError::new(
            ErrorCode::GuestError,
            "ring 3 host call failed to obtain a result".to_string(),
        )
    })?;

    let result = FunctionCallResult::try_from(result_bytes.as_slice()).map_err(|e| {
        HyperlightGuestError::new(
            ErrorCode::GuestError,
            alloc::format!("failed to decode host return value: {e}"),
        )
    })?;

    match result.into_inner() {
        Ok(ret) => T::try_from(ret).map_err(|_| {
            let expected = core::any::type_name::<T>();
            HyperlightGuestError::new(
                ErrorCode::UnsupportedParameterType,
                alloc::format!("Host return value could not be converted to expected {expected}"),
            )
        }),
        Err(e) => Err(HyperlightGuestError {
            kind: e.code,
            message: e.message,
        }),
    }
}

pub fn call_host<T>(function_name: impl AsRef<str>, args: impl ParameterTuple) -> Result<T>
where
    T: SupportedReturnType + TryFrom<ReturnValue>,
{
    call_host_function::<T>(function_name.as_ref(), Some(args.into_value()), T::TYPE)
}

pub fn call_host_function_without_returning_result(
    function_name: &str,
    parameters: Option<Vec<ParameterValue>>,
    return_type: ReturnType,
) -> Result<()> {
    let handle = unsafe { GUEST_HANDLE };
    handle.call_host_function_without_returning_result(function_name, parameters, return_type)
}

pub fn get_host_return_value_raw() -> Result<ReturnValue> {
    let handle = unsafe { GUEST_HANDLE };
    handle.get_host_return_raw()
}

pub fn get_host_return_value<T: TryFrom<ReturnValue>>() -> Result<T> {
    let handle = unsafe { GUEST_HANDLE };
    handle.get_host_return_value::<T>()
}

pub fn read_n_bytes_from_user_memory(num: u64) -> Result<Vec<u8>> {
    let handle = unsafe { GUEST_HANDLE };
    handle.read_n_bytes_from_user_memory(num)
}

/// Print a message using the host's print function.
///
/// This function requires memory to be setup to be used. In particular, the
/// existence of the input and output memory regions.
pub fn print_output_with_host_print(function_call: FunctionCall) -> Result<Vec<u8>> {
    let handle = unsafe { GUEST_HANDLE };
    if let ParameterValue::String(message) = function_call.parameters.unwrap().remove(0) {
        let res = handle.call_host_function::<i32>(
            "HostPrint",
            Some(Vec::from(&[ParameterValue::String(message)])),
            ReturnType::Int,
        )?;

        Ok(get_flatbuffer_result(res))
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "Wrong Parameters passed to print_output_with_host_print".to_string(),
        ))
    }
}
