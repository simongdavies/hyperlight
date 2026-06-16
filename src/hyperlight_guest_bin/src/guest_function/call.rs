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

use alloc::format;
use alloc::vec::Vec;

use flatbuffers::FlatBufferBuilder;
#[cfg(all(feature = "userspace", target_arch = "x86_64"))]
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCallHeader;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
#[cfg(not(all(feature = "userspace", target_arch = "x86_64")))]
use hyperlight_common::flatbuffer_wrappers::function_types::ParameterType;
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_guest::bail;
use hyperlight_guest::error::{HyperlightGuestError, Result};
use tracing::instrument;

use crate::{GUEST_HANDLE, REGISTERED_GUEST_FUNCTIONS};

core::arch::global_asm!(
    ".weak guest_dispatch_function",
    ".set guest_dispatch_function, {}",
    sym guest_dispatch_function_default,
);

#[tracing::instrument(skip_all, parent = tracing::Span::current(), level= "Trace")]
fn guest_dispatch_function_default(function_call: FunctionCall) -> Result<Vec<u8>> {
    let name = &function_call.function_name;
    bail!(ErrorCode::GuestFunctionNotFound => "No handler found for function call: {name:#?}");
}

#[instrument(skip_all, level = "Info")]
#[cfg(all(feature = "userspace", target_arch = "x86_64"))]
pub(crate) fn call_guest_function(header: FunctionCallHeader, raw: &[u8]) -> Result<Vec<u8>> {
    // Validate this is a Guest Function Call
    if header.function_call_type() != FunctionCallType::Guest {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Invalid function call type: {:#?}, should be Guest.",
                header.function_call_type()
            ),
        ));
    }

    // Find the function definition for the function call.
    // Use &raw const to get an immutable reference to the static HashMap
    // this is to avoid the clippy warning "shared reference to mutable static"
    #[allow(clippy::deref_addrof)]
    if let Some(registered_function_definition) =
        unsafe { (*(&raw const REGISTERED_GUEST_FUNCTIONS)).get(&header.function_name) }
    {
        // Verify that the function call has the correct parameter types and
        // length. The parameter *types* come straight from the header (decoded
        // without materialising the values), and the registry read stays in
        // ring 0.
        registered_function_definition.verify_parameters(&header.parameter_types)?;

        // Run the registered function in ring 3 so a bug in user code cannot
        // tamper with the runtime's supervisor state. The lookup and parameter
        // verification above stay in ring 0 (they read the supervisor function
        // registry); only the function body runs in ring 3, decoding its
        // arguments from the forwarded encoded bytes onto the user heap. The
        // original encoded call bytes are forwarded directly, avoiding a
        // re-encode (and avoiding decoding the values in ring 0 at all).
        unsafe {
            crate::arch::ring3::run_registered_guest_fn(
                registered_function_definition.function_pointer,
                raw,
            )
        }
    } else {
        // The given function is not registered. The guest should implement a
        // function called guest_dispatch_function to handle this.
        unsafe extern "Rust" {
            fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>>;
        }

        // `guest_dispatch_function` is user-provided code, so under the userspace
        // feature it must run in ring 3 like every other piece of guest code —
        // never at ring 0. It has the same signature as a registered guest
        // function (`fn(FunctionCall) -> Result<Vec<u8>>`), so it goes through
        // the same ring 3 trampoline, with the original encoded call forwarded
        // unchanged (and decoded in ring 3).
        let f: crate::guest_function::definition::GuestFunc =
            unsafe { core::mem::transmute(guest_dispatch_function as *const ()) };
        unsafe { crate::arch::ring3::run_registered_guest_fn(f, raw) }
    }
}

#[instrument(skip_all, level = "Info")]
#[cfg(not(all(feature = "userspace", target_arch = "x86_64")))]
pub(crate) fn call_guest_function(function_call: FunctionCall) -> Result<Vec<u8>> {
    // Validate this is a Guest Function Call
    if function_call.function_call_type() != FunctionCallType::Guest {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Invalid function call type: {:#?}, should be Guest.",
                function_call.function_call_type()
            ),
        ));
    }

    // Find the function definition for the function call.
    // Use &raw const to get an immutable reference to the static HashMap
    // this is to avoid the clippy warning "shared reference to mutable static"
    #[allow(clippy::deref_addrof)]
    if let Some(registered_function_definition) =
        unsafe { (*(&raw const REGISTERED_GUEST_FUNCTIONS)).get(&function_call.function_name) }
    {
        let function_call_parameter_types: Vec<ParameterType> = function_call
            .parameters
            .iter()
            .flatten()
            .map(|p| p.into())
            .collect();

        // Verify that the function call has the correct parameter types and length.
        registered_function_definition.verify_parameters(&function_call_parameter_types)?;

        (registered_function_definition.function_pointer)(function_call)
    } else {
        // The given function is not registered. The guest should implement a function called
        // guest_dispatch_function to handle this.

        // TODO: ideally we would define a default implementation of this with weak linkage so the guest is not required
        // to implement the function but its seems that weak linkage is an unstable feature so for now its probably better
        // to not do that.
        unsafe extern "Rust" {
            fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>>;
        }

        unsafe { guest_dispatch_function(function_call) }
    }
}

pub(crate) fn internal_dispatch_function() {
    // Read the current TSC to report it to the host with the spans/events
    // This helps calculating the timestamps relative to the guest call
    #[cfg(all(feature = "trace_guest", target_arch = "x86_64"))]
    let _entered = {
        let guest_start_tsc = hyperlight_guest_tracing::invariant_tsc::read_tsc();
        // Reset the trace state for the new guest function call with the new start TSC
        // This clears any existing spans/events from previous calls ensuring a clean state
        hyperlight_guest_tracing::new_call(guest_start_tsc);

        tracing::span!(tracing::Level::INFO, "internal_dispatch_function").entered()
    };

    let handle = unsafe { GUEST_HANDLE };

    // In userspace builds, the encoded call is read **in place** from the
    // supervisor input buffer and forwarded into ring 3 without re-encoding.
    // Only the call *header* (type, name, parameter types) is decoded in ring 0
    // for the security checks (lookup + verification); the parameter *values*
    // are decoded in ring 3, on the user heap. Reading in place means a large
    // payload is never copied onto the runtime's (small) kernel heap — it is
    // staged directly from the input buffer into the user buffer.
    #[cfg(all(feature = "userspace", target_arch = "x86_64"))]
    let res = handle
        .with_popped_input_raw(|raw| {
            let header = FunctionCallHeader::decode(raw)
                .expect("Function call header deserialization failed");
            call_guest_function(header, raw)
        })
        .expect("Function call deserialization failed");
    #[cfg(not(all(feature = "userspace", target_arch = "x86_64")))]
    let res = {
        let function_call = handle
            .try_pop_shared_input_data_into::<FunctionCall>()
            .expect("Function call deserialization failed");
        call_guest_function(function_call)
    };

    match res {
        Ok(bytes) => {
            handle
                .push_shared_output_data(bytes.as_slice())
                .expect("Failed to serialize function call result");
        }
        Err(err) => {
            let guest_error = Err(GuestError::new(err.kind, err.message));
            let fcr = FunctionCallResult::new(guest_error);
            let mut builder = FlatBufferBuilder::new();
            let data = fcr.encode(&mut builder);
            handle
                .push_shared_output_data(data)
                .expect("Failed to serialize function call result");
        }
    }

    // All this tracing logic shall be done right before the call to `hlt` which is done after this
    // function returns
    #[cfg(all(feature = "trace_guest", target_arch = "x86_64"))]
    {
        // This span captures the internal dispatch function only, without tracing internals.
        // Close the span before flushing to ensure that the `flush` call is not included in the span
        // NOTE: This is necessary to avoid closing the span twice. Flush closes all the open
        // spans, when preparing to close a guest function call context.
        // It is not mandatory, though, but avoids a warning on the host that alerts a spans
        // that has not been opened but is being closed.
        _entered.exit();

        // Ensure that any tracing output during the call is flushed to
        // the host, if necessary.
        hyperlight_guest_tracing::flush();
    }
}
