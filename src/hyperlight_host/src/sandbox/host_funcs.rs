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

use std::collections::HashMap;
use std::io::{IsTerminal, Write};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnValue};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tracing::{instrument, Span};

use super::ExtraAllowedSyscall;
use crate::func::HyperlightFunction;
use crate::HyperlightError::HostFunctionNotFound;
use crate::{new_error, Result};

#[derive(Default, Clone)]
/// A Wrapper around details of functions exposed by the Host
pub struct HostFuncsWrapper {
    functions_map: HashMap<String, (HyperlightFunction, Option<Vec<ExtraAllowedSyscall>>)>,
}

impl HostFuncsWrapper {
    /// Register a host function with the sandbox.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn register_host_function(
        &mut self,
        name: String,
        func: HyperlightFunction,
    ) -> Result<()> {
        register_host_function_helper(self, name, func, None)
    }

    /// Register a host function with the sandbox, with a list of extra syscalls
    /// that the function is allowed to make.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    pub(crate) fn register_host_function_with_syscalls(
        &mut self,
        name: String,
        func: HyperlightFunction,
        extra_allowed_syscalls: Vec<ExtraAllowedSyscall>,
    ) -> Result<()> {
        register_host_function_helper(self, name, func, Some(extra_allowed_syscalls))
    }

    /// Assuming a host function called `"HostPrint"` exists, and takes a
    /// single string parameter, call it with the given `msg` parameter.
    ///
    /// Return `Ok` if the function was found and was of the right signature,
    /// and `Err` otherwise.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn host_print(&mut self, msg: String) -> Result<i32> {
        let res = call_host_func_impl(
            &self.functions_map,
            "HostPrint",
            vec![ParameterValue::String(msg)],
        )?;
        res.try_into()
            .map_err(|_| HostFunctionNotFound("HostPrint".to_string()))
    }
    /// From the set of registered host functions, attempt to get the one
    /// named `name`. If it exists, call it with the given arguments list
    /// `args` and return its result.
    ///
    /// Return `Err` if no such function exists,
    /// its parameter list doesn't match `args`, or there was another error
    /// getting, configuring or calling the function.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn call_host_function(
        &self,
        name: &str,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        call_host_func_impl(&self.functions_map, name, args)
    }
}

fn register_host_function_helper(
    self_: &mut HostFuncsWrapper,
    name: String,
    func: HyperlightFunction,
    extra_allowed_syscalls: Option<Vec<ExtraAllowedSyscall>>,
) -> Result<()> {
    if let Some(_syscalls) = extra_allowed_syscalls {
        #[cfg(all(feature = "seccomp", target_os = "linux"))]
        self_.functions_map.insert(name, (func, Some(_syscalls)));

        #[cfg(not(all(feature = "seccomp", target_os = "linux")))]
        return Err(new_error!(
            "Extra syscalls are only supported on Linux with seccomp"
        ));
    } else {
        self_.functions_map.insert(name, (func, None));
    }

    Ok(())
}

#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
fn call_host_func_impl(
    host_funcs: &HashMap<String, (HyperlightFunction, Option<Vec<ExtraAllowedSyscall>>)>,
    name: &str,
    args: Vec<ParameterValue>,
) -> Result<ReturnValue> {
    // Inner function containing the common logic
    fn call_func(
        host_funcs: &HashMap<String, (HyperlightFunction, Option<Vec<ExtraAllowedSyscall>>)>,
        name: &str,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        let func_with_syscalls = host_funcs
            .get(name)
            .ok_or_else(|| HostFunctionNotFound(name.to_string()))?;

        let func = func_with_syscalls.0.clone();

        #[cfg(all(feature = "seccomp", target_os = "linux"))]
        {
            let syscalls = func_with_syscalls.1.clone();
            let seccomp_filter =
                crate::seccomp::guest::get_seccomp_filter_for_host_function_worker_thread(
                    syscalls,
                )?;
            seccompiler::apply_filter(&seccomp_filter)?;
        }

        crate::metrics::maybe_time_and_emit_host_call(name, || func.call(args))
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "seccomp", target_os = "linux"))] {
            // Clone variables for the thread
            let host_funcs_cloned = host_funcs.clone();
            let name_cloned = name.to_string();
            let args_cloned = args.clone();

            // Create a new thread when seccomp is enabled on Linux
            let join_handle = std::thread::Builder::new()
                .name(format!("Host Function Worker Thread for: {:?}", name_cloned))
                .spawn(move || {
                    // We have a `catch_unwind` here because, if a disallowed syscall is issued,
                    // we handle it by panicking. This is to avoid returning execution to the
                    // offending host function—for two reasons: (1) if a host function is issuing
                    // disallowed syscalls, it could be unsafe to return to, and (2) returning
                    // execution after trapping the disallowed syscall can lead to UB (e.g., try
                    // running a host function that attempts to sleep without `SYS_clock_nanosleep`,
                    // you'll block the syscall but panic in the aftermath).
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call_func(&host_funcs_cloned, &name_cloned, args_cloned))) {
                        Ok(val) => val,
                        Err(err) => {
                            if let Some(crate::HyperlightError::DisallowedSyscall) = err.downcast_ref::<crate::HyperlightError>() {
                                return Err(crate::HyperlightError::DisallowedSyscall)
                            }

                            crate::log_then_return!("Host function {} panicked", name_cloned);
                        }
                    }
                })?;

            join_handle.join().map_err(|_| new_error!("Error joining thread executing host function"))?
        } else {
            // Directly call the function without creating a new thread
            call_func(host_funcs, name, args)
        }
    }
}

/// The default writer function is to write to stdout with green text.
#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
pub(super) fn default_writer_func(s: String) -> Result<i32> {
    match std::io::stdout().is_terminal() {
        false => {
            print!("{}", s);
            Ok(s.len() as i32)
        }
        true => {
            let mut stdout = StandardStream::stdout(ColorChoice::Auto);
            let mut color_spec = ColorSpec::new();
            color_spec.set_fg(Some(Color::Green));
            stdout.set_color(&color_spec)?;
            stdout.write_all(s.as_bytes())?;
            stdout.reset()?;
            Ok(s.len() as i32)
        }
    }
}
