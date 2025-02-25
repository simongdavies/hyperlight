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

#![allow(non_snake_case)]
use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue;
use hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition;
use hyperlight_error::HyperlightError::UnexpectedNoOfArguments;
use hyperlight_error::{log_then_return, new_error};
use paste::paste;
use tracing::{instrument, Span};

use super::{HyperlightFunction, SupportedParameterType, SupportedReturnType};
use crate::sandbox::ExtraAllowedSyscall;
use crate::sandbox_state::sandbox::HostFunctionRegistry;
use crate::Result;

macro_rules! host_function {
    // Special case for zero parameters
    (0) => {
        paste! {
            /// Trait for registering a host function with zero parameters.
            pub trait HostFunction0<'a, R: SupportedReturnType<R>, H: HostFunctionRegistry> {
                /// Register the host function with the given name in the sandbox.
                fn register(
                    &self,
                    host_function_registry: &mut H,
                    name: &str,
                ) -> Result<()>;

                /// Register the host function with the given name in the host_function_registry, allowing extra syscalls.
                #[cfg(all(feature = "seccomp", target_os = "linux"))]
                fn register_with_extra_allowed_syscalls(
                    &self,
                    host_function_registry: &mut H,
                    name: &str,
                    extra_allowed_syscalls: Vec<ExtraAllowedSyscall>,
                ) -> Result<()>;
            }

            impl<'a, T, R, H> HostFunction0<'a, R, H> for Arc<Mutex<T>>
            where
                T: FnMut() -> Result<R> + Send + 'static,
                R: SupportedReturnType<R>,
                H: HostFunctionRegistry,
            {
                #[instrument(
                    err(Debug), skip(self, host_function_registry), parent = Span::current(), level = "Trace"
                )]
                fn register(
                    &self,
                    host_function_registry: &mut H,
                    name: &str,
                ) -> Result<()> {
                    register_host_function_0(self.clone(), host_function_registry, name, None)
                }

                #[cfg(all(feature = "seccomp", target_os = "linux"))]
                #[instrument(
                    err(Debug), skip(self, host_function_registry, extra_allowed_syscalls),
                    parent = Span::current(), level = "Trace"
                )]
                fn register_with_extra_allowed_syscalls(
                    &self,
                    host_function_registry: &mut H,
                    name: &str,
                    extra_allowed_syscalls: Vec<ExtraAllowedSyscall>,
                ) -> Result<()> {
                    register_host_function_0(self.clone(), host_function_registry, name, Some(extra_allowed_syscalls))
                }
            }

            fn register_host_function_0<T, R, H>(
                self_: Arc<Mutex<T>>,
                host_function_registry: &mut H,
                name: &str,
                extra_allowed_syscalls: Option<Vec<ExtraAllowedSyscall>>,
            ) -> Result<()>
            where
                T: FnMut() -> Result<R> + Send + 'static,
                R: SupportedReturnType<R>,
                H: HostFunctionRegistry,
            {
                let cloned = self_.clone();
                let func = Box::new(move |_: Vec<ParameterValue>| {
                    let result = cloned
                        .try_lock()
                        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?()?;
                    Ok(result.get_hyperlight_value())
                });

                if let Some(_extra_allowed_syscalls) = extra_allowed_syscalls {
                    if cfg!(all(feature = "seccomp", target_os = "linux")) {
                        // Register with extra allowed syscalls
                        #[cfg(all(feature = "seccomp", target_os = "linux"))]
                        {
                            host_function_registry.register_host_function_with_syscalls(
                                    HostFunctionDefinition::new(name.to_string(), None, R::get_hyperlight_type()),
                                    HyperlightFunction::new(func),
                                    _extra_allowed_syscalls,
                            )?;
                        }
                    } else {
                        // Log and return an error
                        log_then_return!("Extra allowed syscalls are only supported on Linux with seccomp enabled");
                    }
                } else {
                    // Register without extra allowed syscalls
                    host_function_registry.register_host_function(
                        HostFunctionDefinition::new(name.to_string(), None, R::get_hyperlight_type()),
                        HyperlightFunction::new(func),
                )?;
                }

                Ok(())
            }
        }
    };
    // General case for one or more parameters
    ($N:expr, $($P:ident),+) => {
        paste! {
            /// Trait for registering a host function with $N parameters.
            pub trait [<HostFunction $N>]<'a, $($P,)* R, H>
            where
                $($P: SupportedParameterType<$P> + Clone + 'a,)*
                R: SupportedReturnType<R>,
                H: HostFunctionRegistry,
            {
                /// Register the host function with the given name in the sandbox.
                fn register(
                    &self,
                    host_function_registry: &mut H,
                    name: &str,
                ) -> Result<()>;

                /// Register the host function with the given name in the sandbox, allowing extra syscalls.
                #[cfg(all(feature = "seccomp", target_os = "linux"))]
                fn register_with_extra_allowed_syscalls(
                    &self,
                    host_function_registry: &mut H,
                    name: &str,
                    extra_allowed_syscalls: Vec<ExtraAllowedSyscall>,
                ) -> Result<()>;
            }

            impl<'a, T, $($P,)* R, H> [<HostFunction $N>]<'a, $($P,)* R, H> for Arc<Mutex<T>>
            where
                T: FnMut($($P),*) -> Result<R> + Send + 'static,
                $($P: SupportedParameterType<$P> + Clone + 'a,)*
                R: SupportedReturnType<R>,
                H: HostFunctionRegistry,
            {
                #[instrument(
                    err(Debug), skip(self, host_function_registry), parent = Span::current(), level = "Trace"
                )]
                fn register(
                    &self,
                    host_function_registry: &mut H,
                    name: &str,
                ) -> Result<()> {
                    [<register_host_function_ $N>](self.clone(), host_function_registry, name, None)
                }

                #[cfg(all(feature = "seccomp", target_os = "linux"))]
                #[instrument(
                    err(Debug), skip(self, host_function_registry, extra_allowed_syscalls),
                    parent = Span::current(), level = "Trace"
                )]
                fn register_with_extra_allowed_syscalls(
                    &self,
                    host_function_registry: &mut H,
                    name: &str,
                    extra_allowed_syscalls: Vec<ExtraAllowedSyscall>,
                ) -> Result<()> {
                    [<register_host_function_ $N>](self.clone(), host_function_registry, name, Some(extra_allowed_syscalls))
                }
            }

            fn [<register_host_function_ $N>]<'a, T, $($P,)* R, H>(
                self_: Arc<Mutex<T>>,
                host_function_registry: &mut H,
                name: &str,
                extra_allowed_syscalls: Option<Vec<ExtraAllowedSyscall>>,
            ) -> Result<()>
            where
                T: FnMut($($P),*) -> Result<R> + Send + 'static,
                $($P: SupportedParameterType<$P> + Clone + 'a,)*
                R: SupportedReturnType<R>,
                H: HostFunctionRegistry,
            {
                let cloned = self_.clone();
                let func = Box::new(move |args: Vec<ParameterValue>| {
                    if args.len() != $N {
                        log_then_return!(UnexpectedNoOfArguments(args.len(), $N));
                    }

                    let mut args_iter = args.into_iter();
                    $(
                        let $P = $P::get_inner(args_iter.next().unwrap())?;
                    )*

                    let result = cloned
                        .try_lock()
                        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?(
                            $($P),*
                        )?;
                    Ok(result.get_hyperlight_value())
                });

                let parameter_types = Some(vec![$($P::get_hyperlight_type()),*]);

                if let Some(_extra_allowed_syscalls) = extra_allowed_syscalls {
                    if cfg!(all(feature = "seccomp", target_os = "linux")) {
                        // Register with extra allowed syscalls
                        #[cfg(all(feature = "seccomp", target_os = "linux"))]
                        {
                            host_function_registry.register_host_function_with_syscalls(
                                HostFunctionDefinition::new(name.to_string(), parameter_types, R::get_hyperlight_type()),
                                HyperlightFunction::new(func),
                                _extra_allowed_syscalls,
                            )?;
                        }
                    } else {
                        // Log and return an error
                        log_then_return!("Extra allowed syscalls are only supported on Linux with seccomp enabled");
                    }
                } else {
                    host_function_registry.register_host_function(
                        HostFunctionDefinition::new(name.to_string(), parameter_types, R::get_hyperlight_type()),
                        HyperlightFunction::new(func),
                )?;
                }

                Ok(())
            }
        }
    };
}

host_function!(0);
host_function!(1, P1);
host_function!(2, P1, P2);
host_function!(3, P1, P2, P3);
host_function!(4, P1, P2, P3, P4);
host_function!(5, P1, P2, P3, P4, P5);
host_function!(6, P1, P2, P3, P4, P5, P6);
host_function!(7, P1, P2, P3, P4, P5, P6, P7);
host_function!(8, P1, P2, P3, P4, P5, P6, P7, P8);
host_function!(9, P1, P2, P3, P4, P5, P6, P7, P8, P9);
host_function!(10, P1, P2, P3, P4, P5, P6, P7, P8, P9, P10);
