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

use std::fmt::Debug;
use std::panic;

use hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition;
use tracing::{instrument, Span};

use super::transition::TransitionMetadata;
use crate::func::HyperlightFunction;
use crate::sandbox::ExtraAllowedSyscall;
use crate::Result;
/// The minimal functionality of a Hyperlight sandbox. Most of the types
/// and operations within this crate require `Sandbox` implementations.
///
/// `Sandbox`es include the notion of an ordering in a state machine.
/// For example, a given `Sandbox` implementation may be the root node
/// in the state machine to which it belongs, and it may know how to "evolve"
/// into a next state. That "next state" may in turn know how to roll back
/// to the root node.
///
/// These transitions are expressed as `EvolvableSandbox` and
/// `DevolvableSandbox` implementations any `Sandbox` implementation can
/// opt into.
pub trait Sandbox: Sized + Debug {
    /// Check to ensure the current stack cookie matches the one that
    /// was selected when the stack was constructed.
    ///
    /// Return an `Err` if there was an error inspecting the stack, `Ok(false)`
    /// if there was no such error but the stack guard doesn't match, and
    /// `Ok(true)` in the same situation where the stack guard does match.
    ///

    // NOTE: this is only needed for UninitializedSandbox and MultiUseSandbox
    // Those are the only types that need implement this trait
    // The default implementation is provided so that types that implement Sandbox (e.g. JSSandbox) but do not need to implement this trait do not need to provide an implementation
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn check_stack_guard(&self) -> Result<bool> {
        panic!("check_stack_guard not implemented for this type");
    }
}

/// A utility trait to recognize a Sandbox that has not yet been initialized.
/// It allows retrieval of a strongly typed UninitializedSandbox.
pub trait UninitializedSandbox: Sandbox {
    fn get_uninitialized_sandbox(&self) -> &crate::sandbox::UninitializedSandbox;

    fn get_uninitialized_sandbox_mut(&mut self) -> &mut crate::sandbox::UninitializedSandbox;

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn is_running_in_process(&self) -> bool {
        self.get_uninitialized_sandbox().run_inprocess
    }
}
/// A trait to allow registering host functions with a sandbox.
pub trait HostFunctionRegistry {
    fn register_host_function(
        &mut self,
        host_function_definition: HostFunctionDefinition,
        host_function: HyperlightFunction,
    ) -> Result<()>;

    fn register_host_function_with_syscalls(
        &mut self,
        host_function_definition: HostFunctionDefinition,
        host_function: HyperlightFunction,
        syscalls: Vec<ExtraAllowedSyscall>,
    ) -> Result<()>;
}

/// A `Sandbox` that knows how to "evolve" into a next state.
pub trait EvolvableSandbox<Cur: Sandbox, Next: Sandbox, T: TransitionMetadata<Cur, Next>>:
    Sandbox
{
    fn evolve(self, tsn: T) -> Result<Next>;
}

/// A `Sandbox` that knows how to roll back to a "previous" `Sandbox`
pub trait DevolvableSandbox<Cur: Sandbox, Prev: Sandbox, T: TransitionMetadata<Cur, Prev>>:
    Sandbox
{
    fn devolve(self, tsn: T) -> Result<Prev>;
}
