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

use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use tracing::{instrument, Span};

use super::guest_dispatch::call_function_on_guest;
use crate::{MultiUseSandbox, Result};
/// A context for calling guest functions.
///
/// Takes ownership of an existing `MultiUseSandbox`.
/// Once created, guest function calls may be made through this and only this context
/// until it is converted back to the `MultiUseSandbox` from which it originated.
///
/// Upon this conversion,the memory associated with the `MultiUseSandbox` it owns will be reset to the state it was in before
/// this context was created.
///
/// Calls made through this context will cause state to be retained across calls, until such time as the context
/// is converted back to a `MultiUseSandbox`
///
/// If dropped, the `MultiUseSandbox` from which it came will be also be dropped as it is owned by the
/// `MultiUseGuestCallContext` until it is converted back to a `MultiUseSandbox`
///
#[derive(Debug)]
pub struct MultiUseGuestCallContext {
    sbox: MultiUseSandbox,
}

impl MultiUseGuestCallContext {
    /// Creates a new `MultiUseGuestCallContext` by taking ownership of a `MultiUseSandbox`.
    /// 
    /// This function starts a new context for making multiple guest function calls with preserved state
    /// between calls.
    /// 
    /// # Parameters
    /// 
    /// * `sbox` - The `MultiUseSandbox` to use for guest function calls
    /// 
    /// # Returns
    /// 
    /// A new `MultiUseGuestCallContext` that owns the provided sandbox
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// use hyperlight_host::func::call_ctx::MultiUseGuestCallContext;
    /// use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
    /// use hyperlight_host::sandbox_state::transition::Noop;
    /// 
    /// // Create a sandbox
    /// let uninitialized = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("path/to/guest".to_string()),
    ///     None,
    ///     None,
    ///     None
    /// ).unwrap();
    /// 
    /// let sandbox: MultiUseSandbox = uninitialized.evolve(Noop::default()).unwrap();
    /// 
    /// // Start a call context for multiple calls with preserved state
    /// let context = MultiUseGuestCallContext::start(sandbox);
    /// ```
    #[instrument(skip_all, parent = Span::current())]
    pub fn start(sbox: MultiUseSandbox) -> Self {
        Self { sbox }
    }

    /// Calls a guest function with the specified name, return type, and arguments.
    ///
    /// This method allows calling functions in the guest binary while preserving state between calls.
    /// Every call to a guest function through this method will use the same context, meaning that
    /// the guest state resulting from any previous call will be preserved and accessible by 
    /// subsequent function calls.
    ///
    /// # Parameters
    ///
    /// * `func_name` - The name of the guest function to call
    /// * `func_ret_type` - The expected return type of the function
    /// * `args` - Optional vector of parameter values to pass to the function
    ///
    /// # Returns
    ///
    /// * `Ok(ReturnValue)` - The return value from the guest function
    /// * `Err` - If an error occurred during the function call
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// use hyperlight_host::func::call_ctx::MultiUseGuestCallContext;
    /// use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
    /// use hyperlight_host::sandbox_state::transition::Noop;
    /// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType, ReturnValue};
    ///
    /// // Create a sandbox and context
    /// let uninitialized = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("path/to/guest".to_string()),
    ///     None,
    ///     None,
    ///     None
    /// ).unwrap();
    /// let sandbox = uninitialized.evolve(Noop::default()).unwrap();
    /// let mut context = MultiUseGuestCallContext::start(sandbox);
    ///
    /// // Call a guest function that stores a value in static memory
    /// let result1 = context.call(
    ///     "SetValue", 
    ///     ReturnType::Int,
    ///     Some(vec![ParameterValue::Int(42)])
    /// ).unwrap();
    ///
    /// // Call another function that reads the value (state is preserved)
    /// let result2 = context.call(
    ///     "GetValue",
    ///     ReturnType::Int,
    ///     None
    /// ).unwrap();
    ///
    /// // The second call can access state from the first call
    /// assert_eq!(result2, ReturnValue::Int(42));
    /// ```
    ///
    /// # Note
    ///
    /// If you want to reset the guest state, call `finish()` on this context
    /// and create a new context from the resulting `MultiUseSandbox`.
    #[instrument(err(Debug),skip(self, args),parent = Span::current())]
    pub fn call(
        &mut self,
        func_name: &str,
        func_ret_type: ReturnType,
        args: Option<Vec<ParameterValue>>,
    ) -> Result<ReturnValue> {
        // we are guaranteed to be holding a lock now, since `self` can't
        // exist without doing so. Since GuestCallContext is effectively
        // !Send (and !Sync), we also don't need to worry about
        // synchronization

        call_function_on_guest(&mut self.sbox, func_name, func_ret_type, args)
    }

    /// Completes the guest call context and returns the underlying `MultiUseSandbox`.
    /// 
    /// This method restores the sandbox state to what it was before this context was created,
    /// effectively resetting any state changes made during the function calls in this context.
    /// 
    /// # Returns
    /// 
    /// * `Ok(MultiUseSandbox)` - The restored sandbox that can be used for future operations
    /// * `Err` - If an error occurred during state restoration
    /// 
    /// # Example
    /// 
    /// ```no_run
    /// use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// use hyperlight_host::func::call_ctx::MultiUseGuestCallContext;
    /// use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
    /// use hyperlight_host::sandbox_state::transition::Noop;
    /// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
    /// 
    /// // Create a sandbox
    /// let uninitialized = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("path/to/guest".to_string()),
    ///     None,
    ///     None,
    ///     None
    /// ).unwrap();
    /// 
    /// let sandbox = uninitialized.evolve(Noop::default()).unwrap();
    /// 
    /// // Start a call context
    /// let mut context = MultiUseGuestCallContext::start(sandbox);
    /// 
    /// // Make calls that change guest state
    /// context.call(
    ///     "ModifyState", 
    ///     ReturnType::Int,
    ///     Some(vec![ParameterValue::Int(42)])
    /// ).unwrap();
    /// 
    /// // Finish the context and get back the sandbox with restored state
    /// let restored_sandbox = context.finish().unwrap();
    /// 
    /// // The restored sandbox can be used for new operations
    /// // with a clean state
    /// ```
    #[instrument(err(Debug), skip(self), parent = Span::current())]
    pub fn finish(mut self) -> Result<MultiUseSandbox> {
        self.sbox.restore_state()?;
        Ok(self.sbox)
    }

    /// Close out the context and get back the internally-stored
    /// `MultiUseSandbox`.
    ///
    /// Note that this method is pub(crate) and does not reset the state of the
    /// sandbox.
    ///
    /// It is intended to be used when evolving a MultiUseSandbox to a new state
    /// and is not intended to be called publicly. It allows the state of the guest to be altered
    /// during the evolution of one sandbox state to another, enabling the new state created
    /// to be captured and stored in the Sandboxes state stack.
    ///
    pub(crate) fn finish_no_reset(self) -> MultiUseSandbox {
        self.sbox
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::sync_channel;
    use std::thread::{self, JoinHandle};

    use hyperlight_common::flatbuffer_wrappers::function_types::{
        ParameterValue, ReturnType, ReturnValue,
    };
    use hyperlight_testing::simple_guest_as_string;

    use crate::sandbox_state::sandbox::EvolvableSandbox;
    use crate::sandbox_state::transition::Noop;
    use crate::{GuestBinary, HyperlightError, MultiUseSandbox, Result, UninitializedSandbox};

    fn new_uninit() -> Result<UninitializedSandbox> {
        let path = simple_guest_as_string().map_err(|e| {
            HyperlightError::Error(format!("failed to get simple guest path ({e:?})"))
        })?;
        UninitializedSandbox::new(GuestBinary::FilePath(path), None, None, None)
    }

    /// Test to create a `MultiUseSandbox`, then call several guest functions
    /// on it across different threads.
    ///
    /// This test works by passing messages between threads using Rust's
    /// [mpsc crate](https://doc.rust-lang.org/std/sync/mpsc). Details of this
    /// interaction are as follows.
    ///
    /// One thread acts as the receiver (AKA: consumer) and owns the
    /// `MultiUseSandbox`. This receiver fields requests from N senders
    /// (AKA: producers) to make batches of calls.
    ///
    /// Upon receipt of a message to execute a batch, a new
    /// `MultiUseGuestCallContext` is created in the receiver thread from the
    /// existing `MultiUseSandbox`, and the batch is executed.
    ///
    /// After the batch is complete, the `MultiUseGuestCallContext` is done
    /// and it is converted back to the underlying `MultiUseSandbox`
    #[test]
    fn test_multi_call_multi_thread() {
        let (snd, recv) = sync_channel::<Vec<TestFuncCall>>(0);

        // create new receiver thread and on it, begin listening for
        // requests to execute batches of calls
        let recv_hdl = thread::spawn(move || {
            let mut sbox: MultiUseSandbox = new_uninit().unwrap().evolve(Noop::default()).unwrap();
            while let Ok(calls) = recv.recv() {
                let mut ctx = sbox.new_call_context();
                for call in calls {
                    let res = ctx
                        .call(call.func_name.as_str(), call.ret_type, call.params)
                        .unwrap();
                    assert_eq!(call.expected_ret, res);
                }
                sbox = ctx.finish().unwrap();
            }
        });

        // create new sender threads
        let send_handles: Vec<JoinHandle<()>> = (0..10)
            .map(|i| {
                let sender = snd.clone();
                thread::spawn(move || {
                    let calls: Vec<TestFuncCall> = vec![
                        TestFuncCall {
                            func_name: "Echo".to_string(),
                            ret_type: ReturnType::String,
                            params: Some(vec![ParameterValue::String(
                                format!("Hello {}", i).to_string(),
                            )]),
                            expected_ret: ReturnValue::String(format!("Hello {}", i).to_string()),
                        },
                        TestFuncCall {
                            func_name: "CallMalloc".to_string(),
                            ret_type: ReturnType::Int,
                            params: Some(vec![ParameterValue::Int(i + 2)]),
                            expected_ret: ReturnValue::Int(i + 2),
                        },
                    ];
                    sender.send(calls).unwrap();
                })
            })
            .collect();

        for hdl in send_handles {
            hdl.join().unwrap();
        }
        // after all sender threads are done, drop the sender itself
        // so the receiver thread can exit. then, ensure the receiver
        // thread has exited.
        drop(snd);
        recv_hdl.join().unwrap();
    }

    pub struct TestSandbox {
        sandbox: MultiUseSandbox,
    }

    impl TestSandbox {
        /// Creates a new `TestSandbox` instance for testing guest function calls.
        /// 
        /// This method initializes a sandbox with a simple guest binary for testing purposes.
        /// 
        /// # Returns
        /// 
        /// A new `TestSandbox` instance ready for testing.
        /// 
        /// # Example
        /// 
        /// ```no_run
        /// use hyperlight_host::func::call_ctx::tests::TestSandbox;
        /// 
        /// let sandbox = TestSandbox::new();
        /// ```
        pub fn new() -> Self {
            let sbox: MultiUseSandbox = new_uninit().unwrap().evolve(Noop::default()).unwrap();
            Self { sandbox: sbox }
        }
        
        /// Calls the "AddToStatic" guest function multiple times while preserving state.
        /// 
        /// This method demonstrates how to use a `MultiUseGuestCallContext` to make multiple
        /// calls to a guest function while preserving state between calls. Each call to 
        /// "AddToStatic" adds the parameter value to a static variable in the guest, and
        /// returns the running sum.
        /// 
        /// # Parameters
        /// 
        /// * `i` - The number of times to call the function, with values from 0 to i-1
        /// 
        /// # Returns
        /// 
        /// * `Ok(TestSandbox)` - The TestSandbox with updated sandbox state
        /// * `Err` - If an error occurred during the function calls
        /// 
        /// # Example
        /// 
        /// ```no_run
        /// use hyperlight_host::func::call_ctx::tests::TestSandbox;
        /// 
        /// let sandbox = TestSandbox::new();
        /// let updated_sandbox = sandbox.call_add_to_static_multiple_times(5).unwrap();
        /// ```
        pub fn call_add_to_static_multiple_times(mut self, i: i32) -> Result<TestSandbox> {
            let mut ctx = self.sandbox.new_call_context();
            let mut sum: i32 = 0;
            for n in 0..i {
                let result = ctx.call(
                    "AddToStatic",
                    ReturnType::Int,
                    Some(vec![ParameterValue::Int(n)]),
                );
                sum += n;
                println!("{:?}", result);
                let result = result.unwrap();
                assert_eq!(result, ReturnValue::Int(sum));
            }
            let result = ctx.finish();
            assert!(result.is_ok());
            self.sandbox = result.unwrap();
            Ok(self)
        }

        /// Calls the "AddToStatic" guest function multiple times without preserving state.
        /// 
        /// This method demonstrates how individual calls to a guest function through 
        /// `call_guest_function_by_name` reset the guest state after each call. Each call
        /// to "AddToStatic" should return the same parameter value since the static variable
        /// is reset between calls.
        /// 
        /// # Parameters
        /// 
        /// * `i` - The number of times to call the function, with values from 0 to i-1
        /// 
        /// # Returns
        /// 
        /// * `Ok(())` - If all function calls complete successfully
        /// * `Err` - If an error occurred during the function calls
        /// 
        /// # Example
        /// 
        /// ```no_run
        /// use hyperlight_host::func::call_ctx::tests::TestSandbox;
        /// 
        /// let sandbox = TestSandbox::new();
        /// sandbox.call_add_to_static(5).unwrap();
        /// ```
        pub fn call_add_to_static(mut self, i: i32) -> Result<()> {
            for n in 0..i {
                let result = self.sandbox.call_guest_function_by_name(
                    "AddToStatic",
                    ReturnType::Int,
                    Some(vec![ParameterValue::Int(n)]),
                );
                println!("{:?}", result);
                let result = result.unwrap();
                assert_eq!(result, ReturnValue::Int(n));
            }
            Ok(())
        }
    }

    #[test]
    fn ensure_multiusesandbox_multi_calls_dont_reset_state() {
        let sandbox = TestSandbox::new();
        let result = sandbox.call_add_to_static_multiple_times(5);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_multiusesandbox_single_calls_do_reset_state() {
        let sandbox = TestSandbox::new();
        let result = sandbox.call_add_to_static(5);
        assert!(result.is_ok());
    }

    struct TestFuncCall {
        func_name: String,
        ret_type: ReturnType,
        params: Option<Vec<ParameterValue>>,
        expected_ret: ReturnValue,
    }
}
