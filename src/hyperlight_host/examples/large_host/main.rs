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

use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};

fn main() -> hyperlight_host::Result<()> {
    println!("Creating sandbox with 500MB heap...");

    // Create sandbox configuration with 500MB heap
    let mut config = SandboxConfiguration::default();
    config.set_heap_size(500 * 1024 * 1024); // 500MB in bytes

    // Create an uninitialized sandbox with a guest binary and custom configuration
    let uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        Some(config), // Use our custom configuration with 500MB heap
    )?;

    println!("Initializing sandbox...");

    // Initialize sandbox to be able to call guest functions
    let _multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve(Noop::default())?;

    // println!("Calling guest function...");

    // // Call the Echo guest function with a test message
    // let message = "Hello from 500MB heap sandbox!".to_string();
    // let result: String = multi_use_sandbox
    //     .call_guest_function_by_name("Echo", message.clone())?;

    // println!("Guest function returned: {}", result);

    // // Verify the echo worked correctly
    // assert_eq!(result, message);

    println!("Success! Sandbox will now be dropped.");

    // Sandbox automatically drops when it goes out of scope here
    Ok(())
}
