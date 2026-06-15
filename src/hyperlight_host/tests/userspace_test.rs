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

//! Integration tests for running guest code in ring 3 (the `userspace`
//! feature). These require both the host and the guest to be built with the
//! `userspace` feature, so the whole file is gated on it.
#![cfg(feature = "userspace")]

use hyperlight_host::{GuestBinary, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simple_guest_userspace_as_string;

fn new_userspace_sandbox() -> MultiUseSandbox {
    let path = simple_guest_userspace_as_string().expect("userspace guest binary should exist");
    UninitializedSandbox::new(GuestBinary::FilePath(path), None)
        .unwrap()
        .evolve()
        .unwrap()
}

/// Evolving the sandbox runs guest initialisation, which includes the ring 0 ->
/// ring 3 -> ring 0 round-trip self-test. If the transition machinery is
/// broken the guest aborts and `evolve()` fails, so reaching an initialised
/// sandbox already proves the round-trip works.
#[test]
fn userspace_guest_boots_and_selftests() {
    let _sandbox = new_userspace_sandbox();
}

/// A userspace guest still services ordinary guest-function calls end-to-end.
#[test]
fn userspace_guest_echo() {
    let mut sandbox = new_userspace_sandbox();
    let result = sandbox
        .call::<String>("Echo", "hello ring 3".to_string())
        .unwrap();
    assert_eq!(result, "hello ring 3");
}
