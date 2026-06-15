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
/// The guest function runs in ring 3 with its argument and result marshalled
/// across the privilege boundary.
#[test]
fn userspace_guest_echo() {
    let mut sandbox = new_userspace_sandbox();
    let result = sandbox
        .call::<String>("Echo", "hello ring 3".to_string())
        .unwrap();
    assert_eq!(result, "hello ring 3");
}

/// Exercise the ring 3 marshalling across several parameter/return shapes
/// (string, f64, f32) to confirm it is not specific to one type. Each call
/// re-enters ring 3, runs the guest function on the user stack/heap, and
/// marshals the result back.
#[test]
fn userspace_guest_typed_round_trips() {
    let mut sandbox = new_userspace_sandbox();

    let s = sandbox
        .call::<String>("Echo", "ring three".to_string())
        .unwrap();
    assert_eq!(s, "ring three");

    let d = sandbox
        .call::<f64>("EchoDouble", 1.617_281_828_45_f64)
        .unwrap();
    assert_eq!(d, 1.617_281_828_45_f64);

    let f = sandbox.call::<f32>("EchoFloat", 2.5_f32).unwrap();
    assert_eq!(f, 2.5_f32);
}

/// Repeated calls must keep working: the ring 3 user heap and the marshalling
/// buffers have to be freed cleanly after every call, otherwise the user heap
/// would leak and eventually be exhausted.
#[test]
fn userspace_guest_repeated_calls() {
    let mut sandbox = new_userspace_sandbox();
    for i in 0..64 {
        let msg = format!("iteration {i}");
        let result = sandbox.call::<String>("Echo", msg.clone()).unwrap();
        assert_eq!(result, msg);
    }
}

/// Snapshot restore must work with ring 3 guests. Restore is copy-on-write, so
/// after a restore the first ring 3 write to a page dirtied during the previous
/// call (the user stack and user heap) takes a CoW fault from ring 3. The fault
/// handler has to copy the page *and preserve its ring 3 accessibility*;
/// otherwise the page would become supervisor-only and ring 3 would fault on
/// its next access. This exercises a call/restore cycle several times.
#[test]
fn userspace_guest_call_with_restore() {
    let mut sandbox = new_userspace_sandbox();
    let snapshot = sandbox.snapshot().unwrap();
    for i in 0..8 {
        let msg = format!("restore {i}");
        let result = sandbox.call::<String>("Echo", msg.clone()).unwrap();
        assert_eq!(result, msg);
        sandbox.restore(snapshot.clone()).unwrap();
    }
}
