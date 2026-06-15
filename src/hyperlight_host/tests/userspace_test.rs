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

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::{GuestBinary, HyperlightError, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simple_guest_userspace_as_string;

fn new_userspace_sandbox() -> MultiUseSandbox {
    let path = simple_guest_userspace_as_string().expect("userspace guest binary should exist");
    UninitializedSandbox::new(GuestBinary::FilePath(path), None)
        .unwrap()
        .evolve()
        .unwrap()
}

/// Build a userspace sandbox with a specific total guest heap size. The kernel
/// keeps its (small, default) slice and the rest backs the ring 3 user heap.
fn new_userspace_sandbox_with_heap(heap_size: u64) -> MultiUseSandbox {
    let path = simple_guest_userspace_as_string().expect("userspace guest binary should exist");
    let mut cfg = SandboxConfiguration::default();
    cfg.set_heap_size(heap_size);
    UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg))
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

/// A guest function running in ring 3 can call back into a host function. The
/// host call is mediated by a syscall: ring 3 serialises the request, ring 0
/// performs the privileged push/`out`/pop, and the result is marshalled back to
/// ring 3. `Add` is a guest function that calls the `HostAdd` host function.
#[test]
fn userspace_guest_host_call() {
    let path = simple_guest_userspace_as_string().expect("userspace guest binary should exist");
    let mut uninit = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
    uninit
        .register("HostAdd", |a: i32, b: i32| Ok(a + b))
        .unwrap();
    let mut sandbox: MultiUseSandbox = uninit.evolve().unwrap();

    let result = sandbox.call::<i32>("Add", (17_i32, 25_i32)).unwrap();
    assert_eq!(result, 42);
}

/// `hyperlight_main` runs in ring 3, and the function registration it performs
/// (which writes the supervisor-only registry) is mediated back to ring 0 by the
/// `SYS_REGISTER` syscall. This exercises that path end to end:
/// `Ring3DynamicallyRegistered` is **not** registered by the `#[guest_function]`
/// macro — the guest's `hyperlight_main` builds its definition and calls
/// `register_function` at boot, from ring 3. Calling it here proves the
/// definition reached the registry (so `SYS_REGISTER` worked) and that the
/// registered function then dispatches and runs in ring 3.
#[test]
fn userspace_guest_ring3_main_registers_function() {
    let mut sandbox = new_userspace_sandbox();
    let doubled = sandbox
        .call::<i32>("Ring3DynamicallyRegistered", 21_i32)
        .unwrap();
    assert_eq!(doubled, 42);
}

/// The `guest_dispatch_function` fallback for unregistered calls is
/// user-provided code, so it too must run in ring 3 — never at ring 0. The
/// fallback reports the current privilege level (`CS & 3`); calling an
/// unregistered name (`ReportCpl`) routes through it and must return 3 (CPL 3),
/// proving no user code runs at ring 0 on this path.
#[test]
fn userspace_guest_dispatch_fallback_runs_in_ring3() {
    let mut sandbox = new_userspace_sandbox();
    let cpl = sandbox.call::<i32>("ReportCpl", ()).unwrap();
    assert_eq!(cpl, 3, "guest_dispatch_function must run in ring 3 (CPL 3)");
}

/// Repeated ring 3 host calls must keep working: the per-call request/result
/// user buffers have to be freed cleanly each time, and the nested
/// syscall-within-ring-3 stack switching must not corrupt the parked guest-call
/// frame.
#[test]
fn userspace_guest_repeated_host_calls() {
    let path = simple_guest_userspace_as_string().expect("userspace guest binary should exist");
    let mut uninit = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
    uninit
        .register("HostAdd", |a: i32, b: i32| Ok(a + b))
        .unwrap();
    let mut sandbox: MultiUseSandbox = uninit.evolve().unwrap();

    for i in 0..32 {
        let result = sandbox.call::<i32>("Add", (i, 1_i32)).unwrap();
        assert_eq!(result, i + 1);
    }
}

/// A ring 3 guest function that calls `abort_with_code` aborts cleanly: the
/// abort is raised in ring 3 and routed to the host through the SYS_OUTB syscall
/// (ring 3 cannot execute `out` itself), so it surfaces as a normal
/// GuestAborted with the requested code rather than a protection fault.
#[test]
fn userspace_guest_abort_with_code() {
    const ABORT_CODE: i32 = 42;
    let mut sandbox = new_userspace_sandbox();
    let err = sandbox
        .call::<()>("GuestAbortWithCode", ABORT_CODE)
        .unwrap_err();
    assert!(
        matches!(&err, HyperlightError::GuestAborted(code, _) if *code == ABORT_CODE as u8),
        "expected GuestAborted({ABORT_CODE}), got {err:?}"
    );
}

/// A panic inside a ring 3 guest function reaches the host: the panic handler
/// streams the (variable-length) message to the host through repeated SYS_OUTB
/// syscalls, exercising the multi-`out` abort path from ring 3.
#[test]
fn userspace_guest_panic() {
    let mut sandbox = new_userspace_sandbox();
    let err = sandbox
        .call::<()>("guest_panic", "boom from ring 3".to_string())
        .unwrap_err();
    match err {
        HyperlightError::GuestAborted(_, msg) => {
            assert!(
                msg.contains("boom from ring 3"),
                "panic message should reach the host, got {msg:?}"
            );
        }
        other => panic!("expected GuestAborted from a ring 3 panic, got {other:?}"),
    }
}

/// A ring 3 guest function can emit a log record. Logging pushes the serialized
/// record to the supervisor-only shared output buffer and emits a privileged
/// Log `out`, both impossible in ring 3, so the call is mediated by the SYS_LOG
/// syscall. The guest function returning successfully proves the log path does
/// not fault in ring 3.
#[test]
fn userspace_guest_log_message() {
    const LOG_LEVEL_INFORMATION: i32 = 3;
    let mut sandbox = new_userspace_sandbox();
    sandbox
        .call::<()>(
            "LogMessage",
            ("hello from ring 3".to_string(), LOG_LEVEL_INFORMATION),
        )
        .unwrap();
}

/// The ring 3 user heap is backed by the user slice of the *configured* guest
/// heap, so it scales with `heap_size` rather than being a fixed size. With a
/// large enough heap, a ring 3 allocation far bigger than the historical
/// hard-coded user heap (512 KiB) succeeds; a default (small) heap cannot
/// satisfy it and the guest aborts (MallocFailed) instead of corrupting memory.
#[test]
fn userspace_guest_user_heap_scales_with_config() {
    // Larger than the historical fixed 512 KiB user heap.
    const BIG_ALLOC: i32 = 600 * 1024;

    // Big heap: the user slice is several MiB, so a 600 KiB ring 3 allocation
    // (impossible with the old fixed 512 KiB user heap) succeeds.
    let mut big = new_userspace_sandbox_with_heap(8 * 1024 * 1024);
    let ptr = big.call::<i32>("TestMalloc", BIG_ALLOC).unwrap();
    assert_ne!(
        ptr, 0,
        "600 KiB ring 3 allocation should succeed on an 8 MiB heap"
    );

    // Default (small) heap: the user slice is only tens of KiB, so the same
    // allocation cannot be satisfied. The guest aborts with MallocFailed; the
    // abort is raised from ring 3 and routed to the host through the SYS_OUTB
    // syscall, so it surfaces as a clean GuestAborted(MallocFailed) rather than
    // a fault.
    let mut small = new_userspace_sandbox();
    let err = small.call::<i32>("TestMalloc", BIG_ALLOC).unwrap_err();
    assert!(
        matches!(&err, HyperlightError::GuestAborted(code, _) if *code == ErrorCode::MallocFailed as u8),
        "expected a clean MallocFailed abort on the default heap, got {err:?}"
    );
}

// =============================================================================
// Negative security tests
//
// These prove the ring 3 isolation actually holds: a guest function that
// deliberately attempts a privileged or supervisor-only operation must fault
// and abort cleanly, never succeed. The matching guest functions are compiled
// only into the ring 3 build and run their bodies in ring 3.
// =============================================================================

/// Assert that `err` is a guest abort whose message names the expected CPU
/// exception (e.g. "GeneralProtectionFault" or "PageFault"). The host formats
/// exception aborts as "Exception: {:?} | ...", so the fault type appears
/// verbatim in the message.
fn assert_aborted_with_fault(err: &HyperlightError, expected_fault: &str) {
    match err {
        HyperlightError::GuestAborted(_, msg) => assert!(
            msg.contains(expected_fault),
            "expected the abort to be a {expected_fault}, got: {msg}"
        ),
        other => panic!("expected GuestAborted({expected_fault}), got {other:?}"),
    }
}

/// Ring 3 must not be able to execute a privileged instruction. `cli` is CPL 0
/// only, so attempting it in ring 3 raises a general-protection fault.
#[test]
fn userspace_ring3_cannot_execute_privileged_instruction() {
    let mut sandbox = new_userspace_sandbox();
    let err = sandbox
        .call::<()>("Ring3ExecutePrivileged", ())
        .unwrap_err();
    assert_aborted_with_fault(&err, "GeneralProtectionFault");
}

/// Ring 3 must not be able to talk to the host by issuing the privileged `out`
/// instruction directly (bypassing the syscall mediation). It raises a
/// general-protection fault.
#[test]
fn userspace_ring3_cannot_execute_out() {
    let mut sandbox = new_userspace_sandbox();
    let err = sandbox.call::<()>("Ring3ExecuteOut", ()).unwrap_err();
    assert_aborted_with_fault(&err, "GeneralProtectionFault");
}

/// Ring 3 must not be able to read the runtime's supervisor-only memory (here,
/// the kernel stack). The page is present but supervisor-only, so the read
/// raises a page fault rather than leaking kernel data.
#[test]
fn userspace_ring3_cannot_read_kernel_memory() {
    let mut sandbox = new_userspace_sandbox();
    let err = sandbox
        .call::<u64>("Ring3ReadKernelMemory", ())
        .unwrap_err();
    assert_aborted_with_fault(&err, "PageFault");
}

/// Ring 3 must not be able to write the runtime's supervisor-only memory. The
/// write raises a page fault rather than corrupting runtime state.
#[test]
fn userspace_ring3_cannot_write_kernel_memory() {
    let mut sandbox = new_userspace_sandbox();
    let err = sandbox
        .call::<()>("Ring3WriteKernelMemory", ())
        .unwrap_err();
    assert_aborted_with_fault(&err, "PageFault");
}

/// Ring 3 must not be able to reach the runtime's ring-0-only critical data
/// section (`.kdata`: the guest function pointer table, the PEB handle and the
/// exception handler table). Those statics share the user-accessible guest
/// image, so without the `userspace` data-partition hardening ring 3 could read
/// them and — via a copy-on-write fault on the shared image — overwrite the
/// function pointers that ring 0 dereferences when dispatching a call, a direct
/// ring 0 code-execution escalation. `protect_kernel_data` re-protects the
/// section supervisor-only at boot, so the read raises a page fault. Because
/// the protection is established during initialisation, it is captured by the
/// snapshot baseline and so still holds after a restore.
#[test]
fn userspace_ring3_cannot_read_kernel_data_section() {
    let mut sandbox = new_userspace_sandbox();
    let err = sandbox.call::<u64>("Ring3ReadKernelData", ()).unwrap_err();
    assert_aborted_with_fault(&err, "PageFault");
}

/// The `.kdata` supervisor protection is established during initialisation, so
/// it is part of every snapshot baseline and must still hold after a restore.
/// A guest-side re-protection that did not survive restore would silently
/// reopen the escalation on the next call — this guards against that.
#[test]
fn userspace_ring3_kernel_data_protection_survives_restore() {
    let mut sandbox = new_userspace_sandbox();
    let snapshot = sandbox.snapshot().unwrap();

    // First attempt faults because `.kdata` is supervisor-only.
    let err = sandbox.call::<u64>("Ring3ReadKernelData", ()).unwrap_err();
    assert_aborted_with_fault(&err, "PageFault");

    // Restore clears the poison the abort left behind.
    sandbox.restore(snapshot).unwrap();
    assert!(!sandbox.poisoned(), "restore should clear the poison");

    // The protection must still be in force after the restore.
    let err = sandbox.call::<u64>("Ring3ReadKernelData", ()).unwrap_err();
    assert_aborted_with_fault(&err, "PageFault");
}

/// A ring 3 isolation violation aborts the *guest* without corrupting the host:
/// after the abort the sandbox is poisoned, and restoring from a snapshot
/// recovers it so ordinary guest calls work again. This proves the fault is
/// contained.
#[test]
fn userspace_ring3_violation_is_recoverable() {
    let mut sandbox = new_userspace_sandbox();
    let snapshot = sandbox.snapshot().unwrap();

    let err = sandbox
        .call::<()>("Ring3ExecutePrivileged", ())
        .unwrap_err();
    assert_aborted_with_fault(&err, "GeneralProtectionFault");
    assert!(
        sandbox.poisoned(),
        "sandbox should be poisoned after an abort"
    );

    sandbox.restore(snapshot).unwrap();
    assert!(!sandbox.poisoned(), "restore should clear the poison");

    let result = sandbox
        .call::<String>("Echo", "recovered".to_string())
        .unwrap();
    assert_eq!(result, "recovered");
}
