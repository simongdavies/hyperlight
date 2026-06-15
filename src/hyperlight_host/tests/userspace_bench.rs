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

//! Quick A/B timing of ring 0 vs ring 3 guest execution.
//!
//! This is a lightweight, dependency-free harness (not Criterion) used to get a
//! fast read on the ring 3 overhead. It loads the standard simpleguest (ring 0)
//! and the `simpleguest-userspace` build (ring 3), then times identical
//! workloads against each on the same host so the reported delta is a
//! controlled A/B.
//!
//! Workloads, from cheapest to most page-fault-heavy:
//!
//! * `GetStatic` — a minimal-payload guest call (no input, 4-byte result), which
//!   isolates the fixed per-call transition + marshalling overhead;
//! * `Echo` — a string round-trip, which adds payload marshalling in both
//!   directions;
//! * `Add` → `HostAdd` — a guest call that itself calls back into a host
//!   function, exercising the nested ring 3 → ring 0 host-call syscall path;
//! * `CallMalloc` — an allocate/free pair, exercising the CPL-routed allocator
//!   (the ring 3 build allocates from the user heap, the ring 0 build from the
//!   kernel heap);
//! * `Echo` + snapshot restore — surfaces the copy-on-write page-refault cost,
//!   since ring 3 dirties extra writable regions (the user stack and user heap)
//!   each call.
//!
//! Run it directly (it is `#[ignore]`d so it does not run in the normal suite):
//!
//! ```text
//! cargo test -p hyperlight-host --features userspace --test userspace_bench \
//!     -- --ignored --nocapture
//! ```
#![cfg(feature = "userspace")]

use std::time::Instant;

use hyperlight_host::{GuestBinary, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::{simple_guest_as_string, simple_guest_userspace_as_string};

const BATCHES: usize = 100;
const ITERS: usize = 500;
const WARMUP: usize = 100;

fn sandbox_from(path: String) -> MultiUseSandbox {
    UninitializedSandbox::new(GuestBinary::FilePath(path), None)
        .unwrap()
        .evolve()
        .unwrap()
}

/// Build a sandbox from `path` with the `HostAdd` host function registered, as
/// required by the `Add` guest function in the host-call benchmark.
fn sandbox_with_host_add(path: String) -> MultiUseSandbox {
    let mut uninit = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
    uninit
        .register("HostAdd", |a: i32, b: i32| Ok(a + b))
        .unwrap();
    uninit.evolve().unwrap()
}

/// Median of a set of nanosecond samples.
fn median(mut samples: Vec<u128>) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Time `batches * iters_per_batch` invocations of `op` against `sbox`, in
/// batches to reduce timer noise, and return the per-invocation median in
/// nanoseconds.
fn time_op<F>(sbox: &mut MultiUseSandbox, mut op: F) -> u128
where
    F: FnMut(&mut MultiUseSandbox),
{
    // Warm up: the first calls pay one-off costs (lazy page mapping etc.).
    for _ in 0..WARMUP {
        op(sbox);
    }
    let mut per_op: Vec<u128> = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        let start = Instant::now();
        for _ in 0..ITERS {
            op(sbox);
        }
        per_op.push(start.elapsed().as_nanos() / ITERS as u128);
    }
    median(per_op)
}

/// As [`time_op`], but restores `sbox` from a snapshot after each invocation.
///
/// Restore is copy-on-write, so the first write to each page dirtied during the
/// call re-faults it. In ring 3 the user stack and user heap are extra writable
/// regions that get dirtied each call, so this is where any ring 3 page-fault
/// overhead surfaces (the plain [`time_op`] loop keeps its pages resident and
/// never restores, so it does not).
fn time_op_with_restore<F>(sbox: &mut MultiUseSandbox, mut op: F) -> u128
where
    F: FnMut(&mut MultiUseSandbox),
{
    let snapshot = sbox.snapshot().unwrap();
    for _ in 0..WARMUP {
        op(sbox);
        sbox.restore(snapshot.clone()).unwrap();
    }
    let mut per_cycle: Vec<u128> = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        let start = Instant::now();
        for _ in 0..ITERS {
            op(sbox);
            sbox.restore(snapshot.clone()).unwrap();
        }
        per_cycle.push(start.elapsed().as_nanos() / ITERS as u128);
    }
    median(per_cycle)
}

/// Print a ring 0 vs ring 3 comparison for one workload.
fn report(title: &str, t0: u128, t3: u128) {
    let overhead_ns = t3.saturating_sub(t0);
    let pct = (overhead_ns as f64 / t0 as f64) * 100.0;
    println!("\n=== ring 0 vs ring 3: {title} ===");
    println!("  ring 0 : {t0:>7} ns");
    println!("  ring 3 : {t3:>7} ns");
    println!("  delta  : {overhead_ns:>7} ns  (+{pct:.1}%)");
    println!("  (batches={BATCHES}, iters/batch={ITERS})");
}

// === Workloads ===

fn op_get_static(sbox: &mut MultiUseSandbox) {
    let _ = sbox.call::<i32>("GetStatic", ()).unwrap();
}

fn op_echo(sbox: &mut MultiUseSandbox) {
    let _ = sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();
}

fn op_add_hostcall(sbox: &mut MultiUseSandbox) {
    let _ = sbox.call::<i32>("Add", (17_i32, 25_i32)).unwrap();
}

fn op_malloc(sbox: &mut MultiUseSandbox) {
    let _ = sbox.call::<i32>("CallMalloc", 1024_i32).unwrap();
}

#[test]
#[ignore = "perf harness; run explicitly with --ignored --nocapture"]
fn bench_ring0_vs_ring3_get_static() {
    let mut ring0 = sandbox_from(simple_guest_as_string().unwrap());
    let mut ring3 = sandbox_from(simple_guest_userspace_as_string().unwrap());
    let t0 = time_op(&mut ring0, op_get_static);
    let t3 = time_op(&mut ring3, op_get_static);
    report("GetStatic minimal guest call (median per call)", t0, t3);
}

#[test]
#[ignore = "perf harness; run explicitly with --ignored --nocapture"]
fn bench_ring0_vs_ring3_echo() {
    let mut ring0 = sandbox_from(simple_guest_as_string().unwrap());
    let mut ring3 = sandbox_from(simple_guest_userspace_as_string().unwrap());
    let t0 = time_op(&mut ring0, op_echo);
    let t3 = time_op(&mut ring3, op_echo);
    report("Echo guest call (median per call)", t0, t3);
}

#[test]
#[ignore = "perf harness; run explicitly with --ignored --nocapture"]
fn bench_ring0_vs_ring3_host_call() {
    let mut ring0 = sandbox_with_host_add(simple_guest_as_string().unwrap());
    let mut ring3 = sandbox_with_host_add(simple_guest_userspace_as_string().unwrap());
    let t0 = time_op(&mut ring0, op_add_hostcall);
    let t3 = time_op(&mut ring3, op_add_hostcall);
    report(
        "Add -> HostAdd host call from guest (median per call)",
        t0,
        t3,
    );
}

#[test]
#[ignore = "perf harness; run explicitly with --ignored --nocapture"]
fn bench_ring0_vs_ring3_malloc() {
    let mut ring0 = sandbox_from(simple_guest_as_string().unwrap());
    let mut ring3 = sandbox_from(simple_guest_userspace_as_string().unwrap());
    let t0 = time_op(&mut ring0, op_malloc);
    let t3 = time_op(&mut ring3, op_malloc);
    report("CallMalloc 1 KiB allocate/free (median per call)", t0, t3);
}

#[test]
#[ignore = "perf harness; run explicitly with --ignored --nocapture"]
fn bench_ring0_vs_ring3_echo_with_restore() {
    let mut ring0 = sandbox_from(simple_guest_as_string().unwrap());
    let mut ring3 = sandbox_from(simple_guest_userspace_as_string().unwrap());
    let t0 = time_op_with_restore(&mut ring0, op_echo);
    let t3 = time_op_with_restore(&mut ring3, op_echo);
    report("Echo + snapshot restore (median per cycle)", t0, t3);
    println!("  note: restore is copy-on-write; ring 3 re-faults the extra user stack/heap pages");
}
