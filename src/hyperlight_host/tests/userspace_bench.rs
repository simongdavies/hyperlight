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

//! Quick A/B timing of ring 0 vs ring 3 guest-function calls.
//!
//! This is a lightweight, dependency-free harness (not Criterion) used to get a
//! fast read on the ring 3 overhead. It loads the standard simpleguest (ring 0)
//! and the `simpleguest-userspace` build (ring 3), then times identical `Echo`
//! and `EchoDouble` calls against each on the same host.
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

fn sandbox_from(path: String) -> MultiUseSandbox {
    UninitializedSandbox::new(GuestBinary::FilePath(path), None)
        .unwrap()
        .evolve()
        .unwrap()
}

/// Median of a set of nanosecond samples.
fn median(mut samples: Vec<u128>) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Time `iters` calls of `Echo` and return the per-call median in nanoseconds,
/// measured in batches to reduce timer noise.
fn time_echo(sbox: &mut MultiUseSandbox, batches: usize, iters_per_batch: usize) -> u128 {
    // Warm up (first call pays one-off costs).
    for _ in 0..50 {
        let _ = sbox.call::<String>("Echo", "warmup".to_string()).unwrap();
    }
    let mut per_call: Vec<u128> = Vec::with_capacity(batches);
    for _ in 0..batches {
        let start = Instant::now();
        for _ in 0..iters_per_batch {
            let _ = sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();
        }
        per_call.push(start.elapsed().as_nanos() / iters_per_batch as u128);
    }
    median(per_call)
}

/// Time `iters` cycles of "Echo then restore-from-snapshot" and return the
/// per-cycle median in nanoseconds.
///
/// Restore is copy-on-write, so the first write to each page dirtied during the
/// call re-faults it. In ring 3 the user stack and user heap are extra writable
/// regions that get dirtied each call, so this is where any ring 3 page-fault
/// overhead surfaces (the plain `time_echo` loop keeps its pages resident and
/// never restores, so it does not).
fn time_echo_with_restore(
    sbox: &mut MultiUseSandbox,
    batches: usize,
    iters_per_batch: usize,
) -> u128 {
    let snapshot = sbox.snapshot().unwrap();
    // Warm up.
    for _ in 0..50 {
        let _ = sbox.call::<String>("Echo", "warmup".to_string()).unwrap();
        sbox.restore(snapshot.clone()).unwrap();
    }
    let mut per_cycle: Vec<u128> = Vec::with_capacity(batches);
    for _ in 0..batches {
        let start = Instant::now();
        for _ in 0..iters_per_batch {
            let _ = sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();
            sbox.restore(snapshot.clone()).unwrap();
        }
        per_cycle.push(start.elapsed().as_nanos() / iters_per_batch as u128);
    }
    median(per_cycle)
}

#[test]
#[ignore = "perf harness; run explicitly with --ignored --nocapture"]
fn bench_ring0_vs_ring3_echo() {
    const BATCHES: usize = 50;
    const ITERS: usize = 200;

    let mut ring0 = sandbox_from(simple_guest_as_string().unwrap());
    let mut ring3 = sandbox_from(simple_guest_userspace_as_string().unwrap());

    let t0 = time_echo(&mut ring0, BATCHES, ITERS);
    let t3 = time_echo(&mut ring3, BATCHES, ITERS);

    let overhead_ns = t3.saturating_sub(t0);
    let pct = (overhead_ns as f64 / t0 as f64) * 100.0;

    println!("\n=== ring 0 vs ring 3: Echo guest call (median per call) ===");
    println!("  ring 0 : {t0:>7} ns");
    println!("  ring 3 : {t3:>7} ns");
    println!("  delta  : {overhead_ns:>7} ns  (+{pct:.1}%)");
    println!("  (batches={BATCHES}, iters/batch={ITERS})\n");
}

#[test]
#[ignore = "perf harness; run explicitly with --ignored --nocapture"]
fn bench_ring0_vs_ring3_echo_with_restore() {
    const BATCHES: usize = 50;
    const ITERS: usize = 200;

    let mut ring0 = sandbox_from(simple_guest_as_string().unwrap());
    let mut ring3 = sandbox_from(simple_guest_userspace_as_string().unwrap());

    let t0 = time_echo_with_restore(&mut ring0, BATCHES, ITERS);
    let t3 = time_echo_with_restore(&mut ring3, BATCHES, ITERS);

    let overhead_ns = t3.saturating_sub(t0);
    let pct = (overhead_ns as f64 / t0 as f64) * 100.0;

    println!("\n=== ring 0 vs ring 3: Echo + snapshot restore (median per cycle) ===");
    println!("  ring 0 : {t0:>7} ns");
    println!("  ring 3 : {t3:>7} ns");
    println!("  delta  : {overhead_ns:>7} ns  (+{pct:.1}%)");
    println!("  (batches={BATCHES}, iters/batch={ITERS})");
    println!(
        "  note: restore is copy-on-write; ring 3 re-faults the extra user stack/heap pages\n"
    );
}
