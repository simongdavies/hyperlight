/*
Copyright 2025 The Hyperlight Authors.

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

//! Build script for `hyperlight-guest-bin`.
//!
//! Under the `userspace` feature this crate runs guest code in ring 3 and
//! re-protects a set of ring-0-only critical statics supervisor-only at boot
//! (see `arch::ring3::protect_kernel_data`). Those statics are tagged
//! `#[link_section = ".kdata"]`; collecting them into a single page-aligned,
//! bounded `.kdata` output section requires an augmenting linker script.
//!
//! Cargo does not propagate a library's `rustc-link-arg` to the final binary
//! link, so this crate cannot inject the `-T` argument itself. Instead it
//! *generates* the script (so its content lives once, with the runtime) and
//! exports the path via the `links` metadata channel. A guest binary then adds
//! the `-T` argument from a tiny, uniform build script that reads
//! `DEP_HYPERLIGHT_GUEST_BIN_KDATA_LINKER_SCRIPT` (see
//! `src/tests/rust_guests/simpleguest/build.rs`).
//!
//! Without the feature nothing is emitted, so the default (ring 0) guest build
//! is byte-for-byte unchanged.

fn main() {
    // Only the `userspace` feature needs the `.kdata` partition. `CARGO_FEATURE_*`
    // is set by cargo for each enabled feature.
    if std::env::var_os("CARGO_FEATURE_USERSPACE").is_none() {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts");
    let script_path = format!("{out_dir}/kdata.ld");

    // Augment lld's default script (via INSERT) with a page-aligned, bounded
    // `.kdata` section holding the runtime's ring-0-only critical statics. The
    // `.text` anchor is always present; page alignment of *both* bounds is
    // essential because re-protection works a whole page at a time, so `.kdata`
    // must not share a page with anything ring 3 still needs.
    let script = "\
SECTIONS {
  .kdata : ALIGN(0x1000) {
    __kdata_start = .;
    KEEP(*(.kdata))
    KEEP(*(.kdata.*))
    . = ALIGN(0x1000);
    __kdata_end = .;
  }
} INSERT AFTER .text;
";
    std::fs::write(&script_path, script).expect("can write the .kdata linker script");

    // Export the path to direct dependents (the guest binary) via `links`
    // metadata: a `cargo:KEY=VALUE` line becomes `DEP_<LINKS>_<KEY>` in their
    // build scripts, where `<LINKS>` is the `links` manifest value uppercased.
    println!("cargo:kdata-linker-script={script_path}");
    println!("cargo:rerun-if-changed=build.rs");
}
