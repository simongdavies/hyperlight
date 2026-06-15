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

//! Build script for `simpleguest`.
//!
//! Under the `userspace` feature this guest runs its user code in ring 3. The
//! runtime's ring-0-only critical statics are tagged
//! `#[link_section = ".kdata"]` in `hyperlight_guest_bin`; this script supplies
//! an augmenting linker script that gathers them into a single page-aligned,
//! bounded section (`__kdata_start` / `__kdata_end`) so the guest can
//! re-protect them supervisor-only at boot. See
//! `hyperlight_guest_bin::arch::ring3::protect_kernel_data` and
//! `docs/userspace-ring3.md`.
//!
//! Without the feature this script does nothing, so the default (ring 0) guest
//! build is byte-for-byte unchanged.
//!
//! Note: because the `-T` link argument is emitted from this binary crate's
//! build script, the hardening is **not** automatic for other guests — each
//! guest that opts into `userspace` needs an equivalent script until this is
//! folded into the shared guest build tooling (`cargo hyperlight`).

fn main() {
    // `cargo:rustc-link-arg` from a build script reaches `rust-lld` through
    // `cargo hyperlight build`, so no change to the guest build tool is needed.
    #[cfg(feature = "userspace")]
    {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is always set by cargo for build scripts");
        println!("cargo:rustc-link-arg=-T{manifest_dir}/userspace.ld");
        println!("cargo:rerun-if-changed=userspace.ld");
    }
}
