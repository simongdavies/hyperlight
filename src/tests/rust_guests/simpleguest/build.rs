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
//! Under the `userspace` feature, apply the `.kdata` hardening linker script
//! that `hyperlight-guest-bin` generates and exports. Cargo cannot propagate a
//! library's link arguments to the final binary link, so each `userspace` guest
//! needs this tiny, uniform build script; the script *content* lives once, in
//! the runtime crate (`hyperlight_guest_bin/build.rs`). Without the feature
//! nothing is emitted and the default build is byte-for-byte unchanged.

fn main() {
    // `hyperlight-guest-bin`'s build script exports the generated script's path
    // via `links` metadata, but only when its `userspace` feature is enabled.
    if let Some(script) = std::env::var_os("DEP_HYPERLIGHT_GUEST_BIN_KDATA_LINKER_SCRIPT") {
        let script = script.to_string_lossy();
        println!("cargo:rustc-link-arg=-T{script}");
        println!("cargo:rerun-if-changed=build.rs");
    }
}
