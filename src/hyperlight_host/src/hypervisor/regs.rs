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

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::collections::HashSet;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;

// `FromWhpRegisterError` is only produced by the x86-64 WHP register
// conversions; the aarch64 WHP backend parses registers positionally.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[derive(Debug, PartialEq)]
pub(crate) enum FromWhpRegisterError {
    MissingRegister(HashSet<i32>),
    InvalidLength(usize),
    InvalidEncoding,
    DuplicateRegister(i32),
    InvalidRegister(i32),
}

/// WHV_REGISTER_VALUE must be 16-byte aligned, but the rust struct is incorrectly generated
/// as 8-byte aligned. This is a workaround to ensure that the struct is 16-byte aligned.
///
/// This is architecture-neutral (it wraps the WHP register-value union used by both the
/// x86-64 and aarch64 WHP backends), so it lives here in the shared `regs` module.
#[cfg(target_os = "windows")]
#[repr(C, align(16))]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct Align16<T>(pub(crate) T);

#[cfg(target_os = "windows")]
const _: () = {
    use windows::Win32::System::Hypervisor::WHV_REGISTER_VALUE;
    assert!(
        std::mem::size_of::<Align16<WHV_REGISTER_VALUE>>()
            == std::mem::size_of::<WHV_REGISTER_VALUE>()
    );
};
