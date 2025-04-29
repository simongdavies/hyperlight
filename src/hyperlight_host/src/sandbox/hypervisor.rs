/*
Copyright 2024 The Hyperlight Authors.

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

use std::fmt::Debug;
use std::sync::OnceLock;

#[cfg(mshv)]
use crate::hypervisor::hyperv_linux;
#[cfg(kvm)]
use crate::hypervisor::kvm;

static AVAILABLE_HYPERVISOR: OnceLock<Option<HypervisorType>> = OnceLock::new();

/// Retrieves information about the available hypervisor on the current system.
///
/// This function checks which hypervisor technology is available on the current system and
/// returns a reference to a static Option containing the hypervisor type if one is available.
/// The result is cached after the first call for efficiency.
///
/// # Returns
///
/// A reference to a static Option that contains:
/// * `Some(HypervisorType)` - If a compatible hypervisor is available
/// * `None` - If no compatible hypervisor is available
///
/// # Supported Hypervisors
///
/// Depending on the platform and compilation features, this may check for:
/// - KVM (Linux) - When compiled with the `kvm` feature
/// - MSHV (Linux) - When compiled with the `mshv` feature
/// - Windows Hypervisor Platform (Windows) - On Windows platforms
///
/// # Example (internal usage)
///
/// ```no_run
/// use hyperlight_host::sandbox::hypervisor::get_available_hypervisor;
///
/// let hypervisor = get_available_hypervisor();
/// match hypervisor {
///     Some(_) => println!("A hypervisor is available"),
///     None => println!("No hypervisor is available, using in-process mode"),
/// }
/// ```
///
/// # Note
///
/// This is primarily an internal function used by `is_hypervisor_present()` and other
/// parts of the Hyperlight runtime to determine hypervisor availability.
pub fn get_available_hypervisor() -> &'static Option<HypervisorType> {
    AVAILABLE_HYPERVISOR.get_or_init(|| {
        cfg_if::cfg_if! {
            if #[cfg(all(kvm, mshv))] {
                // If both features are enabled, we need to determine hypervisor at runtime.
                // Currently /dev/kvm and /dev/mshv cannot exist on the same machine, so the first one
                // that works is guaranteed to be correct.
                if hyperv_linux::is_hypervisor_present() {
                    Some(HypervisorType::Mshv)
                } else if kvm::is_hypervisor_present() {
                    Some(HypervisorType::Kvm)
                } else {
                    None
                }
            } else if #[cfg(kvm)] {
                if kvm::is_hypervisor_present() {
                    Some(HypervisorType::Kvm)
                } else {
                    None
                }
            } else if #[cfg(mshv)] {
                if hyperv_linux::is_hypervisor_present() {
                    Some(HypervisorType::Mshv)
                } else {
                    None
                }
            } else if #[cfg(target_os = "windows")] {
                use crate::sandbox::windows_hypervisor_platform;

                if windows_hypervisor_platform::is_hypervisor_present() {
                    Some(HypervisorType::Whp)
                } else {
                    None
                }
            } else {
                None
            }
        }
    })
}

/// Represents the available hypervisor technologies supported by Hyperlight.
///
/// This enum identifies which specific hypervisor implementation is being used
/// by the Hyperlight runtime to provide hardware isolation. The available options
/// depend on the platform and compile-time features.
///
/// # Variants
///
/// * `Kvm` - Kernel-based Virtual Machine (available on Linux with KVM support)
/// * `Mshv` - Microsoft Hypervisor (available on Linux with MSHV support)
/// * `Whp` - Windows Hypervisor Platform (available on Windows 11+ or Windows Server 2022+)
#[derive(PartialEq, Eq, Debug)]
pub(crate) enum HypervisorType {
    #[cfg(kvm)]
    Kvm,

    #[cfg(mshv)]
    Mshv,

    #[cfg(target_os = "windows")]
    Whp,
}
