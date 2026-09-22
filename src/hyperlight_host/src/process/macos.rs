// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use super::provider::MeshProcessProvider;
use crate::{Result, new_error};

pub(super) fn unsupported_provider() -> Result<MeshProcessProvider> {
    Err(new_error!(
        "Mesh process placement is unsupported on macOS: App Sandbox requires \
         signed static entitlements, while the dynamic sandbox_init interface is \
         deprecated and has no supported replacement"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{ProcessControl, RequestedControl};

    fn unsupported_reason(control: &ProcessControl) -> &'static str {
        match control {
            ProcessControl::MemoryLimit(_) | ProcessControl::CpuBudget { .. } => {
                "POSIX limits do not provide the required process-domain semantics"
            }
            ProcessControl::DenyNetwork | ProcessControl::DenyChildProcesses => {
                "App Sandbox policy is fixed by signed entitlements"
            }
        }
    }

    #[test]
    fn macos_provider_fails_closed() {
        let error = unsupported_provider().unwrap_err();
        let message = error.to_string();
        assert!(message.contains("unsupported on macOS"));
        assert!(message.contains("signed static entitlements"));
        assert!(message.contains("deprecated"));
    }

    #[test]
    fn every_process_control_has_an_explicit_unsupported_reason() {
        let controls = [
            ProcessControl::MemoryLimit(1),
            ProcessControl::CpuBudget {
                quota: std::time::Duration::from_millis(1),
                period: std::time::Duration::from_millis(2),
            },
            ProcessControl::DenyNetwork,
            ProcessControl::DenyChildProcesses,
        ];
        for control in controls {
            let request = RequestedControl {
                control,
                required: true,
            };
            assert!(!unsupported_reason(&request.control).is_empty());
        }
    }
}
