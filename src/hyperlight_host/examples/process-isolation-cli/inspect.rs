// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub struct ProcessDetails {
    pub process_id: u32,
    pub parent_id: Option<u32>,
    pub executable: Option<PathBuf>,
    pub state: String,
}

pub fn inspect_process(process_id: u32) -> ProcessDetails {
    platform::inspect(process_id)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub fn inspect(process_id: u32) -> ProcessDetails {
        let stat = std::fs::read_to_string(format!("/proc/{process_id}/stat"));
        let executable = std::fs::read_link(format!("/proc/{process_id}/exe")).ok();
        match stat {
            Ok(stat) => {
                let suffix = stat.rsplit_once(") ").map(|(_, suffix)| suffix);
                let mut fields = suffix.into_iter().flat_map(str::split_whitespace);
                let state = fields.next().unwrap_or("?").to_owned();
                let parent_id = fields.next().and_then(|field| field.parse().ok());
                ProcessDetails {
                    process_id,
                    parent_id,
                    executable,
                    state: format!("live ({state})"),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ProcessDetails {
                process_id,
                parent_id: None,
                executable: None,
                state: "exited before inspection".to_owned(),
            },
            Err(error) => ProcessDetails {
                process_id,
                parent_id: None,
                executable,
                state: format!("inspection unavailable: {error}"),
            },
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows::core::PWSTR;

    use super::*;

    pub fn inspect(process_id: u32) -> ProcessDetails {
        match inspect_native(process_id) {
            Ok(details) => details,
            Err(error) => ProcessDetails {
                process_id,
                parent_id: None,
                executable: None,
                state: format!("exited or inspection unavailable: {error}"),
            },
        }
    }

    fn inspect_native(process_id: u32) -> windows::core::Result<ProcessDetails> {
        let parent_id = parent_id(process_id)?;
        let executable = executable(process_id).ok();
        Ok(ProcessDetails {
            process_id,
            parent_id: Some(parent_id),
            executable,
            state: "live".to_owned(),
        })
    }

    fn parent_id(process_id: u32) -> windows::core::Result<u32> {
        // SAFETY: the snapshot handle is closed before return. PROCESSENTRY32W
        // is initialized with its required size before the ToolHelp calls.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            let mut found = None;
            let mut available = Process32FirstW(snapshot, &mut entry).is_ok();
            while available {
                if entry.th32ProcessID == process_id {
                    found = Some(entry.th32ParentProcessID);
                    break;
                }
                available = Process32NextW(snapshot, &mut entry).is_ok();
            }
            CloseHandle(snapshot)?;
            found.ok_or_else(|| {
                windows::core::Error::new(
                    windows::core::HRESULT(0x8000_4005_u32 as i32),
                    "process not found",
                )
            })
        }
    }

    fn executable(process_id: u32) -> windows::core::Result<PathBuf> {
        // SAFETY: the process handle is closed before return. The writable
        // buffer and its length remain valid for QueryFullProcessImageNameW.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)?;
            let mut buffer = vec![0_u16; MAX_PATH as usize * 4];
            let mut length = buffer.len() as u32;
            let result = QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            );
            let close = CloseHandle(process);
            result?;
            close?;
            buffer.truncate(length as usize);
            Ok(PathBuf::from(String::from_utf16_lossy(&buffer)))
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub fn inspect(process_id: u32) -> ProcessDetails {
        let output = std::process::Command::new("/bin/ps")
            .args(["-o", "ppid=,state=,command=", "-p", &process_id.to_string()])
            .output();
        let Ok(output) = output else {
            return unavailable(process_id, "ps could not be started");
        };
        if !output.status.success() || output.stdout.is_empty() {
            return ProcessDetails {
                process_id,
                parent_id: None,
                executable: None,
                state: "exited before inspection".to_owned(),
            };
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut fields = text.split_whitespace();
        let parent_id = fields.next().and_then(|field| field.parse().ok());
        let state = fields.next().unwrap_or("?").to_owned();
        let executable = fields.next().map(PathBuf::from);
        ProcessDetails {
            process_id,
            parent_id,
            executable,
            state: format!("live ({state})"),
        }
    }

    fn unavailable(process_id: u32, reason: &str) -> ProcessDetails {
        ProcessDetails {
            process_id,
            parent_id: None,
            executable: None,
            state: format!("inspection unavailable: {reason}"),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
mod platform {
    use super::*;

    pub fn inspect(process_id: u32) -> ProcessDetails {
        ProcessDetails {
            process_id,
            parent_id: None,
            executable: None,
            state: "native inspection is unavailable on this platform".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_current_process() {
        let details = inspect_process(std::process::id());
        assert_eq!(details.process_id, std::process::id());
        assert!(details.state.contains("live"));
    }
}
