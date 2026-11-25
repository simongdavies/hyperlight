// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::io::{BufRead, IsTerminal, Write};

use hyperlight_host::process::{ControlResult, ProcessControl, ProcessReport};
use hyperlight_host::{Result, new_error};

use crate::inspect::{ProcessDetails, inspect_process};

pub fn heading(title: &str) {
    println!();
    println!("============================================================================");
    println!("{title}");
    println!("============================================================================");
}

pub fn step(title: &str) {
    println!();
    println!("--- {title} ---------------------------------------------------------------");
}

pub fn note(label: &str, message: impl std::fmt::Display) {
    println!("{label:<12} {message}");
}

pub fn process_table(label: &str, reports: &[ProcessReport], details: bool) {
    step(label);
    println!(
        "{:<18} {:>8} {:>8}  {:<18} EXECUTABLE",
        "ROLE", "PID", "PARENT", "PLACEMENT"
    );
    println!("{}", "-".repeat(76));
    let controller = inspect_process(std::process::id());
    print_process("application", "caller", &controller);
    note("profile", "application ambient permissions");
    note("controls", "no separate native-process controls");
    for report in reports {
        let process = inspect_process(report.root_process_id as u32);
        let role = match report.role {
            hyperlight_host::process::program::ProgramRole::SandboxHost => "VM host",
            hyperlight_host::process::program::ProgramRole::FunctionWorker => "function worker",
        };
        print_process(role, &report.name, &process);
        note("profile", profile_name(report));
        note("boundary", report.effective_isolation());
        if report.controls.is_empty() {
            note("controls", "none requested");
        }
        for outcome in &report.controls {
            note("requested", control_text(&outcome.requested.control));
            match &outcome.result {
                ControlResult::Applied {
                    effective,
                    mechanism,
                } => note(
                    "enforced",
                    format!("{} via {mechanism}", control_text(effective)),
                ),
                ControlResult::NotApplied { reason } => note(
                    "not applied",
                    format!("{}: {reason}", control_text(&outcome.requested.control)),
                ),
            }
        }
        if details {
            note("state", &process.state);
            if let Some(percent) = report.windows_cpu_rate_limit_percent() {
                note("CPU cap", format!("{percent}% aggregate host capacity"));
            }
        }
        println!();
    }
}

fn print_process(role: &str, placement: &str, process: &ProcessDetails) {
    let parent = process
        .parent_id
        .map_or_else(|| "?".to_owned(), |value| value.to_string());
    let executable = process.executable.as_ref().map_or_else(
        || "<unavailable>".to_owned(),
        |path| path.display().to_string(),
    );
    println!(
        "{role:<18} {:>8} {parent:>8}  {placement:<18} {executable}",
        process.process_id
    );
}

pub fn lifecycle_after(reports: &[ProcessReport]) {
    step("After shutdown");
    for report in reports {
        let observed = inspect_process(report.root_process_id as u32);
        note(
            &report.name,
            format!("PID {}: {}", observed.process_id, observed.state),
        );
    }
    if reports.is_empty() {
        note("native", "no additional process existed");
    }
}

pub fn pause(non_interactive: bool) -> Result<()> {
    if non_interactive {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(new_error!(
            "Interactive input is not a terminal. Use --non-interactive"
        ));
    }
    print!("Press Enter to continue and stop the live processes... ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        return Err(new_error!("Interactive input closed before Enter"));
    }
    Ok(())
}

fn profile_name(report: &ProcessReport) -> &'static str {
    if report.controls.is_empty() {
        "unrestricted"
    } else {
        "restricted"
    }
}

fn control_text(control: &ProcessControl) -> String {
    match control {
        ProcessControl::MemoryLimit(bytes) => format!("memory limit {} MiB", bytes >> 20),
        ProcessControl::CpuBudget { quota, period } => format!(
            "CPU budget {} ms per {} ms",
            quota.as_millis(),
            period.as_millis()
        ),
        ProcessControl::DenyNetwork => "deny network".to_owned(),
        ProcessControl::DenyChildProcesses => "deny child processes".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_controls_in_plain_english() {
        assert_eq!(
            control_text(&ProcessControl::MemoryLimit(512 << 20)),
            "memory limit 512 MiB"
        );
        assert_eq!(
            control_text(&ProcessControl::DenyChildProcesses),
            "deny child processes"
        );
    }
}
