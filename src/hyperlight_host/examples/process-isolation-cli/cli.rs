// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::ffi::OsString;
use std::path::PathBuf;

use hyperlight_host::{Result, new_error};

pub const COMMANDS: &[Command] = &[
    Command::Placement,
    Command::Containment,
    Command::Recovery,
    Command::Resources,
    Command::VmAuthority,
    Command::ChildPolicy,
    Command::Timing,
    Command::All,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Placement,
    Containment,
    Recovery,
    Resources,
    VmAuthority,
    ChildPolicy,
    Timing,
    All,
}

impl Command {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "placement" => Ok(Self::Placement),
            "containment" => Ok(Self::Containment),
            "recovery" => Ok(Self::Recovery),
            "resources" => Ok(Self::Resources),
            "vm-authority" => Ok(Self::VmAuthority),
            "child-policy" => Ok(Self::ChildPolicy),
            "timing" => Ok(Self::Timing),
            "all" => Ok(Self::All),
            _ => Err(new_error!("Unknown command '{value}'\n\n{}", help_text())),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Placement => "placement",
            Self::Containment => "containment",
            Self::Recovery => "recovery",
            Self::Resources => "resources",
            Self::VmAuthority => "vm-authority",
            Self::ChildPolicy => "child-policy",
            Self::Timing => "timing",
            Self::All => "all",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Placement => "Compare local, worker, VM-host, and combined placement",
            Self::Containment => "Report unrestricted and restricted platform enforcement",
            Self::Recovery => "Crash a worker and observe idempotent retry and restart",
            Self::Resources => "Transfer typed files with read/write and read-only rights",
            Self::VmAuthority => "Grant one worker generation authority for one nested VM",
            Self::ChildPolicy => "Observe allowed and blocked worker child creation",
            Self::Timing => "Compare basic local and isolated callback timing",
            Self::All => "Run every scenario without prompts",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub command: Option<Command>,
    pub guest: PathBuf,
    pub non_interactive: bool,
    pub details: bool,
    pub iterations: usize,
}

impl Config {
    pub fn parse(arguments: &[OsString]) -> Result<Self> {
        if arguments
            .iter()
            .any(|argument| argument == "--help" || argument == "-h")
        {
            println!("{}", help_text());
            std::process::exit(0);
        }

        let mut command = None;
        let mut guest = None;
        let mut non_interactive = false;
        let mut details = false;
        let mut iterations = 100;
        let mut index = 0;
        while index < arguments.len() {
            let argument = arguments[index]
                .to_str()
                .ok_or_else(|| new_error!("Arguments must be valid Unicode"))?;
            match argument {
                "--guest" => {
                    index += 1;
                    let value = arguments
                        .get(index)
                        .ok_or_else(|| new_error!("--guest requires a path"))?;
                    guest = Some(PathBuf::from(value));
                }
                "--non-interactive" => non_interactive = true,
                "--details" => details = true,
                "--iterations" => {
                    index += 1;
                    let value = arguments
                        .get(index)
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| new_error!("--iterations requires a positive integer"))?;
                    iterations = value.parse().map_err(|_| {
                        new_error!("--iterations requires a positive integer, got '{value}'")
                    })?;
                    if iterations == 0 {
                        return Err(new_error!("--iterations must be greater than zero"));
                    }
                }
                value if value.starts_with('-') => {
                    return Err(new_error!("Unknown option '{value}'\n\n{}", help_text()));
                }
                value if command.is_none() => command = Some(Command::parse(value)?),
                value => return Err(new_error!("Unexpected argument '{value}'")),
            }
            index += 1;
        }
        let guest = guest.ok_or_else(|| {
            new_error!(
                "--guest is required. Pass a built Hyperlight guest binary.\n\n{}",
                help_text()
            )
        })?;
        Ok(Self {
            command,
            guest,
            non_interactive,
            details,
            iterations,
        })
    }
}

pub fn help_text() -> String {
    let commands = COMMANDS
        .iter()
        .map(|command| format!("  {:<14} {}", command.name(), command.description()))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Hyperlight process-isolation sample\n\n\
         Usage:\n  process_isolation_cli --guest PATH [OPTIONS] [COMMAND]\n\n\
         With no command, an interactive menu runs one scenario at a time.\n\n\
         Commands:\n{commands}\n\n\
         Options:\n\
           --guest PATH          Built Hyperlight guest binary\n\
           --non-interactive     Do not pause while native processes are live\n\
           --details             Show native inspection and enforcement details\n\
           --iterations COUNT    Calls per timing mode, default 100\n\
           --help                Show this help"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scriptable_command_and_options() {
        let arguments = [
            "recovery",
            "--guest",
            "guest.bin",
            "--non-interactive",
            "--details",
            "--iterations",
            "12",
        ]
        .map(OsString::from);
        assert_eq!(
            Config::parse(&arguments).unwrap(),
            Config {
                command: Some(Command::Recovery),
                guest: PathBuf::from("guest.bin"),
                non_interactive: true,
                details: true,
                iterations: 12,
            }
        );
    }

    #[test]
    fn rejects_zero_iterations() {
        let arguments = ["--guest", "guest.bin", "--iterations", "0"].map(OsString::from);
        assert!(
            Config::parse(&arguments)
                .unwrap_err()
                .to_string()
                .contains("greater than zero")
        );
    }

    #[test]
    fn help_lists_every_command() {
        let help = help_text();
        assert!(COMMANDS.iter().all(|command| help.contains(command.name())));
    }
}
