// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Application-facing process-isolation walkthrough.

mod cli;
mod inspect;
mod output;
mod scenarios;

use hyperlight_host::process::ProcessStartup;

fn main() -> hyperlight_host::Result<()> {
    // SAFETY: process startup capture is the first operation, before threads,
    // logging, argument access, or inherited-resource users.
    match unsafe { ProcessStartup::capture() }? {
        Some(startup) => scenarios::run_process(startup),
        None => {
            let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
            if arguments == ["--policy-child"] {
                return Ok(());
            }
            let config = cli::Config::parse(&arguments)?;
            scenarios::run_controller(config)
        }
    }
}
