// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#[cfg(target_os = "linux")]
fn main() -> hyperlight_host::Result<()> {
    use hyperlight_host::{new_error, process};

    // SAFETY: the trusted launcher enters this fixture before any threads exist.
    let startup = unsafe { process::ProcessStartup::capture() }?
        .ok_or_else(|| new_error!("Worker startup resources are required"))?;
    let mut functions = process::ProcessHostFunctions::default();
    functions.bind(
        process::HostFunctionContract::<(i32, i32), i32>::new(
            "HostAdd",
            process::Idempotency::Idempotent,
        ),
        |a, b| {
            let check = || {
                let error = std::process::Command::new("/program")
                    .status()
                    .expect_err("Child process creation must be denied");
                assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            };
            check();
            std::thread::spawn(move || {
                check();
                a + b
            })
            .join()
            .expect("Confined Rust thread must complete")
        },
    )?;
    functions.bind(
        process::HostFunctionContract::<(), u32>::new(
            "ProcessId",
            process::Idempotency::Idempotent,
        ),
        std::process::id,
    )?;
    functions.run(startup)
}

#[cfg(not(target_os = "linux"))]
fn main() -> hyperlight_host::Result<()> {
    Err(hyperlight_host::new_error!("Linux qualification fixture"))
}
