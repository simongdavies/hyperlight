// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Mesh-provider process-placement example. See dev/process-isolation/QUICKSTART.md.

#[cfg(target_os = "linux")]
mod isolation_bench_contracts;

#[cfg(target_os = "linux")]
mod demo {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use hyperlight_host::process::{
        HostFunctionContract, HostFunctionProcess, Idempotency, MeshProcessProvider,
        ProcessControl, ProcessHostFunctions, ProcessOptions, ProcessProfile, ProcessStartup,
        RequestedControl, SandboxHost,
    };
    use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
    use hyperlight_host::{MultiUseSandbox, Result, SandboxBuilder, new_error};

    use super::isolation_bench_contracts::{ADD, ECHO, add, echo};

    const PID: HostFunctionContract<(), u32> =
        HostFunctionContract::new("ProcessId", Idempotency::Idempotent);

    fn placement(name: &str) -> Result<(bool, bool)> {
        match name {
            "local" => Ok((false, false)),
            "worker" | "children-allow" | "children-deny" => Ok((false, true)),
            "sandbox" => Ok((true, false)),
            "sandbox-worker" => Ok((true, true)),
            _ => Err(new_error!(
                "Placement must be local, worker, sandbox, sandbox-worker, children-allow or children-deny"
            )),
        }
    }

    fn profile(allow_children: bool) -> ProcessProfile {
        let mut controls = vec![
            RequestedControl {
                control: ProcessControl::MemoryLimit(512 << 20),
                required: true,
            },
            RequestedControl {
                control: ProcessControl::DenyNetwork,
                required: true,
            },
            RequestedControl {
                control: ProcessControl::CpuBudget {
                    quota: Duration::from_millis(50),
                    period: Duration::from_millis(100),
                },
                required: true,
            },
        ];
        if !allow_children {
            controls.push(RequestedControl {
                control: ProcessControl::DenyChildProcesses,
                required: true,
            });
        }
        ProcessProfile::new(controls)
    }

    fn options(name: &str, allow_children: bool) -> ProcessOptions {
        ProcessOptions::for_provider(name, profile(allow_children))
    }

    fn check_calls(sandbox: &mut MultiUseSandbox, child_policy: bool) -> Result<()> {
        if sandbox.call::<i32>("Add", (17, 25))? != 42
            || (!child_policy
                && sandbox.call::<String>("RoundTripHostString", "hello".to_owned())? != "hello")
        {
            return Err(new_error!("Placement changed the callback result"));
        }
        Ok(())
    }

    fn create_output(path: &Path) -> Result<()> {
        std::fs::create_dir(path).map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => new_error!(
                "Output directory {} already exists. Preserve or rename it, then choose a new path",
                path.display()
            ),
            std::io::ErrorKind::NotFound => new_error!(
                "Output parent for {} does not exist. Create only its parent directory first",
                path.display()
            ),
            _ => new_error!("Creating output directory {}: {error}", path.display()),
        })
    }

    pub fn run_process(startup: ProcessStartup) -> Result<()> {
        let role = startup.role()?;
        let name = startup.name()?;
        let mut functions = ProcessHostFunctions::default();
        match (role, name.as_str()) {
            (hyperlight_host::process::program::ProgramRole::FunctionWorker, "functions") => {
                functions.bind(ADD, add)?;
                functions.bind(ECHO, echo)?;
                functions.run(startup)
            }
            (
                hyperlight_host::process::program::ProgramRole::FunctionWorker,
                "children-allow" | "children-deny",
            ) => {
                let allow_children = name == "children-allow";
                functions.bind(ADD, move |a, b| {
                    let check = move || {
                        let result = std::process::Command::new("/program")
                            .arg("--policy-child")
                            .status();
                        if allow_children {
                            assert!(result.expect("Child creation must succeed").success());
                        } else {
                            let error = result.expect_err("Child process creation must be denied");
                            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
                        }
                    };
                    check();
                    std::thread::spawn(move || {
                        check();
                        a + b
                    })
                    .join()
                    .expect("Confined Rust thread must complete")
                })?;
                functions.bind(PID, std::process::id)?;
                functions.run(startup)
            }
            (hyperlight_host::process::program::ProgramRole::SandboxHost, "sandbox-local") => {
                functions.bind(ADD, add)?;
                functions.bind(ECHO, echo)?;
                SandboxHost::new(functions).run(startup)
            }
            (hyperlight_host::process::program::ProgramRole::SandboxHost, "sandbox-remote") => {
                SandboxHost::new(functions).run(startup)
            }
            _ => Err(new_error!(
                "Unknown Mesh process role '{role:?}' for '{name}'"
            )),
        }
    }

    pub fn run_controller() -> Result<()> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args == ["--policy-child"] {
            return Ok(());
        }
        if args.len() != 3 {
            return Err(new_error!(
                "Usage: process_placement PLACEMENT GUEST NEW_OUTPUT_DIRECTORY"
            ));
        }
        let scenario = args[0]
            .to_str()
            .ok_or_else(|| new_error!("Invalid placement"))?;
        let (dedicated, remote) = placement(scenario)?;
        let child_policy = scenario.starts_with("children-");
        let guest_input = Path::new(&args[1]);
        let guest = std::fs::canonicalize(guest_input).map_err(|error| {
            new_error!(
                "Guest binary {} is unavailable: {error}. Build the guest and pass its existing path",
                guest_input.display()
            )
        })?;
        let output = Path::new(&args[2]);
        create_output(output)?;
        let provider = (dedicated || remote)
            .then(MeshProcessProvider::discover)
            .transpose()?;
        let mut builder = SandboxBuilder::from_file(guest);
        if let Some(provider) = &provider {
            builder = builder.mesh_process_provider(provider.clone());
        }
        if remote {
            let worker_name = if child_policy { scenario } else { "functions" };
            let mut worker =
                HostFunctionProcess::new(options(worker_name, scenario == "children-allow"))
                    .function(ADD);
            worker = if child_policy {
                worker.function(PID)
            } else {
                worker.function(ECHO)
            };
            builder = builder.host_function_process(worker);
        } else if !dedicated {
            builder = builder
                .host_function("HostAdd", add)
                .host_function("HostEchoString", echo);
        }
        if dedicated {
            builder = builder.sandbox_process(options(
                if remote {
                    "sandbox-remote"
                } else {
                    "sandbox-local"
                },
                false,
            ));
            if !remote {
                builder = builder
                    .sandbox_host_function(ADD)
                    .sandbox_host_function(ECHO);
            }
        }
        let mut sandbox = builder.build()?;
        check_calls(&mut sandbox, child_policy)?;
        println!("Original processes: {:#?}", sandbox.process_reports());
        let state = sandbox.call::<i32>("GetStatic", ())?;
        let snapshot = sandbox.snapshot()?;
        if sandbox.call::<i32>("AddToStatic", 7)? != state + 7 {
            return Err(new_error!("Guest mutation failed"));
        }
        sandbox.restore(snapshot.clone())?;
        if sandbox.call::<i32>("GetStatic", ())? != state {
            return Err(new_error!("Guest restore failed"));
        }
        let layout = output.join("snapshot");
        let tag = OciTag::new("placement")?;
        let digest = match &provider {
            Some(provider) => snapshot.save_with_process_provider(&layout, &tag, provider)?,
            None => snapshot.save(&layout, &tag)?,
        };
        drop(sandbox);
        drop(snapshot);
        let loaded = Arc::new(Snapshot::checked_load(&layout, digest.clone())?);
        let mut builder = SandboxBuilder::from_snapshot(loaded);
        if dedicated || remote {
            builder =
                builder.mesh_process_provider(MeshProcessProvider::discover_for_snapshot(&layout)?);
        } else {
            builder = builder
                .host_function("HostAdd", add)
                .host_function("HostEchoString", echo);
        }
        let mut fresh = builder.build()?;
        check_calls(&mut fresh, child_policy)?;
        if fresh.call::<i32>("GetStatic", ())? != state {
            return Err(new_error!("OCI guest state differs"));
        }
        println!("Reconstructed processes: {:#?}", fresh.process_reports());
        println!("{scenario}: callbacks, guest restore and OCI reconstruction passed (Add = 42)");
        println!("OCI layout: {}\nManifest: {digest}", layout.display());
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn placements_are_independent() {
            for (name, dedicated, remote) in [
                ("local", false, false),
                ("worker", false, true),
                ("sandbox", true, false),
                ("sandbox-worker", true, true),
                ("children-allow", false, true),
                ("children-deny", false, true),
            ] {
                assert_eq!(placement(name).unwrap(), (dedicated, remote));
            }
            assert!(placement("unknown").is_err());
        }

        #[test]
        fn output_directory_must_be_new_below_an_existing_parent() {
            let parent = tempfile::tempdir().unwrap();
            let output = parent.path().join("run");
            create_output(&output).unwrap();
            assert!(
                create_output(&output)
                    .unwrap_err()
                    .to_string()
                    .contains("already exists")
            );
            assert!(
                create_output(&parent.path().join("missing").join("run"))
                    .unwrap_err()
                    .to_string()
                    .contains("Create only its parent")
            );
        }
    }
}

fn main() -> hyperlight_host::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: capture is the first operation, before threads or environment access.
        let startup = unsafe { hyperlight_host::process::ProcessStartup::capture() }?;
        match startup {
            Some(startup) => demo::run_process(startup),
            None => {
                env_logger::init();
                demo::run_controller()
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    Err(hyperlight_host::new_error!("This example requires Linux"))
}
