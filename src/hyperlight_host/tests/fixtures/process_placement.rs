// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Mesh-provider process-placement example. See dev/process-isolation/QUICKSTART.md.

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod isolation_bench_contracts;

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod demo {
    use std::path::Path;
    use std::sync::Arc;
    #[cfg(target_os = "linux")]
    use std::time::Duration;

    use hyperlight_host::process::{
        ControlResult, HostFunctionContract, HostFunctionProcess, Idempotency, MeshProcessProvider,
        ProcessControl, ProcessHostFunctions, ProcessOptions, ProcessProfile, ProcessReport,
        ProcessStartup, RequestedControl, SandboxHost,
    };
    use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
    use hyperlight_host::{MultiUseSandbox, Result, SandboxBuilder, new_error};

    use super::isolation_bench_contracts::{ADD, ECHO, add, echo};

    const PID: HostFunctionContract<(), u32> =
        HostFunctionContract::new("ProcessId", Idempotency::Idempotent);
    const WINDOWS_VM_HOST_CONSENT: &str = "--allow-windows-vm-host";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Scenario {
        Local,
        FunctionWorker,
        VmHost,
        VmHostAndFunctionWorker,
        WorkerChildrenAllowed,
        WorkerChildrenBlocked,
    }

    impl Scenario {
        fn parse(name: &str) -> Result<Self> {
            match name {
                "local" => Ok(Self::Local),
                "function-worker" | "worker" => Ok(Self::FunctionWorker),
                "vm-host" | "sandbox" => Ok(Self::VmHost),
                "vm-host-and-function-worker" | "sandbox-worker" => {
                    Ok(Self::VmHostAndFunctionWorker)
                }
                "worker-children-allowed" | "children-allow" => Ok(Self::WorkerChildrenAllowed),
                "worker-children-blocked" | "children-deny" => Ok(Self::WorkerChildrenBlocked),
                _ => Err(new_error!(
                    "Mode must be local, function-worker, vm-host, \
                     vm-host-and-function-worker, worker-children-allowed or \
                     worker-children-blocked"
                )),
            }
        }

        fn name(self) -> &'static str {
            match self {
                Self::Local => "local",
                Self::FunctionWorker => "function-worker",
                Self::VmHost => "vm-host",
                Self::VmHostAndFunctionWorker => "vm-host-and-function-worker",
                Self::WorkerChildrenAllowed => "worker-children-allowed",
                Self::WorkerChildrenBlocked => "worker-children-blocked",
            }
        }

        fn dedicated_vm_host(self) -> bool {
            matches!(self, Self::VmHost | Self::VmHostAndFunctionWorker)
        }

        fn remote_functions(self) -> bool {
            matches!(
                self,
                Self::FunctionWorker
                    | Self::VmHostAndFunctionWorker
                    | Self::WorkerChildrenAllowed
                    | Self::WorkerChildrenBlocked
            )
        }

        fn child_policy(self) -> bool {
            matches!(
                self,
                Self::WorkerChildrenAllowed | Self::WorkerChildrenBlocked
            )
        }

        fn description(self) -> &'static str {
            match self {
                Self::Local => "VM and host functions run in the caller process",
                Self::FunctionWorker => {
                    "VM runs in the caller; host functions run in one confined function worker"
                }
                Self::VmHost => "VM and host functions share one dedicated sandbox host",
                Self::VmHostAndFunctionWorker => {
                    "VM runs in a dedicated sandbox host; host functions run in a separate confined function worker"
                }
                Self::WorkerChildrenAllowed => {
                    "VM runs in the caller; the confined function worker may create children"
                }
                Self::WorkerChildrenBlocked => {
                    "VM runs in the caller; the confined function worker cannot create children"
                }
            }
        }
    }

    fn profile(allow_children: bool, windows_vm_host: bool) -> ProcessProfile {
        let mut controls = vec![RequestedControl {
            control: ProcessControl::MemoryLimit(512 << 20),
            required: true,
        }];
        #[cfg(target_os = "linux")]
        controls.push(RequestedControl {
            control: ProcessControl::CpuBudget {
                quota: Duration::from_millis(50),
                period: Duration::from_millis(100),
            },
            required: true,
        });
        if !windows_vm_host {
            controls.push(RequestedControl {
                control: ProcessControl::DenyNetwork,
                required: true,
            });
        }
        if !allow_children {
            controls.push(RequestedControl {
                control: ProcessControl::DenyChildProcesses,
                required: true,
            });
        }
        let profile = ProcessProfile::new(controls);
        #[cfg(target_os = "windows")]
        let profile = profile
            .windows_cpu_rate_limit_percent(50)
            .expect("The fixed Windows CPU rate is valid");
        profile
    }

    fn options(name: &str, allow_children: bool, windows_vm_host: bool) -> ProcessOptions {
        ProcessOptions::for_provider(name, profile(allow_children, windows_vm_host))
    }

    fn check_calls(sandbox: &mut MultiUseSandbox, child_policy: bool) -> Result<()> {
        let result = sandbox.call::<i32>("Add", (17, 25))?;
        if result != 42 {
            return Err(new_error!("Placement changed Add = 42 to {result}"));
        }
        if !child_policy
            && sandbox.call::<String>("RoundTripHostString", "hello".to_owned())? != "hello"
        {
            return Err(new_error!("Placement changed the string callback result"));
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

    #[cfg(target_os = "windows")]
    fn validate_output_path(path: &Path) -> Result<()> {
        const MAX_PATH_WITHOUT_NUL: usize = 259;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| new_error!("Output directory needs a final path component"))?;
        let absolute = std::fs::canonicalize(parent)
            .map_err(|error| {
                new_error!("Output parent {} is unavailable: {error}", parent.display())
            })?
            .join(name);
        let blob = absolute
            .join("snapshot")
            .join("blobs")
            .join("sha256")
            .join("0".repeat(64));
        let root_units = windows_legacy_path_units(&absolute);
        let blob_units = windows_legacy_path_units(&blob);
        if blob_units > MAX_PATH_WITHOUT_NUL {
            let suffix_units = blob_units - root_units;
            let maximum = MAX_PATH_WITHOUT_NUL - suffix_units;
            return Err(new_error!(
                "Windows output directory is {root_units} UTF-16 units after resolution; \
                 the maximum is {maximum} because OCI snapshot blob paths add {suffix_units}. \
                 Choose a shorter parent or output name"
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn windows_legacy_path_units(path: &Path) -> usize {
        use std::os::windows::ffi::OsStrExt;
        use std::path::{Component, Prefix};

        let units = path.as_os_str().encode_wide().count();
        match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::VerbatimDisk(_) => units - 4,
                Prefix::VerbatimUNC(_, _) => units - 6,
                _ => units,
            },
            _ => units,
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn validate_output_path(_: &Path) -> Result<()> {
        Ok(())
    }

    fn print_reports(label: &str, reports: &[ProcessReport]) {
        println!("{label}:");
        if reports.is_empty() {
            println!("  No additional native processes. The VM and functions use the caller.");
            return;
        }
        for report in reports {
            println!(
                "  {:?} '{}' PID {}",
                report.role, report.name, report.root_process_id
            );
            println!("    Boundary: {}", report.effective_isolation());
            if let Some(percent) = report.windows_cpu_rate_limit_percent() {
                println!(
                    "    Applied Windows CPU rate: {percent}% of aggregate host processor capacity"
                );
            }
            for control in &report.controls {
                match &control.result {
                    ControlResult::Applied {
                        effective,
                        mechanism,
                    } => println!("    Applied {effective:?}: {mechanism}"),
                    ControlResult::NotApplied { reason } => {
                        println!("    Not applied {:?}: {reason}", control.requested.control)
                    }
                }
            }
        }
    }

    fn validate_consent(scenario: Scenario, consent: bool) -> Result<()> {
        if cfg!(target_os = "windows") && scenario.dedicated_vm_host() && !consent {
            return Err(new_error!(
                "{} requires {} because its VM host runs outside AppContainer. \
                 That host has no AppContainer filesystem or network isolation",
                scenario.name(),
                WINDOWS_VM_HOST_CONSENT
            ));
        }
        if consent && (!cfg!(target_os = "windows") || !scenario.dedicated_vm_host()) {
            return Err(new_error!(
                "{} is valid only for Windows vm-host modes",
                WINDOWS_VM_HOST_CONSENT
            ));
        }
        Ok(())
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
                "worker-children-allowed" | "worker-children-blocked",
            ) => {
                let allow_children = name == "worker-children-allowed";
                functions.bind(ADD, move |a, b| {
                    let check = move || -> std::result::Result<(), i32> {
                        let result = std::process::Command::new(
                            std::env::current_exe().expect("Current executable must be available"),
                        )
                        .arg("--policy-child")
                        .status();
                        if allow_children {
                            assert!(result.expect("Child creation must succeed").success());
                            Ok(())
                        } else {
                            child_creation_denied(result)
                        }
                    };
                    if let Err(code) = check() {
                        return code;
                    }
                    if let Err(code) = std::thread::spawn(check)
                        .join()
                        .expect("Confined Rust thread must complete")
                    {
                        return code;
                    }
                    a + b
                })?;
                functions.bind(PID, std::process::id)?;
                functions.run(startup)
            }
            (hyperlight_host::process::program::ProgramRole::SandboxHost, "vm-host-local") => {
                functions.bind(ADD, add)?;
                functions.bind(ECHO, echo)?;
                SandboxHost::new(functions).run(startup)
            }
            (hyperlight_host::process::program::ProgramRole::SandboxHost, "vm-host-remote") => {
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
        if args == ["--help"] || args == ["-h"] {
            println!("{}", help_text());
            return Ok(());
        }
        if !(args.len() == 3 || args.len() == 4) {
            return Err(new_error!(
                "Usage: process_placement MODE GUEST NEW_OUTPUT_DIRECTORY \
                 [--allow-windows-vm-host]"
            ));
        }
        let scenario = Scenario::parse(
            args[0]
                .to_str()
                .ok_or_else(|| new_error!("Invalid placement mode"))?,
        )?;
        let consent = args
            .get(3)
            .is_some_and(|arg| arg == WINDOWS_VM_HOST_CONSENT);
        if args.len() == 4 && !consent {
            return Err(new_error!("Unknown option '{}'", args[3].to_string_lossy()));
        }
        validate_consent(scenario, consent)?;
        let dedicated = scenario.dedicated_vm_host();
        let remote = scenario.remote_functions();
        let child_policy = scenario.child_policy();
        let guest_input = Path::new(&args[1]);
        let guest = std::fs::canonicalize(guest_input).map_err(|error| {
            new_error!(
                "Guest binary {} is unavailable: {error}. Build the guest and pass its existing path",
                guest_input.display()
            )
        })?;
        let output = Path::new(&args[2]);
        validate_output_path(output)?;
        create_output(output)?;
        println!("Mode: {}. {}", scenario.name(), scenario.description());
        if cfg!(target_os = "windows") && scenario == Scenario::VmHost {
            println!(
                "Security note: co-located host functions share the VM host. They do not have AppContainer filesystem or network isolation."
            );
        }
        let provider = (dedicated || remote)
            .then(MeshProcessProvider::discover)
            .transpose()?;
        let mut builder = SandboxBuilder::from_file(guest);
        if let Some(provider) = &provider {
            builder = builder.mesh_process_provider(provider.clone());
        }
        if remote {
            let worker_name = match scenario {
                Scenario::WorkerChildrenAllowed => "worker-children-allowed",
                Scenario::WorkerChildrenBlocked => "worker-children-blocked",
                _ => "functions",
            };
            let mut worker = HostFunctionProcess::new(options(
                worker_name,
                scenario == Scenario::WorkerChildrenAllowed,
                false,
            ))
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
            let options = options(
                if remote {
                    "vm-host-remote"
                } else {
                    "vm-host-local"
                },
                false,
                cfg!(target_os = "windows"),
            );
            #[cfg(target_os = "windows")]
            {
                builder = builder.windows_vm_host_process(options);
            }
            #[cfg(target_os = "linux")]
            {
                builder = builder.sandbox_process(options);
            }
            if !remote {
                builder = builder
                    .sandbox_host_function(ADD)
                    .sandbox_host_function(ECHO);
            }
        }
        let mut sandbox = builder.build()?;
        check_calls(&mut sandbox, child_policy)?;
        let original_reports = sandbox.process_reports();
        print_reports("Original process report", &original_reports);
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
        sandbox.shutdown()?;
        drop(sandbox);
        verify_processes_stopped(&original_reports)?;
        drop(snapshot);
        let loaded = Arc::new(Snapshot::checked_load(&layout, digest.clone())?);
        let mut builder = SandboxBuilder::from_snapshot(loaded);
        if dedicated || remote {
            builder =
                builder.mesh_process_provider(MeshProcessProvider::discover_for_snapshot(&layout)?);
            #[cfg(target_os = "windows")]
            if dedicated {
                builder = builder.allow_windows_vm_host();
            }
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
        let reconstructed_reports = fresh.process_reports();
        print_reports("Reconstructed process report", &reconstructed_reports);
        fresh.shutdown()?;
        drop(fresh);
        verify_processes_stopped(&reconstructed_reports)?;
        println!(
            "PASS: {}. Callbacks, Add = 42, guest restore, OCI reconstruction and checked process cleanup succeeded.",
            scenario.name()
        );
        println!("OCI layout: {}\nManifest: {digest}", layout.display());
        Ok(())
    }

    fn help_text() -> &'static str {
        "Usage: process_placement MODE GUEST NEW_OUTPUT_DIRECTORY [--allow-windows-vm-host]\n\
\n\
Modes:\n\
  local                         VM and host functions use the caller process\n\
  function-worker               VM uses the caller; functions use one confined worker\n\
  vm-host                       VM and host functions share one dedicated VM host\n\
  vm-host-and-function-worker   VM host and confined function worker are separate\n\
  worker-children-allowed       Confined function worker may create child processes\n\
  worker-children-blocked       Confined function worker cannot create child processes\n\
\n\
The output directory must not exist. Windows VM-host modes require\n\
--allow-windows-vm-host because the VM host runs outside AppContainer."
    }

    fn verify_processes_stopped(reports: &[ProcessReport]) -> Result<()> {
        for report in reports {
            if process_exists(report.root_process_id)? {
                return Err(new_error!(
                    "Process cleanup left PID {} running for '{}'",
                    report.root_process_id,
                    report.name
                ));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn process_exists(pid: i32) -> Result<bool> {
        let stat = Path::new("/proc").join(pid.to_string()).join("stat");
        match std::fs::read_to_string(stat) {
            Ok(contents) => {
                let state = contents
                    .rsplit_once(") ")
                    .and_then(|(_, suffix)| suffix.chars().next())
                    .ok_or_else(|| new_error!("Malformed process status for PID {pid}"))?;
                Ok(state != 'Z')
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(new_error!("Checking PID {pid}: {error}")),
        }
    }

    #[cfg(target_os = "windows")]
    fn process_exists(pid: i32) -> Result<bool> {
        use windows::Win32::Foundation::{CloseHandle, E_INVALIDARG, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        };

        // SAFETY: the queried handle is valid until it is closed below.
        unsafe {
            let handle = match OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid as u32,
            ) {
                Ok(handle) => handle,
                Err(error) if error.code() == E_INVALIDARG => return Ok(false),
                Err(error) => return Err(new_error!("Opening PID {pid}: {error}")),
            };
            let wait = WaitForSingleObject(handle, 0);
            CloseHandle(handle).map_err(|error| new_error!("Closing PID {pid}: {error}"))?;
            if wait == WAIT_TIMEOUT {
                Ok(true)
            } else if wait == WAIT_OBJECT_0 {
                Ok(false)
            } else {
                Err(new_error!("Waiting for PID {pid} returned {wait:?}"))
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn child_creation_denied(
        result: std::io::Result<std::process::ExitStatus>,
    ) -> std::result::Result<(), i32> {
        const ERROR_CHILD_PROCESS_BLOCKED: i32 = 367;
        const ERROR_NOT_ENOUGH_QUOTA: i32 = 1816;
        match result {
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(ERROR_CHILD_PROCESS_BLOCKED | ERROR_NOT_ENOUGH_QUOTA)
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(negative_diagnostic(error.raw_os_error())),
            Ok(_) => Err(i32::MAX),
        }
    }

    #[cfg(target_os = "linux")]
    fn child_creation_denied(
        result: std::io::Result<std::process::ExitStatus>,
    ) -> std::result::Result<(), i32> {
        match result {
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => Ok(()),
            Err(error) => Err(negative_diagnostic(error.raw_os_error())),
            Ok(_) => Err(i32::MAX),
        }
    }

    fn negative_diagnostic(code: Option<i32>) -> i32 {
        let code = code.unwrap_or(i32::MAX);
        if code == i32::MIN {
            i32::MIN
        } else {
            -code.abs()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn six_plain_english_modes_are_independent() {
            for (name, expected) in [
                ("local", Scenario::Local),
                ("function-worker", Scenario::FunctionWorker),
                ("vm-host", Scenario::VmHost),
                (
                    "vm-host-and-function-worker",
                    Scenario::VmHostAndFunctionWorker,
                ),
                ("worker-children-allowed", Scenario::WorkerChildrenAllowed),
                ("worker-children-blocked", Scenario::WorkerChildrenBlocked),
            ] {
                assert_eq!(Scenario::parse(name).unwrap(), expected);
            }
            assert!(Scenario::parse("unknown").is_err());
        }

        #[test]
        fn help_lists_all_modes_and_windows_consent() {
            let help = help_text();
            for mode in [
                "local",
                "function-worker",
                "vm-host",
                "vm-host-and-function-worker",
                "worker-children-allowed",
                "worker-children-blocked",
            ] {
                assert!(help.contains(mode));
            }
            assert!(help.contains("--allow-windows-vm-host"));
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

        #[cfg(target_os = "windows")]
        #[test]
        fn windows_output_path_budget_accepts_boundary_and_rejects_next_unit() {
            let parent = tempfile::tempdir().unwrap();
            let canonical_parent = std::fs::canonicalize(parent.path()).unwrap();
            let parent_units = windows_legacy_path_units(&canonical_parent);
            let suffix_units = windows_legacy_path_units(
                &Path::new("snapshot")
                    .join("blobs")
                    .join("sha256")
                    .join("0".repeat(64)),
            ) + 1;
            let maximum_root = 259 - suffix_units;
            let separator = usize::from(!canonical_parent.as_os_str().is_empty());
            let boundary_name = "x".repeat(maximum_root - parent_units - separator);
            let boundary = parent.path().join(&boundary_name);
            validate_output_path(&boundary).unwrap();
            let over = parent.path().join(format!("{boundary_name}x"));
            let error = validate_output_path(&over).unwrap_err().to_string();
            assert!(error.contains("the maximum is"));
            assert!(error.contains("Choose a shorter parent or output name"));
            assert!(!boundary.exists());
            assert!(!over.exists());
        }
    }
}

fn main() -> hyperlight_host::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
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
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    Err(hyperlight_host::new_error!(
        "This example requires Linux or Windows"
    ))
}
