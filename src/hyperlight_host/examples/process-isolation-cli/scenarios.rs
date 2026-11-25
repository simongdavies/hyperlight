// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyperlight_host::process::{
    HostFunctionContract, HostFunctionProcess, Idempotency, MeshProcessProvider, OsResourceRights,
    ProcessControl, ProcessHostFunctions, ProcessOptions, ProcessProfile, ProcessResourceManifest,
    ProcessStartup, RequestedControl, RestartPolicy, SandboxHost, VmBackend,
};
use hyperlight_host::{MultiUseSandbox, Result, SandboxBuilder, new_error};

use crate::cli::{COMMANDS, Command, Config};
use crate::output::{heading, lifecycle_after, note, pause, process_table, step};

const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("HostAdd", Idempotency::Idempotent);
const CRASH_ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("HostAdd", Idempotency::Idempotent);
const PID: HostFunctionContract<(), u32> =
    HostFunctionContract::new("ProcessId", Idempotency::Idempotent);
const ECHO: HostFunctionContract<(String,), String> =
    HostFunctionContract::new("HostEchoString", Idempotency::NonIdempotent);
const FILE_RIGHTS: OsResourceRights = OsResourceRights::READ.union(OsResourceRights::WRITE);

pub fn run_controller(config: Config) -> Result<()> {
    let guest = std::fs::canonicalize(&config.guest).map_err(|error| {
        new_error!(
            "Guest binary {} is unavailable: {error}",
            config.guest.display()
        )
    })?;
    match config.command {
        Some(Command::All) => run_all(&guest, config.details, config.iterations),
        Some(command) => run_command(
            command,
            &guest,
            config.non_interactive,
            config.details,
            config.iterations,
        ),
        None => interactive(&guest, config.details, config.iterations),
    }
}

pub fn run_process(startup: ProcessStartup) -> Result<()> {
    let role = startup.role()?;
    let name = startup.name()?;
    match (role, name.as_str()) {
        (hyperlight_host::process::program::ProgramRole::FunctionWorker, "sample-worker") => {
            run_sample_worker(startup)
        }
        (
            hyperlight_host::process::program::ProgramRole::FunctionWorker,
            "containment-unrestricted" | "containment-restricted" | "timing-worker",
        ) => run_add_worker(startup),
        (hyperlight_host::process::program::ProgramRole::FunctionWorker, "crash-worker") => {
            run_crash_worker(startup)
        }
        (hyperlight_host::process::program::ProgramRole::FunctionWorker, "resource-worker") => {
            run_resource_worker(startup)
        }
        (hyperlight_host::process::program::ProgramRole::FunctionWorker, "vm-authority-worker") => {
            run_vm_authority_worker(startup)
        }
        (
            hyperlight_host::process::program::ProgramRole::FunctionWorker,
            "children-allowed" | "children-blocked",
        ) => run_child_policy_worker(startup, name == "children-allowed"),
        (hyperlight_host::process::program::ProgramRole::SandboxHost, "sample-vm-local") => {
            let mut functions = ProcessHostFunctions::default();
            functions.bind(ADD, add)?;
            functions.bind(ECHO, echo)?;
            SandboxHost::new(functions).run(startup)
        }
        (hyperlight_host::process::program::ProgramRole::SandboxHost, "sample-vm-remote") => {
            SandboxHost::new(ProcessHostFunctions::default()).run(startup)
        }
        _ => Err(new_error!(
            "Unknown process-isolation sample role '{role:?}' for '{name}'"
        )),
    }
}

fn interactive(guest: &Path, details: bool, iterations: usize) -> Result<()> {
    heading("Hyperlight process isolation");
    println!("Choose one scenario. The sample keeps native processes live for inspection.");
    loop {
        println!();
        for (index, command) in COMMANDS
            .iter()
            .copied()
            .filter(|command| *command != Command::All)
            .enumerate()
        {
            println!(
                "  {}. {:<14} {}",
                index + 1,
                command.name(),
                command.description()
            );
        }
        println!("  q. quit");
        print!("Selection: ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input)? == 0 {
            return Ok(());
        }
        let value = input.trim();
        if value.eq_ignore_ascii_case("q") {
            return Ok(());
        }
        let commands = COMMANDS
            .iter()
            .copied()
            .filter(|command| *command != Command::All)
            .collect::<Vec<_>>();
        let command = value
            .parse::<usize>()
            .ok()
            .and_then(|index| commands.get(index.wrapping_sub(1)).copied())
            .or_else(|| Command::parse(value).ok())
            .ok_or_else(|| new_error!("Choose a listed number or command name"))?;
        run_command(command, guest, false, details, iterations)?;
    }
}

fn run_all(guest: &Path, details: bool, iterations: usize) -> Result<()> {
    heading("Complete non-interactive walkthrough");
    for command in COMMANDS
        .iter()
        .copied()
        .filter(|command| *command != Command::All)
    {
        run_command(command, guest, true, details, iterations)?;
    }
    heading("Walkthrough complete");
    note("result", "all applicable scenarios completed");
    Ok(())
}

fn run_command(
    command: Command,
    guest: &Path,
    non_interactive: bool,
    details: bool,
    iterations: usize,
) -> Result<()> {
    match command {
        Command::Placement => placement(guest, non_interactive, details),
        Command::Containment => containment(guest, non_interactive, details),
        Command::Recovery => recovery(guest, non_interactive, details),
        Command::Resources => resources(guest, non_interactive, details),
        Command::VmAuthority => vm_authority(guest, non_interactive, details),
        Command::ChildPolicy => child_policy(guest, non_interactive, details),
        Command::Timing => timing(guest, iterations, details),
        Command::All => run_all(guest, details, iterations),
    }
}

fn add(left: i32, right: i32) -> i32 {
    left + right
}

fn echo(value: String) -> String {
    value
}

fn unrestricted_options(name: &str) -> ProcessOptions {
    ProcessOptions::for_provider(name, ProcessProfile::unrestricted())
}

fn restricted_profile(deny_network: bool, deny_children: bool) -> ProcessProfile {
    let mut controls = vec![RequestedControl {
        control: ProcessControl::MemoryLimit(512 << 20),
        required: true,
    }];
    if deny_network {
        controls.push(RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        });
    }
    if deny_children {
        controls.push(RequestedControl {
            control: ProcessControl::DenyChildProcesses,
            required: true,
        });
    }
    let profile = ProcessProfile::new(controls);
    #[cfg(target_os = "windows")]
    let profile = profile
        .windows_cpu_rate_limit_percent(50)
        .expect("fixed sample CPU rate is valid");
    profile
}

#[derive(Clone, Copy)]
enum Placement {
    Local,
    Worker,
    VmHost,
    VmHostAndWorker,
}

impl Placement {
    const ALL: [Self; 4] = [
        Self::Local,
        Self::Worker,
        Self::VmHost,
        Self::VmHostAndWorker,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Worker => "function worker",
            Self::VmHost => "dedicated VM host",
            Self::VmHostAndWorker => "VM host and function worker",
        }
    }
}

fn placement(guest: &Path, non_interactive: bool, details: bool) -> Result<()> {
    heading("Placement modes");
    for placement in Placement::ALL {
        step(placement.name());
        let mut sandbox = build_placement(guest, placement)?;
        let before = sandbox.process_reports();
        process_table("Before guest call", &before, details);
        let result = sandbox.call::<i32>("Add", (17, 25))?;
        note("program", format!("Add(17, 25) returned {result}"));
        if result != 42 {
            return Err(new_error!("Placement changed Add result to {result}"));
        }
        pause(non_interactive)?;
        sandbox.shutdown()?;
        lifecycle_after(&before);
    }
    Ok(())
}

fn build_placement(guest: &Path, placement: Placement) -> Result<MultiUseSandbox> {
    let mut builder = SandboxBuilder::from_file(guest);
    if !matches!(placement, Placement::Local) {
        builder = builder.mesh_process_provider(MeshProcessProvider::discover()?);
    }
    if matches!(placement, Placement::Worker | Placement::VmHostAndWorker) {
        builder = builder.host_function_process(
            HostFunctionProcess::new(unrestricted_options("sample-worker"))
                .function(ADD)
                .function(ECHO),
        );
    } else if matches!(placement, Placement::Local) {
        builder = builder
            .host_function("HostAdd", add)
            .host_function("HostEchoString", echo);
    }
    if matches!(placement, Placement::VmHost | Placement::VmHostAndWorker) {
        let name = if matches!(placement, Placement::VmHost) {
            "sample-vm-local"
        } else {
            "sample-vm-remote"
        };
        #[cfg(target_os = "windows")]
        {
            builder = builder.windows_vm_host_process(unrestricted_options(name));
        }
        #[cfg(not(target_os = "windows"))]
        {
            builder = builder.sandbox_process(unrestricted_options(name));
        }
        if matches!(placement, Placement::VmHost) {
            builder = builder
                .sandbox_host_function(ADD)
                .sandbox_host_function(ECHO);
        }
    }
    builder.build()
}

fn run_sample_worker(startup: ProcessStartup) -> Result<()> {
    let mut functions = ProcessHostFunctions::default();
    functions.bind(ADD, add)?;
    functions.bind(ECHO, echo)?;
    functions.run(startup)
}

fn run_add_worker(startup: ProcessStartup) -> Result<()> {
    let mut functions = ProcessHostFunctions::default();
    functions.bind(ADD, add)?;
    functions.run(startup)
}

fn containment(guest: &Path, non_interactive: bool, details: bool) -> Result<()> {
    heading("Containment and platform capability reporting");
    note("platform", std::env::consts::OS);
    step("Unrestricted worker");
    let mut unrestricted = build_worker(
        guest,
        "containment-unrestricted",
        ProcessProfile::unrestricted(),
        ADD,
    )?;
    let reports = unrestricted.process_reports();
    process_table("Observed unrestricted process", &reports, true);
    note(
        "meaning",
        "caller-user execution. No process restriction is claimed",
    );
    pause(non_interactive)?;
    unrestricted.shutdown()?;
    lifecycle_after(&reports);

    step("Restricted worker");
    let profile = restricted_profile(true, true);
    match build_worker(guest, "containment-restricted", profile, ADD) {
        Ok(mut restricted) => {
            let reports = restricted.process_reports();
            process_table("Observed restricted process", &reports, details);
            let result = restricted.call::<i32>("Add", (20, 22))?;
            note("program", format!("Add(20, 22) returned {result}"));
            pause(non_interactive)?;
            restricted.shutdown()?;
            lifecycle_after(&reports);
        }
        Err(error) if cfg!(target_os = "macos") => {
            note("expected", "restricted macOS launch rejected before spawn");
            note("observed", error);
            note(
                "enforced",
                "none claimed because no process report was created",
            );
        }
        Err(error) => {
            note("unavailable", error);
            note(
                "enforced",
                "none claimed. This host did not produce an enforcement report",
            );
        }
    }
    Ok(())
}

fn build_worker(
    guest: &Path,
    name: &str,
    profile: ProcessProfile,
    contract: HostFunctionContract<(i32, i32), i32>,
) -> Result<MultiUseSandbox> {
    SandboxBuilder::from_file(guest)
        .mesh_process_provider(MeshProcessProvider::discover()?)
        .host_function_process(
            HostFunctionProcess::new(ProcessOptions::for_provider(name, profile))
                .function(contract),
        )
        .build()
}

fn recovery(guest: &Path, non_interactive: bool, details: bool) -> Result<()> {
    heading("Worker crash, restart, and idempotent retry");
    let marker = tempfile::tempfile()?;
    let mut verification = marker.try_clone()?;
    let mut provider = MeshProcessProvider::discover()?;
    provider.register_file("crash-worker", marker, FILE_RIGHTS)?;
    let policy = RestartPolicy {
        max_restarts: 2,
        window: Duration::from_secs(30),
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
    };
    let mut sandbox = SandboxBuilder::from_file(guest)
        .mesh_process_provider(provider)
        .process_restart_policy(policy)
        .host_function_process(
            HostFunctionProcess::new(unrestricted_options("crash-worker")).function(CRASH_ADD),
        )
        .build()?;
    let before = sandbox.process_reports();
    process_table("Before crash", &before, details);
    let result = sandbox.call::<i32>("Add", (20, 22))?;
    let after = sandbox.process_reports();
    process_table("After automatic recovery", &after, details);
    note("program", format!("idempotent Add returned {result}"));
    let old = before.first().map(|report| report.root_process_id);
    let new = after.first().map(|report| report.root_process_id);
    note(
        "lifecycle",
        format!("worker PID {old:?} replaced by {new:?}"),
    );
    verification.seek(SeekFrom::Start(0))?;
    let mut dispatches = String::new();
    verification.read_to_string(&mut dispatches)?;
    note(
        "retry",
        format!(
            "{} dispatch records. The idempotency contract allowed replay",
            dispatches.lines().count()
        ),
    );
    pause(non_interactive)?;
    sandbox.shutdown()?;
    lifecycle_after(&after);
    Ok(())
}

fn run_crash_worker(startup: ProcessStartup) -> Result<()> {
    let manifest = ProcessResourceManifest::new().with_file(FILE_RIGHTS)?;
    ProcessHostFunctions::run_with_resources(
        startup,
        [CRASH_ADD.erase()],
        manifest,
        |resources, functions| {
            let ids = resources.ids();
            let [marker_id] = ids.as_slice() else {
                return Err(new_error!("Crash worker requires one marker file"));
            };
            let marker = resources.take_file(*marker_id, FILE_RIGHTS)?;
            let marker = Arc::new(Mutex::new(marker));
            functions.bind(CRASH_ADD, move |left, right| -> Result<i32> {
                let mut marker = marker
                    .lock()
                    .map_err(|error| new_error!("Crash marker lock failed: {error}"))?;
                marker.seek(SeekFrom::Start(0))?;
                let mut existing = String::new();
                marker.read_to_string(&mut existing)?;
                marker.seek(SeekFrom::End(0))?;
                writeln!(marker, "dispatched")?;
                marker.flush()?;
                if existing.is_empty() {
                    std::process::exit(86);
                }
                Ok(left + right)
            })
        },
    )
}

fn resources(guest: &Path, non_interactive: bool, details: bool) -> Result<()> {
    heading("Typed file transfer and rights");
    let mut writable = tempfile::tempfile()?;
    writable.write_all(b"write:")?;
    writable.seek(SeekFrom::Start(0))?;
    let mut writable_check = writable.try_clone()?;
    let mut read_only_temp = tempfile::NamedTempFile::new()?;
    read_only_temp.write_all(b"read-only")?;
    let mut read_only_check = read_only_temp.reopen()?;
    let read_only = File::open(read_only_temp.path())?;
    let mut provider = MeshProcessProvider::discover()?;
    provider.register_file("resource-worker", writable, FILE_RIGHTS)?;
    provider.register_file("resource-worker", read_only, OsResourceRights::READ)?;
    let mut sandbox = SandboxBuilder::from_file(guest)
        .mesh_process_provider(provider)
        .host_function_process(
            HostFunctionProcess::new(unrestricted_options("resource-worker")).function(ECHO),
        )
        .build()?;
    let reports = sandbox.process_reports();
    process_table("Before resource call", &reports, details);
    let response = sandbox.call::<String>("RoundTripHostString", "capability".to_owned())?;
    note("worker", response);
    writable_check.seek(SeekFrom::Start(0))?;
    let mut writable_value = String::new();
    writable_check.read_to_string(&mut writable_value)?;
    read_only_check.seek(SeekFrom::Start(0))?;
    let mut read_only_value = String::new();
    read_only_check.read_to_string(&mut read_only_value)?;
    note("read/write", writable_value);
    note("read-only", read_only_value);
    pause(non_interactive)?;
    sandbox.shutdown()?;
    lifecycle_after(&reports);
    Ok(())
}

fn run_resource_worker(startup: ProcessStartup) -> Result<()> {
    let manifest = ProcessResourceManifest::new()
        .with_file(FILE_RIGHTS)?
        .with_file(OsResourceRights::READ)?;
    ProcessHostFunctions::run_with_resources(
        startup,
        [ECHO.erase()],
        manifest,
        |resources, functions| {
            let ids = resources.ids();
            let [writable_id, read_only_id] = ids.as_slice() else {
                return Err(new_error!("Resource worker requires two files"));
            };
            let writable = resources.take_file(*writable_id, FILE_RIGHTS)?;
            let read_only = resources.take_file(*read_only_id, OsResourceRights::READ)?;
            let files = Arc::new(Mutex::new((writable, read_only)));
            functions.bind(ECHO, move |input: String| -> Result<String> {
                let mut files = files
                    .lock()
                    .map_err(|error| new_error!("Resource file lock failed: {error}"))?;
                let (writable, read_only) = &mut *files;
                writable.seek(SeekFrom::End(0))?;
                writable.write_all(input.as_bytes())?;
                writable.flush()?;
                read_only.seek(SeekFrom::Start(0))?;
                let mut value = String::new();
                read_only.read_to_string(&mut value)?;
                if read_only.write_all(input.as_bytes()).is_ok() {
                    return Err(new_error!("Read-only file unexpectedly allowed a write"));
                }
                Ok(format!(
                    "read/write succeeded; read-only value '{value}'; write denied=true"
                ))
            })
        },
    )
}

fn vm_authority(guest: &Path, non_interactive: bool, details: bool) -> Result<()> {
    heading("VM authority and nested sandbox");
    let backend = match vm_backend() {
        Ok(backend) => backend,
        Err(error) => {
            note("unavailable", error);
            note("authority", "none granted");
            return Ok(());
        }
    };
    let mut provider = match MeshProcessProvider::discover() {
        Ok(provider) => provider,
        Err(error) => {
            note("unavailable", error);
            note("authority", "none granted");
            return Ok(());
        }
    };
    provider.register_vm_authority("vm-authority-worker", backend)?;
    provider.register_file(
        "vm-authority-worker",
        File::open(guest)?,
        OsResourceRights::READ,
    )?;
    let worker = HostFunctionProcess::new(ProcessOptions::for_provider(
        "vm-authority-worker",
        restricted_profile(false, true),
    ))
    .function(ECHO);
    let mut sandbox = match SandboxBuilder::from_file(guest)
        .mesh_process_provider(provider)
        .host_function_process(worker)
        .build()
    {
        Ok(sandbox) => sandbox,
        Err(error) => {
            note("unavailable", error);
            note("authority", "none observed or claimed");
            return Ok(());
        }
    };
    let reports = sandbox.process_reports();
    process_table("Generation-bound worker", &reports, details);
    let expected = "nested Hyperlight sandbox".to_owned();
    let actual = sandbox.call::<String>("RoundTripHostString", expected.clone())?;
    if actual != expected {
        return Err(new_error!("Nested sandbox returned '{actual}'"));
    }
    note("authority", format!("{backend:?}, one worker generation"));
    note("program", actual);
    pause(non_interactive)?;
    sandbox.shutdown()?;
    lifecycle_after(&reports);
    Ok(())
}

fn vm_backend() -> Result<VmBackend> {
    #[cfg(target_os = "windows")]
    {
        Ok(VmBackend::Whp)
    }
    #[cfg(target_os = "linux")]
    {
        if Path::new("/dev/kvm").exists() {
            Ok(VmBackend::Kvm)
        } else if Path::new("/dev/mshv").exists() {
            Ok(VmBackend::Mshv)
        } else {
            Err(new_error!(
                "No /dev/kvm or /dev/mshv authority is available"
            ))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(new_error!(
            "Nested worker VM authority is unavailable on this platform"
        ))
    }
}

fn run_vm_authority_worker(startup: ProcessStartup) -> Result<()> {
    let backend = startup.vm_authority_backend()?;
    let manifest = ProcessResourceManifest::new()
        .with_vm_authority(backend)?
        .with_file(OsResourceRights::READ)?;
    ProcessHostFunctions::run_with_resources(
        startup,
        [ECHO.erase()],
        manifest,
        move |resources, functions| {
            resources
                .take_vm_authority(backend)?
                .install_for_current_generation()?;
            let ids = resources.ids();
            let [guest_id] = ids.as_slice() else {
                return Err(new_error!("VM-authority worker requires one guest file"));
            };
            let mut guest = resources.take_file(*guest_id, OsResourceRights::READ)?;
            let mut bytes = Vec::new();
            guest.read_to_end(&mut bytes)?;
            let nested = Mutex::new(SandboxBuilder::from_bytes(bytes).build()?);
            functions.bind(ECHO, move |input: String| -> Result<String> {
                nested
                    .lock()
                    .map_err(|error| new_error!("Nested sandbox lock failed: {error}"))?
                    .call("Echo", input)
            })
        },
    )
}

fn child_policy(guest: &Path, non_interactive: bool, details: bool) -> Result<()> {
    heading("Worker child-process policy");
    run_child_mode(
        guest,
        "children-allowed",
        ProcessProfile::unrestricted(),
        true,
        non_interactive,
        details,
    )?;
    match run_child_mode(
        guest,
        "children-blocked",
        restricted_profile(false, true),
        false,
        non_interactive,
        details,
    ) {
        Ok(()) => {}
        Err(error) if cfg!(target_os = "macos") => {
            note("expected", "blocked mode rejected before spawn on macOS");
            note("observed", error);
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn run_child_mode(
    guest: &Path,
    name: &str,
    profile: ProcessProfile,
    expected_allowed: bool,
    non_interactive: bool,
    details: bool,
) -> Result<()> {
    step(name);
    let mut sandbox = SandboxBuilder::from_file(guest)
        .mesh_process_provider(MeshProcessProvider::discover()?)
        .host_function_process(
            HostFunctionProcess::new(ProcessOptions::for_provider(name, profile))
                .function(ADD)
                .function(PID),
        )
        .build()?;
    let reports = sandbox.process_reports();
    process_table("Before child attempt", &reports, details);
    let result = sandbox.call::<i32>("Add", (17, 25))?;
    if result != 42 {
        return Err(new_error!(
            "Child-policy worker returned diagnostic {result}"
        ));
    }
    note(
        "observed",
        if expected_allowed {
            "child process started and exited successfully"
        } else {
            "child creation was denied while a Rust thread still completed"
        },
    );
    pause(non_interactive)?;
    sandbox.shutdown()?;
    lifecycle_after(&reports);
    Ok(())
}

fn run_child_policy_worker(startup: ProcessStartup, allow_children: bool) -> Result<()> {
    let mut functions = ProcessHostFunctions::default();
    functions.bind(ADD, move |left, right| {
        let check = move || {
            let result = std::process::Command::new(
                std::env::current_exe().expect("current worker executable is available"),
            )
            .arg("--policy-child")
            .status();
            if allow_children {
                result
                    .ok()
                    .filter(std::process::ExitStatus::success)
                    .map(|_| ())
                    .ok_or(-1)
            } else if child_creation_denied(result) {
                Ok(())
            } else {
                Err(-2)
            }
        };
        if let Err(code) = check() {
            return code;
        }
        if let Err(code) = std::thread::spawn(check)
            .join()
            .expect("confined Rust thread must complete")
        {
            return code;
        }
        left + right
    })?;
    functions.bind(PID, std::process::id)?;
    functions.run(startup)
}

#[cfg(target_os = "linux")]
fn child_creation_denied(result: std::io::Result<std::process::ExitStatus>) -> bool {
    result
        .as_ref()
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(libc::EPERM))
}

#[cfg(target_os = "windows")]
fn child_creation_denied(result: std::io::Result<std::process::ExitStatus>) -> bool {
    const ERROR_CHILD_PROCESS_BLOCKED: i32 = 367;
    const ERROR_NOT_ENOUGH_QUOTA: i32 = 1816;
    result.as_ref().err().is_some_and(|error| {
        matches!(
            error.raw_os_error(),
            Some(ERROR_CHILD_PROCESS_BLOCKED | ERROR_NOT_ENOUGH_QUOTA)
        )
    })
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn child_creation_denied(_: std::io::Result<std::process::ExitStatus>) -> bool {
    false
}

fn timing(guest: &Path, iterations: usize, details: bool) -> Result<()> {
    heading("Basic timing comparison");
    note("scope", "illustrative wall-clock timing, not a benchmark");
    note("calls", iterations);

    let mut local = SandboxBuilder::from_file(guest)
        .host_function("HostAdd", add)
        .build()?;
    local.call::<i32>("Add", (1, 2))?;
    let local_elapsed = time_calls(&mut local, iterations)?;
    local.shutdown()?;

    let mut worker = build_worker(guest, "timing-worker", ProcessProfile::unrestricted(), ADD)?;
    let reports = worker.process_reports();
    if details {
        process_table("Timed worker", &reports, true);
    }
    worker.call::<i32>("Add", (1, 2))?;
    let worker_elapsed = time_calls(&mut worker, iterations)?;
    worker.shutdown()?;
    lifecycle_after(&reports);

    println!();
    println!("{:<18} {:>12} {:>16}", "MODE", "TOTAL", "PER CALL");
    println!("{}", "-".repeat(50));
    timing_row("local", local_elapsed, iterations);
    timing_row("function worker", worker_elapsed, iterations);
    note(
        "caution",
        "startup excluded. Results vary by host, profile, and load",
    );
    Ok(())
}

fn time_calls(sandbox: &mut MultiUseSandbox, iterations: usize) -> Result<Duration> {
    let start = Instant::now();
    for _ in 0..iterations {
        if sandbox.call::<i32>("Add", (20, 22))? != 42 {
            return Err(new_error!("Timed call returned the wrong value"));
        }
    }
    Ok(start.elapsed())
}

fn timing_row(name: &str, elapsed: Duration, iterations: usize) {
    let per_call = average_micros(elapsed, iterations);
    println!(
        "{name:<18} {:>9.3} ms {:>12.1} us",
        elapsed.as_secs_f64() * 1_000.0,
        per_call
    );
}

fn average_micros(elapsed: Duration, iterations: usize) -> f64 {
    elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_names_are_distinct() {
        let names = Placement::ALL.map(Placement::name);
        assert_eq!(
            names,
            [
                "local",
                "function worker",
                "dedicated VM host",
                "VM host and function worker",
            ]
        );
    }

    #[test]
    fn computes_average_call_time() {
        assert_eq!(average_micros(Duration::from_millis(2), 4), 500.0);
    }
}
