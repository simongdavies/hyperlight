// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::fs::OpenOptions;
use std::io::{BufRead, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use hyperlight_host::process::{
    HostFunctionContract, HostFunctionProcess, Idempotency, MeshProcessProvider,
    OsResourceExportPolicy, OsResourceRights, ProcessControl, ProcessHostFunctions, ProcessOptions,
    ProcessProfile, ProcessResourceManifest, ProcessStartup, RequestedControl,
};
use hyperlight_host::{Result, SandboxBuilder, new_error};

const WORKER: &str = "file-resource";
const RIGHTS: OsResourceRights = OsResourceRights::READ.union(OsResourceRights::WRITE);
const ECHO: HostFunctionContract<(String,), String> =
    HostFunctionContract::new("HostEchoString", Idempotency::NonIdempotent);

fn copy_command(command: &str) -> bool {
    if command.len() > 8192 || command.contains('\0') || command.contains('\x1b') {
        return false;
    }
    let provider = [
        "/mnt/c/Windows/System32/clip.exe",
        "/mnt/c/Windows/Sysnative/clip.exe",
    ]
    .into_iter()
    .map(std::path::PathBuf::from)
    .find(|path| path.is_file());
    let Some(provider) = provider else {
        return false;
    };
    for content in ["", command] {
        let Ok(mut child) = Command::new(&provider)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        if child
            .stdin
            .take()
            .is_none_or(|mut input| input.write_all(content.as_bytes()).is_err())
            || !child.wait().is_ok_and(|status| status.success())
        {
            return false;
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn workload_process(root_process: u32) -> Result<u32> {
    let cgroup_membership = std::fs::read_to_string(format!("/proc/{root_process}/cgroup"))?;
    let cgroup = cgroup_membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| new_error!("Typed resource worker cgroup is unavailable"))?;
    let members = std::fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/cgroup.procs"))?;
    members
        .lines()
        .filter_map(|value| value.parse().ok())
        .find(|process| {
            *process != root_process
                && std::fs::read(format!("/proc/{process}/cmdline")).is_ok_and(|command| {
                    !command
                        .windows(b"/minijail0".len())
                        .any(|window| window == b"/minijail0")
                })
        })
        .ok_or_else(|| new_error!("Typed resource workload PID is unavailable"))
}

fn inspection_command(root_process: i32) -> Result<String> {
    let controller = std::process::id();
    #[cfg(target_os = "linux")]
    {
        let root_process = u32::try_from(root_process)
            .map_err(|_| new_error!("Typed resource worker PID is invalid"))?;
        let workload = workload_process(root_process)?;
        let entries =
            format!("controller:{controller} domain-root:{root_process} workload:{workload}");
        Ok(format!(
            "entries='{entries}'; \
         nsid() {{ value=$(readlink \"/proc/$1/ns/$2\"); value=${{value#*[}}; printf '%s' \"${{value%]}}\"; }}; \
         printf '\\nPROCESSES\\n%-16s %-8s %-8s %-6s %s\\n' ROLE PID PPID STATE COMMAND; \
         for item in $entries; do role=${{item%%:*}}; p=${{item##*:}}; printf '%-16s %-8s ' \"$role\" \"$p\"; ps -p \"$p\" -o ppid=,stat=,args=; done; \
         printf '\\nCGROUPS AND EFFECTIVE LIMITS\\n%-16s %-8s %-7s %-12s %-18s %s\\n' ROLE PID MEMBER MEMORY CPU TASKS/POLICY; \
         for item in $entries; do role=${{item%%:*}}; p=${{item##*:}}; pcg=$(cut -d: -f3 \"/proc/$p/cgroup\"); proot=/sys/fs/cgroup$pcg; \
         member=no; grep -qx \"$p\" \"$proot/cgroup.procs\" 2>/dev/null && member=yes; memory=$(cat \"$proot/memory.max\" 2>/dev/null || printf n/a); cpu=$(cat \"$proot/cpu.max\" 2>/dev/null || printf n/a); tasks=$(cat \"$proot/pids.max\" 2>/dev/null || printf n/a); controllers=$(cat \"$proot/cgroup.controllers\" 2>/dev/null | tr ' ' ',' || true); \
         printf '%-16s %-8s %-7s %-12s %-18s tasks=%s controllers=%s\\n' \"$role\" \"$p\" \"$member\" \"$memory\" \"$cpu\" \"$tasks\" \"${{controllers:-none}}\"; printf '  cgroup: %s\\n' \"$pcg\"; done; \
         cpid=$(nsid {controller} pid); cmnt=$(nsid {controller} mnt); cipc=$(nsid {controller} ipc); cnet=$(nsid {controller} net); cuser=$(nsid {controller} user); \
         printf '\\nNAMESPACES\\n%-16s %-8s %-12s %-12s %-12s %-12s %-12s\\n' ROLE PID PID MOUNT IPC NETWORK USER; \
         for item in $entries; do role=${{item%%:*}}; p=${{item##*:}}; pid=$(nsid \"$p\" pid); mnt=$(nsid \"$p\" mnt); ipc=$(nsid \"$p\" ipc); net=$(nsid \"$p\" net); user=$(nsid \"$p\" user); \
         printf '%-16s %-8s %-12s %-12s %-12s %-12s %-12s\\n' \"$role\" \"$p\" \"$pid\" \"$mnt\" \"$ipc\" \"$net\" \"$user\"; \
         if [ \"$p\" = {controller} ]; then printf '  relation: CALLER ENVIRONMENT\\n'; else \
         [ \"$pid\" = \"$cpid\" ] && rpid=SAME || rpid=PRIVATE; [ \"$mnt\" = \"$cmnt\" ] && rmnt=SAME || rmnt=PRIVATE; [ \"$ipc\" = \"$cipc\" ] && ripc=SAME || ripc=PRIVATE; [ \"$net\" = \"$cnet\" ] && rnet=SAME || rnet=PRIVATE; [ \"$user\" = \"$cuser\" ] && ruser=SAME || ruser=PRIVATE; \
         printf '  vs controller: pid=%s mount=%s ipc=%s network=%s user=%s\\n' \"$rpid\" \"$rmnt\" \"$ripc\" \"$rnet\" \"$ruser\"; fi; done"
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(format!(
            "Get-Process -Id {controller},{root_process} | Format-Table Id,ProcessName,Path"
        ))
    }
}

#[cfg(target_os = "linux")]
fn anonymous_file() -> Result<std::fs::File> {
    use std::os::fd::FromRawFd;

    // SAFETY: memfd_create returns a new owned descriptor on success.
    let descriptor =
        unsafe { libc::memfd_create(c"hyperlight-process-resource".as_ptr(), libc::MFD_CLOEXEC) };
    if descriptor == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is the unique owned result of memfd_create.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(not(target_os = "linux"))]
fn anonymous_file() -> Result<std::fs::File> {
    Ok(tempfile::tempfile()?)
}

fn qualification_rights() -> Result<Option<OsResourceRights>> {
    match std::env::var("HYPERLIGHT_TEST_RESOURCE_RIGHTS").as_deref() {
        Ok("read") => Ok(Some(OsResourceRights::READ)),
        Ok("write") => Ok(Some(OsResourceRights::WRITE)),
        Ok("read-write") => Ok(Some(RIGHTS)),
        Err(_) => Ok(None),
        Ok(value) => Err(new_error!("Unknown test resource rights '{value}'")),
    }
}

fn run_qualification_worker(startup: ProcessStartup, rights: OsResourceRights) -> Result<()> {
    let mut manifest = ProcessResourceManifest::new().with_file(rights)?;
    if std::env::var("HYPERLIGHT_TEST_RESOURCE_EXPORTS").as_deref() != Ok("disabled") {
        manifest = manifest
            .with_file_exports(OsResourceExportPolicy::files(OsResourceRights::READ, 1)?)?;
    }
    ProcessHostFunctions::run_with_resources(
        startup,
        [ECHO.erase()],
        manifest,
        move |resources, functions| {
            let ids = resources.ids();
            let [id] = ids.as_slice() else {
                return Err(new_error!(
                    "The file-resource worker requires exactly one resource"
                ));
            };
            let file = Arc::new(Mutex::new(resources.take_file(*id, rights)?));
            let generation = resources
                .generation()
                .ok_or_else(|| new_error!("The file-resource worker has no resource generation"))?;
            let exporter = resources.exporter();
            functions.bind(ECHO, move |input: String| -> Result<String> {
                let mut file = file
                    .lock()
                    .map_err(|error| new_error!("Transferred file lock failed: {error}"))?;
                let mut original = String::new();
                if rights.contains(OsResourceRights::READ) {
                    file.seek(SeekFrom::Start(0))?;
                    file.read_to_string(&mut original)?;
                }
                if rights.contains(OsResourceRights::WRITE) {
                    file.seek(SeekFrom::End(0))?;
                    write!(file, "[generation={generation}]{input}")?;
                    file.flush()?;
                }
                if let Some(exporter) = &exporter {
                    let result = format!("{original}[generation={generation}]{input}");
                    let mut exported = anonymous_file()?;
                    exported.write_all(result.as_bytes())?;
                    exported.seek(SeekFrom::Start(0))?;
                    exporter.export_file(&exported, OsResourceRights::READ)?;
                }
                Ok(original)
            })
        },
    )
}

fn run_scenario_worker(startup: ProcessStartup) -> Result<()> {
    let manifest = ProcessResourceManifest::new()
        .with_file(RIGHTS)?
        .with_file(OsResourceRights::READ)?;
    ProcessHostFunctions::run_with_resources(
        startup,
        [ECHO.erase()],
        manifest,
        move |resources, functions| {
            let ids = resources.ids();
            let [read_write_id, read_only_id] = ids.as_slice() else {
                return Err(new_error!(
                    "The resource-transfer scenario requires exactly two resources"
                ));
            };
            let read_write = resources.take_file(*read_write_id, RIGHTS)?;
            let read_only = resources.take_file(*read_only_id, OsResourceRights::READ)?;
            let files = Arc::new(Mutex::new((read_write, read_only)));
            functions.bind(ECHO, move |input: String| -> Result<String> {
                let mut files = files
                    .lock()
                    .map_err(|error| new_error!("Transferred file lock failed: {error}"))?;
                let (read_write, read_only) = &mut *files;
                read_write.seek(SeekFrom::Start(0))?;
                let mut writable_value = String::new();
                read_write.read_to_string(&mut writable_value)?;
                read_write.seek(SeekFrom::End(0))?;
                write!(read_write, "{input}")?;
                read_write.flush()?;

                read_only.seek(SeekFrom::Start(0))?;
                let mut read_only_value = String::new();
                read_only.read_to_string(&mut read_only_value)?;
                let denial = match read_only.write_all(input.as_bytes()) {
                    Ok(()) => {
                        return Err(new_error!(
                            "Read-only capability unexpectedly permitted a write"
                        ));
                    }
                    Err(denial) => denial,
                };
                #[cfg(unix)]
                let expected_denial = denial.kind() == std::io::ErrorKind::PermissionDenied
                    || denial.raw_os_error() == Some(libc::EBADF);
                #[cfg(not(unix))]
                let expected_denial = denial.kind() == std::io::ErrorKind::PermissionDenied;
                if !expected_denial {
                    return Err(new_error!(
                        "Read-only capability returned an unexpected write error: {denial}"
                    ));
                }
                Ok(format!(
                    "read-write={writable_value};read-only={read_only_value};write-denied=true"
                ))
            })
        },
    )
}

fn run_worker(startup: ProcessStartup) -> Result<()> {
    if startup.name()? != WORKER {
        return Err(new_error!("Unexpected file-resource worker name"));
    }
    match qualification_rights()? {
        Some(rights) => run_qualification_worker(startup, rights),
        None => run_scenario_worker(startup),
    }
}

fn profile() -> ProcessProfile {
    ProcessProfile::new(vec![RequestedControl {
        control: ProcessControl::MemoryLimit(512 << 20),
        required: true,
    }])
}

fn run_controller() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() < 4 {
        return Err(new_error!(
            "Usage: process_file_resource GUEST READ_WRITE_FILE READ_ONLY_FILE INPUT [--noninteractive] [--no-clipboard]"
        ));
    }
    let [guest, read_write_path, read_only_path, input] = &args[..4] else {
        unreachable!()
    };
    let mut noninteractive = false;
    let mut no_clipboard = std::env::var_os("HYPERLIGHT_DEMO_NO_CLIPBOARD").is_some();
    let mut no_color = std::env::var_os("NO_COLOR").is_some();
    for option in &args[4..] {
        match option.to_str() {
            Some("--noninteractive") => noninteractive = true,
            Some("--no-clipboard") => no_clipboard = true,
            Some("--no-color") => no_color = true,
            Some(value) => return Err(new_error!("Unknown resource demo option '{value}'")),
            None => return Err(new_error!("Resource demo options must be valid Unicode")),
        }
    }
    if !noninteractive && !std::io::stdin().is_terminal() {
        return Err(new_error!(
            "Interactive resource demo input is not a terminal. Run with --noninteractive"
        ));
    }
    let input = input
        .to_str()
        .ok_or_else(|| new_error!("Input must be valid UTF-8"))?
        .to_owned();
    let read_write_path = Path::new(read_write_path);
    let read_only_path = Path::new(read_only_path);
    let mut read_write = OpenOptions::new()
        .read(true)
        .write(true)
        .open(read_write_path)?;
    let read_write_verification = read_write.try_clone()?;
    read_write.seek(SeekFrom::Start(0))?;
    let mut writable_original = String::new();
    read_write.read_to_string(&mut writable_original)?;
    let mut read_only = OpenOptions::new().read(true).open(read_only_path)?;
    let mut read_only_verification = read_only.try_clone()?;
    let mut read_only_original = String::new();
    read_only.read_to_string(&mut read_only_original)?;

    let mut provider = MeshProcessProvider::discover().map_err(|error| {
        new_error!(
            "Process provider setup failed: {error}. See dev/process-isolation/QUICKSTART.md"
        )
    })?;
    provider.register_file(WORKER, read_write, RIGHTS)?;
    provider.register_file(WORKER, read_only, OsResourceRights::READ)?;
    let worker =
        HostFunctionProcess::new(ProcessOptions::for_provider(WORKER, profile())).function(ECHO);
    let mut sandbox = SandboxBuilder::from_file(guest)
        .mesh_process_provider(provider.clone())
        .host_function_process(worker)
        .build()?;
    let result = sandbox.call::<String>("RoundTripHostString", input.clone())?;
    let expected_result =
        format!("read-write={writable_original};read-only={read_only_original};write-denied=true");
    if result != expected_result {
        return Err(new_error!(
            "Typed resource transfer returned '{result}', expected '{expected_result}'"
        ));
    }
    let mut read_write_verification = read_write_verification;
    read_write_verification.seek(SeekFrom::Start(0))?;
    let mut writable_actual = String::new();
    read_write_verification.read_to_string(&mut writable_actual)?;
    if writable_actual != format!("{writable_original}{input}") {
        return Err(new_error!(
            "Read/write capability did not update its resource"
        ));
    }
    read_only_verification.seek(SeekFrom::Start(0))?;
    let mut read_only_actual = String::new();
    read_only_verification.read_to_string(&mut read_only_actual)?;
    if read_only_actual != read_only_original {
        return Err(new_error!("Read-only capability changed its resource"));
    }
    let worker = sandbox
        .process_reports()
        .into_iter()
        .find(|report| report.name == WORKER)
        .ok_or_else(|| new_error!("Typed resource worker report is missing"))?;
    if !noninteractive && !no_color && std::io::stdout().is_terminal() {
        print!("\x1b[2J\x1b[H");
        std::io::stdout().flush()?;
    }
    println!("Process topology");
    println!("  Controller PID {}", std::process::id());
    println!("  `- Function worker PID {}", worker.root_process_id);
    println!("     `- HostEchoString uses two opened file capabilities");
    println!();
    println!("Capability results");
    println!("  {:<14} read succeeded; append succeeded", "read/write");
    println!("  {:<14} read succeeded; write denied", "read-only");
    println!();
    println!("Verification");
    println!("  PASS caller observed the requested append in the read/write file");
    println!("  PASS caller observed no change in the read-only file");
    println!("  The worker could use only the rights attached to each opened file.");
    if !noninteractive {
        let command = inspection_command(worker.root_process_id)?;
        if !no_clipboard && copy_command(&command) {
            println!();
            println!(
                "Clipboard cleared and inspection command copied. Paste it into a second WSL terminal."
            );
        } else if !no_clipboard {
            println!();
            println!("Clipboard unavailable. Run in a second WSL terminal: {command}");
        }
        print!("Press Enter to release the file capabilities and stop the worker... ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line)? == 0 {
            return Err(new_error!(
                "Interactive resource demo input closed before Enter"
            ));
        }
        if !no_color && std::io::stdout().is_terminal() {
            print!("\x1b[2J\x1b[H");
            std::io::stdout().flush()?;
        }
    }
    sandbox.shutdown()?;
    drop(sandbox);
    drop(provider);
    println!();
    println!("PASS typed resource delegation");
    Ok(())
}

fn main() -> Result<()> {
    // SAFETY: capture is the first operation, before threads or environment access.
    match unsafe { ProcessStartup::capture() }? {
        Some(startup) => run_worker(startup),
        None => run_controller(),
    }
}
