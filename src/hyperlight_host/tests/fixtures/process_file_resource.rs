// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
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

fn run_worker(startup: ProcessStartup) -> Result<()> {
    if startup.name()? != WORKER {
        return Err(new_error!("Unexpected file-resource worker name"));
    }
    let rights = match std::env::var("HYPERLIGHT_TEST_RESOURCE_RIGHTS").as_deref() {
        Ok("read") => OsResourceRights::READ,
        Ok("write") => OsResourceRights::WRITE,
        Ok("read-write") | Err(_) => RIGHTS,
        Ok(value) => return Err(new_error!("Unknown test resource rights '{value}'")),
    };
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

fn profile() -> ProcessProfile {
    ProcessProfile::new(vec![RequestedControl {
        control: ProcessControl::MemoryLimit(512 << 20),
        required: true,
    }])
}

fn run_controller() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [guest, path, input] = args.as_slice() else {
        return Err(new_error!(
            "Usage: process_file_resource GUEST EXISTING_FILE INPUT"
        ));
    };
    let input = input
        .to_str()
        .ok_or_else(|| new_error!("Input must be valid UTF-8"))?
        .to_owned();
    let path = Path::new(path);
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let verification = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut original = String::new();
    file.read_to_string(&mut original)?;

    let mut provider = MeshProcessProvider::discover().map_err(|error| {
        new_error!(
            "Process provider setup failed: {error}. See dev/process-isolation/QUICKSTART.md"
        )
    })?;
    provider.register_file(WORKER, file, RIGHTS)?;
    provider.allow_file_exports(
        WORKER,
        OsResourceExportPolicy::files(OsResourceRights::READ, 1)?,
    )?;

    std::fs::remove_file(path).map_err(|error| {
        new_error!(
            "The input path must be removable after opening to prove no path reopen: {error}"
        )
    })?;
    let worker =
        HostFunctionProcess::new(ProcessOptions::for_provider(WORKER, profile())).function(ECHO);
    let mut sandbox = SandboxBuilder::from_file(guest)
        .mesh_process_provider(provider.clone())
        .host_function_process(worker)
        .build()?;
    let worker_read = sandbox.call::<String>("RoundTripHostString", input.clone())?;
    if worker_read != original {
        return Err(new_error!(
            "Worker did not read the transferred file object"
        ));
    }

    let mut exported = provider
        .take_exported_file(WORKER)?
        .ok_or_else(|| new_error!("Worker did not export its pathname-free result object"))?;
    let generation = exported.id().generation();
    let expected = format!("{original}[generation={generation}]{input}");
    let mut verification = verification;
    verification.seek(SeekFrom::Start(0))?;
    let mut actual = String::new();
    verification.read_to_string(&mut actual)?;
    if actual != expected {
        return Err(new_error!(
            "Calling host did not observe the worker write through the transferred object"
        ));
    }
    let mut exported_result = String::new();
    exported.seek(SeekFrom::Start(0))?;
    exported.read_to_string(&mut exported_result)?;
    if exported_result != expected {
        return Err(new_error!(
            "Calling host did not receive the exact worker result object"
        ));
    }
    println!("Bidirectional file capability transfer verified after removing the input path");
    Ok(())
}

fn main() -> Result<()> {
    // SAFETY: capture is the first operation, before threads or environment access.
    match unsafe { ProcessStartup::capture() }? {
        Some(startup) => run_worker(startup),
        None => run_controller(),
    }
}
