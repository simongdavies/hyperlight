// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::launch::{PreparedProcess, ProcessGuard};
use super::program::{ProcessDefinition, ProgramRole, ValidatedProgram};
use crate::{Result, new_error};

pub(super) fn validate_profile(profile: &super::ProcessProfile) -> Result<()> {
    profile.validate()?;
    if !profile.is_unrestricted() {
        return Err(new_error!(
            "Restricted process profiles are not implemented on macOS"
        ));
    }
    Ok(())
}

struct UnrestrictedGuard {
    image: Mutex<Option<tempfile::TempDir>>,
}

impl ProcessGuard for UnrestrictedGuard {
    fn start_launch(&self) {}

    fn terminate_domain(&self) -> Result<()> {
        Ok(())
    }

    fn wait_empty(&self, _deadline: Instant) -> Result<()> {
        Ok(())
    }

    fn release_resources(&self, _deadline: Instant) -> Result<()> {
        self.image
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        Ok(())
    }
}

fn stage_program(program: &ValidatedProgram) -> Result<(tempfile::TempDir, std::path::PathBuf)> {
    let image = tempfile::Builder::new()
        .prefix("hyperlight-unrestricted-")
        .tempdir()?;
    let image_root = image.path().canonicalize()?;
    if std::fs::symlink_metadata(image.path())?
        .file_type()
        .is_symlink()
    {
        return Err(new_error!("macOS private process image is a symlink"));
    }
    let executable = image_root.join("program");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&executable)?;
    file.write_all(program.executable())?;
    file.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    drop(file);
    let executable = executable.canonicalize()?;
    if !executable.starts_with(&image_root)
        || std::fs::symlink_metadata(&executable)?
            .file_type()
            .is_symlink()
    {
        return Err(new_error!(
            "macOS staged executable escaped its private image"
        ));
    }
    #[cfg(test)]
    tests::STAGED_PROGRAMS.with(|paths| paths.borrow_mut().push(executable.clone()));
    Ok((image, executable))
}

pub(super) fn prepare(
    role: ProgramRole,
    definition: &ProcessDefinition,
    program: &ValidatedProgram,
) -> Result<PreparedProcess> {
    validate_profile(&definition.profile())?;
    if !program.runtime_files().is_empty() {
        return Err(new_error!(
            "macOS unrestricted process preparation requires a self-contained executable"
        ));
    }
    if program.config().role != role
        || program.config().target.os != "macos"
        || program.config().target.architecture != std::env::consts::ARCH
    {
        return Err(new_error!(
            "macOS program identity, role or target mismatch"
        ));
    }

    let (image, executable) = stage_program(program)?;

    let guard = Arc::new(UnrestrictedGuard {
        image: Mutex::new(Some(image)),
    });
    let config = mesh_process::ProcessConfig::new(definition.name())
        .process_name(executable)
        .skip_worker_arg(true);
    Ok(PreparedProcess {
        config,
        guard,
        controls: Vec::new(),
        windows_policy: None,
        resources: Vec::new(),
        export_authority: None,
        resource_generation: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::program::{
        FunctionContractDefinition, LocalProgramStore, ProgramConfig, ProgramFile, ProgramTarget,
    };
    use crate::process::{
        HostFunctionContract, HostFunctionProcess, Idempotency, MeshProcessProvider,
        OsResourceRights, ProcessControl, ProcessOptions, ProcessProfile, RequestedControl,
    };

    thread_local! {
        pub(super) static STAGED_PROGRAMS: std::cell::RefCell<Vec<std::path::PathBuf>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    const ADD: HostFunctionContract<(i32, i32), i32> =
        HostFunctionContract::new("HostAdd", Idempotency::Idempotent);
    const PID: HostFunctionContract<(), u32> =
        HostFunctionContract::new("ProcessId", Idempotency::Idempotent);
    const PRINT: HostFunctionContract<(String,), i32> =
        HostFunctionContract::new("HostPrint", Idempotency::Idempotent);

    fn fixture(name: &str) -> std::path::PathBuf {
        std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples")
            .join(name)
    }

    fn provider() -> MeshProcessProvider {
        MeshProcessProvider::discover()
            .unwrap()
            .with_program("sandbox", fixture("sandbox_worker"))
            .unwrap()
            .with_program("worker", fixture("process_worker"))
            .unwrap()
    }

    fn options(name: &str) -> ProcessOptions {
        ProcessOptions::for_provider(name, ProcessProfile::unrestricted())
    }

    fn root_image(report: &super::super::ProcessReport) -> std::path::PathBuf {
        let output = std::process::Command::new("/bin/ps")
            .args([
                "-p",
                &report.root_process_id.to_string(),
                "-o",
                "uid=,comm=",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout).unwrap();
        let mut fields = output.split_whitespace();
        let uid: u32 = fields.next().unwrap().parse().unwrap();
        // SAFETY: geteuid has no preconditions and returns this process's effective UID.
        assert_eq!(uid, unsafe { libc::geteuid() });
        let image = std::path::PathBuf::from(fields.next().unwrap());
        assert_eq!(image.file_name().unwrap(), "program");
        assert!(
            image
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("hyperlight-unrestricted-")
        );
        assert_eq!(
            std::fs::metadata(&image).unwrap().permissions().mode() & 0o777,
            0o500
        );
        assert!(report.controls.is_empty());
        assert_ne!(report.root_process_id as u32, std::process::id());
        image
    }

    fn assert_removed(images: &[std::path::PathBuf]) {
        for image in images {
            assert!(!image.parent().unwrap().exists(), "{}", image.display());
        }
    }

    #[test]
    fn native_roles_recover_reconstruct_snapshots_and_clean_independent_roots() {
        use crate::sandbox::snapshot::{OciTag, Snapshot};

        for (vm_host, worker) in [(true, false), (false, true), (true, true)] {
            let directory = tempfile::tempdir().unwrap();
            let provider = provider();
            let mut builder =
                crate::SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
                    .scratch_size(16 << 20)
                    .g2h_queue_size(512)
                    .h2g_queue_size(512)
                    .g2h_pool_pages(512)
                    .h2g_pool_pages(512)
                    .mesh_process_provider(provider.clone());
            if vm_host {
                builder = builder
                    .sandbox_process(options("sandbox"))
                    .sandbox_host_function(PRINT);
            }
            if worker {
                builder = builder.host_function_process(
                    HostFunctionProcess::new(options("worker"))
                        .function(ADD)
                        .function(PID),
                );
            }
            let mut sandbox = builder.build().unwrap();
            assert_eq!(sandbox.call::<i32>("EchoI32", 42).unwrap(), 42);
            let large = "x".repeat(1 << 20);
            assert_eq!(
                sandbox.call::<String>("Echo", large.clone()).unwrap(),
                large
            );
            let reports = sandbox.process_reports();
            assert_eq!(reports.len(), usize::from(vm_host) + usize::from(worker));
            let images: Vec<_> = reports.iter().map(root_image).collect();
            if vm_host {
                assert_eq!(
                    sandbox
                        .call::<i32>("PrintOutput", "pid".to_owned())
                        .unwrap(),
                    reports[0].root_process_id,
                );
            }
            if vm_host && worker {
                assert_ne!(reports[0].root_process_id, reports[1].root_process_id);
            }
            let snapshot = sandbox.snapshot().unwrap();
            let topology = snapshot.process_topology().unwrap().clone();
            let initial = sandbox.call::<i32>("GetStatic", ()).unwrap();
            sandbox.call::<i32>("AddToStatic", 7).unwrap();
            sandbox.restore(snapshot.clone()).unwrap();
            assert_eq!(sandbox.call::<i32>("GetStatic", ()).unwrap(), initial);
            if worker {
                let old_worker = reports
                    .iter()
                    .find(|report| report.role == ProgramRole::FunctionWorker)
                    .unwrap();
                assert!(
                    std::process::Command::new("/bin/kill")
                        .args(["-KILL", &old_worker.root_process_id.to_string()])
                        .status()
                        .unwrap()
                        .success()
                );
                assert_eq!(sandbox.call::<i32>("Add", (17, 25)).unwrap(), 42);
                let current = sandbox.process_reports();
                let replacement = current
                    .iter()
                    .find(|report| report.role == ProgramRole::FunctionWorker)
                    .unwrap();
                assert_ne!(replacement.root_process_id, old_worker.root_process_id);
                root_image(replacement);
                let old_index = reports
                    .iter()
                    .position(|report| report.role == ProgramRole::FunctionWorker)
                    .unwrap();
                assert_removed(&images[old_index..=old_index]);
                if vm_host {
                    assert_eq!(current[0].root_process_id, reports[0].root_process_id);
                }
            }
            let layout = directory.path().join("snapshot");
            snapshot
                .save_with_process_provider(&layout, &OciTag::new("native").unwrap(), &provider)
                .unwrap();
            let snapshot =
                Arc::new(Snapshot::load(&layout, OciTag::new("native").unwrap()).unwrap());
            assert_eq!(snapshot.process_topology(), Some(&topology));
            let builder = crate::SandboxBuilder::from_snapshot(snapshot).mesh_process_provider(
                MeshProcessProvider::discover_for_snapshot(&layout).unwrap(),
            );
            let mut fresh = builder.build().unwrap();
            assert_eq!(fresh.call::<i32>("GetStatic", ()).unwrap(), initial);
            if worker {
                assert_eq!(fresh.call::<i32>("Add", (20, 22)).unwrap(), 42);
            }
            let current_images: Vec<_> = sandbox.process_reports().iter().map(root_image).collect();
            let fresh_images: Vec<_> = fresh.process_reports().iter().map(root_image).collect();
            let start = Instant::now();
            sandbox.shutdown().unwrap();
            assert!(start.elapsed() < std::time::Duration::from_secs(35));
            assert_removed(&current_images);
            assert_eq!(fresh.call::<i32>("EchoI32", 9).unwrap(), 9);
            assert!(fresh_images.iter().all(|image| image.exists()));
            fresh.shutdown().unwrap();
            assert_removed(&fresh_images);
        }
    }

    #[test]
    fn native_file_resources_preserve_read_write_rights() {
        let directory = tempfile::tempdir().unwrap();
        let writable = directory.path().join("writable");
        let readonly = directory.path().join("readonly");
        std::fs::write(&writable, b"writable").unwrap();
        std::fs::write(&readonly, b"readonly").unwrap();
        let mut provider = MeshProcessProvider::discover()
            .unwrap()
            .with_program("file-resource", fixture("process_file_resource"))
            .unwrap();
        provider
            .register_file(
                "file-resource",
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&writable)
                    .unwrap(),
                OsResourceRights::READ | OsResourceRights::WRITE,
            )
            .unwrap();
        provider
            .register_file(
                "file-resource",
                std::fs::File::open(&readonly).unwrap(),
                OsResourceRights::READ,
            )
            .unwrap();
        let echo = HostFunctionContract::<(String,), String>::new(
            "HostEchoString",
            Idempotency::NonIdempotent,
        );
        let mut sandbox =
            crate::SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
                .mesh_process_provider(provider)
                .host_function_process(
                    HostFunctionProcess::new(options("file-resource")).function(echo),
                )
                .build()
                .unwrap();
        let images: Vec<_> = sandbox.process_reports().iter().map(root_image).collect();
        assert_eq!(
            sandbox
                .call::<String>("RoundTripHostString", "appended".to_owned())
                .unwrap(),
            "read-write=writable;read-only=readonly;write-denied=true"
        );
        assert_eq!(std::fs::read(&writable).unwrap(), b"writableappended");
        assert_eq!(std::fs::read(&readonly).unwrap(), b"readonly");
        sandbox.shutdown().unwrap();
        assert_removed(&images);
    }

    #[test]
    fn mixed_restricted_topologies_fail_before_any_staging() {
        for restricted_role in [ProgramRole::SandboxHost, ProgramRole::FunctionWorker] {
            for control in [
                ProcessControl::DenyNetwork,
                ProcessControl::DenyChildProcesses,
                ProcessControl::MemoryLimit(512 << 20),
                ProcessControl::CpuBudget {
                    quota: std::time::Duration::from_millis(10),
                    period: std::time::Duration::from_millis(100),
                },
            ] {
                let profile = |role| {
                    if role == restricted_role {
                        ProcessProfile::new([RequestedControl {
                            control: control.clone(),
                            required: true,
                        }])
                    } else {
                        ProcessProfile::unrestricted()
                    }
                };
                let before = STAGED_PROGRAMS.with(|paths| paths.borrow().len());
                let error = crate::SandboxBuilder::from_bytes([])
                    .mesh_process_provider(provider())
                    .sandbox_process(ProcessOptions::for_provider(
                        "sandbox",
                        profile(ProgramRole::SandboxHost),
                    ))
                    .sandbox_host_function(PRINT)
                    .host_function_process(
                        HostFunctionProcess::new(ProcessOptions::for_provider(
                            "worker",
                            profile(ProgramRole::FunctionWorker),
                        ))
                        .function(ADD)
                        .function(PID),
                    )
                    .build()
                    .unwrap_err();
                assert!(
                    error.to_string().contains("not implemented on macOS"),
                    "{error}"
                );
                assert_eq!(STAGED_PROGRAMS.with(|paths| paths.borrow().len()), before);
            }
        }
    }

    #[test]
    fn failed_native_guest_startup_releases_both_staged_images() {
        let before = STAGED_PROGRAMS.with(|paths| paths.borrow().len());
        let error = crate::SandboxBuilder::from_bytes([0])
            .mesh_process_provider(provider())
            .sandbox_process(options("sandbox"))
            .sandbox_host_function(PRINT)
            .host_function_process(
                HostFunctionProcess::new(options("worker"))
                    .function(ADD)
                    .function(PID),
            )
            .build()
            .unwrap_err();
        assert!(!super::super::launch::has_cleanup_owner(&error), "{error}");
        let images = STAGED_PROGRAMS.with(|paths| paths.borrow()[before..].to_vec());
        assert_eq!(images.len(), 2);
        assert_removed(&images);
    }

    fn validated(role: ProgramRole) -> (tempfile::TempDir, ValidatedProgram, ProcessDefinition) {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(directory.path().join("store"));
        let functions = if role == ProgramRole::FunctionWorker {
            vec![FunctionContractDefinition::from_contract(
                &HostFunctionContract::<(), i32>::new("worker", Idempotency::Idempotent),
            )]
        } else {
            Vec::new()
        };
        let config = ProgramConfig {
            schema_version: 1,
            role,
            target: ProgramTarget::current(Default::default()),
            functions: functions.clone(),
        };
        let artifact = store.package(&config, b"native program").unwrap();
        let definition = ProcessDefinition::new(
            "native",
            artifact.clone(),
            &ProcessProfile::unrestricted(),
            functions,
        )
        .unwrap();
        let program = store.validate(&artifact, &config.target).unwrap();
        (directory, program, definition)
    }

    #[test]
    fn stages_fixed_private_executable_and_cleans_up() {
        let (_directory, program, _definition) = validated(ProgramRole::SandboxHost);
        let (image, executable) = stage_program(&program).unwrap();
        let image_path = image.path().to_owned();

        assert!(executable.is_absolute());
        assert_eq!(
            executable.file_name(),
            Some(std::ffi::OsStr::new("program"))
        );
        assert_eq!(std::fs::read(&executable).unwrap(), b"native program");
        assert_eq!(
            std::fs::metadata(&executable).unwrap().permissions().mode() & 0o777,
            0o500
        );
        drop(image);
        assert!(!image_path.exists());
    }

    #[test]
    fn prepares_both_unrestricted_process_roles() {
        for role in [ProgramRole::SandboxHost, ProgramRole::FunctionWorker] {
            let (_directory, program, definition) = validated(role);
            let prepared = prepare(role, &definition, &program).unwrap();
            assert!(prepared.controls.is_empty());
        }
    }

    #[test]
    fn rejects_restricted_profiles_before_preparation() {
        let (_directory, program, mut definition) = validated(ProgramRole::SandboxHost);
        let artifact = definition.program().clone();
        definition = ProcessDefinition::new(
            "native",
            artifact,
            &ProcessProfile::new([RequestedControl {
                control: ProcessControl::DenyNetwork,
                required: true,
            }]),
            Vec::new(),
        )
        .unwrap();

        let error = prepare(ProgramRole::SandboxHost, &definition, &program)
            .err()
            .expect("Restricted macOS preparation must fail");

        assert!(error.to_string().contains("not implemented on macOS"));
    }

    #[test]
    fn rejects_runtime_file_closures_explicitly() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(directory.path().join("store"));
        let config = ProgramConfig {
            schema_version: 1,
            role: ProgramRole::SandboxHost,
            target: ProgramTarget::current(Default::default()),
            functions: Vec::new(),
        };
        let artifact = store
            .package_with_runtime(
                &config,
                b"native program",
                &[ProgramFile::new("/lib/helper.dylib", b"helper".to_vec()).unwrap()],
            )
            .unwrap();
        let definition = ProcessDefinition::new(
            "native",
            artifact.clone(),
            &ProcessProfile::unrestricted(),
            Vec::new(),
        )
        .unwrap();
        let program = store.validate(&artifact, &config.target).unwrap();

        let error = prepare(ProgramRole::SandboxHost, &definition, &program)
            .err()
            .expect("macOS preparation must reject runtime file closures");

        assert!(error.to_string().contains("self-contained executable"));
    }
}
