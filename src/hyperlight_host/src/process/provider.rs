// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Mesh/PAL process-placement authority.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::launch::{ConfiguredLauncher, ProcessLauncher};
use super::program::{
    FunctionContractDefinition, LocalProgramStore, ProcessTopologyDefinition, ProgramArtifact,
    ProgramConfig, ProgramFile, ProgramRole, ProgramTarget,
};
use crate::{Result, new_error};

pub(super) const MAX_PROGRAM_BYTES: u64 = 256 * 1024 * 1024;

/// Mesh-owned authority for packaging and launching constrained native processes.
///
/// Applications pass this opaque capability to [`crate::SandboxBuilder`].
/// Platform confinement details and host authority do not enter snapshots.
#[derive(Clone)]
pub struct MeshProcessProvider {
    inner: Arc<Provider>,
}

pub(super) struct Provider {
    store: LocalProgramStore,
    target: ProgramTarget,
    current_program: Option<ProgramSource>,
    programs: std::collections::BTreeMap<String, ProgramSource>,
    #[cfg(target_os = "linux")]
    linux: Option<super::LinuxProcessResources>,
    _temporary_store: Option<Arc<tempfile::TempDir>>,
}

struct ProgramSource {
    executable: Vec<u8>,
    _runtime_files: Vec<ProgramFile>,
    _captured_executable: PathBuf,
    #[cfg(target_os = "linux")]
    _capture_root: PathBuf,
    _capture: tempfile::TempDir,
}

#[derive(Debug)]
pub(super) struct CapturedFile {
    pub bytes: Vec<u8>,
    pub permissions: std::fs::Permissions,
}

impl std::fmt::Debug for MeshProcessProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeshProcessProvider")
            .field("target", &self.inner.target)
            .finish_non_exhaustive()
    }
}

impl MeshProcessProvider {
    /// Discovers the current host's Mesh/PAL process-placement capability.
    ///
    /// Linux discovery requires operator-delegated authority. macOS currently
    /// fails closed because no supported dynamic confinement API is available.
    pub fn discover() -> Result<Self> {
        Self::discover_with_store(None)
    }

    /// Reauthorizes a loaded snapshot against the current host.
    ///
    /// `layout` supplies immutable program artifacts only. Host authority is
    /// discovered again and is never taken from the snapshot.
    pub fn discover_for_snapshot(layout: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::discover_with_store(Some(LocalProgramStore::new(layout.as_ref())))
    }

    fn discover_with_store(store: Option<LocalProgramStore>) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let _ = store;
            return super::macos::unsupported_provider();
        }

        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            let snapshot_store = store.is_some();
            let (store, temporary_store) = match store {
                Some(store) => (store, None),
                None => {
                    let directory = Arc::new(
                        tempfile::Builder::new()
                            .prefix("hyperlight-mesh-programs-")
                            .tempdir()?,
                    );
                    (LocalProgramStore::new(directory.path()), Some(directory))
                }
            };
            let current_program = (!snapshot_store)
                .then(|| {
                    let executable = std::env::current_exe().map_err(|error| {
                        new_error!("Mesh provider cannot locate this executable: {error}")
                    })?;
                    program_source(&executable)
                })
                .transpose()?;
            #[cfg(target_os = "linux")]
            let linux = super::linux::discover_provider()?;
            Ok(Self {
                inner: Arc::new(Provider {
                    store,
                    target: ProgramTarget::current(Default::default()),
                    current_program,
                    programs: Default::default(),
                    #[cfg(target_os = "linux")]
                    linux: Some(linux),
                    _temporary_store: temporary_store,
                }),
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            let _ = store;
            Err(new_error!(
                "Mesh process placement is unavailable on this host"
            ))
        }
    }

    /// Builds a provider from explicit local resources for qualification or embedders.
    pub fn from_local_programs(store: LocalProgramStore, target: ProgramTarget) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let _ = (store, target);
            super::macos::unsupported_provider()
        }
        #[cfg(not(target_os = "macos"))]
        {
            if target != ProgramTarget::current(target.os_dependencies.clone()) {
                return Err(new_error!(
                    "Program execution target must match the current host"
                ));
            }
            Ok(Self {
                inner: Arc::new(Provider {
                    store,
                    target,
                    current_program: None,
                    programs: Default::default(),
                    #[cfg(target_os = "linux")]
                    linux: None,
                    _temporary_store: None,
                }),
            })
        }
    }

    /// Adds explicit Linux launch authority for qualification or custom embedders.
    #[cfg(target_os = "linux")]
    pub fn with_linux_resources(mut self, resources: super::LinuxProcessResources) -> Result<Self> {
        Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Configure Linux resources before cloning the provider"))?
            .linux = Some(resources);
        Ok(self)
    }

    /// Registers a dedicated executable while the provider owns its packaging.
    ///
    /// The logical name must match the corresponding [`super::ProcessOptions`].
    pub fn with_program(
        mut self,
        name: impl Into<String>,
        executable: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        if self.inner._temporary_store.is_none() {
            return Err(new_error!(
                "A snapshot provider cannot package new native programs"
            ));
        }
        let name = name.into();
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(new_error!(
                "Provider program name must be nonempty and contain no control characters"
            ));
        }
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Register provider programs before cloning the provider"))?;
        if provider.programs.contains_key(&name) {
            return Err(new_error!("Duplicate provider program '{name}'"));
        }
        let source = program_source(executable.as_ref())?;
        provider.programs.insert(name, source);
        Ok(self)
    }

    /// Adds one verified runtime file to the default application executable.
    ///
    /// Use this for application-local files that automatic platform discovery
    /// cannot identify. The image path is relative to the staged program root.
    #[cfg(target_os = "windows")]
    pub fn with_runtime_file(
        mut self,
        image_path: impl AsRef<std::path::Path>,
        source: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        let files = runtime_files(image_path.as_ref(), source.as_ref())?;
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Register provider runtime files before cloning it"))?;
        let program = provider.current_program.as_mut().ok_or_else(|| {
            new_error!("This provider cannot add files to the application program")
        })?;
        for file in files {
            add_runtime_file(program, file)?;
        }
        Ok(self)
    }

    /// Adds one verified runtime file to a named dedicated executable.
    #[cfg(target_os = "windows")]
    pub fn with_program_runtime_file(
        mut self,
        name: &str,
        image_path: impl AsRef<std::path::Path>,
        source: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        let files = runtime_files(image_path.as_ref(), source.as_ref())?;
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Register provider runtime files before cloning it"))?;
        let program = provider
            .programs
            .get_mut(name)
            .ok_or_else(|| new_error!("Unknown provider program '{name}'"))?;
        for file in files {
            add_runtime_file(program, file)?;
        }
        Ok(self)
    }

    pub(crate) fn resolve_program(
        &self,
        name: &str,
        role: ProgramRole,
        functions: &[FunctionContractDefinition],
        artifact: Option<&ProgramArtifact>,
    ) -> Result<ProgramArtifact> {
        if let Some(artifact) = artifact {
            self.inner.store.validate(artifact, &self.inner.target)?;
            return Ok(artifact.clone());
        }
        let source = self
            .inner
            .programs
            .get(name)
            .or(self.inner.current_program.as_ref())
            .ok_or_else(|| {
                new_error!("This MeshProcessProvider requires an explicit program artifact")
            })?;
        #[cfg(target_os = "linux")]
        let runtime_files =
            super::linux::runtime_closure_in(&source._captured_executable, &source._capture_root)
                .map_err(|error| {
                new_error!("Mesh provider cannot package native program '{name}': {error}")
            })?;
        #[cfg(target_os = "windows")]
        let runtime_files =
            super::windows::runtime_closure(&source.executable, &source._runtime_files).map_err(
                |error| new_error!("Mesh provider cannot package native program '{name}': {error}"),
            )?;
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let runtime_files = source._runtime_files.clone();
        self.inner.store.package_with_runtime(
            &ProgramConfig {
                schema_version: 1,
                role,
                target: self.inner.target.clone(),
                functions: functions.to_vec(),
            },
            &source.executable,
            &runtime_files,
        )
    }

    pub(crate) fn launcher(
        &self,
        definition: &ProcessTopologyDefinition,
    ) -> Result<Arc<dyn ProcessLauncher>> {
        definition.validate_programs(&self.inner.store, &self.inner.target)?;
        Ok(Arc::new(ConfiguredLauncher {
            store: self.inner.store.clone(),
            target: self.inner.target.clone(),
            #[cfg(target_os = "windows")]
            windows: super::windows::WindowsPrincipals::new(definition)?,
            #[cfg(target_os = "linux")]
            linux: self.inner.linux.clone(),
            _provider: self.inner.clone(),
        }))
    }

    pub(crate) fn export_programs(
        &self,
        topology: &ProcessTopologyDefinition,
        destination: &LocalProgramStore,
    ) -> Result<()> {
        self.inner.store.export(&topology.programs(), destination)
    }
}

fn program_source(executable: &std::path::Path) -> Result<ProgramSource> {
    program_source_with(executable, |_| {})
}

fn program_source_with(
    executable: &Path,
    capture_hook: impl FnMut(CaptureStage),
) -> Result<ProgramSource> {
    let source = std::fs::canonicalize(executable).map_err(|error| {
        new_error!(
            "Mesh provider cannot resolve native program '{}': {error}",
            executable.display()
        )
    })?;
    let captured = capture_file_with(&source, capture_hook).map_err(|error| {
        new_error!(
            "Mesh provider cannot read native program '{}': {error}",
            source.display()
        )
    })?;
    let capture = tempfile::Builder::new()
        .prefix("hyperlight-program-capture-")
        .tempdir()?;
    #[cfg(target_os = "linux")]
    let capture_root = capture.path().join("root");
    #[cfg(target_os = "linux")]
    let captured_executable = {
        let relative = source
            .strip_prefix(Path::new("/"))
            .map_err(|_| new_error!("Native Linux program path must be absolute"))?;
        capture_root.join(relative)
    };
    #[cfg(not(target_os = "linux"))]
    let captured_executable = capture.path().join(
        source
            .file_name()
            .ok_or_else(|| new_error!("Native program path has no file name"))?,
    );
    #[cfg(target_os = "linux")]
    let capture_boundary = &capture_root;
    #[cfg(not(target_os = "linux"))]
    let capture_boundary = capture.path();
    if !captured_executable.starts_with(capture_boundary) {
        return Err(new_error!(
            "Captured native program path escaped provider-owned storage"
        ));
    }
    std::fs::create_dir_all(
        captured_executable
            .parent()
            .ok_or_else(|| new_error!("Captured native program has no parent directory"))?,
    )?;
    std::fs::write(&captured_executable, &captured.bytes)?;
    std::fs::set_permissions(&captured_executable, captured.permissions)?;
    #[cfg(target_os = "linux")]
    super::linux::capture_origin_dependencies(
        &captured.bytes,
        source.parent(),
        captured_executable
            .parent()
            .ok_or_else(|| new_error!("Captured native program has no parent directory"))?,
        &capture_root,
    )?;
    #[cfg(target_os = "linux")]
    let runtime_files = Vec::new();
    #[cfg(target_os = "windows")]
    let runtime_files =
        super::windows::capture_adjacent_dependencies(&captured.bytes, source.parent())?;
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let runtime_files = Vec::new();
    Ok(ProgramSource {
        executable: captured.bytes,
        _runtime_files: runtime_files,
        _captured_executable: captured_executable,
        #[cfg(target_os = "linux")]
        _capture_root: capture_root,
        _capture: capture,
    })
}

#[cfg(target_os = "windows")]
fn runtime_files(image_path: &Path, source: &Path) -> Result<Vec<ProgramFile>> {
    if image_path.is_absolute()
        || image_path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(new_error!(
            "Provider runtime image path must be relative and remain below the program root"
        ));
    }
    let image_path = format!("/{}", image_path.to_string_lossy().replace('\\', "/"));
    let captured = capture_file(source).map_err(|error| {
        new_error!(
            "Mesh provider cannot read runtime file '{}': {error}",
            source.display()
        )
    })?;
    Ok(vec![ProgramFile::new(image_path, captured.bytes)?])
}

pub(super) fn capture_file(path: &Path) -> Result<CapturedFile> {
    capture_file_with(path, |_| {})
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureStage {
    Opened,
    Read,
}

fn capture_file_with(path: &Path, capture_hook: impl FnMut(CaptureStage)) -> Result<CapturedFile> {
    capture_file_with_limit(path, MAX_PROGRAM_BYTES, capture_hook)
}

fn capture_file_with_limit(
    path: &Path,
    limit: u64,
    mut capture_hook: impl FnMut(CaptureStage),
) -> Result<CapturedFile> {
    let file = File::open(path)?;
    let permissions = file.metadata()?.permissions();
    capture_hook(CaptureStage::Opened);
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    capture_hook(CaptureStage::Read);
    if bytes.len() as u64 > limit {
        return Err(new_error!(
            "Native program file '{}' exceeds the 256 MiB limit",
            path.display()
        ));
    }
    Ok(CapturedFile { bytes, permissions })
}

#[cfg(target_os = "windows")]
fn add_runtime_file(program: &mut ProgramSource, file: ProgramFile) -> Result<()> {
    if program._runtime_files.len() >= 128 {
        return Err(new_error!(
            "Windows native program dependency closure exceeds 128 DLLs"
        ));
    }
    if program._runtime_files.iter().any(|existing| {
        existing
            .image_path()
            .eq_ignore_ascii_case(file.image_path())
    }) {
        return Err(new_error!(
            "Duplicate provider runtime image path '{}'",
            file.image_path()
        ));
    }
    program
        ._runtime_files
        .iter()
        .try_fold(program.executable.len(), |total, existing| {
            total.checked_add(existing.bytes().len())
        })
        .and_then(|total| total.checked_add(file.bytes().len()))
        .filter(|total| *total as u64 <= MAX_PROGRAM_BYTES)
        .ok_or_else(|| new_error!("Native program and runtime files exceed the 256 MiB limit"))?;
    program._runtime_files.push(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(packaging: bool) -> MeshProcessProvider {
        let directory = Arc::new(tempfile::tempdir().unwrap());
        MeshProcessProvider {
            inner: Arc::new(Provider {
                store: LocalProgramStore::new(directory.path()),
                target: ProgramTarget::current(Default::default()),
                current_program: None,
                programs: Default::default(),
                #[cfg(target_os = "linux")]
                linux: None,
                _temporary_store: packaging.then_some(directory),
            }),
        }
    }

    #[cfg(target_os = "windows")]
    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    #[cfg(target_os = "windows")]
    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[cfg(target_os = "windows")]
    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[cfg(target_os = "windows")]
    fn pe_fixture(imports: &[String], is_dll: bool) -> Vec<u8> {
        const PE: usize = 0x80;
        const OPTIONAL: usize = PE + 24;
        const SECTION: usize = OPTIONAL + 0xf0;
        const RAW: usize = 0x200;
        const RVA: u32 = 0x1000;
        let descriptors = (imports.len() + 1) * 20;
        let iat = descriptors.next_multiple_of(8);
        let names = iat + 8;
        let data_size = names + imports.iter().map(|name| name.len() + 1).sum::<usize>();
        let raw_size = data_size.next_multiple_of(0x200);
        let mut bytes = vec![0_u8; RAW + raw_size];
        bytes[..2].copy_from_slice(b"MZ");
        write_u32(&mut bytes, 0x3c, PE as u32);
        bytes[PE..PE + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut bytes, PE + 4, 0x8664);
        write_u16(&mut bytes, PE + 6, 1);
        write_u16(&mut bytes, PE + 20, 0xf0);
        write_u16(&mut bytes, PE + 22, if is_dll { 0x2022 } else { 0x0022 });
        write_u16(&mut bytes, OPTIONAL, 0x20b);
        write_u32(&mut bytes, OPTIONAL + 20, RVA);
        write_u64(&mut bytes, OPTIONAL + 24, 0x140000000);
        write_u32(&mut bytes, OPTIONAL + 32, 0x1000);
        write_u32(&mut bytes, OPTIONAL + 36, 0x200);
        write_u16(&mut bytes, OPTIONAL + 40, 6);
        write_u16(&mut bytes, OPTIONAL + 48, 6);
        write_u32(&mut bytes, OPTIONAL + 56, 0x2000);
        write_u32(&mut bytes, OPTIONAL + 60, RAW as u32);
        write_u16(&mut bytes, OPTIONAL + 68, 3);
        write_u32(&mut bytes, OPTIONAL + 108, 16);
        write_u32(&mut bytes, OPTIONAL + 120, RVA);
        write_u32(&mut bytes, OPTIONAL + 124, descriptors as u32);
        bytes[SECTION..SECTION + 6].copy_from_slice(b".rdata");
        write_u32(&mut bytes, SECTION + 8, data_size as u32);
        write_u32(&mut bytes, SECTION + 12, RVA);
        write_u32(&mut bytes, SECTION + 16, raw_size as u32);
        write_u32(&mut bytes, SECTION + 20, RAW as u32);
        write_u32(&mut bytes, SECTION + 36, 0x40000040);
        let mut name_offset = names;
        for (index, name) in imports.iter().enumerate() {
            let descriptor = RAW + index * 20;
            write_u32(&mut bytes, descriptor, RVA + iat as u32);
            write_u32(&mut bytes, descriptor + 12, RVA + name_offset as u32);
            write_u32(&mut bytes, descriptor + 16, RVA + iat as u32);
            bytes[RAW + name_offset..RAW + name_offset + name.len()]
                .copy_from_slice(name.as_bytes());
            name_offset += name.len() + 1;
        }
        bytes
    }

    #[cfg(target_os = "windows")]
    fn exe_fixture(imports: &[String]) -> Vec<u8> {
        pe_fixture(imports, false)
    }

    #[cfg(target_os = "windows")]
    fn dll_fixture(imports: &[String]) -> Vec<u8> {
        pe_fixture(imports, true)
    }

    #[cfg(target_os = "windows")]
    fn packaged_program(
        provider: &MeshProcessProvider,
        name: &str,
    ) -> Result<super::super::program::ValidatedProgram> {
        use super::super::{
            HostFunctionContract, HostFunctionProcess, Idempotency, ProcessControl, ProcessOptions,
            ProcessProfile, RequestedControl,
        };
        let contract = HostFunctionContract::<(), i32>::new("Fixture", Idempotency::Idempotent);
        let topology = crate::SandboxBuilder::from_bytes([])
            .mesh_process_provider(provider.clone())
            .host_function_process(
                HostFunctionProcess::new(ProcessOptions::for_provider(
                    name,
                    ProcessProfile::new([RequestedControl {
                        control: ProcessControl::DenyNetwork,
                        required: true,
                    }]),
                ))
                .function(contract),
            )
            .process_topology()?
            .unwrap();
        provider
            .inner
            .store
            .validate(topology.workers()[0].program(), &provider.inner.target)
    }

    #[test]
    fn duplicate_named_program_is_rejected() {
        let executable = std::env::current_exe().unwrap();
        let provider = provider(true).with_program("worker", &executable).unwrap();
        let error = provider.with_program("worker", executable).unwrap_err();
        assert!(error.to_string().contains("Duplicate provider program"));
    }

    #[test]
    fn snapshot_provider_cannot_package_programs() {
        let error = provider(false)
            .with_program("worker", std::env::current_exe().unwrap())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot package new native programs")
        );
    }

    #[test]
    fn program_bytes_are_captured_before_source_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory
            .path()
            .join(std::env::current_exe().unwrap().file_name().unwrap());
        let original = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        std::fs::write(&source, &original).unwrap();
        let mut permissions = std::fs::metadata(&source).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&source, permissions).unwrap();
        let replacement = b"replacement".to_vec();
        let captured = program_source_with(&source, |stage| {
            if stage == CaptureStage::Opened {
                let opened = directory.path().join("opened");
                std::fs::rename(&source, opened).unwrap();
                std::fs::write(&source, &replacement).unwrap();
            }
        })
        .unwrap();
        assert_eq!(captured.executable, original);
        assert!(
            std::fs::metadata(&captured._captured_executable)
                .unwrap()
                .permissions()
                .readonly()
        );
        assert_eq!(std::fs::read(source).unwrap(), replacement);
    }

    #[test]
    fn program_capture_survives_source_removal_after_read() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory
            .path()
            .join(std::env::current_exe().unwrap().file_name().unwrap());
        let original = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        std::fs::write(&source, &original).unwrap();
        let captured = program_source_with(&source, |stage| {
            if stage == CaptureStage::Read {
                std::fs::remove_file(&source).unwrap();
            }
        })
        .unwrap();
        assert_eq!(captured.executable, original);
        assert!(!source.exists());
    }

    #[test]
    fn bounded_capture_rejects_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("oversized");
        std::fs::write(&source, [0_u8; 17]).unwrap();
        let error = capture_file_with_limit(&source, 16, |_| {}).unwrap_err();
        assert!(error.to_string().contains("exceeds the 256 MiB limit"));
    }

    #[cfg(target_os = "linux")]
    fn relative_from_current(path: &Path) -> PathBuf {
        let current = std::env::current_dir().unwrap();
        let from = current.components().collect::<Vec<_>>();
        let to = path.components().collect::<Vec<_>>();
        let common = from
            .iter()
            .zip(&to)
            .take_while(|(left, right)| left == right)
            .count();
        std::iter::repeat_n(
            std::path::Component::ParentDir.as_os_str(),
            from.len() - common,
        )
        .chain(to[common..].iter().map(|component| component.as_os_str()))
        .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cloned_provider_rejects_linux_resource_configuration() {
        use sha2::{Digest, Sha256};

        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("minijail");
        std::fs::write(&helper, b"helper").unwrap();
        let resources = super::super::LinuxProcessResources::new(
            directory.path(),
            &helper,
            Sha256::digest(b"helper").into(),
        )
        .unwrap();
        let provider = provider(false);
        let _clone = provider.clone();
        let error = provider.with_linux_resources(resources).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Configure Linux resources before cloning")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn program_source_preserves_origin_dependency_context() {
        let directory = tempfile::tempdir().unwrap();
        let library_source = directory.path().join("helper.c");
        let program_source_path = directory.path().join("program.c");
        let library = directory.path().join("libprovider_origin.so");
        let program = directory.path().join("origin-program");
        std::fs::write(
            &library_source,
            "int provider_origin(void) { return 42; }\n",
        )
        .unwrap();
        std::fs::write(
            &program_source_path,
            "extern int provider_origin(void); int main(void) { return provider_origin() != 42; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libprovider_origin.so"])
                .arg(&library_source)
                .arg("-o")
                .arg(&library)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("cc")
                .arg(&program_source_path)
                .arg("-L")
                .arg(directory.path())
                .arg("-lprovider_origin")
                .arg("-Wl,-rpath,$ORIGIN")
                .arg("-o")
                .arg(&program)
                .status()
                .unwrap()
                .success()
        );
        let expected = std::fs::read(&library).unwrap();
        let relative_program = relative_from_current(&program);
        assert!(
            relative_program
                .components()
                .any(|component| { component == std::path::Component::ParentDir })
        );
        let source = program_source(&relative_program).unwrap();
        assert!(
            source
                ._captured_executable
                .starts_with(&source._capture_root)
        );
        std::fs::remove_file(program).unwrap();
        std::fs::remove_file(library).unwrap();
        assert!(
            std::process::Command::new(&source._captured_executable)
                .status()
                .unwrap()
                .success()
        );
        let files = super::super::linux::runtime_closure_in(
            &source._captured_executable,
            &source._capture_root,
        )
        .unwrap();
        assert_eq!(
            files
                .iter()
                .find(|file| file.image_path() == "/libprovider_origin.so")
                .unwrap()
                .bytes(),
            expected
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn program_source_preserves_origin_lists_and_inherited_rpath() {
        let directory = tempfile::tempdir().unwrap();
        let libraries = directory.path().join("lib");
        std::fs::create_dir(&libraries).unwrap();
        let leaf_source = directory.path().join("leaf.c");
        let helper_source = directory.path().join("helper.c");
        let program_source_path = directory.path().join("program.c");
        let leaf = libraries.join("libprovider_leaf.so");
        let helper = libraries.join("libprovider_helper.so");
        let program = directory.path().join("origin-program");
        std::fs::write(&leaf_source, "int provider_leaf(void) { return 42; }\n").unwrap();
        std::fs::write(
            &helper_source,
            "extern int provider_leaf(void); int provider_helper(void) { return provider_leaf(); }\n",
        )
        .unwrap();
        std::fs::write(
            &program_source_path,
            "extern int provider_helper(void); int main(void) { return provider_helper() != 42; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libprovider_leaf.so"])
                .arg(&leaf_source)
                .arg("-o")
                .arg(&leaf)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libprovider_helper.so"])
                .arg(&helper_source)
                .arg("-L")
                .arg(&libraries)
                .arg("-lprovider_leaf")
                .arg("-o")
                .arg(&helper)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("cc")
                .arg(&program_source_path)
                .arg("-L")
                .arg(&libraries)
                .arg("-lprovider_helper")
                .arg("-Wl,--disable-new-dtags,-rpath,$ORIGIN/missing:$ORIGIN/lib")
                .arg("-Wl,-rpath-link")
                .arg(&libraries)
                .arg("-o")
                .arg(&program)
                .status()
                .unwrap()
                .success()
        );
        let expected_helper = std::fs::read(&helper).unwrap();
        let expected_leaf = std::fs::read(&leaf).unwrap();
        let relative_program = relative_from_current(&program);
        let source = program_source(&relative_program).unwrap();
        assert!(
            source
                ._captured_executable
                .starts_with(&source._capture_root)
        );
        std::fs::remove_file(program).unwrap();
        std::fs::remove_file(helper).unwrap();
        std::fs::remove_file(leaf).unwrap();
        assert!(
            std::process::Command::new(&source._captured_executable)
                .status()
                .unwrap()
                .success()
        );
        let files = super::super::linux::runtime_closure_in(
            &source._captured_executable,
            &source._capture_root,
        )
        .unwrap();
        let files = files
            .iter()
            .map(|file| (file.image_path(), file.bytes()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(files["/lib/libprovider_helper.so"], expected_helper);
        assert_eq!(files["/lib/libprovider_leaf.so"], expected_leaf);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn program_source_preserves_parent_origin_layout() {
        let directory = tempfile::tempdir().unwrap();
        let bin = directory.path().join("bin");
        let lib = directory.path().join("lib");
        std::fs::create_dir(&bin).unwrap();
        std::fs::create_dir(&lib).unwrap();
        let library_source = directory.path().join("helper.c");
        let program_source_path = directory.path().join("program.c");
        let library = lib.join("libprovider_parent.so");
        let program = bin.join("origin-program");
        std::fs::write(
            &library_source,
            "int provider_parent(void) { return 42; }\n",
        )
        .unwrap();
        std::fs::write(
            &program_source_path,
            "extern int provider_parent(void); int main(void) { return provider_parent() != 42; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libprovider_parent.so"])
                .arg(&library_source)
                .arg("-o")
                .arg(&library)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("cc")
                .arg(&program_source_path)
                .arg("-L")
                .arg(&lib)
                .arg("-lprovider_parent")
                .arg("-Wl,-rpath,$ORIGIN/../lib")
                .arg("-o")
                .arg(&program)
                .status()
                .unwrap()
                .success()
        );
        let expected = std::fs::read(&library).unwrap();
        let relative_program = relative_from_current(&program);
        assert!(
            relative_program
                .components()
                .filter(|component| *component == std::path::Component::ParentDir)
                .count()
                >= 2
        );
        let source = program_source(&relative_program).unwrap();
        assert!(
            source
                ._captured_executable
                .starts_with(&source._capture_root)
        );
        std::fs::remove_dir_all(directory.path()).unwrap();
        assert!(
            std::process::Command::new(&source._captured_executable)
                .status()
                .unwrap()
                .success()
        );
        let files = super::super::linux::runtime_closure_in(
            &source._captured_executable,
            &source._capture_root,
        )
        .unwrap();
        assert_eq!(
            files
                .iter()
                .find(|file| file.image_path() == "/lib/libprovider_parent.so")
                .unwrap()
                .bytes(),
            expected
        );
        let captured_executable = source._captured_executable.clone();
        let capture_root = source._capture_root.clone();
        drop(source);
        assert!(!captured_executable.exists());
        assert!(!capture_root.exists());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn explicit_runtime_file_uses_relative_image_path() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("helper.dll");
        std::fs::write(&runtime, b"dll").unwrap();
        let provider = provider(true);
        let source = program_source(&std::env::current_exe().unwrap()).unwrap();
        let provider = MeshProcessProvider {
            inner: Arc::new(Provider {
                current_program: Some(source),
                ..Arc::try_unwrap(provider.inner).ok().unwrap()
            }),
        }
        .with_runtime_file("bin/helper.dll", &runtime)
        .unwrap();
        let file = &provider
            .inner
            .current_program
            .as_ref()
            .unwrap()
            ._runtime_files[0];
        assert_eq!(file.image_path(), "/bin/helper.dll");
        assert_eq!(file.bytes(), b"dll");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_packages_adjacent_dll() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.dll");
        let program_bytes = exe_fixture(&["helper.dll".to_owned()]);
        let helper_bytes = dll_fixture(&[]);
        std::fs::write(&program, program_bytes).unwrap();
        std::fs::write(&helper, &helper_bytes).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.runtime_files().len(), 1);
        assert_eq!(packaged.runtime_files()[0].image_path(), "/helper.dll");
        assert_eq!(packaged.runtime_files()[0].bytes(), helper_bytes);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_uses_captured_program_after_source_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let original = exe_fixture(&[]);
        std::fs::write(&program, &original).unwrap();
        let provider = provider(true).with_program("worker", &program).unwrap();
        std::fs::write(&program, b"replacement").unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.executable(), original);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_uses_captured_dll_after_source_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.dll");
        let original = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, &original).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        std::fs::write(&helper, b"replacement").unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.runtime_files()[0].bytes(), original);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_packages_transitive_adjacent_dlls() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.dll");
        let leaf = directory.path().join("leaf.dll");
        let helper_bytes = dll_fixture(&["leaf.dll".to_owned()]);
        let leaf_bytes = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, &helper_bytes).unwrap();
        std::fs::write(&leaf, &leaf_bytes).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        let files = packaged
            .runtime_files()
            .iter()
            .map(|file| (file.image_path(), file.bytes()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(files["/helper.dll"], helper_bytes);
        assert_eq!(files["/leaf.dll"], leaf_bytes);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_prefers_private_dll_over_system32_fallback() {
        let system32 =
            std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
        let known = super::super::windows::known_dlls().unwrap();
        let collision = std::fs::read_dir(system32)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .find(|name| {
                name.to_ascii_lowercase().ends_with(".dll")
                    && !known.contains(&name.to_ascii_lowercase())
            })
            .expect("System32 must contain a non-KnownDLL fallback");
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let private = directory.path().join(&collision);
        let leaf = directory.path().join("leaf.dll");
        let private_bytes = dll_fixture(&["leaf.dll".to_owned()]);
        let leaf_bytes = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(std::slice::from_ref(&collision))).unwrap();
        std::fs::write(&private, &private_bytes).unwrap();
        std::fs::write(&leaf, &leaf_bytes).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        let files = packaged
            .runtime_files()
            .iter()
            .map(|file| (file.image_path().to_ascii_lowercase(), file.bytes()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            files[&format!("/{}", collision.to_ascii_lowercase())],
            private_bytes
        );
        assert_eq!(files["/leaf.dll"], leaf_bytes);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_missing_dll_during_placement() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        std::fs::write(&program, exe_fixture(&["missing.dll".to_owned()])).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        let error = packaged_program(&provider, "worker").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("missing.dll"));
        assert!(message.contains("with_program_runtime_file"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_repairs_missing_dll_with_explicit_declaration() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("declared-helper.bin");
        let helper_bytes = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, &helper_bytes).unwrap();
        let provider = provider(true)
            .with_program("worker", program)
            .unwrap()
            .with_program_runtime_file("worker", "helper.dll", helper)
            .unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.runtime_files()[0].image_path(), "/helper.dll");
        assert_eq!(packaged.runtime_files()[0].bytes(), helper_bytes);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_validates_transitive_explicit_dlls() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.bin");
        let leaf = directory.path().join("leaf.bin");
        let helper_bytes = dll_fixture(&["leaf.dll".to_owned()]);
        let leaf_bytes = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, &helper_bytes).unwrap();
        std::fs::write(&leaf, &leaf_bytes).unwrap();
        let provider = provider(true)
            .with_program("worker", program)
            .unwrap()
            .with_program_runtime_file("worker", "helper.dll", helper)
            .unwrap()
            .with_program_runtime_file("worker", "leaf.dll", leaf)
            .unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.runtime_files().len(), 2);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_excessive_import_count() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let imports = (0..129)
            .map(|index| format!("x{index:03}.dll"))
            .collect::<Vec<_>>();
        std::fs::write(&program, exe_fixture(&imports)).unwrap();
        let error = provider(true).with_program("worker", program).unwrap_err();
        assert!(error.to_string().contains("exceeds 128 DLLs"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_dll_as_program() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        std::fs::write(&program, dll_fixture(&[])).unwrap();
        let error = provider(true).with_program("worker", program).unwrap_err();
        assert!(error.to_string().contains("marked as a DLL"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_executable_as_runtime_dll() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.dll");
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, exe_fixture(&[])).unwrap();
        let error = provider(true).with_program("worker", program).unwrap_err();
        assert!(error.to_string().contains("not marked as a DLL"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_excessive_explicit_runtime_files() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let runtime = directory.path().join("runtime.dll");
        std::fs::write(&program, exe_fixture(&[])).unwrap();
        std::fs::write(&runtime, dll_fixture(&[])).unwrap();
        let mut provider = provider(true).with_program("worker", program).unwrap();
        for index in 0..128 {
            provider = provider
                .with_program_runtime_file("worker", format!("runtime-{index:03}.dll"), &runtime)
                .unwrap();
        }
        let error = provider
            .with_program_runtime_file("worker", "runtime-128.dll", runtime)
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 128 DLLs"));
    }
}
