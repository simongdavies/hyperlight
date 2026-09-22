// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::FutureExt;
use mesh_process::Mesh;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) use mesh_process::OwnedHost;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use mesh_process::PendingHostLaunch;

use super::program::{
    LocalProgramStore, ProcessDefinition, ProgramArtifact, ProgramRole, ProgramTarget,
};
use super::{ProcessControl, RequestedControl};
use crate::{HyperlightError, Result, new_error};

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(super) struct OwnedHost;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl OwnedHost {
    pub(super) fn id(&self) -> i32 {
        0
    }

    pub(super) fn terminate_root(&self) -> Result<()> {
        Err(new_error!(
            "Mesh owned-process launch is unavailable on this host"
        ))
    }

    pub(super) async fn wait_root(&mut self) -> Result<()> {
        Err(new_error!(
            "Mesh owned-process launch is unavailable on this host"
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
struct PendingHostLaunch;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl PendingHostLaunch {
    fn cancel(&self) -> Result<()> {
        Err(new_error!(
            "Mesh owned-process launch is unavailable on this host"
        ))
    }

    async fn wait_completion(&self) -> Result<()> {
        Err(new_error!(
            "Mesh owned-process launch is unavailable on this host"
        ))
    }
}

/// Effective enforcement or an explicit omission of one requested restriction.
#[derive(Clone, Debug)]
pub enum ControlResult {
    /// The effective restriction and its OS enforcement mechanism.
    Applied {
        /// The limit or restriction actually enforced.
        effective: ProcessControl,
        /// Identifies the OS mechanism and its accounting scope.
        mechanism: String,
    },
    /// Optional restrictions may be omitted with an explicit reason.
    NotApplied {
        /// Why the restriction could not be enforced.
        reason: String,
    },
}

/// Enforcement evidence for one requested control.
#[derive(Clone, Debug)]
pub struct ControlOutcome {
    /// The caller's immutable request.
    pub requested: RequestedControl,
    /// The effective enforcement result.
    pub result: ControlResult,
}

/// A ready process and its effective restrictions.
#[derive(Clone, Debug)]
pub struct ProcessReport {
    /// Executable protocol hosted by this process.
    pub role: ProgramRole,
    /// Logical owner name within the sandbox.
    pub name: String,
    /// Immutable program identity.
    pub program: ProgramArtifact,
    /// Original owned root identity. A confinement supervisor may be this root.
    pub root_process_id: i32,
    /// Requested, effective and explicitly omitted controls.
    pub controls: Vec<ControlOutcome>,
}

pub(crate) trait ProcessGuard: Send + Sync {
    /// A pending native birth prevents fallback resource deletion.
    fn start_launch(&self);
    fn terminate_domain(&self) -> Result<()>;
    fn wait_empty(&self, deadline: Instant) -> Result<()>;
    /// Only called after original-root completion and domain emptiness.
    fn release_resources(&self, deadline: Instant) -> Result<()>;
}

pub(crate) struct PreparedProcess {
    pub config: mesh_process::ProcessConfig,
    pub guard: Arc<dyn ProcessGuard>,
    pub controls: Vec<ControlOutcome>,
}

pub(super) async fn launch_owned<T: 'static + mesh::message::MeshField + Send>(
    mesh: &Mesh,
    config: mesh_process::ProcessConfig,
    initial: T,
    guard: Arc<dyn ProcessGuard>,
    cancellation: mesh::CancelContext,
    timeout: Duration,
) -> Result<OwnedHost> {
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (mesh, config, initial, guard, cancellation, timeout);
        return Err(new_error!(
            "Mesh owned-process launch is unavailable on this host"
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        guard.start_launch();
        let mut pending = mesh.begin_launch_host_owned(config, initial);
        let result = cancellation
            .with_timeout(timeout)
            .until_cancelled(pending.wait_host())
            .await;
        let error = match result {
            Ok(Ok(root)) => return Ok(root),
            // OpenVMM owns this foreign error type. Preserve its source chain.
            Ok(Err(error)) => HyperlightError::from(error),
            Err(error) => new_error!("Process launch cancelled: {error}"),
        };
        let deadline = Instant::now() + timeout;
        let cancelled = pending.cancel();
        let initial_kill = guard.terminate_domain();
        let completion = mesh::CancelContext::new()
            .with_timeout(deadline.saturating_duration_since(Instant::now()))
            .until_cancelled(pending.wait_completion())
            .await;
        let release = finish_cleanup(guard.as_ref(), matches!(completion, Ok(Ok(_))), deadline);
        let message = format!(
            "Process launch failed: {error}; cancel: {cancelled:?}; initial termination: {initial_kill:?}; root: {completion:?}; cleanup: {release:?}"
        );
        if release.is_ok() {
            Err(new_error!("{message}"))
        } else {
            Err(Box::new(ProcessCleanupError {
                message,
                source: Box::new(error),
                owner: CleanupOwner::Launch(UnconfirmedLaunch {
                    pending: Mutex::new(pending),
                    guard,
                    deadline,
                    released: AtomicBool::new(false),
                }),
            })
            .into())
        }
    }
}

/// An incomplete cleanup and the capability for its remaining bounded attempts.
///
/// Dropping the final error is best effort. Unconfirmed cleanup can leave
/// descendants or resources without a retry owner.
#[derive(thiserror::Error)]
#[error("{message}")]
pub struct ProcessCleanupError {
    message: String,
    #[source]
    source: Box<HyperlightError>,
    owner: CleanupOwner,
}

pub(super) enum CleanupOwner {
    Runtime {
        _owner: Arc<super::runtime::Runtime>,
    },
    Sandbox {
        _owner: Box<super::sandbox::SandboxProcess>,
    },
    Launch(UnconfirmedLaunch),
}

impl ProcessCleanupError {
    pub(super) fn retain(error: HyperlightError, owner: CleanupOwner) -> HyperlightError {
        Box::new(Self {
            message: error.to_string(),
            source: Box::new(error),
            owner,
        })
        .into()
    }
}

impl std::fmt::Debug for ProcessCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessCleanupError")
            .field("message", &self.message)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// The error retains the pending operation and its resources if cleanup fails.
pub(super) struct UnconfirmedLaunch {
    pending: Mutex<PendingHostLaunch>,
    guard: Arc<dyn ProcessGuard>,
    deadline: Instant,
    released: AtomicBool,
}

impl UnconfirmedLaunch {
    fn retry_cleanup(&self, deadline: Instant) -> Result<()> {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.released.load(Ordering::Acquire) {
            return Ok(());
        }
        let cancelled = pending.cancel();
        let initial_kill = self.guard.terminate_domain();
        let completion = futures_lite::future::block_on(
            mesh::CancelContext::new()
                .with_timeout(deadline.saturating_duration_since(Instant::now()))
                .until_cancelled(pending.wait_completion()),
        );
        finish_cleanup(self.guard.as_ref(), matches!(completion, Ok(Ok(_))), deadline)
            .map_err(|error| new_error!(
                "Launch cleanup retry failed: cancel: {cancelled:?}; termination: {initial_kill:?}; root: {completion:?}; cleanup: {error}"
            ))?;
        self.released.store(true, Ordering::Release);
        Ok(())
    }
}

pub(super) fn has_unconfirmed_launch(error: &HyperlightError) -> bool {
    matches!(error, HyperlightError::ProcessCleanup(error) if matches!(error.owner, CleanupOwner::Launch(_)))
}

pub(super) fn has_cleanup_owner(error: &HyperlightError) -> bool {
    let mut source: &(dyn std::error::Error + 'static) = error;
    loop {
        if source.is::<ProcessCleanupError>()
            || matches!(
                source.downcast_ref::<HyperlightError>(),
                Some(HyperlightError::ProcessCleanup(_))
            )
        {
            return true;
        }
        match source.source() {
            Some(next) => source = next,
            None => return false,
        }
    }
}

pub(super) fn retry_unconfirmed_launch(error: &HyperlightError, deadline: Instant) -> Result<()> {
    match error {
        HyperlightError::ProcessCleanup(error) => match &error.owner {
            CleanupOwner::Launch(launch) => launch.retry_cleanup(deadline),
            _ => Err(new_error!("Expected retained launch cleanup ownership")),
        },
        _ => Err(new_error!("Expected retained launch cleanup ownership")),
    }
}

impl Drop for UnconfirmedLaunch {
    fn drop(&mut self) {
        if self.released.load(Ordering::Acquire) {
            return;
        }
        let pending = self
            .pending
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        let cancel = pending.cancel();
        let root = pending.wait_completion().now_or_never();
        if let Err(error) = finish_cleanup(
            self.guard.as_ref(),
            matches!(root, Some(Ok(_))),
            self.deadline,
        ) {
            tracing::error!(
                ?cancel,
                ?root,
                ?error,
                "Final launch cleanup incomplete. Dropping this cleanup owner"
            );
        }
    }
}

pub(super) async fn cleanup_owned(
    root: &mut OwnedHost,
    guard: &dyn ProcessGuard,
    deadline: Instant,
) -> Result<()> {
    let initial = guard.terminate_domain();
    let requested = root.terminate_root();
    let reaped = mesh::CancelContext::new()
        .with_timeout(deadline.saturating_duration_since(Instant::now()))
        .until_cancelled(root.wait_root())
        .await;
    match finish_cleanup(guard, matches!(reaped, Ok(Ok(_))), deadline) {
        Ok(()) => {
            if initial.is_err() || requested.is_err() {
                tracing::warn!(
                    ?initial,
                    ?requested,
                    "Process cleanup verified after termination reported an error"
                );
            }
            Ok(())
        }
        Err(error) => Err(new_error!(
            "Process cleanup failed: initial termination: {initial:?}; root termination: {requested:?}; reap: {reaped:?}; cleanup: {error}"
        )),
    }
}

fn finish_cleanup(guard: &dyn ProcessGuard, root_complete: bool, deadline: Instant) -> Result<()> {
    // Native creation may have crossed the first domain kill.
    let killed = guard.terminate_domain();
    let empty = guard.wait_empty(deadline);
    if !root_complete || empty.is_err() {
        return Err(new_error!(
            "Cleanup unconfirmed: root complete: {root_complete}; termination: {killed:?}; empty: {empty:?}"
        ));
    }
    if let Err(error) = killed {
        tracing::warn!(
            ?error,
            "Domain emptiness verified after termination reported an error"
        );
    }
    guard.release_resources(deadline)
}

pub(crate) trait ProcessLauncher: Send + Sync {
    fn prepare(&self, role: ProgramRole, definition: &ProcessDefinition)
    -> Result<PreparedProcess>;
}

pub(super) struct ConfiguredLauncher {
    pub store: LocalProgramStore,
    pub target: ProgramTarget,
    #[cfg(target_os = "windows")]
    pub windows: super::windows::WindowsPrincipals,
    #[cfg(target_os = "linux")]
    pub linux: Option<super::LinuxProcessResources>,
    pub _provider: Arc<super::provider::Provider>,
}

impl ProcessLauncher for ConfiguredLauncher {
    fn prepare(
        &self,
        role: ProgramRole,
        definition: &ProcessDefinition,
    ) -> Result<PreparedProcess> {
        let program = self.store.validate(definition.program(), &self.target)?;
        if program.config().role != role {
            return Err(crate::new_error!("Process program role changed"));
        }
        let mut actual = program.config().functions.clone();
        let mut expected = definition.functions().to_vec();
        actual.sort_by(|left, right| left.name().cmp(right.name()));
        expected.sort_by(|left, right| left.name().cmp(right.name()));
        if actual != expected {
            return Err(crate::new_error!("Process program contracts changed"));
        }
        #[cfg(target_os = "windows")]
        let mut prepared = super::windows::prepare(role, definition, &program, &self.windows)?;
        #[cfg(target_os = "linux")]
        let mut prepared = super::linux::prepare(
            role,
            definition,
            &program,
            self.linux
                .as_ref()
                .ok_or_else(|| crate::new_error!("Linux process resources are required"))?,
        )?;
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            prepared.config = prepared.config.env([
                (
                    std::ffi::OsString::from("HYPERLIGHT_PROCESS_ROLE"),
                    match role {
                        ProgramRole::SandboxHost => "sandbox",
                        ProgramRole::FunctionWorker => "worker",
                    }
                    .into(),
                ),
                (
                    std::ffi::OsString::from("HYPERLIGHT_PROCESS_NAME"),
                    definition.name().into(),
                ),
            ]);
            Ok(prepared)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(crate::new_error!(
                "Process confinement is unavailable on this host"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[derive(Default)]
    struct RecordingGuard {
        events: Mutex<Vec<&'static str>>,
        deadlines: Mutex<Vec<Instant>>,
        fail_empty: AtomicBool,
    }

    impl RecordingGuard {
        fn record(&self, event: &'static str) {
            self.events.lock().unwrap().push(event);
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }
    }

    impl ProcessGuard for RecordingGuard {
        fn start_launch(&self) {
            self.record("start");
        }

        fn terminate_domain(&self) -> Result<()> {
            self.record("terminate");
            Ok(())
        }

        fn wait_empty(&self, deadline: Instant) -> Result<()> {
            self.record("empty");
            self.deadlines.lock().unwrap().push(deadline);
            if self.fail_empty.load(Ordering::Acquire) {
                Err(new_error!("Fixture domain is not empty"))
            } else {
                Ok(())
            }
        }

        fn release_resources(&self, deadline: Instant) -> Result<()> {
            self.record("release");
            self.deadlines.lock().unwrap().push(deadline);
            Ok(())
        }
    }

    #[test]
    fn release_requires_original_root_completion_and_domain_emptiness() {
        for root_complete in [false, true] {
            for empty in [false, true] {
                let guard = RecordingGuard::default();
                guard.fail_empty.store(!empty, Ordering::Release);
                let deadline = Instant::now() + Duration::from_secs(1);
                let result = finish_cleanup(&guard, root_complete, deadline);
                assert_eq!(result.is_ok(), root_complete && empty);
                let mut expected = vec!["terminate", "empty"];
                if root_complete && empty {
                    expected.push("release");
                }
                assert_eq!(guard.events(), expected);
                let deadlines = guard.deadlines.lock().unwrap().clone();
                assert!(deadlines.iter().all(|observed| *observed == deadline));
            }
        }
    }

    #[test]
    fn failed_native_launch_releases_only_after_completion() {
        check_failed_launch(false);
    }

    #[test]
    fn failed_native_launch_error_retains_unconfirmed_cleanup() {
        check_failed_launch(true);
    }

    #[test]
    fn permanent_cleanup_failure_does_not_claim_release_on_final_error_drop() {
        futures_lite::future::block_on(async {
            let mesh = Mesh::new("permanent-cleanup-failure".to_owned()).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let guard = Arc::new(RecordingGuard::default());
            guard.fail_empty.store(true, Ordering::Release);
            let error = launch_owned(
                &mesh,
                mesh_process::ProcessConfig::new("missing")
                    .process_name(directory.path().join("missing-worker"))
                    .skip_worker_arg(true),
                (),
                guard.clone(),
                mesh::CancelContext::new(),
                Duration::from_secs(5),
            )
            .await
            .err()
            .expect("Missing executable must fail");
            assert_eq!(Arc::strong_count(&guard), 2);
            drop(error);
            assert!(!guard.events().contains(&"release"));
            // Final Drop retains no retry owner. This is not a cleanup guarantee.
            assert_eq!(Arc::strong_count(&guard), 1);
            mesh::CancelContext::new()
                .with_timeout(Duration::from_secs(5))
                .until_cancelled(mesh.shutdown())
                .await
                .unwrap();
        });
    }

    fn check_failed_launch(fail_empty: bool) {
        futures_lite::future::block_on(async {
            let mesh = Mesh::new("failed-launch".to_owned()).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let guard = Arc::new(RecordingGuard::default());
            guard.fail_empty.store(fail_empty, Ordering::Release);
            let error = launch_owned(
                &mesh,
                mesh_process::ProcessConfig::new("missing")
                    .process_name(directory.path().join("missing-executable"))
                    .skip_worker_arg(true),
                (),
                guard.clone(),
                mesh::CancelContext::new(),
                Duration::from_secs(5),
            )
            .await
            .err()
            .expect("Missing executable must fail");
            let mut expected = vec!["start", "terminate", "terminate", "empty"];
            if fail_empty {
                assert_eq!(guard.events(), expected);
                assert_eq!(Arc::strong_count(&guard), 2);
                guard.fail_empty.store(false, Ordering::Release);
                expected.extend(["terminate", "empty"]);
            }
            drop(error);
            expected.push("release");
            assert_eq!(guard.events(), expected);
            assert_eq!(Arc::strong_count(&guard), 1);
            let deadlines = guard.deadlines.lock().unwrap().clone();
            assert!(deadlines.iter().all(|deadline| *deadline == deadlines[0]));
            mesh::CancelContext::new()
                .with_timeout(Duration::from_secs(5))
                .until_cancelled(mesh.shutdown())
                .await
                .unwrap();
        });
    }
}
