// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use futures::StreamExt;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    FunctionCallResult, ParameterValue, ReturnValue,
};
use mesh::MeshPayload;
use mesh::rpc::{Rpc, RpcSend};

use super::program::FunctionContractDefinition;
use super::{FunctionDefinition, Idempotency, ProcessHostFunctions};
use crate::func::host_functions::TypeErasedHostFunction;
use crate::sandbox::host_funcs::FunctionEntry;
use crate::{HostFunctions, Result, new_error};

const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, MeshPayload, PartialEq, Eq)]
struct WireContract {
    name: String,
    parameters: Vec<u32>,
    output: u32,
    idempotency: u32,
}

impl From<&FunctionDefinition> for WireContract {
    fn from(definition: &FunctionDefinition) -> Self {
        Self::from(&FunctionContractDefinition::from_definition(definition))
    }
}

impl From<&FunctionContractDefinition> for WireContract {
    fn from(definition: &FunctionContractDefinition) -> Self {
        Self {
            name: definition.name().to_owned(),
            parameters: definition
                .parameters()
                .iter()
                .map(|ty| ty.clone() as u32)
                .collect(),
            output: definition.output() as u32,
            idempotency: match definition.idempotency() {
                Idempotency::Unspecified => 0,
                Idempotency::NonIdempotent => 1,
                Idempotency::Idempotent => 2,
            },
        }
    }
}

#[derive(MeshPayload)]
pub(super) struct Bootstrap {
    version: u32,
    contracts: Vec<WireContract>,
    requests: mesh::Receiver<Request>,
    ready: mesh::OneshotSender<std::result::Result<(), String>>,
}

#[derive(MeshPayload)]
pub(super) enum Request {
    Call(Rpc<Vec<u8>, std::result::Result<Vec<u8>, String>>),
    Stop(Rpc<(), ()>),
}

#[derive(MeshPayload)]
pub(super) struct WorkerGeneration {
    number: u64,
    requests: mesh::Sender<Request>,
    contracts: Vec<WireContract>,
}

impl WorkerGeneration {
    pub(super) fn new(
        number: u64,
        requests: mesh::Sender<Request>,
        definitions: &[FunctionContractDefinition],
    ) -> Self {
        Self {
            number,
            requests,
            contracts: wire_contracts(definitions),
        }
    }
}

// No call name, arguments, return value, or replay permission crosses this channel.
#[derive(MeshPayload)]
enum LifecycleRequest {
    Refresh(Rpc<(usize, u64), std::result::Result<WorkerGeneration, String>>),
}

/// A direct worker endpoint and a separate parent-owned lifecycle capability.
#[derive(MeshPayload)]
pub(super) struct SupervisedConnection {
    initial: WorkerGeneration,
    lifecycle: mesh::Sender<LifecycleRequest>,
    worker_index: usize,
}

fn wire_contracts(definitions: &[FunctionContractDefinition]) -> Vec<WireContract> {
    let mut contracts: Vec<_> = definitions.iter().map(WireContract::from).collect();
    contracts.sort_by(|left, right| left.name.cmp(&right.name));
    contracts
}

/// One-shot startup resources supplied by the trusted process launcher.
pub struct ProcessStartup(mesh_process::OwnedInvitation);

impl ProcessStartup {
    pub(super) fn into_inner(self) -> mesh_process::OwnedInvitation {
        self.0
    }

    /// Role supplied by the Mesh/PAL launch capability.
    pub fn role(&self) -> Result<super::program::ProgramRole> {
        match std::env::var("HYPERLIGHT_PROCESS_ROLE").as_deref() {
            Ok("sandbox") => Ok(super::program::ProgramRole::SandboxHost),
            Ok("worker") => Ok(super::program::ProgramRole::FunctionWorker),
            _ => Err(new_error!(
                "Mesh provider did not identify the process role"
            )),
        }
    }

    /// Logical process owner supplied by the Mesh/PAL launch capability.
    pub fn name(&self) -> Result<String> {
        let name = std::env::var("HYPERLIGHT_PROCESS_NAME")
            .map_err(|_| new_error!("Mesh provider did not identify the process owner"))?;
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(new_error!(
                "Mesh provider supplied an invalid process owner"
            ));
        }
        Ok(name)
    }

    /// Captures worker startup resources, or returns `None` in an application role.
    ///
    /// # Safety
    ///
    /// Call once before threads, tracing or concurrent environment access.
    /// Inherited IPC resources must come from the trusted launcher and have no
    /// other owner or concurrent user. Do not spawn processes during capture.
    pub unsafe fn capture() -> Result<Option<Self>> {
        // SAFETY: the caller upholds the inherited-resource and environment contract.
        Ok(unsafe { mesh_process::OwnedInvitation::capture_from_environment() }?.map(Self))
    }
}

pub(super) fn bootstrap(
    definitions: &[FunctionContractDefinition],
    requests: mesh::Receiver<Request>,
    ready: mesh::OneshotSender<std::result::Result<(), String>>,
) -> Bootstrap {
    Bootstrap {
        version: PROTOCOL_VERSION,
        contracts: wire_contracts(definitions),
        requests,
        ready,
    }
}

#[cfg(test)]
struct RemoteRoute {
    requests: mesh::Sender<Request>,
    definition: FunctionContractDefinition,
    _runtime: std::sync::Arc<super::runtime::Runtime>,
}

#[cfg(test)]
impl RemoteRoute {
    fn call(&self, parameters: Vec<ParameterValue>) -> Result<ReturnValue> {
        futures_lite::future::block_on(invoke(&self.requests, &self.definition, parameters))
    }
}

#[cfg(test)]
pub(super) async fn register_ready_routes(
    requests: mesh::Sender<Request>,
    readiness: mesh::OneshotReceiver<std::result::Result<(), String>>,
    definitions: &[FunctionContractDefinition],
    runtime: std::sync::Arc<super::runtime::Runtime>,
) -> Result<HostFunctions> {
    wait_ready(readiness).await?;
    let mut unique = std::collections::BTreeSet::new();
    for definition in definitions {
        if definition.name().is_empty() || !unique.insert(definition.name()) {
            return Err(new_error!("Duplicate or empty process function name"));
        }
    }
    let mut registrations = HostFunctions::empty();
    for definition in definitions {
        let route = RemoteRoute {
            requests: requests.clone(),
            definition: definition.clone(),
            _runtime: runtime.clone(),
        };
        let function = TypeErasedHostFunction::new(move |parameters| route.call(parameters));
        registrations.inner_mut().register_host_function(
            definition.name().to_owned(),
            FunctionEntry {
                function,
                parameter_types: definition.parameters().into(),
                return_type: definition.output(),
            },
        );
    }
    Ok(registrations)
}

pub(super) async fn wait_ready(
    readiness: mesh::OneshotReceiver<std::result::Result<(), String>>,
) -> Result<()> {
    mesh::CancelContext::new()
        .with_timeout(std::time::Duration::from_secs(30))
        .until_cancelled(readiness)
        .await
        .map_err(|error| new_error!("Function-process readiness timed out: {error}"))?
        .map_err(|error| new_error!("Function-process readiness failed: {error}"))?
        .map_err(|error| new_error!("Function-process manifest rejected: {error}"))?;
    Ok(())
}

pub(super) fn register_runtime_routes(
    worker_index: usize,
    definitions: &[FunctionContractDefinition],
    runtime: std::sync::Arc<super::runtime::Runtime>,
) -> HostFunctions {
    let mut registrations = HostFunctions::empty();
    for definition in definitions {
        let owner = runtime.clone();
        let contract = definition.clone();
        let function = TypeErasedHostFunction::new(move |parameters| {
            let payload = encode_call(&contract, parameters);
            decode_response(&owner.invoke(worker_index, &contract, payload)?)
        });
        registrations.inner_mut().register_host_function(
            definition.name().to_owned(),
            FunctionEntry {
                function,
                parameter_types: definition.parameters().into(),
                return_type: definition.output(),
            },
        );
    }
    registrations
}

/// Owns one lifecycle consumer for the sandbox. The thread never owns this guard.
pub(super) struct LifecycleSupervisor {
    runtime: std::sync::Arc<super::runtime::Runtime>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for LifecycleSupervisor {
    fn drop(&mut self) {
        if let Err(error) = self.runtime.stop() {
            tracing::error!(%error, "Lifecycle supervisor cleanup failed");
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("Lifecycle supervisor panicked");
        }
    }
}

/// Call data flows directly from the VM to physical worker endpoints.
pub(super) fn supervised_connections(
    runtime: std::sync::Arc<super::runtime::Runtime>,
    count: usize,
) -> Result<(Vec<SupervisedConnection>, LifecycleSupervisor)> {
    if count == 0 {
        return Ok((
            Vec::new(),
            LifecycleSupervisor {
                runtime,
                thread: None,
            },
        ));
    }
    let (lifecycle, mut requests) = mesh::channel();
    let connections = (0..count)
        .map(|worker_index| {
            Ok(SupervisedConnection {
                initial: runtime.worker_generation(worker_index)?,
                lifecycle: lifecycle.clone(),
                worker_index,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut cancellation = runtime.cancellation();
    let owner = std::sync::Arc::downgrade(&runtime);
    let thread = std::thread::Builder::new()
        .name("hyperlight-function-lifecycle".to_owned())
        .spawn(move || {
            futures_lite::future::block_on(async move {
                while let Ok(Some(request)) = cancellation.until_cancelled(requests.next()).await {
                    match request {
                        LifecycleRequest::Refresh(refresh) => {
                            refresh.handle_sync(|(worker_index, generation)| {
                                owner
                                    .upgrade()
                                    .ok_or_else(|| new_error!("Function-process owner was dropped"))
                                    .and_then(|owner| {
                                        owner.refresh_worker(worker_index, generation)
                                    })
                                    .map_err(|error| error.to_string())
                            })
                        }
                    }
                }
            });
        })?;
    Ok((
        connections,
        LifecycleSupervisor {
            runtime,
            thread: Some(thread),
        },
    ))
}

struct SupervisedRoute {
    generation: std::sync::Mutex<WorkerGeneration>,
    lifecycle: mesh::Sender<LifecycleRequest>,
    contracts: Vec<WireContract>,
    runtime: std::sync::Arc<super::runtime::Runtime>,
    worker_index: usize,
}

impl SupervisedRoute {
    fn call(
        &self,
        contract: &FunctionContractDefinition,
        parameters: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        self.runtime.ensure_active()?;
        let payload = encode_call(contract, parameters);
        let mut generation = self
            .generation
            .lock()
            .map_err(|error| new_error!("Worker generation lock failed: {error}"))?;
        self.runtime.ensure_active()?;
        futures_lite::future::block_on(async {
            loop {
                self.runtime.ensure_active()?;
                // Only this VM-side route sends call data. The parent receives
                // generation numbers on a separate lifecycle-only endpoint.
                let response = self
                    .runtime
                    .cancellation()
                    .until_cancelled(generation.requests.call(Request::Call, payload.clone()))
                    .await
                    .map_err(|error| new_error!("Intentional function-process stop: {error}"))?;
                match response {
                    Ok(response) => {
                        return decode_response(&response.map_err(|error| {
                            new_error!("Host-function process call failed: {error}")
                        })?);
                    }
                    Err(error) => {
                        self.runtime.ensure_active()?;
                        let replacement = self
                            .runtime
                            .cancellation()
                            .until_cancelled(self.lifecycle.call(
                                LifecycleRequest::Refresh,
                                (self.worker_index, generation.number),
                            ))
                            .await
                            .map_err(|error| {
                                new_error!("Intentional function-process stop: {error}")
                            })?;
                        let replacement = match replacement {
                            Ok(Ok(replacement)) => replacement,
                            other => {
                                self.runtime.mark_poisoned();
                                return Err(new_error!(
                                    "Function-process lifecycle recovery failed: {}",
                                    match other {
                                        Ok(Err(error)) => error,
                                        Err(error) => error.to_string(),
                                        _ => unreachable!(),
                                    }
                                ));
                            }
                        };
                        if replacement.number <= generation.number
                            || replacement.contracts != self.contracts
                        {
                            self.runtime.mark_poisoned();
                            return Err(new_error!(
                                "Function-process replacement generation or immutable manifest mismatch"
                            ));
                        }
                        *generation = replacement;
                        // No response is never proof of non-dispatch. This decision
                        // uses the VM's trusted, immutable registration only.
                        if contract.idempotency() != Idempotency::Idempotent {
                            return Err(new_error!(
                                "Host-function process disconnected; execution is uncertain and replay is forbidden: {error}"
                            ));
                        }
                    }
                }
            }
        })
    }
}

/// Installs direct calls and trusted replay logic inside the VM process.
pub(super) fn register_supervised_routes(
    connection: SupervisedConnection,
    definitions: &[FunctionContractDefinition],
    runtime: std::sync::Arc<super::runtime::Runtime>,
) -> Result<HostFunctions> {
    let contracts = wire_contracts(definitions);
    if connection.initial.contracts != contracts
        || contracts.iter().any(|contract| contract.name.is_empty())
        || contracts
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
    {
        return Err(new_error!(
            "Function-process initial immutable manifest mismatch"
        ));
    }
    let route = std::sync::Arc::new(SupervisedRoute {
        generation: std::sync::Mutex::new(connection.initial),
        lifecycle: connection.lifecycle,
        contracts,
        runtime: runtime.clone(),
        worker_index: connection.worker_index,
    });
    let mut registrations = HostFunctions::empty();
    for definition in definitions {
        let route = route.clone();
        let contract = definition.clone();
        registrations.inner_mut().register_host_function(
            definition.name().to_owned(),
            FunctionEntry {
                function: TypeErasedHostFunction::new(move |parameters| {
                    route.call(&contract, parameters)
                }),
                parameter_types: definition.parameters().into(),
                return_type: definition.output(),
            },
        );
    }
    registrations.inner_mut().process_runtime = Some(runtime);
    Ok(registrations)
}

fn encode_call(
    definition: &FunctionContractDefinition,
    parameters: Vec<ParameterValue>,
) -> Vec<u8> {
    let call = FunctionCall::new(
        definition.name().to_owned(),
        Some(parameters),
        FunctionCallType::Host,
        definition.output(),
    );
    let mut buffer = flatbuffers::FlatBufferBuilder::new();
    call.encode(&mut buffer).to_vec()
}

fn decode_response(response: &[u8]) -> Result<ReturnValue> {
    FunctionCallResult::try_from(response)?
        .into_inner()
        .map_err(|error| new_error!("Host-function process returned a guest error: {error:?}"))
}

#[cfg(test)]
async fn invoke(
    requests: &mesh::Sender<Request>,
    definition: &FunctionContractDefinition,
    parameters: Vec<ParameterValue>,
) -> Result<ReturnValue> {
    let response = requests
        .call(Request::Call, encode_call(definition, parameters))
        .await
        .map_err(|error| new_error!("Host-function process disconnected: {error}"))?
        .map_err(|error| new_error!("Host-function process call failed: {error}"))?;
    decode_response(&response)
}

impl ProcessHostFunctions {
    /// Serves registrations in a framework-launched function process.
    ///
    /// The launcher must establish containment before this executable starts.
    /// Capture startup resources before creating threads. The owned value can
    /// then be passed here after initialization.
    pub fn run(self, startup: ProcessStartup) -> Result<()> {
        mesh_process::run_mesh_host(
            startup.into_inner(),
            "hyperlight-function",
            // OpenVMM requires anyhow at its callback boundary.
            async move |bootstrap| self.serve(bootstrap).await.map_err(anyhow::Error::new),
        )?;
        Err(new_error!("Function-process bootstrap did not enter Mesh"))
    }

    async fn serve(self, mut bootstrap: Bootstrap) -> Result<()> {
        let expected: Vec<_> = self.contracts.values().map(WireContract::from).collect();
        if bootstrap.version != PROTOCOL_VERSION || bootstrap.contracts != expected {
            bootstrap.ready.send(Err(
                "Function-process protocol or registration manifest mismatch".to_owned(),
            ));
            return Err(new_error!(
                "Function-process protocol or registration manifest mismatch"
            ));
        }
        bootstrap.ready.send(Ok(()));
        while let Some(request) = bootstrap.requests.next().await {
            match request {
                Request::Call(call) => {
                    let (payload, call) = call.split();
                    let response = match self.dispatch(&payload) {
                        Ok(value) => Ok(value),
                        Err(error) if super::launch::has_cleanup_owner(&error) => {
                            return Err(error);
                        }
                        Err(error) => Err(error.to_string()),
                    };
                    call.complete(response);
                }
                Request::Stop(stop) => {
                    stop.complete(());
                    break;
                }
            }
        }
        Ok(())
    }

    fn dispatch(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let call = FunctionCall::try_from(payload)?;
        if call.function_call_type() != FunctionCallType::Host {
            return Err(new_error!("Function process received a non-host call"));
        }
        let definition = self
            .contracts
            .get(call.function_name.as_str())
            .ok_or_else(|| new_error!("Undeclared host function '{}'", call.function_name))?;
        if call.expected_return_type != definition.output {
            return Err(new_error!(
                "Return type mismatch for '{}'",
                call.function_name
            ));
        }
        let result = self
            .functions
            .inner()
            .call_host_function(&call.function_name, call.parameters.unwrap_or_default())?;
        Ok(Vec::<u8>::try_from(&result)?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::func::{ParameterTuple, SupportedReturnType};
    use crate::process::HostFunctionContract;

    mod process_contracts {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/process_contracts.rs"
        ));
    }
    use process_contracts::{ADD, PID};

    fn definitions() -> Vec<FunctionContractDefinition> {
        vec![
            FunctionContractDefinition::from_contract(&ADD),
            FunctionContractDefinition::from_contract(&PID),
        ]
    }

    // This trusted fixture qualifies transport, not OS containment.
    #[tokio::test]
    async fn mesh_child_validates_manifest_calls_and_shutdown() {
        run_fixture(false).await;
    }

    #[tokio::test]
    async fn guest_calls_mesh_child() {
        run_fixture(true).await;
    }

    fn fixture_path() -> std::path::PathBuf {
        let executable = std::env::current_exe().unwrap();
        let worker = executable
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples")
            .join(format!("process_worker{}", std::env::consts::EXE_SUFFIX));
        assert!(
            worker.is_file(),
            "Build the main-entry fixture with cargo build -p hyperlight-host --example process_worker --features process-isolation"
        );
        worker
    }

    fn fixture_config() -> mesh_process::ProcessConfig {
        mesh_process::ProcessConfig::new("function-test")
            .skip_worker_arg(true)
            .process_name(fixture_path())
    }

    struct RecoveryFixture {
        args: Vec<std::ffi::OsString>,
        prepares: std::sync::atomic::AtomicUsize,
        fail_reverification: bool,
        change_manifest: bool,
        store: super::super::program::LocalProgramStore,
        lifecycle: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
        fail_cleanup: std::sync::Arc<std::sync::atomic::AtomicBool>,
        guards: std::sync::Mutex<Vec<std::sync::Weak<RecoveryFixtureGuard>>>,
    }

    // This guard observes ordering only. The main-entry fixture is explicitly trusted.
    struct RecoveryFixtureGuard {
        lifecycle: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
        fail_cleanup: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl super::super::launch::ProcessGuard for RecoveryFixtureGuard {
        fn start_launch(&self) {}

        fn release_resources(&self, _: std::time::Instant) -> Result<()> {
            self.lifecycle
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push("release");
            Ok(())
        }

        fn terminate_domain(&self) -> Result<()> {
            self.lifecycle
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push("terminate");
            Ok(())
        }

        fn wait_empty(&self, _deadline: std::time::Instant) -> Result<()> {
            self.lifecycle
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push("empty");
            if self.fail_cleanup.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(new_error!("Test domain failed to become empty"));
            }
            Ok(())
        }
    }

    impl super::super::launch::ProcessLauncher for RecoveryFixture {
        fn prepare(
            &self,
            role: super::super::program::ProgramRole,
            definition: &super::super::program::ProcessDefinition,
        ) -> Result<super::super::launch::PreparedProcess> {
            use std::sync::atomic::Ordering;
            let attempt = self.prepares.fetch_add(1, Ordering::SeqCst);
            self.lifecycle.lock().unwrap().push("prepare");
            if attempt > 0 && self.fail_reverification {
                return Err(new_error!("Test program reverification rejected"));
            }
            // Even this explicitly trusted fixture checks the complete immutable
            // program manifest on every replacement.
            let topology = super::super::program::ProcessTopologyDefinition::new(
                None,
                vec![definition.clone()],
            )?;
            topology.validate_programs(
                &self.store,
                &super::super::program::ProgramTarget::current(Default::default()),
            )?;
            assert_eq!(role, super::super::program::ProgramRole::FunctionWorker);
            let mut args = self.args.clone();
            if attempt > 0 && self.change_manifest {
                args.push("non-idempotent".into());
            }
            let guard = std::sync::Arc::new(RecoveryFixtureGuard {
                lifecycle: self.lifecycle.clone(),
                fail_cleanup: self.fail_cleanup.clone(),
            });
            self.guards
                .lock()
                .unwrap()
                .push(std::sync::Arc::downgrade(&guard));
            Ok(super::super::launch::PreparedProcess {
                config: fixture_config().args(args),
                guard,
                controls: vec![],
            })
        }
    }

    fn recovery_fixture(
        directory: &std::path::Path,
        mode: &str,
        idempotency: Idempotency,
        fail_reverification: bool,
        change_manifest: bool,
    ) -> (
        super::super::program::ProcessTopologyDefinition,
        std::sync::Arc<RecoveryFixture>,
    ) {
        use super::super::program::*;
        use super::super::{ProcessControl, ProcessProfile, RequestedControl};
        let contract = HostFunctionContract::<(i32, i32), i32>::new("HostAdd", idempotency);
        let definitions = vec![
            FunctionContractDefinition::from_contract(&contract),
            FunctionContractDefinition::from_contract(&PID),
        ];
        let store = LocalProgramStore::new(directory.join("programs"));
        let program = store
            .package(
                &ProgramConfig {
                    schema_version: 1,
                    role: ProgramRole::FunctionWorker,
                    target: ProgramTarget::current(Default::default()),
                    functions: definitions.clone(),
                },
                &std::fs::read(fixture_path()).unwrap(),
            )
            .unwrap();
        let profile = ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyChildProcesses,
            required: true,
        }]);
        let topology = ProcessTopologyDefinition::new(
            None,
            vec![
                ProcessDefinition::new("recovery-fixture", program, &profile, definitions).unwrap(),
            ],
        )
        .unwrap();
        let mut args = if mode.is_empty() {
            vec![]
        } else {
            vec![mode.into(), directory.join("dispatches").into_os_string()]
        };
        match idempotency {
            Idempotency::Unspecified => args.push("unmarked".into()),
            Idempotency::NonIdempotent => args.push("non-idempotent".into()),
            Idempotency::Idempotent => {}
        }
        (
            topology,
            std::sync::Arc::new(RecoveryFixture {
                args,
                prepares: std::sync::atomic::AtomicUsize::new(0),
                fail_reverification,
                change_manifest,
                store,
                lifecycle: Default::default(),
                fail_cleanup: Default::default(),
                guards: Default::default(),
            }),
        )
    }

    fn recovery_runtime(
        topology: &super::super::program::ProcessTopologyDefinition,
        launcher: std::sync::Arc<RecoveryFixture>,
    ) -> std::sync::Arc<super::super::runtime::Runtime> {
        super::super::runtime::Runtime::start_workers(
            topology.workers(),
            launcher,
            super::super::runtime::RestartPolicy {
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(4),
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn recovery_call(
        runtime: &super::super::runtime::Runtime,
        contract: &FunctionContractDefinition,
        parameters: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        decode_response(&runtime.invoke(0, contract, encode_call(contract, parameters))?)
    }

    fn dispatch_count(directory: &std::path::Path) -> usize {
        std::fs::read_to_string(directory.join("dispatches"))
            .unwrap()
            .lines()
            .count()
    }

    #[test]
    fn recovery_replays_idempotent_actual_crash_with_new_root() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Idempotent,
            false,
            false,
        );
        let runtime = recovery_runtime(&topology, launcher.clone());
        let initial_pid = runtime.reports()[0].root_process_id;
        let contract = &topology.workers()[0].functions()[0];
        // Exercise the synchronous route under an already-entered executor.
        futures::executor::block_on(async {
            let routes =
                register_runtime_routes(0, topology.workers()[0].functions(), runtime.clone());
            let result = routes
                .inner()
                .call_host_function(contract.name(), (10_i32, 32_i32).into_value())
                .unwrap();
            assert_eq!(i32::try_from(result).unwrap(), 42);
        });
        assert_ne!(initial_pid, runtime.reports()[0].root_process_id);
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        assert_eq!(dispatch_count(directory.path()), 2);
        assert!(!runtime.is_poisoned());
        let events = launcher.lifecycle.lock().unwrap().clone();
        assert_eq!(
            events,
            [
                "prepare",
                "terminate",
                "terminate",
                "empty",
                "release",
                "prepare"
            ]
        );
    }

    #[test]
    fn recovery_retries_confirmed_cleaned_launch_failure() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        use super::super::launch::{PreparedProcess, ProcessLauncher};
        use super::super::program::{ProcessDefinition, ProgramRole};

        struct MissingOnce {
            launcher: Arc<RecoveryFixture>,
            missing: std::path::PathBuf,
        }
        impl ProcessLauncher for MissingOnce {
            fn prepare(
                &self,
                role: ProgramRole,
                definition: &ProcessDefinition,
            ) -> Result<PreparedProcess> {
                let mut prepared = self.launcher.prepare(role, definition)?;
                if self.launcher.prepares.load(Ordering::SeqCst) == 2 {
                    prepared.config = prepared.config.process_name(&self.missing);
                }
                Ok(prepared)
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Idempotent,
            false,
            false,
        );
        let runtime = super::super::runtime::Runtime::start_workers(
            topology.workers(),
            Arc::new(MissingOnce {
                launcher: launcher.clone(),
                missing: directory.path().join("missing-worker"),
            }),
            super::super::runtime::RestartPolicy {
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(4),
                ..Default::default()
            },
        )
        .unwrap();
        let initial_pid = runtime.reports()[0].root_process_id;
        let result = recovery_call(
            &runtime,
            &topology.workers()[0].functions()[0],
            (10_i32, 32_i32).into_value(),
        );
        assert!(
            result.is_ok(),
            "Confirmed-cleaned launch must be retryable: {result:?}"
        );
        assert_eq!(i32::try_from(result.unwrap()).unwrap(), 42);
        assert!(!runtime.is_poisoned());
        assert_ne!(initial_pid, runtime.reports()[0].root_process_id);
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 3);
        assert_eq!(dispatch_count(directory.path()), 2);
        assert!(
            launcher.guards.lock().unwrap()[..2]
                .iter()
                .all(|guard| guard.upgrade().is_none())
        );
        runtime.stop().unwrap();
        assert_eq!(
            launcher
                .lifecycle
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "release")
                .count(),
            3
        );
    }

    #[test]
    fn recovery_requires_empty_domain_before_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Idempotent,
            false,
            false,
        );
        let runtime = recovery_runtime(&topology, launcher.clone());
        launcher
            .fail_cleanup
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let error = recovery_call(
            &runtime,
            &topology.workers()[0].functions()[0],
            (1_i32, 2_i32).into_value(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cleanup failed"), "{error}");
        assert!(runtime.is_poisoned());
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(dispatch_count(directory.path()), 1);
        let events = launcher.lifecycle.lock().unwrap().clone();
        assert_eq!(events, ["prepare", "terminate", "terminate", "empty"]);
    }

    #[test]
    fn recovery_regression_failed_stop_retains_cleanup_ownership() {
        use std::sync::atomic::Ordering;

        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        let mut runtime = recovery_runtime(&topology, launcher.clone());
        let guard = launcher.guards.lock().unwrap()[0].clone();
        launcher.fail_cleanup.store(true, Ordering::SeqCst);
        assert!(
            std::sync::Arc::get_mut(&mut runtime)
                .unwrap()
                .shutdown()
                .is_err()
        );
        assert!(
            guard.upgrade().is_some(),
            "Failed cleanup lost its domain capability"
        );
        assert_eq!(runtime.reports().len(), 1);
        assert!(!launcher.lifecycle.lock().unwrap().contains(&"release"));
        launcher.fail_cleanup.store(false, Ordering::SeqCst);
        std::sync::Arc::get_mut(&mut runtime)
            .unwrap()
            .shutdown()
            .unwrap();
        runtime.stop().unwrap();
        assert!(guard.upgrade().is_none());
        assert!(runtime.reports().is_empty());
        assert_eq!(
            launcher
                .lifecycle
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "release")
                .count(),
            1
        );
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn recovery_regression_unready_replacement_retains_cleanup_ownership() {
        use std::sync::atomic::Ordering;

        use super::super::launch::{PreparedProcess, ProcessLauncher};
        use super::super::program::{ProcessDefinition, ProgramRole};

        struct FailReplacementCleanup(std::sync::Arc<RecoveryFixture>);
        impl ProcessLauncher for FailReplacementCleanup {
            fn prepare(
                &self,
                role: ProgramRole,
                definition: &ProcessDefinition,
            ) -> Result<PreparedProcess> {
                let prepared = self.0.prepare(role, definition)?;
                if self.0.prepares.load(Ordering::SeqCst) > 1 {
                    self.0.fail_cleanup.store(true, Ordering::SeqCst);
                }
                Ok(prepared)
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Idempotent,
            false,
            true,
        );
        let runtime = super::super::runtime::Runtime::start_workers(
            topology.workers(),
            std::sync::Arc::new(FailReplacementCleanup(launcher.clone())),
            super::super::runtime::RestartPolicy {
                initial_backoff: Duration::from_millis(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            recovery_call(
                &runtime,
                &topology.workers()[0].functions()[0],
                (1_i32, 2_i32).into_value(),
            )
            .is_err()
        );
        assert!(runtime.is_poisoned());
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 2);
        assert_eq!(dispatch_count(directory.path()), 1);
        let guard = launcher.guards.lock().unwrap()[1].clone();
        assert!(
            guard.upgrade().is_some(),
            "Unready cleanup lost its domain capability"
        );
        launcher.fail_cleanup.store(false, Ordering::SeqCst);
        runtime.stop().unwrap();
        assert!(guard.upgrade().is_none());
        assert_eq!(
            launcher
                .lifecycle
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "release")
                .count(),
            2
        );
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn recovery_regression_stopped_route_never_enqueues() {
        use futures::FutureExt;

        let runtime = super::super::runtime::Runtime::remote();
        let (requests, mut calls) = mesh::channel();
        let (lifecycle, mut refreshes) = mesh::channel();
        let definitions = definitions();
        let routes = register_supervised_routes(
            SupervisedConnection {
                initial: WorkerGeneration::new(0, requests, &definitions),
                lifecycle,
                worker_index: 0,
            },
            &definitions,
            runtime.clone(),
        )
        .unwrap();
        runtime.stop().unwrap();
        assert!(
            routes
                .inner()
                .call_host_function("HostAdd", (1_i32, 2_i32).into_value())
                .is_err()
        );
        assert!(
            calls.next().now_or_never().is_none(),
            "Stopped route enqueued a call"
        );
        assert!(refreshes.next().now_or_never().is_none());
        assert!(!runtime.is_poisoned());
    }

    #[test]
    fn recovery_regression_initial_readiness_failure_retries_cleanup() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Instant;

        use super::super::launch::{PreparedProcess, ProcessGuard, ProcessLauncher};
        use super::super::program::{ProcessDefinition, ProgramRole};

        struct RetryGuard {
            inner: Arc<dyn ProcessGuard>,
            fail_cleanup: Arc<AtomicBool>,
        }

        impl ProcessGuard for RetryGuard {
            fn start_launch(&self) {
                self.inner.start_launch();
            }
            fn terminate_domain(&self) -> Result<()> {
                self.inner.terminate_domain()
            }
            fn wait_empty(&self, deadline: Instant) -> Result<()> {
                let result = self.inner.wait_empty(deadline);
                self.fail_cleanup.store(false, Ordering::SeqCst);
                result
            }
            fn release_resources(&self, deadline: Instant) -> Result<()> {
                self.inner.release_resources(deadline)
            }
        }

        struct RetryLauncher(Arc<RecoveryFixture>);
        impl ProcessLauncher for RetryLauncher {
            fn prepare(
                &self,
                role: ProgramRole,
                definition: &ProcessDefinition,
            ) -> Result<PreparedProcess> {
                let mut prepared = self.0.prepare(role, definition)?;
                prepared.guard = Arc::new(RetryGuard {
                    inner: prepared.guard,
                    fail_cleanup: self.0.fail_cleanup.clone(),
                });
                Ok(prepared)
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let (topology, mut launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        Arc::get_mut(&mut launcher).unwrap().args = vec![
            "--crash-once".into(),
            directory.path().join("dispatches").into_os_string(),
            "non-idempotent".into(),
        ];
        launcher.fail_cleanup.store(true, Ordering::SeqCst);
        assert!(
            super::super::runtime::Runtime::start_workers(
                topology.workers(),
                Arc::new(RetryLauncher(launcher.clone())),
                Default::default(),
            )
            .is_err()
        );
        assert!(launcher.guards.lock().unwrap()[0].upgrade().is_none());
        assert_eq!(
            launcher
                .lifecycle
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "release")
                .count(),
            1
        );
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 1);
        assert!(!directory.path().join("dispatches").exists());
    }

    #[test]
    fn recovery_regression_unconfirmed_launch_survives_constructor_and_rpc_errors() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        use super::super::launch::{PreparedProcess, ProcessLauncher};
        use super::super::program::{ProcessDefinition, ProgramRole};

        struct MissingExecutable {
            launcher: Arc<RecoveryFixture>,
            missing: std::path::PathBuf,
            first: bool,
        }
        impl ProcessLauncher for MissingExecutable {
            fn prepare(
                &self,
                role: ProgramRole,
                definition: &ProcessDefinition,
            ) -> Result<PreparedProcess> {
                let mut prepared = self.launcher.prepare(role, definition)?;
                if self.first || self.launcher.prepares.load(Ordering::SeqCst) > 1 {
                    self.launcher.fail_cleanup.store(true, Ordering::SeqCst);
                    prepared.config = prepared.config.process_name(&self.missing);
                }
                Ok(prepared)
            }
        }

        for initial in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) =
                recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
            let result = super::super::runtime::Runtime::start_workers(
                topology.workers(),
                Arc::new(MissingExecutable {
                    launcher: launcher.clone(),
                    missing: directory.path().join("missing-worker"),
                    first: initial,
                }),
                super::super::runtime::RestartPolicy {
                    initial_backoff: Duration::from_millis(1),
                    ..Default::default()
                },
            );
            if initial {
                let error = result.err().expect("Missing initial executable must fail");
                let guard = launcher.guards.lock().unwrap()[0].clone();
                assert!(
                    guard.upgrade().is_some(),
                    "Constructor error lost pending launch ownership"
                );
                assert!(!launcher.lifecycle.lock().unwrap().contains(&"release"));
                launcher.fail_cleanup.store(false, Ordering::SeqCst);
                drop(error);
                assert!(guard.upgrade().is_none());
            } else {
                let runtime = result.unwrap();
                let (connections, supervisor) = supervised_connections(runtime.clone(), 1).unwrap();
                let error = futures_lite::future::block_on(
                    connections[0]
                        .lifecycle
                        .call(LifecycleRequest::Refresh, (0, 0)),
                )
                .unwrap()
                .err()
                .expect("Missing replacement must fail");
                drop(error);
                let guard = launcher.guards.lock().unwrap()[1].clone();
                assert!(
                    guard.upgrade().is_some(),
                    "RPC error consumed pending launch ownership"
                );
                assert!(runtime.is_poisoned());
                launcher.fail_cleanup.store(false, Ordering::SeqCst);
                runtime.stop().unwrap();
                runtime.stop().unwrap();
                assert!(guard.upgrade().is_none());
                drop(supervisor);
            }
            assert_eq!(
                launcher
                    .lifecycle
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == "release")
                    .count(),
                if initial { 1 } else { 2 }
            );
        }
    }

    #[test]
    fn local_guest_startup_failure_retains_worker_cleanup() {
        use std::sync::atomic::Ordering;

        for fail_cleanup in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) =
                recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
            let mut functions = HostFunctions::default();
            super::super::runtime::start_with_policy(
                topology,
                launcher.clone(),
                &mut functions,
                Default::default(),
            )
            .unwrap();
            launcher.fail_cleanup.store(fail_cleanup, Ordering::SeqCst);
            let error = crate::SandboxBuilder::from_bytes(vec![0])
                .started_process_functions(functions)
                .build()
                .expect_err("Malformed guest must fail after worker startup");
            let guard = launcher.guards.lock().unwrap()[0].clone();
            assert_eq!(
                super::super::launch::has_cleanup_owner(&error),
                fail_cleanup
            );
            assert_eq!(guard.upgrade().is_some(), fail_cleanup);
            assert_eq!(
                launcher.lifecycle.lock().unwrap().contains(&"release"),
                !fail_cleanup,
            );
            launcher.fail_cleanup.store(false, Ordering::SeqCst);
            drop(error);
            assert!(guard.upgrade().is_none());
            assert_eq!(
                launcher
                    .lifecycle
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == "release")
                    .count(),
                1,
            );
        }
    }

    #[test]
    fn recovery_regression_failed_readiness_error_retains_runtime_until_drop() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        let directory = tempfile::tempdir().unwrap();
        let (topology, mut launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        Arc::get_mut(&mut launcher).unwrap().args = vec![
            "--crash-once".into(),
            directory.path().join("dispatches").into_os_string(),
            "non-idempotent".into(),
        ];
        launcher.fail_cleanup.store(true, Ordering::SeqCst);
        let error = super::super::runtime::Runtime::start_workers(
            topology.workers(),
            launcher.clone(),
            Default::default(),
        )
        .err()
        .expect("Readiness rejection must fail");
        let guard = launcher.guards.lock().unwrap()[0].clone();
        assert!(guard.upgrade().is_some());
        assert!(!launcher.lifecycle.lock().unwrap().contains(&"release"));
        launcher.fail_cleanup.store(false, Ordering::SeqCst);
        drop(error);
        assert!(guard.upgrade().is_none());
        assert_eq!(
            launcher
                .lifecycle
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "release")
                .count(),
            1
        );
    }

    #[test]
    fn recovery_prepares_every_program_before_launch_and_rolls_back_partial_startup() {
        for fail_validation in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) = recovery_fixture(
                directory.path(),
                "--crash-once",
                Idempotency::Idempotent,
                fail_validation,
                !fail_validation,
            );
            // Each fixture declares the same manifest. The second launch either
            // fails preparation or deliberately supplies a different manifest.
            let definition = topology.workers()[0].clone();
            let result = super::super::runtime::Runtime::start_workers(
                &[definition.clone(), definition],
                launcher.clone(),
                Default::default(),
            );
            assert!(result.is_err());
            let events = launcher.lifecycle.lock().unwrap().clone();
            if fail_validation {
                assert_eq!(events, ["prepare", "prepare"]);
            } else {
                assert_eq!(
                    events,
                    [
                        "prepare",
                        "prepare",
                        "terminate",
                        "terminate",
                        "empty",
                        "release",
                        "terminate",
                        "terminate",
                        "empty",
                        "release"
                    ]
                );
            }
            assert!(!directory.path().join("dispatches").exists());
        }
    }

    #[test]
    fn recovery_never_replays_ambiguous_unmarked_or_non_idempotent_calls() {
        for idempotency in [Idempotency::Unspecified, Idempotency::NonIdempotent] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) =
                recovery_fixture(directory.path(), "--crash-once", idempotency, false, false);
            let runtime = recovery_runtime(&topology, launcher.clone());
            let contract = &topology.workers()[0].functions()[0];
            let error =
                recovery_call(&runtime, contract, (10_i32, 32_i32).into_value()).unwrap_err();
            assert!(error.to_string().contains("replay is forbidden"), "{error}");
            assert_eq!(dispatch_count(directory.path()), 1);
            assert_eq!(
                launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                2
            );
            let result = recovery_call(&runtime, contract, (10_i32, 32_i32).into_value()).unwrap();
            assert_eq!(i32::try_from(result).unwrap(), 42);
            assert_eq!(dispatch_count(directory.path()), 2);
            assert!(!runtime.is_poisoned());
        }
    }

    #[test]
    fn recovery_can_dispatch_unmarked_call_after_proven_pre_enqueue_death() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Unspecified,
            false,
            false,
        );
        // The test externally kills the idle root. The dispatch itself must not crash.
        std::fs::write(directory.path().join("dispatches"), b"").unwrap();
        let runtime = recovery_runtime(&topology, launcher.clone());
        runtime.terminate_fixture_root(0);
        let result = recovery_call(
            &runtime,
            &topology.workers()[0].functions()[0],
            (10_i32, 32_i32).into_value(),
        )
        .unwrap();
        assert_eq!(i32::try_from(result).unwrap(), 42);
        assert_eq!(dispatch_count(directory.path()), 1);
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    #[test]
    fn recovery_exhaustion_poisons_owner_without_affecting_sibling() {
        let failing_directory = tempfile::tempdir().unwrap();
        let healthy_directory = tempfile::tempdir().unwrap();
        let (failing, launcher) = recovery_fixture(
            failing_directory.path(),
            "--crash-always",
            Idempotency::Idempotent,
            false,
            false,
        );
        let (healthy, healthy_launcher) = recovery_fixture(
            healthy_directory.path(),
            "",
            Idempotency::Idempotent,
            false,
            false,
        );
        let failing_runtime = recovery_runtime(&failing, launcher.clone());
        let healthy_runtime = recovery_runtime(&healthy, healthy_launcher.clone());
        let healthy_pid = healthy_runtime.reports()[0].root_process_id;
        let contract = &failing.workers()[0].functions()[0];
        let error =
            recovery_call(&failing_runtime, contract, (1_i32, 2_i32).into_value()).unwrap_err();
        assert!(error.to_string().contains("budget exhausted"), "{error}");
        assert!(failing_runtime.is_poisoned());
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            4
        );
        assert_eq!(dispatch_count(failing_directory.path()), 4);
        assert!(recovery_call(&failing_runtime, contract, (1_i32, 2_i32).into_value()).is_err());
        assert_eq!(dispatch_count(failing_directory.path()), 4);
        let result = recovery_call(
            &healthy_runtime,
            &healthy.workers()[0].functions()[0],
            (10_i32, 32_i32).into_value(),
        )
        .unwrap();
        assert_eq!(i32::try_from(result).unwrap(), 42);
        assert_eq!(healthy_pid, healthy_runtime.reports()[0].root_process_id);
        assert!(!healthy_runtime.is_poisoned());
        assert_eq!(
            healthy_launcher
                .prepares
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn recovery_reverifies_program_and_exact_manifest_before_replay() {
        for change_manifest in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) = recovery_fixture(
                directory.path(),
                "--crash-once",
                Idempotency::Idempotent,
                !change_manifest,
                change_manifest,
            );
            let runtime = recovery_runtime(&topology, launcher.clone());
            let error = recovery_call(
                &runtime,
                &topology.workers()[0].functions()[0],
                (1_i32, 2_i32).into_value(),
            )
            .unwrap_err();
            assert!(error.to_string().contains("budget exhausted"), "{error}");
            assert_eq!(
                launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                4
            );
            assert_eq!(dispatch_count(directory.path()), 1);
            assert!(runtime.is_poisoned());
        }
    }

    #[test]
    fn recovery_intentional_shutdown_does_not_consume_restart_budget() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        let mut runtime = recovery_runtime(&topology, launcher.clone());
        std::sync::Arc::get_mut(&mut runtime)
            .unwrap()
            .shutdown()
            .unwrap();
        assert!(
            recovery_call(
                &runtime,
                &topology.workers()[0].functions()[0],
                (1_i32, 2_i32).into_value()
            )
            .is_err()
        );
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(!runtime.is_poisoned());
    }

    #[test]
    fn recovery_exhaustion_is_terminal_only_for_owning_guest_sandbox() {
        use crate::sandbox::initialized_multi_use::SandboxStatus;
        let failing_directory = tempfile::tempdir().unwrap();
        let healthy_directory = tempfile::tempdir().unwrap();
        let build = |directory: &std::path::Path, mode| {
            let (topology, launcher) =
                recovery_fixture(directory, mode, Idempotency::Idempotent, false, false);
            let mut functions = HostFunctions::default();
            super::super::runtime::start_with_policy(
                topology,
                launcher,
                &mut functions,
                super::super::runtime::RestartPolicy {
                    initial_backoff: Duration::from_millis(1),
                    max_backoff: Duration::from_millis(4),
                    ..Default::default()
                },
            )
            .unwrap();
            // Production initializes the process runtime inside build(), after
            // collecting user functions. Install this trusted fixture at that seam.
            let mut sandbox = crate::UninitializedSandbox::new(
                crate::GuestBinary::FilePath(hyperlight_testing::simple_guest_as_pathbuf()),
                None,
            )
            .unwrap();
            sandbox.host_funcs = std::sync::Arc::new(std::sync::Mutex::new(functions.into_inner()));
            sandbox.evolve().unwrap()
        };
        let mut failing = build(failing_directory.path(), "--crash-always");
        let mut healthy = build(healthy_directory.path(), "");
        let snapshot = failing.snapshot().unwrap();
        assert!(failing.call::<i32>("Add", (10_i32, 32_i32)).is_err());
        assert_eq!(failing.status(), SandboxStatus::Unrecoverable);
        assert!(failing.restore(snapshot).is_err());
        assert_eq!(healthy.call::<i32>("Add", (10_i32, 32_i32)).unwrap(), 42);
        assert!(healthy.status().is_ready());
        assert_eq!(dispatch_count(failing_directory.path()), 4);
    }

    #[test]
    fn recovery_direct_generation_refresh_and_cancels_blocked_native_call() {
        for mode in ["--crash-once", "--block-native"] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) = recovery_fixture(
                directory.path(),
                mode,
                Idempotency::Idempotent,
                false,
                false,
            );
            let runtime = recovery_runtime(&topology, launcher.clone());
            let (mut connections, _supervisor) =
                supervised_connections(runtime.clone(), 1).unwrap();
            let connection = connections.remove(0);
            let connection =
                mesh::OwnedMessage::serialized(mesh::OwnedMessage::new(connection).serialize())
                    .parse::<SupervisedConnection>()
                    .unwrap();
            let client = super::super::runtime::Runtime::new().unwrap();
            let functions = register_supervised_routes(
                connection,
                topology.workers()[0].functions(),
                client.clone(),
            )
            .unwrap();
            if mode == "--crash-once" {
                let result = functions
                    .inner()
                    .call_host_function("HostAdd", (10_i32, 32_i32).into_value())
                    .unwrap();
                assert_eq!(i32::try_from(result).unwrap(), 42);
                assert_eq!(dispatch_count(directory.path()), 2);
                assert_eq!(runtime.worker_generation(0).unwrap().number, 1);
                // Repeated refreshes for a stale generation reuse the verified
                // endpoint instead of consuming another restart.
                assert_eq!(runtime.refresh_worker(0, 0).unwrap().number, 1);
                assert_eq!(
                    launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                    2
                );
                client.stop().unwrap();
                runtime.stop().unwrap();
            } else {
                let pending = std::thread::spawn(move || {
                    functions
                        .inner()
                        .call_host_function("HostAdd", (10_i32, 32_i32).into_value())
                });
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while !directory.path().join("dispatches").is_file() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "Worker never entered native call"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                let start = std::time::Instant::now();
                client.stop().unwrap();
                runtime.stop().unwrap();
                assert!(start.elapsed() < Duration::from_secs(35));
                assert!(pending.join().unwrap().is_err());
                assert_eq!(
                    launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                    1
                );
                assert!(!runtime.is_poisoned());
                assert!(!client.is_poisoned());
            }
        }
    }

    #[test]
    fn recovery_direct_routes_never_replay_ambiguous_unmarked_calls() {
        for idempotency in [Idempotency::Unspecified, Idempotency::NonIdempotent] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) =
                recovery_fixture(directory.path(), "--crash-once", idempotency, false, false);
            let owner = recovery_runtime(&topology, launcher.clone());
            let client = super::super::runtime::Runtime::new().unwrap();
            let (mut connections, _supervisor) = supervised_connections(owner.clone(), 1).unwrap();
            let routes = register_supervised_routes(
                connections.remove(0),
                topology.workers()[0].functions(),
                client.clone(),
            )
            .unwrap();
            let error = routes
                .inner()
                .call_host_function("HostAdd", (10_i32, 32_i32).into_value())
                .unwrap_err();
            assert!(error.to_string().contains("replay is forbidden"), "{error}");
            assert_eq!(dispatch_count(directory.path()), 1);
            assert_eq!(
                launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                2
            );
            let result = routes
                .inner()
                .call_host_function("HostAdd", (10_i32, 32_i32).into_value())
                .unwrap();
            assert_eq!(i32::try_from(result).unwrap(), 42);
            assert_eq!(dispatch_count(directory.path()), 2);
            assert!(!client.is_poisoned());
            owner.stop().unwrap();
        }
    }

    #[test]
    fn recovery_direct_exhaustion_poisons_vm_without_parent_call_relay() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-always",
            Idempotency::Idempotent,
            false,
            false,
        );
        let owner = recovery_runtime(&topology, launcher.clone());
        let client = super::super::runtime::Runtime::new().unwrap();
        let (mut connections, _supervisor) = supervised_connections(owner.clone(), 1).unwrap();
        let routes = register_supervised_routes(
            connections.remove(0),
            topology.workers()[0].functions(),
            client.clone(),
        )
        .unwrap();
        assert!(
            routes
                .inner()
                .call_host_function("HostAdd", (1_i32, 2_i32).into_value())
                .is_err()
        );
        assert!(owner.is_poisoned());
        assert!(client.is_poisoned());
        assert_eq!(dispatch_count(directory.path()), 4);
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            4
        );
        owner.stop().unwrap();
    }

    #[test]
    fn recovery_idle_lifecycle_endpoint_does_not_keep_owner_alive() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        let owner = recovery_runtime(&topology, launcher);
        let (mut connections, supervisor) = supervised_connections(owner.clone(), 1).unwrap();
        let connection = connections.remove(0);
        let weak = std::sync::Arc::downgrade(&owner);
        drop(owner);
        drop(supervisor);
        assert!(weak.upgrade().is_none());
        let response = futures_lite::future::block_on(
            connection.lifecycle.call(LifecycleRequest::Refresh, (0, 0)),
        );
        assert!(response.is_err() || response.unwrap().is_err());
    }

    #[test]
    fn recovery_direct_routes_reject_changed_manifest_or_stale_generation_before_replay() {
        for change_manifest in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) = recovery_fixture(
                directory.path(),
                "--crash-once",
                Idempotency::Idempotent,
                false,
                false,
            );
            let owner = recovery_runtime(&topology, launcher.clone());
            let initial = owner.worker_generation(0).unwrap();
            let mut replacement = owner.worker_generation(0).unwrap();
            if change_manifest {
                replacement.number = 1;
                replacement.contracts[0].idempotency = 1;
            }
            let (lifecycle, mut receive) = mesh::channel();
            let responder = std::thread::spawn(move || {
                futures_lite::future::block_on(async move {
                    let LifecycleRequest::Refresh(refresh) = receive.next().await.unwrap();
                    refresh.handle_sync(|generation| {
                        assert_eq!(generation, (0, 0));
                        Ok(replacement)
                    });
                });
            });
            let client = super::super::runtime::Runtime::new().unwrap();
            let routes = register_supervised_routes(
                SupervisedConnection {
                    initial,
                    lifecycle,
                    worker_index: 0,
                },
                topology.workers()[0].functions(),
                client.clone(),
            )
            .unwrap();
            let error = routes
                .inner()
                .call_host_function("HostAdd", (1_i32, 2_i32).into_value())
                .unwrap_err();
            assert!(
                error.to_string().contains("immutable manifest mismatch"),
                "{error}"
            );
            assert!(client.is_poisoned());
            assert_eq!(dispatch_count(directory.path()), 1);
            assert_eq!(
                launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            responder.join().unwrap();
            owner.stop().unwrap();
        }
    }

    #[test]
    fn snapshot_captures_runtime_owners_and_reconstructs_owned_signatures() {
        futures::executor::block_on(async {
            snapshot_roundtrip();
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn snapshot_runtime_progresses_with_blocked_tokio_reactor() {
        snapshot_roundtrip();
    }

    fn snapshot_roundtrip() {
        use super::super::program::{
            LocalProgramStore, ProcessDefinition, ProcessTopologyDefinition, ProgramConfig,
            ProgramRole, ProgramTarget,
        };
        use super::super::{ProcessControl, ProcessProfile, RequestedControl, runtime};
        use crate::func::Registerable;

        let directory = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(directory.path());
        let program = store
            .package(
                &ProgramConfig {
                    schema_version: 1,
                    role: ProgramRole::FunctionWorker,
                    target: ProgramTarget::current(Default::default()),
                    functions: definitions(),
                },
                &std::fs::read(fixture_path()).unwrap(),
            )
            .unwrap();
        let profile = ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        }]);
        // Prepared fixtures qualify routing and snapshots, not containment.
        let topology = ProcessTopologyDefinition::new(
            None,
            vec![
                ProcessDefinition::new("arithmetic", program.clone(), &profile, definitions())
                    .unwrap(),
            ],
        )
        .unwrap();
        let launch = |definition| {
            let mut functions = HostFunctions::default();
            runtime::start_prepared(definition, vec![fixture_config()], &mut functions).unwrap();
            functions
        };
        let functions = launch(topology.clone());
        let mut uninitialized = crate::UninitializedSandbox::new(
            crate::GuestBinary::FilePath(hyperlight_testing::simple_guest_as_pathbuf()),
            None,
        )
        .unwrap();
        uninitialized.host_funcs =
            std::sync::Arc::new(std::sync::Mutex::new(functions.into_inner()));
        let mut sandbox = uninitialized.evolve().unwrap();
        let process_id = |sandbox: &crate::MultiUseSandbox| {
            u32::try_from(
                sandbox
                    .host_funcs
                    .lock()
                    .unwrap()
                    .call_host_function(PID.definition.name, Vec::new())
                    .unwrap(),
            )
            .unwrap()
        };
        let original_pid = process_id(&sandbox);
        let snapshot = sandbox.snapshot().unwrap();
        assert_eq!(snapshot.process_topology(), Some(&topology));
        assert!(
            crate::SandboxBuilder::from_snapshot(snapshot.clone())
                .build()
                .unwrap_err()
                .to_string()
                .contains("requires a MeshProcessProvider capability")
        );
        sandbox.restore(snapshot.clone()).unwrap();
        assert_eq!(process_id(&sandbox), original_pid);
        assert!(
            sandbox
                .register_host_function(ADD.definition.name, |a: i32, b: i32| a + b)
                .is_err()
        );
        assert_eq!(sandbox.call::<i32>("Add", (10, 32)).unwrap(), 42);

        let local_functions = || {
            let mut functions = HostFunctions::default();
            functions
                .register_host_function(ADD.definition.name, |a: i32, b: i32| a + b)
                .unwrap();
            functions
                .register_host_function(PID.definition.name, std::process::id)
                .unwrap();
            functions
        };
        assert!(
            crate::MultiUseSandbox::from_snapshot(snapshot.clone(), local_functions(), None)
                .unwrap_err()
                .to_string()
                .contains("process topology")
        );
        assert!(
            crate::SandboxBuilder::from_snapshot(snapshot.clone())
                .host_functions(local_functions())
                .build()
                .unwrap_err()
                .to_string()
                .contains("process topology")
        );
        let mut local =
            crate::SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
                .host_functions(local_functions())
                .build()
                .unwrap();
        assert!(
            local
                .restore(snapshot.clone())
                .unwrap_err()
                .to_string()
                .contains("process topology")
        );
        assert!(local.status().is_ready());
        assert_eq!(local.call::<i32>("Add", (10, 32)).unwrap(), 42);

        let guest_only = local.snapshot().unwrap();
        assert!(guest_only.process_topology().is_none());
        sandbox.restore(guest_only).unwrap();
        assert_eq!(
            sandbox.snapshot().unwrap().process_topology(),
            Some(&topology)
        );
        assert_eq!(process_id(&sandbox), original_pid);
        assert_eq!(sandbox.call::<i32>("Add", (12, 30)).unwrap(), 42);

        let wrong_owner = ProcessTopologyDefinition::new(
            None,
            vec![
                ProcessDefinition::new("different-owner", program, &profile, definitions())
                    .unwrap(),
            ],
        )
        .unwrap();
        assert!(
            crate::MultiUseSandbox::from_snapshot(snapshot.clone(), launch(wrong_owner), None)
                .unwrap_err()
                .to_string()
                .contains("process topology")
        );
        let parsed = serde_json::from_slice(
            &serde_json::to_vec(snapshot.process_topology().unwrap()).unwrap(),
        )
        .unwrap();
        let mut restored =
            crate::MultiUseSandbox::from_snapshot(snapshot, launch(parsed), None).unwrap();
        assert_ne!(process_id(&restored), original_pid);
        assert_eq!(restored.call::<i32>("Add", (10, 32)).unwrap(), 42);
        assert_eq!(
            restored.snapshot().unwrap().process_topology(),
            Some(&topology)
        );
    }

    async fn run_fixture(with_guest: bool) {
        let runtime = super::super::runtime::Runtime::new().unwrap();
        let (send, requests) = mesh::channel();
        let (ready, readiness) = mesh::oneshot();
        let config = fixture_config();
        let bootstrap = Bootstrap {
            version: PROTOCOL_VERSION,
            contracts: vec![
                WireContract::from(&ADD.definition),
                WireContract::from(&PID.definition),
            ],
            requests,
            ready,
        };
        let pid = runtime
            .launch(config, bootstrap, send.clone())
            .await
            .unwrap();
        let exchange = tokio::time::timeout(Duration::from_secs(30), async {
            let registrations =
                register_ready_routes(send.clone(), readiness, &definitions(), runtime.clone())
                    .await
                    .unwrap();
            let child_pid = call_fixture(&send, PID, ()).await.unwrap();
            assert_eq!(child_pid, u32::try_from(pid).unwrap());
            assert_ne!(child_pid, std::process::id());
            assert_eq!(call_fixture(&send, ADD, (10, 32)).await.unwrap(), 42);
            if with_guest {
                tokio::task::spawn_blocking(move || {
                    let mut sandbox = crate::SandboxBuilder::from_file(
                        hyperlight_testing::simple_guest_as_pathbuf(),
                    )
                    .host_functions(registrations)
                    .build()
                    .unwrap();
                    for i in 0_i32..10 {
                        assert_eq!(sandbox.call::<i32>("Add", (i, 32)).unwrap(), i + 32);
                    }
                })
                .await
                .unwrap();
            }
            send.call(Request::Stop, ()).await.unwrap();
        })
        .await;
        drop(send);
        drop(runtime);
        exchange.expect("Mesh child request timed out");
    }

    #[tokio::test]
    async fn owned_cleanup_reaps_blocked_startup_and_native_call() {
        for mode in ["--block-before-run", "--block-native"] {
            let mut runtime = super::super::runtime::Runtime::new().unwrap();
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("entered");
            let config = fixture_config().args([mode.into(), marker.clone().into_os_string()]);
            let (send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            runtime
                .launch(
                    config,
                    bootstrap(&definitions(), requests, ready),
                    send.clone(),
                )
                .await
                .unwrap();
            let pending = if mode == "--block-native" {
                readiness.await.unwrap().unwrap();
                let call = FunctionCall::new(
                    ADD.definition.name.to_owned(),
                    Some((1_i32, 2_i32).into_value()),
                    FunctionCallType::Host,
                    ADD.definition.output,
                );
                let mut buffer = flatbuffers::FlatBufferBuilder::new();
                Some(send.call(Request::Call, call.encode(&mut buffer).to_vec()))
            } else {
                None
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                while !marker.is_file() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("Child never entered the blocking operation");
            let start = std::time::Instant::now();
            // Cleanup must progress while both calling executors are blocked.
            futures::executor::block_on(async {
                std::sync::Arc::get_mut(&mut runtime)
                    .unwrap()
                    .shutdown()
                    .unwrap();
            });
            assert!(start.elapsed() < Duration::from_secs(40));
            if let Some(pending) = pending {
                assert!(pending.await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn owned_cleanup_rolls_back_partial_startup() {
        let mut runtime = super::super::runtime::Runtime::new().unwrap();
        let mut routes = Vec::new();
        for valid in [true, false] {
            let (send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            let mut definitions = definitions();
            if !valid {
                definitions.pop();
            }
            runtime
                .launch(
                    fixture_config(),
                    bootstrap(&definitions, requests, ready),
                    send.clone(),
                )
                .await
                .unwrap();
            let result =
                register_ready_routes(send, readiness, &definitions, runtime.clone()).await;
            if valid {
                routes.push(result.unwrap());
            } else {
                assert!(result.is_err());
            }
        }
        drop(routes);
        futures::executor::block_on(async {
            std::sync::Arc::get_mut(&mut runtime)
                .unwrap()
                .shutdown()
                .unwrap();
        });
    }

    async fn call_fixture<A: ParameterTuple, O: SupportedReturnType>(
        send: &mesh::Sender<Request>,
        contract: HostFunctionContract<A, O>,
        parameters: A,
    ) -> Result<O> {
        let value = invoke(
            send,
            &FunctionContractDefinition::from_contract(&contract),
            parameters.into_value(),
        )
        .await?;
        Ok(O::from_value(value)?)
    }

    #[test]
    fn mesh_transports_registered_call_and_stop() {
        futures::executor::block_on(async {
            let contract =
                HostFunctionContract::<(i32, i32), i32>::new("Add", Idempotency::Idempotent);
            let mut functions = ProcessHostFunctions::default();
            functions.bind(contract, |a: i32, b: i32| a + b).unwrap();
            let (send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            let bootstrap = Bootstrap {
                version: PROTOCOL_VERSION,
                contracts: vec![WireContract::from(&contract.definition)],
                requests,
                ready,
            };
            // Encode/decode exercises transferable endpoints, not only local messages.
            let bootstrap =
                mesh::OwnedMessage::serialized(mesh::OwnedMessage::new(bootstrap).serialize())
                    .parse()
                    .unwrap();
            let client = async {
                readiness.await.unwrap().unwrap();
                let call = FunctionCall::new(
                    "Add".to_owned(),
                    Some((10_i32, 32_i32).into_value()),
                    FunctionCallType::Host,
                    <i32 as SupportedReturnType>::TYPE,
                );
                let mut buffer = flatbuffers::FlatBufferBuilder::new();
                let response = send
                    .call(Request::Call, call.encode(&mut buffer).to_vec())
                    .await
                    .unwrap()
                    .unwrap();
                let value = FunctionCallResult::try_from(response.as_slice())
                    .unwrap()
                    .into_inner()
                    .unwrap();
                assert_eq!(<i32 as SupportedReturnType>::from_value(value).unwrap(), 42);
                send.call(Request::Stop, ()).await.unwrap();
            };
            let (result, ()) = futures::join!(functions.serve(bootstrap), client);
            result.unwrap();
        });
    }

    #[test]
    fn manifest_mismatch_never_reports_ready() {
        futures::executor::block_on(async {
            let functions = ProcessHostFunctions::default();
            let (_send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            let bootstrap = Bootstrap {
                version: PROTOCOL_VERSION + 1,
                contracts: vec![],
                requests,
                ready,
            };
            assert!(functions.serve(bootstrap).await.is_err());
            assert!(readiness.await.unwrap().is_err());
        });
    }

    #[test]
    fn malformed_calls_do_not_execute_implementation() {
        let mut functions = ProcessHostFunctions::default();
        functions
            .bind(
                HostFunctionContract::<(), i32>::new("Fail", Idempotency::Unspecified),
                || -> i32 { panic!("invalid call reached user code") },
            )
            .unwrap();
        assert!(functions.dispatch(&[]).is_err());
        for (name, kind, result, parameters) in [
            (
                "Fail",
                FunctionCallType::Guest,
                <i32 as SupportedReturnType>::TYPE,
                None,
            ),
            (
                "Unknown",
                FunctionCallType::Host,
                <i32 as SupportedReturnType>::TYPE,
                None,
            ),
            (
                "Fail",
                FunctionCallType::Host,
                <u64 as SupportedReturnType>::TYPE,
                None,
            ),
            (
                "Fail",
                FunctionCallType::Host,
                <i32 as SupportedReturnType>::TYPE,
                Some((7_i32,).into_value()),
            ),
        ] {
            let call = FunctionCall::new(name.to_owned(), parameters, kind, result);
            let mut buffer = flatbuffers::FlatBufferBuilder::new();
            assert!(functions.dispatch(call.encode(&mut buffer)).is_err());
        }
    }
}
