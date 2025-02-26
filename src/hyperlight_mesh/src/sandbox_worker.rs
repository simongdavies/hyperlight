use std::sync::{Arc, Mutex};

use anyhow::Result;
use futures::FutureExt;
use futures_concurrency::future::Race;
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use mesh::error::RemoteError;
use mesh::rpc::{FailableRpc, RpcSend};
use mesh::MeshPayload;
use mesh_worker::{Worker, WorkerId, WorkerRpc};

use super::host_functions::{HostFunctionCall, HostFunctionWorkerRpc, RegisterHostFunctionHandler};
use super::sandbox_mesh::get_runtime;
use crate::host_functions::HostFunctionWorkerHandler;
use super::mesh_sandbox_builder::MeshSandboxConfiguration;
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox, SandboxRunOptions, UninitializedSandbox};

pub(crate) const SANDBOX_WORKER_ID: WorkerId<SandboxWorkerParameters> =
    WorkerId::new("SandboxWorker");

#[derive(MeshPayload)]
pub(crate) struct SandboxWorkerParameters {
    sandbox_rpc_rx: mesh::Receiver<SandboxWorkerRpc>,
    host_function_rpc_tx: Arc<mesh::Sender<HostFunctionWorkerRpc>>,
}

impl SandboxWorkerParameters {
    pub(crate) fn new(
        sandbox_rpc_rx: mesh::Receiver<SandboxWorkerRpc>,
        host_function_rpc_tx: Arc<mesh::Sender<HostFunctionWorkerRpc>>,
    ) -> Self {
        Self {
            sandbox_rpc_rx,
            host_function_rpc_tx,
        }
    }
}

#[derive(MeshPayload)]
pub(crate) struct GuestFunctionCall {
    function_name: String,
    function_return_type: ReturnType,
    function_args: Option<Vec<ParameterValue>>,
}

impl GuestFunctionCall {
    pub(crate) fn new(
        function_name: String,
        function_return_type: ReturnType,
        function_args: Option<Vec<ParameterValue>>,
    ) -> Self {
        Self {
            function_name,
            function_return_type,
            function_args,
        }
    }
}

#[derive(MeshPayload)]
pub(crate) enum SandboxWorkerRpc {
    CreateSandbox(FailableRpc<MeshSandboxConfiguration, ()>),
    CallGuestFunction(FailableRpc<GuestFunctionCall, ReturnValue>),
}

pub(super) struct SandboxWorker {
    sandbox_rpc_rx: mesh::Receiver<SandboxWorkerRpc>,
    sandbox: Option<MultiUseSandbox>,
    host_function_rpc_tx: Arc<mesh::Sender<HostFunctionWorkerRpc>>,
}

impl Worker for SandboxWorker {
    type Parameters = SandboxWorkerParameters;
    type State = ();
    const ID: mesh_worker::WorkerId<Self::Parameters> = SANDBOX_WORKER_ID;

    fn new(parameters: Self::Parameters) -> Result<Self> {
        let sandbox_rpc_rx = parameters.sandbox_rpc_rx;
        let host_function_rpc_tx = parameters.host_function_rpc_tx;
        Ok(Self {
            sandbox_rpc_rx,
            sandbox: None,
            host_function_rpc_tx,
        })
    }

    fn run(self, worker_rpc: mesh::Receiver<WorkerRpc<Self::State>>) -> anyhow::Result<()> {
        // TODO: Need to find a way of not blocking here and still being able to run the worker
        get_runtime().block_on(self.run_worker(worker_rpc))?;
        Ok(())
    }

    fn restart(_state: Self::State) -> anyhow::Result<Self> {
        todo!()
    }
}

impl SandboxWorker {
    async fn run_worker(
        mut self,
        mut worker_rpc: mesh::Receiver<WorkerRpc<()>>,
    ) -> anyhow::Result<()> {
        enum Event {
            WorkerRpc(Result<WorkerRpc<()>, mesh::RecvError>),
            SandboxWorkerRpc(Result<SandboxWorkerRpc, mesh::RecvError>),
        }

        loop {
            let event = {
                let worker_rpc = worker_rpc.recv().map(Event::WorkerRpc);
                let simple_worker_rpc = self.sandbox_rpc_rx.recv().map(Event::SandboxWorkerRpc);
                (worker_rpc, simple_worker_rpc).race().await
            };

            match event {
                Event::WorkerRpc(Ok(WorkerRpc::Stop)) => {
                    break Ok(());
                }
                Event::WorkerRpc(Ok(WorkerRpc::Restart(_state))) => {}

                Event::WorkerRpc(Ok(WorkerRpc::Inspect(_))) => {
                    unimplemented!();
                }
                Event::WorkerRpc(Err(e)) => {
                    break Err(anyhow::anyhow!("Error {:?}", e));
                }
                Event::SandboxWorkerRpc(Ok(SandboxWorkerRpc::CreateSandbox(failable_rpc))) => {
                    let res = {
                        let mesh_sandbox_configuration = failable_rpc.input();
                        let mut cfg = SandboxConfiguration::default();
                        if let Some(size) = mesh_sandbox_configuration.heap_size() {
                            cfg.set_heap_size(size);
                        }
                        if let Some(size) = mesh_sandbox_configuration.stack_size() {
                            cfg.set_stack_size(size);
                        }

                        let run_options = Some(SandboxRunOptions::RunInHypervisor);
                        let sandbox = UninitializedSandbox::new(
                            GuestBinary::FilePath(
                                mesh_sandbox_configuration.guest_binary().to_string(),
                            ),
                            Some(cfg),
                            run_options,
                            None,
                        );

                        let res = match sandbox {
                            Ok(mut sandbox) => {
                                if let Some(host_functions) =
                                    mesh_sandbox_configuration.host_functions()
                                {
                                    for host_function in host_functions {
                                        let host_function_definition =
                                            host_function.definition().clone();
                                        let function_return_type =
                                            host_function_definition.return_type;
                                        let sender = self.host_function_rpc_tx.clone();
                                        let function_name =
                                            host_function_definition.function_name.clone();

                                        let func: HostFunctionWorkerHandler = Arc::new(Mutex::new(
                                            move |args: Vec<ParameterValue>| {
                                                let args = match args.len() {
                                                    0 => None,
                                                    _ => Some(args),
                                                };

                                                let call = HostFunctionCall::new(
                                                    function_name.clone(),
                                                    function_return_type,
                                                    args,
                                                );
                                                get_runtime()
                                                    .block_on(sender.call_failable(
                                                        HostFunctionWorkerRpc::CallHostFunction,
                                                        call,
                                                    ))
                                                    .map_err(|e| {
                                                        hyperlight_error::new_error!(
                                                            "Error calling host function: {:?}",
                                                            e
                                                        )
                                                    })
                                            },
                                        ));

                                        match host_function.syscalls() {
                                            Some(_syscalls) => {
                                                #[cfg(all(
                                                    feature = "seccomp",
                                                    target_os = "linux"
                                                ))]
                                                func.register_with_extra_allowed_syscalls(
                                                    &mut sandbox,
                                                    host_function_definition.function_name.as_str(),
                                                    host_function_definition.parameter_types,
                                                    host_function_definition.return_type,
                                                    _syscalls.clone(),
                                                )?;
                                            }
                                            None => {
                                                func.register(
                                                    &mut sandbox,
                                                    host_function_definition.function_name.as_str(),
                                                    host_function_definition.parameter_types,
                                                    host_function_definition.return_type,
                                                )?;
                                            }
                                        }
                                    }
                                }

                                let sandbox = sandbox.evolve(Noop::default());
                                match sandbox {
                                    Ok(sandbox) => {
                                        self.sandbox = Some(sandbox);
                                        Ok(())
                                    }
                                    Err(e) => Err(e),
                                }
                            }
                            Err(e) => Err(e),
                        };
                        res
                    };
                    failable_rpc.complete(res.map_err(|e| RemoteError::new(e.to_string())))
                }
                Event::SandboxWorkerRpc(Ok(SandboxWorkerRpc::CallGuestFunction(failable_rpc))) => {
                    failable_rpc.handle_failable_sync(|input| {
                        let sandbox = self
                            .sandbox
                            .as_mut()
                            .ok_or_else(|| anyhow::anyhow!("Sandbox not created"))?;
                        sandbox.call_guest_function_by_name(
                            &input.function_name,
                            input.function_return_type,
                            input.function_args,
                        )
                    });
                }
                Event::SandboxWorkerRpc(Err(e)) => {
                    break Err(anyhow::anyhow!("Error {:?}", e));
                }
            }
        }
    }
}
