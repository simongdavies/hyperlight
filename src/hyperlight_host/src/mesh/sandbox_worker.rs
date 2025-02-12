use anyhow::Result;
use futures::executor::block_on;
use futures::FutureExt;
use futures_concurrency::future::Race;
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use mesh::error::RemoteError;
use mesh::rpc::FailableRpc;
use mesh::MeshPayload;
use mesh_worker::{Worker, WorkerId, WorkerRpc};

use crate::sandbox_state::sandbox::EvolvableSandbox;
use crate::sandbox_state::transition::Noop;
use crate::{GuestBinary, MultiUseSandbox, UninitializedSandbox};
pub(crate) const SANDBOX_WORKER_ID: WorkerId<SandboxWorkerParameters> =
    WorkerId::new("SandboxWorker");

#[derive(MeshPayload)]
pub(crate) struct SandboxWorkerParameters {
    pub rpc: mesh::Receiver<SandboxWorkerRpc>,
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
    CreateSandbox(FailableRpc<String, ()>),
    CallGuestFunction(FailableRpc<GuestFunctionCall, ReturnValue>),
}

pub(super) struct SandboxWorker {
    rpc: mesh::Receiver<SandboxWorkerRpc>,
    sandbox: Option<MultiUseSandbox>,
}

impl Worker for SandboxWorker {
    type Parameters = SandboxWorkerParameters;
    type State = ();
    const ID: mesh_worker::WorkerId<Self::Parameters> = SANDBOX_WORKER_ID;

    fn new(parameters: Self::Parameters) -> Result<Self> {
        Ok(Self {
            rpc: parameters.rpc,
            sandbox: None,
        })
    }

    fn run(self, worker_rpc: mesh::Receiver<WorkerRpc<Self::State>>) -> anyhow::Result<()> {
        block_on(self.run_worker(worker_rpc))?;
        Ok(())
    }

    fn restart(_state: Self::State) -> anyhow::Result<Self> {
        unimplemented!()
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
                let simple_worker_rpc = self.rpc.recv().map(Event::SandboxWorkerRpc);
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
                        let guest_binary = failable_rpc.input();
                        match UninitializedSandbox::new(
                            GuestBinary::FilePath(guest_binary.clone()),
                            None,
                            None,
                            None,
                        ) {
                            Ok(sandbox) => {
                                let res = match sandbox.evolve(Noop::default()) {
                                    Ok(sandbox) => {
                                        self.sandbox = Some(sandbox);
                                        Ok(())
                                    }
                                    Err(e) => Err(e),
                                };
                                res
                            }
                            Err(e) => Err(e),
                        }
                    };
                    failable_rpc.complete(res.map_err(|e| RemoteError::new(e.to_string())))
                }
                Event::SandboxWorkerRpc(Ok(SandboxWorkerRpc::CallGuestFunction(failable_rpc))) => {
                    // let res = {
                    //     //let guest_function_call = failable_rpc.input();
                    //     let sandbox = self.sandbox.as_mut().ok_or_else(|| anyhow::anyhow!("Sandbox not created"))?;
                    //     let res = match sandbox.call_guest_function_by_name(&guest_function_call.function_name, guest_function_call.function_return_type.clone(), guest_function_call.function_args){
                    //         Ok(return_value) => Ok(return_value),
                    //         Err(e) => Err(e),
                    //     };
                    //     res
                    // };

                    failable_rpc.handle_failable_sync(|input| {
                        let sandbox = self
                            .sandbox
                            .as_mut()
                            .ok_or_else(|| anyhow::anyhow!("Sandbox not created"))?;
                        sandbox.call_guest_function_by_name(
                            &input.function_name,
                            input.function_return_type.clone(),
                            input.function_args,
                        )
                    });

                    //failable_rpc.complete(res.map_err(|e| RemoteError::new(e.to_string())))
                }
                Event::SandboxWorkerRpc(Err(e)) => {
                    break Err(anyhow::anyhow!("Error {:?}", e));
                }
            }
        }
    }
}
