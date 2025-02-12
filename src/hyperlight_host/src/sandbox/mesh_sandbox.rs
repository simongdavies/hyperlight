use std::sync::Arc;

use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use mesh::rpc::RpcSend;
use mesh_worker::WorkerHandle;
use uuid::Uuid;

use crate::mesh::sandbox_mesh::{run_mesh_host, SandboxMesh};
use crate::mesh::sandbox_worker::{self, GuestFunctionCall, SandboxWorkerRpc, SANDBOX_WORKER_ID};
use crate::Result;

/// A sandbox that is created and managed in a mesh
pub struct MeshSandbox {
    mesh_name: String,
    sandbox_worker: WorkerHandle,
    sandbox_rpc_tx: Arc<mesh::Sender<SandboxWorkerRpc>>,
    sandbox_mesh: SandboxMesh,
}

impl MeshSandbox {
    /// Create a new MeshSandbox
    pub fn new(guest_binary: String, single_process: bool) -> Result<MeshSandbox> {
        let mesh_name = format!("sandbox_{}", Uuid::new_v4());
        run_mesh_host(mesh_name.as_str())?;
        let sandbox_mesh = SandboxMesh::new(single_process, &mesh_name)?;
        let (sandbox_rpc_tx, sandbox_worker) = futures::executor::block_on(async {Self::run_sandbox_worker(&sandbox_mesh).await})?;

        // Send the create sandbox rpc

        futures::executor::block_on(
            sandbox_rpc_tx.call_failable(SandboxWorkerRpc::CreateSandbox, guest_binary),
        )?;

        Ok(MeshSandbox {
            mesh_name,
            sandbox_worker,
            sandbox_rpc_tx,
            sandbox_mesh,
        })
    }

    /// Call a function in the sandbox
    pub fn call_function(
        &self,
        function_name: String,
        function_return_type: ReturnType,
        function_args: Option<Vec<ParameterValue>>,
    ) -> Result<ReturnValue> {
        let call = GuestFunctionCall::new(function_name, function_return_type, function_args);
        let result = futures::executor::block_on(
            self.sandbox_rpc_tx
                .call_failable(SandboxWorkerRpc::CallGuestFunction, call),
        )?;
        Ok(result)
    }

    /// Get the name of the mesh for this sandbox
    pub fn mesh_name(&self) -> &str {
        self.mesh_name.as_str()
    }

    async fn run_sandbox_worker(
        sandbox_mesh: &SandboxMesh,
    ) -> anyhow::Result<(Arc<mesh::Sender<SandboxWorkerRpc>>, WorkerHandle)> {
        let (sandbox_rpc_tx, sandbox_rpc_rx) = mesh::channel();
        let sandbox_rpc_tx = Arc::new(sandbox_rpc_tx);
        let sandbox_worker = {
            let sandbox_host = sandbox_mesh.create_worker_host("sandboxworkerhost").await?;
            let sandbox_worker_parameters = sandbox_worker::SandboxWorkerParameters {
                rpc: sandbox_rpc_rx,
            }; 
            sandbox_host.launch_worker(SANDBOX_WORKER_ID, sandbox_worker_parameters).await?
        };
        Ok((sandbox_rpc_tx, sandbox_worker))
    }
}

impl Drop for MeshSandbox {
    fn drop(&mut self) {
        self.sandbox_worker.stop();
        self.sandbox_mesh.shutdown();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hyperlight_common::flatbuffer_wrappers::function_types::{
        ParameterValue, ReturnType, ReturnValue,
    };
    use hyperlight_testing::simple_guest_as_string;

    #[test]
    fn test_mesh_sandbox_creation() {
        let guest_binary = simple_guest_as_string().unwrap();
        let single_process = true;
        let result = MeshSandbox::new(guest_binary, single_process);
        assert!(result.is_ok());
    }

    #[test]
    fn test_call_function_with_args() {
        let guest_binary =  simple_guest_as_string().unwrap();
        let single_process = true;
        let sandbox = MeshSandbox::new(guest_binary, single_process).unwrap();
        let function_name = "Echo".to_string();
        let function_return_type = ReturnType::String;
        let function_args = Some(vec![ParameterValue::String("Hello, World!".to_string())]);
        let result = sandbox.call_function(function_name, function_return_type, function_args);
        assert!(result.is_ok());
        if let ReturnValue::String(value) = result.unwrap() {
            assert_eq!(value, "Hello, World!");
        } else {
            panic!("Unexpected return value type");
        }
    }

    #[test]
    fn test_mesh_name() {
        let guest_binary =  simple_guest_as_string().unwrap();
        let single_process = true;
        let sandbox = MeshSandbox::new(guest_binary, single_process).unwrap();
        assert!(sandbox.mesh_name().starts_with("sandbox_"));
    }
}
