use std::sync::Arc;

use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use mesh::rpc::RpcSend;
use mesh_worker::WorkerHandle;

use super::mesh_sandbox_builder::HostFunction;
use crate::mesh::host_functions::{HostFunctionCall, HostFunctionWorkerRpc};
use crate::mesh::sandbox_mesh::{get_runtime, SandboxMesh};
use crate::mesh::sandbox_worker::{GuestFunctionCall, SandboxWorkerRpc};
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
    pub(super) fn new(
        mesh_name: String,
        sandbox_worker: WorkerHandle,
        sandbox_rpc_tx: Arc<mesh::Sender<SandboxWorkerRpc>>,
        sandbox_mesh: SandboxMesh,
        host_funcs: Option<Vec<HostFunction>>,
        host_function_rpc_rx: mesh::Receiver<HostFunctionWorkerRpc>,
    ) -> MeshSandbox {
        Self::process_host_function_calls(host_function_rpc_rx, host_funcs);
        MeshSandbox {
            mesh_name,
            sandbox_worker,
            sandbox_rpc_tx,
            sandbox_mesh,
        }
    }

    /// Call a function in the sandbox
    pub fn call_function(
        &self,
        function_name: String,
        function_return_type: ReturnType,
        function_args: Option<Vec<ParameterValue>>,
    ) -> Result<ReturnValue> {
        let call = GuestFunctionCall::new(function_name, function_return_type, function_args);
        let result = get_runtime().block_on(
            self.sandbox_rpc_tx
                .call_failable(SandboxWorkerRpc::CallGuestFunction, call),
        )?;
        Ok(result)
    }

    fn process_host_function_calls(
        mut host_function_rpc_rx: mesh::Receiver<HostFunctionWorkerRpc>,
        host_funcs: Option<Vec<HostFunction>>,
    ) {
        if let Some(host_funcs) = host_funcs {
            get_runtime().spawn(async move {
                loop {
                    match host_function_rpc_rx.recv().await {
                        Ok(HostFunctionWorkerRpc::CallHostFunction(failable_rpc)) => {
                            failable_rpc.handle_failable_sync(|input| -> Result<ReturnValue> {
                                let HostFunctionCall {
                                    function_name,
                                    function_return_type: _,
                                    function_args,
                                } = input;
                                let host_function = host_funcs
                                    .iter()
                                    .find(|host_function| {
                                        host_function.definition().function_name == function_name
                                    })
                                    .ok_or_else(|| anyhow::anyhow!("Host function not found"))?;
                                let args = function_args.unwrap_or_default();
                                let function = host_function.function();
                                function.call(args)
                            });
                        }
                        Err(e) => {
                            match e {
                                mesh::RecvError::Closed => {
                                    break;
                                }
                                mesh::RecvError::Error(e) => {
                                    //TODO: Handle error
                                    eprintln!(
                                        "Error Receiving Host Function Call Message: {:?}",
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    /// Get the name of the mesh for this sandbox
    pub fn mesh_name(&self) -> &str {
        self.mesh_name.as_str()
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
    use std::sync::{Arc, Mutex};

    use hyperlight_common::flatbuffer_wrappers::function_types::{
        ParameterValue, ReturnType, ReturnValue,
    };
    use hyperlight_testing::{callback_guest_as_string, simple_guest_as_string};

    use crate::func::HostFunction2;
    use crate::sandbox::MeshSandboxBuilder;

    #[test]
    fn test_mesh_sandbox_creation() {
        let guest_binary = simple_guest_as_string().unwrap();
        let builder = MeshSandboxBuilder::new(guest_binary).set_single_process(true);
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_call_function_with_args() {
        let guest_binary = simple_guest_as_string().unwrap();
        let builder = MeshSandboxBuilder::new(guest_binary).set_single_process(true);
        let sandbox = builder.build().unwrap();
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
        let guest_binary = simple_guest_as_string().unwrap();
        let builder = MeshSandboxBuilder::new(guest_binary).set_single_process(true);
        let sandbox = builder.build().unwrap();
        assert!(sandbox.mesh_name().starts_with("sandbox_"));
    }

    #[test]
    fn test_with_heap_size() {
        let guest_binary = simple_guest_as_string().unwrap();
        let builder = MeshSandboxBuilder::new(guest_binary)
            .set_single_process(true)
            .set_heap_size(1024 * 1024);
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_stack_size() {
        let guest_binary = simple_guest_as_string().unwrap();
        let builder = MeshSandboxBuilder::new(guest_binary)
            .set_single_process(true)
            .set_stack_size(128 * 1024);
        let result = builder.build();
        assert!(result.is_ok());
    }
    #[test]
    fn test_calling_host_function() {
        let guest_binary = callback_guest_as_string().unwrap();
        let mut builder = MeshSandboxBuilder::new(guest_binary).set_single_process(true);
        // Create a host function
        let host_function = Arc::new(Mutex::new(|a: i32, b: i32| Ok(a + b)));
        host_function.register(&mut builder, "Add").unwrap();
        let sandbox = builder.build().unwrap();
        let function_name = "AddUsingHost".to_string();
        let function_return_type = ReturnType::Int;
        let function_args = Some(vec![ParameterValue::Int(5), ParameterValue::Int(10)]);
        let result = sandbox.call_function(function_name, function_return_type, function_args);
        print!("Result: {:?}", result);
        assert!(result.is_ok());
        if let ReturnValue::Int(value) = result.unwrap() {
            assert_eq!(value, 15);
        } else {
            panic!("Unexpected return value type");
        }
    }
}
