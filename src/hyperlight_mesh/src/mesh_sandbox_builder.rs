use std::sync::{Arc, Mutex};

use hyperlight_host::func::{HostFunction1, HyperlightFunction};
use hyperlight_host::sandbox::host_funcs::default_writer_func;
use hyperlight_host::sandbox::ExtraAllowedSyscall;
use hyperlight_host::sandbox_state::sandbox::HostFunctionRegistry;
use hyperlight_host::Result;
use mesh::rpc::RpcSend;
use mesh::MeshPayload;
use mesh_worker::WorkerHandle;
use uuid::Uuid;

use super::host_functions::HostFunctionWorkerRpc;
use super::sandbox_mesh::{get_runtime, run_mesh_host, SandboxMesh};
use super::sandbox_worker::{self, SandboxWorkerRpc, SANDBOX_WORKER_ID};
use super::MeshSandbox;

/// A builder for creating a MeshSandbox
pub struct MeshSandboxBuilder {
    single_process: bool,
    mesh_sandbox_configuration: MeshSandboxConfiguration,
    custom_sandbox_host_program_name: Option<String>,
}

#[derive(Clone, MeshPayload)]
pub(crate) struct HostFunction {
    host_function_definition:
        hyperlight_common::wrappers::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition,
    host_function: HyperlightFunction,
    syscalls: Option<Vec<ExtraAllowedSyscall>>,
}

impl HostFunction {
    pub(crate) fn new(
        host_function_definition: hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition,
        host_function: HyperlightFunction,
        syscalls: Option<Vec<ExtraAllowedSyscall>>,
    ) -> Self {
        Self {
            host_function_definition,
            host_function,
            syscalls,
        }
    }
    pub(crate) fn definition(
        &self,
    ) -> &hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition
    {
        &self.host_function_definition
    }

    pub(crate) fn function(&self) -> HyperlightFunction {
        self.host_function.clone()
    }

    pub(crate) fn syscalls(&self) -> Option<&Vec<ExtraAllowedSyscall>> {
        self.syscalls.as_ref()
    }
}

#[derive(Clone, MeshPayload)]
pub(crate) struct MeshSandboxConfiguration {
    guest_binary: String,
    heap_size: Option<u64>,
    stack_size: Option<u64>,
    host_functions: Option<Vec<HostFunction>>,
}

impl MeshSandboxConfiguration {
    pub fn new(guest_binary: String) -> MeshSandboxConfiguration {
        MeshSandboxConfiguration {
            guest_binary,
            heap_size: None,
            stack_size: None,
            host_functions: None,
        }
    }

    pub fn guest_binary(&self) -> &str {
        &self.guest_binary
    }

    pub fn set_heap_size(mut self, size: u64) -> Self {
        self.heap_size = Some(size);
        self
    }

    pub fn heap_size(&self) -> Option<u64> {
        self.heap_size
    }

    pub fn set_stack_size(mut self, size: u64) -> Self {
        self.stack_size = Some(size);
        self
    }

    pub fn stack_size(&self) -> Option<u64> {
        self.stack_size
    }

    pub fn host_functions(&self) -> Option<&Vec<HostFunction>> {
        self.host_functions.as_ref()
    }
}

impl MeshSandboxBuilder {
    /// Create a new MeshSandboxBuilder
    pub fn new(guest_binary: String) -> Self {
        let mesh_sandbox_configuration = MeshSandboxConfiguration::new(guest_binary);
        MeshSandboxBuilder {
            single_process: true,
            mesh_sandbox_configuration,
            custom_sandbox_host_program_name: None,
        }
    }

    /// Set whether the sandbox should run in a single process
    pub fn set_single_process(mut self, single_process: bool) -> Self {
        self.single_process = single_process;
        self
    }

    /// Set the heap size for the sandbox
    pub fn set_heap_size(mut self, size: u64) -> Self {
        self.mesh_sandbox_configuration = self.mesh_sandbox_configuration.set_heap_size(size);
        self
    }

    /// Set the stack size for the sandbox
    pub fn set_stack_size(mut self, size: u64) -> Self {
        self.mesh_sandbox_configuration = self.mesh_sandbox_configuration.set_stack_size(size);
        self
    }
    /// Set the custom sandbox host program name for the sandbox
    pub fn set_custom_sandbox_host_program_name(mut self, name: Option<String>) -> Self {
        self.custom_sandbox_host_program_name = name;
        self
    }

    /// Build the MeshSandbox
    pub fn build(&mut self) -> Result<MeshSandbox> {
        let mesh_name = format!("sandbox_{}", Uuid::new_v4());
        run_mesh_host(mesh_name.as_str())?;
        let sandbox_mesh = SandboxMesh::new(
            self.single_process,
            &mesh_name,
            self.custom_sandbox_host_program_name.clone(),
        )?;
        let (sandbox_rpc_tx, sandbox_worker, host_function_rpc_rx) =
            get_runtime().block_on(async { Self::run_sandbox_workers(&sandbox_mesh).await })?;

        // Register the default writer function

        #[cfg(all(feature = "seccomp", target_os = "linux"))]
        let extra_allowed_syscalls_for_writer_func = vec![
            libc::SYS_mmap,
            libc::SYS_brk,
            libc::SYS_mprotect,
            libc::SYS_close,
        ];
        let default_writer = Arc::new(Mutex::new(default_writer_func));
        #[cfg(all(feature = "seccomp", target_os = "linux"))]
        default_writer.register_with_extra_allowed_syscalls(
            self,
            "Writer",
            extra_allowed_syscalls_for_writer_func,
        )?;

        #[cfg(not(all(feature = "seccomp", target_os = "linux")))]
        default_writer.register(self, "Writer")?;

        // Send the create sandbox rpc

        get_runtime().block_on(sandbox_rpc_tx.call_failable(
            SandboxWorkerRpc::CreateSandbox,
            self.mesh_sandbox_configuration.clone(),
        ))?;

        Ok(MeshSandbox::new(
            mesh_name,
            sandbox_worker,
            sandbox_rpc_tx,
            sandbox_mesh,
            self.mesh_sandbox_configuration.host_functions.clone(),
            host_function_rpc_rx,
        ))
    }

    async fn run_sandbox_workers(
        sandbox_mesh: &SandboxMesh,
    ) -> anyhow::Result<(
        Arc<mesh::Sender<SandboxWorkerRpc>>,
        WorkerHandle,
        mesh::Receiver<HostFunctionWorkerRpc>,
    )> {
        let (host_function_rpc_tx, host_function_rpc_rx) = mesh::channel();
        let host_function_rpc_tx = Arc::new(host_function_rpc_tx);
        let (sandbox_rpc_tx, sandbox_rpc_rx) = mesh::channel();
        let sandbox_rpc_tx = Arc::new(sandbox_rpc_tx);
        let sandbox_worker = {
            let sandbox_host = sandbox_mesh
                .create_sandbox_worker_host("sandboxworkerhost")
                .await?;
            let sandbox_worker_parameters =
                sandbox_worker::SandboxWorkerParameters::new(sandbox_rpc_rx, host_function_rpc_tx);
            sandbox_host
                .launch_worker(SANDBOX_WORKER_ID, sandbox_worker_parameters)
                .await?
        };

        Ok((sandbox_rpc_tx, sandbox_worker, host_function_rpc_rx))
    }

    fn register_host_function(
        &mut self,
        host_function_definition: hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition,
        host_function: HyperlightFunction,
        syscalls: Option<Vec<ExtraAllowedSyscall>>,
    ) -> Result<()> {
        let host_function = HostFunction {
            host_function_definition,
            host_function,
            syscalls,
        };
        match &mut self.mesh_sandbox_configuration.host_functions {
            Some(host_functions) => host_functions.push(host_function),
            None => self.mesh_sandbox_configuration.host_functions = Some(vec![host_function]),
        }
        Ok(())
    }
}

impl HostFunctionRegistry for MeshSandboxBuilder {
    fn register_host_function(
        &mut self,
        host_function_definition: hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition,
        host_function: HyperlightFunction,
    ) -> Result<()> {
        self.register_host_function(host_function_definition, host_function, None)?;
        Ok(())
    }

    fn register_host_function_with_syscalls(
        &mut self,
        host_function_definition: hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition,
        host_function: HyperlightFunction,
        syscalls: Vec<ExtraAllowedSyscall>,
    ) -> Result<()> {
        self.register_host_function(host_function_definition, host_function, Some(syscalls))?;
        Ok(())
    }
}
