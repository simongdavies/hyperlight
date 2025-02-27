use std::sync::Arc;

use hyperlight_host::Result;
use mesh::MeshPayload;
use mesh_process::{try_run_mesh_host, Mesh, ProcessConfig};
use mesh_worker::{RegisteredWorkers, WorkerHost, WorkerHostRunner};
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

static RUNTIME: Lazy<Arc<Runtime>> = Lazy::new(|| Arc::new(Runtime::new().unwrap()));

pub(crate) fn get_runtime() -> Arc<Runtime> {
    RUNTIME.clone()
}

/// The initial message to send when launching a mesh child process.
#[derive(MeshPayload)]
pub(crate) struct SandboxMeshHostParameters {
    runner: WorkerHostRunner,
}

pub fn run_mesh_host(name: &str) -> Result<()> {
    try_run_mesh_host(name, |params: SandboxMeshHostParameters| async {
        params.runner.run(RegisteredWorkers).await;
        Ok(())
    })?;
    Ok(())
}
pub(crate) struct SandboxMesh {
    mesh: Option<Mesh>,
    local_host: WorkerHost,
    mesh_program_name: Option<String>,
}

impl SandboxMesh {
    pub(crate) fn new(single_process: bool, mesh_name: impl Into<String>,mesh_program_name: Option<String>) -> Result<Self> {
        let mesh = if single_process {
            None
        } else {
            Some(Mesh::new(mesh_name.into())?)
        };

        let (local_host, runner) = mesh_worker::worker_host();
        let _task = get_runtime().spawn(runner.run(RegisteredWorkers));
        Ok(Self { mesh, local_host, mesh_program_name })
    }

    pub async fn create_sandbox_worker_host(
        &self,
        name: impl Into<String>,
    ) -> anyhow::Result<WorkerHost> {
        let host = if let Some(mesh) = &self.mesh {
            //TODO: Work out how to constrain the process that is crate
            let (host, runner) = mesh_worker::worker_host();
            let process_config = match &self.mesh_program_name {
                Some(mesh_program_name) => ProcessConfig::new(name).process_name(mesh_program_name),
                None => ProcessConfig::new(name),
            };
            mesh.launch_host(
                process_config,
                SandboxMeshHostParameters { runner },
            )
            .await?;
            host
        } else {
            self.local_host.clone()
        };
        Ok(host)
    }

    pub fn shutdown(&mut self) {
        if let Some(mesh) = self.mesh.take() {
            get_runtime().block_on(mesh.shutdown());
        }
    }
}
