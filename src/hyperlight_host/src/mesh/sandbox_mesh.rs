use futures::executor::block_on;
use mesh::MeshPayload;
use mesh_process::{try_run_mesh_host, Mesh, ProcessConfig};
use mesh_worker::{RegisteredWorkers, WorkerHost, WorkerHostRunner};
use tokio::task::JoinHandle;

use crate::Result;

/// The initial message to send when launching a mesh child process.
#[derive(MeshPayload)]
pub(crate) struct SandboxMeshHostParameters {
    runner: WorkerHostRunner,
}

pub(crate) fn run_mesh_host(name: &str) -> Result<()> {
    try_run_mesh_host(name, |params: SandboxMeshHostParameters| async {
        params.runner.run(RegisteredWorkers).await;
        Ok(())
    })?;
    Ok(())
}
pub(crate) struct SandboxMesh {
    mesh: Option<Mesh>,
    local_host: WorkerHost,
    rt: Option<tokio::runtime::Runtime>,
    _task: JoinHandle<()>,
}

impl SandboxMesh {
    pub(crate) fn new(single_process: bool, mesh_name: impl Into<String>) -> Result<Self> {
        let mesh = if single_process {
            None
        } else {
            Some(Mesh::new(mesh_name.into())?)
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let (local_host, runner) = mesh_worker::worker_host();
        let task = rt.spawn(runner.run(RegisteredWorkers));
        Ok(Self {
            mesh,
            local_host,
            _task: task,
            rt: Some(rt),
        })
    }

    pub async fn create_worker_host(&self, name: impl Into<String>) -> anyhow::Result<WorkerHost> {
        let host = if let Some(mesh) = &self.mesh {
            //TODO: Work out how to constrain the process that is crate
            let (host, runner) = mesh_worker::worker_host();
            mesh.launch_host(
                ProcessConfig::new(name),
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
            block_on(mesh.shutdown());
        }
        if let Some(runtime) = self.rt.take() {
            runtime.shutdown_background();
        }
    }
}
