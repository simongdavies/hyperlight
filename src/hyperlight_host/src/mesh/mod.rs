pub(crate) mod sandbox_mesh;
pub(crate) mod sandbox_worker;
use sandbox_worker::SandboxWorker;

// Register the SandboxWorker with
mesh_worker::register_workers! {
    SandboxWorker
}
