use std::sync::{Arc, Mutex};

use hyperlight_host::func::host_functions::HostFunction2;
use hyperlight_mesh::{mesh_host_function_registry, sandbox_mesh};
fn main() {
    let mut mesh_host_function_registry =
        mesh_host_function_registry::MeshHostFunctionRegistry::new();

    // Create and register a host function
    let host_function = Arc::new(Mutex::new(|a: i32, b: i32| Ok(a + b + 10)));
    host_function
        .register(&mut mesh_host_function_registry, "Add")
        .unwrap();

    // Join the mesh (Mesh will start this program with the name of the mesh as the first argument)

    let mesh_name = std::env::args().nth(1).unwrap_or("".to_string());
    sandbox_mesh::run_mesh_host(&mesh_name).unwrap();
}
