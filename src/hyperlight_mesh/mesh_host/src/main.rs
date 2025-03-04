use std::sync::{Arc, Mutex};

use hyperlight_host::func::host_functions::HostFunction2;
use hyperlight_mesh::{mesh_host_function_registry, sandbox_mesh};
fn main() {
    let mut mesh_host_function_registry =
        mesh_host_function_registry::MeshHostFunctionRegistry::new();

    // Create and register a host function
    // This version of add adds 10 to the result to make it easy/clear to see that this host function is being called
    let host_function = Arc::new(Mutex::new(|a: i32, b: i32| Ok(a + b + 10)));
    host_function
        .register(&mut mesh_host_function_registry, "Add")
        .unwrap();

    // Run the mesh host
    sandbox_mesh::run_host().expect("Failed to run mesh host");
}
