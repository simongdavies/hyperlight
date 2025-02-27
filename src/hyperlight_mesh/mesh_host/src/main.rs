use hyperlight_mesh::sandbox_mesh;
fn main() {
    let mesh_name = std::env::args().nth(1).unwrap_or("".to_string());
    sandbox_mesh::run_mesh_host(&mesh_name).unwrap();
}
