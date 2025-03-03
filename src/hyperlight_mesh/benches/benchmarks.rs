/*
Copyright 2024 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


use criterion::{criterion_group, criterion_main, Criterion};
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_mesh::MeshSandbox;
use hyperlight_testing::{callback_guest_as_string, simple_guest_as_string};
use hyperlight_mesh::MeshSandboxBuilder;

fn create_mesh_sandbox(guest_binary: String, in_process: bool, custom_sandbox_host_program_name: Option<String>) -> MeshSandbox {

    let mut builder = MeshSandboxBuilder::new(guest_binary)
        .set_single_process(in_process)
        .set_custom_sandbox_host_program_name(custom_sandbox_host_program_name);
    builder.build().unwrap()
}

fn guest_call_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("guest_functions");

    let path = env!("CARGO_MANIFEST_DIR");
    let path = format!("{}/../../target/release/mesh_host", path);
    println!("Path: {}", path);
    // Benchmarks a single guest function call.
    group.bench_function("guest_call_in_custom_sandbox_host", |b| {
        let binary = simple_guest_as_string().unwrap();
        let sandbox = create_mesh_sandbox(binary, false, Some(path.clone()));

        b.iter_with_large_drop(|| {
            sandbox
                .call_function(
                    "Echo".to_string(),
                    ReturnType::Int,
                    Some(vec![ParameterValue::String("hello\n".to_string())]),
                )
                .unwrap()
        });
    });

    let function_return_type = ReturnType::Int;
    let a = 5;
    let b = 10;

    let function_args = Some(vec![ParameterValue::Int(a), ParameterValue::Int(b)]);


    // Benchmarks a guest function call calling into the host.
    group.bench_function("guest_call_with_host_call_in_custom_sandbox_host", |b| {
        let binary = callback_guest_as_string().unwrap();
        let sandbox = create_mesh_sandbox(binary, false, Some(path.clone()));

        b.iter_with_large_drop(|| {
            sandbox
                .call_function(
                    "AddUsingHost".to_string(),
                    function_return_type,
                    function_args.clone(),
                )
                .unwrap()
        });
    });

    group.finish();
}

fn sandbox_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandboxes");
    let path = env!("CARGO_MANIFEST_DIR");
    let path = format!("{}/../../target/release/mesh_host", path);

    // Benchmarks the time to create a new sandbox.
    // Does **not** include the time to drop the sandbox.
    group.bench_function("create_custom_process_sandbox", |b| {
        let binary = simple_guest_as_string().unwrap();
        b.iter_with_large_drop(|| create_mesh_sandbox(binary.clone(), false, Some(path.clone())));
    });

    // Benchmarks the time to create a new sandbox and drop it.
    group.bench_function("create_custom_process_sandbox_and_drop", |b| {
        let binary = simple_guest_as_string().unwrap();
        b.iter(|| create_mesh_sandbox(binary.clone(), false, Some(path.clone())));
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = guest_call_benchmark, sandbox_benchmark
}
criterion_main!(benches);
