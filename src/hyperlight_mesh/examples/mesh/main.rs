use std::sync::{Arc, Mutex};

use clap::builder::ValueParser;
use clap::{Arg, Command};
use hyperlight_host::func::{HostFunction2, ParameterValue, ReturnType, ReturnValue};
use hyperlight_mesh::{sandbox_mesh, MeshSandboxBuilder};
use hyperlight_testing::{callback_guest_as_string, simple_guest_as_string};

fn main() {
    // Use clap to parse command line arguments
    let matches = Command::new("mesh")
        .ignore_errors(true)
        .arg(
            Arg::new("in_process")
                .value_parser(ValueParser::bool())
                .short('i')
                .help("Run in process"),
        )
        .arg(
            Arg::new("host-program-name")
                .value_parser(ValueParser::string())
                .help("Name of the mesh")
                .short('n')
                .long("name"),
        )
        .get_matches();

    let run_in_process = matches.get_one::<bool>("in_process");
    let host_program_name = matches.get_one::<String>("host-program-name");
    let host_program_name = match host_program_name {
        Some(val) => {
            // val should be a valid binary, check if it exists
            if std::path::Path::new(val).exists() {
                Some(val)
            } else {
                println!("Host program name {} is not a valid binary", val);
                None
            }
        },
        None => None,
    };

    match run_in_process {
        Some(val) => {
            create_sandboxes_and_call_functions(*val, host_program_name.cloned());
        }
        None => {
            let mesh_name = std::env::args().nth(1).unwrap_or("".to_string());
            sandbox_mesh::run_mesh_host(&mesh_name).unwrap();
        }
    }


}

fn create_sandboxes_and_call_functions(run_in_process: bool, host_program_name: Option<String>) {
    println!("Running Mesh Example In Process: {}", run_in_process);

    if !run_in_process{
        println!("Host Program Name: {:?}", host_program_name);
    }

    // Create a new MeshSandbox
    let guest_binary = simple_guest_as_string().unwrap();
    let mut builder = MeshSandboxBuilder::new(guest_binary).set_single_process(run_in_process).set_host_program_name(host_program_name.clone());
    let sandbox = builder.build().unwrap();

    // Call a function in the guest

    println!("Calling function in guest");

    let function_name = "Echo".to_string();
    let function_return_type = ReturnType::String;
    let function_args = Some(vec![ParameterValue::String("Hello, World!".to_string())]);
    let result = sandbox.call_function(function_name, function_return_type, function_args);
    assert!(result.is_ok());
    if let ReturnValue::String(value) = result.unwrap() {
        assert_eq!(value, "Hello, World!");
        println!("{}", value);
    } else {
        panic!("Unexpected return value type");
    }

    // Call a function that prints to the host
    println!("Calling function in guest that prints to host");
    let res = sandbox.call_function(
        "PrintOutput".to_string(),
        ReturnType::Int,
        Some(vec![ParameterValue::String("Print Hello!!\n".to_string())]),
    );
    assert!(res.is_ok());
    if let ReturnValue::Int(value) = res.unwrap() {
        println!("Return Value {}", value);
    } else {
        panic!("Unexpected return value type");
    }

    #[cfg(target_os = "windows")]
    // Need to drop the sandbox in Windows so we drop the SurrogateProcess as we only have one configured in mesh.
    if run_in_process {
        drop(sandbox);
    }

    // Call a function on the guest that calls a host function

    let guest_binary = callback_guest_as_string().unwrap();
    // TODO: for now we can only run in process when calling a host function
    let mut builder = MeshSandboxBuilder::new(guest_binary).set_single_process(run_in_process).set_host_program_name(host_program_name);
    // Create a host function
    let host_function = Arc::new(Mutex::new(|a: i32, b: i32| Ok(a + b)));
    host_function.register(&mut builder, "Add").unwrap();
    let sandbox = builder.build().unwrap();
    let function_name = "AddUsingHost".to_string();
    let function_return_type = ReturnType::Int;
    let function_args = Some(vec![ParameterValue::Int(5), ParameterValue::Int(10)]);

    println!("Calling function in guest that calls host function");

    let result = sandbox.call_function(function_name, function_return_type, function_args);
    println!("Result: {:?}", result);
    assert!(result.is_ok());
    if let ReturnValue::Int(value) = result.unwrap() {
        assert_eq!(value, 15);
    } else {
        panic!("Unexpected return value type");
    }

    println!("Success!");
}
