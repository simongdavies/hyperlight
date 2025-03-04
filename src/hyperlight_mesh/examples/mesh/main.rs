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
            Arg::new("custom-sandbox-host-program-name")
                .value_parser(ValueParser::string())
                .help("Name of the custom sandbox host program")
                .short('n')
                .long("name"),
        )
        .get_matches();

    let run_in_process = matches.get_one::<bool>("in_process");
    let custom_sandbox_host_program_name =
        matches.get_one::<String>("custom-sandbox-host-program-name");
    let custom_sandbox_host_program_name = match custom_sandbox_host_program_name {
        Some(val) => {
            // val should be a valid binary, check if it exists
            if std::path::Path::new(val).exists() {
                Some(val)
            } else {
                println!("Host program name {} is not a valid binary", val);
                None
            }
        }
        None => None,
    };

    if run_in_process.is_some()
        && *run_in_process.unwrap()
        && custom_sandbox_host_program_name.is_some()
    {
        eprint!("Cannot specify custom-sandbox-host-program-name when running in process");
        std::process::exit(1);
    }

    match run_in_process {
        Some(val) => {
            run_hyperlight_host(*val, custom_sandbox_host_program_name.cloned());
        }
        None => {
            // If run in process flag was not received, then this proogram was probably started as a mesh host
            // Run the mesh host
            sandbox_mesh::run_host().expect("Failed to run mesh host");
        }
    }
}

fn run_hyperlight_host(run_in_process: bool, custom_sandbox_host_program_name: Option<String>) {
    let mut running_sandbox_in_custom_host = false;
    if let Some(_) = custom_sandbox_host_program_name {
        running_sandbox_in_custom_host = true;
    }

    if run_in_process {
        println!("Running Sandbox In Process with Hyperlight Host");
    } else {
        if running_sandbox_in_custom_host {
            println!("Running Sandbox Out Of Process with a Custom Sandbox Host Program");
        } else {
            println!("Running Sandbox Out Of Process from Hyperlight Host - this program will be used as the host for the sandbox");
        }
    }

    // Create a new MeshSandbox
    let guest_binary = simple_guest_as_string().unwrap();
    let mut builder = MeshSandboxBuilder::new(guest_binary)
        .set_single_process(run_in_process)
        .set_custom_sandbox_host_program_name(custom_sandbox_host_program_name.clone());
    let sandbox = builder.build().unwrap();

    // Call a function in the guest

    let message = "Hello, World!";
    let function_name = "Echo";
    println!("");
    println!(
        "Calling function {} in guest with argument {}",
        function_name, message
    );

    let function_return_type = ReturnType::String;
    let function_args = Some(vec![ParameterValue::String(message.to_string())]);
    let result = sandbox.call_function(
        function_name.to_string(),
        function_return_type,
        function_args,
    );
    assert!(result.is_ok());
    if let ReturnValue::String(value) = result.unwrap() {
        assert_eq!(value, message);
        println!("{}", value);
    } else {
        panic!("Unexpected return value type");
    }

    // Call a function that prints to the host
    let message = "Hello Mesh!!!!";
    let function_name = "PrintOutput";

    println!("");
    println!(
        "Calling function {} in guest that prints {} to host",
        function_name, message
    );
    let res = sandbox.call_function(
        function_name.to_string(),
        ReturnType::Int,
        Some(vec![ParameterValue::String(
            format!("{}\n", message).to_string(),
        )]),
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

    let mut builder = MeshSandboxBuilder::new(guest_binary)
        .set_single_process(run_in_process)
        .set_custom_sandbox_host_program_name(custom_sandbox_host_program_name.clone());

    let guest_function_name = "AddUsingHost";
    let host_function_name = "Add";

    println!("");
    println!(
        "Calling function {} in guest that calls host function {}",
        guest_function_name, host_function_name
    );

    // Host functions can run in the hyperight host, or in the case of running a custom host program for the sandbox in that program

    // If a custom host program name is provided, then the host function should be registered in that host program
    // otherwise, the host function should be registered in the hyperlight host (this) program

    match custom_sandbox_host_program_name {
        Some(ref name) => {
            println!("");
            println!("Custom Sandbox Host Program name: {:?}", name);
            println!(
                "Host Function {} is expected to be  registered in Custom Sandbox Host Program Name: {:?} and the function is expected to add 10 to the result",
                host_function_name,
                name
            );
        }
        None => {
            println!("");
            println!(
                "Host Function {} is being registered in Hyperlight Host",
                host_function_name
            );
            // Create a host function
            let host_function = Arc::new(Mutex::new(|a: i32, b: i32| Ok(a + b)));
            host_function
                .register(&mut builder, host_function_name)
                .unwrap();
        }
    }

    let sandbox = builder.build().unwrap();
    let function_return_type = ReturnType::Int;
    let a = 5;
    let b = 10;

    let function_args = Some(vec![ParameterValue::Int(a), ParameterValue::Int(b)]);

    println!("");
    println!(
        "Calling guest function {} with args {} and {}",
        guest_function_name, a, b
    );

    let result = sandbox.call_function(
        guest_function_name.to_string(),
        function_return_type,
        function_args,
    );
    assert!(result.is_ok());
    if let ReturnValue::Int(value) = result.unwrap() {
        println!("Return Value {}", value);
        if running_sandbox_in_custom_host {
            // the add function in the custom host program adds 10 to the result
            assert_eq!(value, 25);
        } else {
            assert_eq!(value, 15);
        }
    } else {
        panic!("Unexpected return value type");
    }

    println!("Success!");
}
