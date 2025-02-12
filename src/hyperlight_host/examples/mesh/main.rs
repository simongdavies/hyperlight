use std::env;
use hyperlight_testing::simple_guest_as_string;
use hyperlight_host::{func::{ParameterValue, ReturnType, ReturnValue}, sandbox::MeshSandbox};

fn main() {
    // Collect the command line arguments
    let args: Vec<String> = env::args().collect();

    // Check if the correct number of arguments is provided
    if args.len() != 2 {
        eprintln!("Usage: {} <run_in_process>", args[0]);
        std::process::exit(1);
    }

    // Parse the argument as a boolean
    let run_in_process: bool = match args[1].parse() {
        Ok(val) => val,
        Err(_) => {
            eprintln!("Invalid argument: {}. Expected a boolean value (true/false).", args[1]);
            eprintln!("Running out of process by default.");
            false
        }
    };

    // Create a new MeshSandbox
    let guest_binary =  simple_guest_as_string().unwrap();
    let sandbox = MeshSandbox::new(guest_binary, run_in_process).unwrap();
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

    println!("Success!");
}
