
use hyperlight_testing::simple_guest_as_string;
use hyperlight_host::{func::{ParameterValue, ReturnType, ReturnValue}, sandbox::MeshSandbox};
use clap::{builder::{ ValueParser}, Arg, Command};

fn main() {
    // Use clap to parse command line arguments
    let matches = Command::new("Mesh Example").ignore_errors(true)
    .arg(
        Arg::new("in_process")
        .value_parser(ValueParser::bool())
                .short('i')
                .default_value("false")
                .help("Run in process"),
        )
        .get_matches();

    // Get the value of the --in-process argument
    let run_in_process = match matches.get_one::<bool>("in_process") {
        Some(value) => value.clone(),
        None => {
            eprintln!("Invalid value for --in-process argument");
            return;
        }
    };

    // Create a new MeshSandbox
    let guest_binary = simple_guest_as_string().unwrap();
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
