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

use alloc::string::ToString;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;

use crate::host_function_call::{outb, OutBAction};
use crate::shared_output_data::push_shared_output_data;

/// Prepares and sends log data to the shared output buffer.
///
/// This internal helper function creates a `GuestLogData` structure containing the log
/// information, serializes it, and writes it to the shared output buffer. It does not
/// notify the host that log data is available - that's handled by the `log_message` function
/// which calls this function.
///
/// # Parameters
///
/// * `log_level` - The severity level of the log message
/// * `message` - The actual text content of the log message
/// * `source` - The component or module that generated the log
/// * `caller` - The function that triggered the log
/// * `source_file` - The source file containing the log statement
/// * `line` - The line number in the source file
///
/// # Panics
///
/// This function will panic if:
/// * The `GuestLogData` structure cannot be serialized
/// * The shared output buffer is full or in an invalid state
///
/// # Implementation Details
///
/// This function:
/// 1. Creates a `GuestLogData` object with the provided log information
/// 2. Serializes the object to a byte array
/// 3. Writes the serialized data to the shared output buffer
///
/// It is an internal function called by the public `log_message` function, which also
/// handles notifying the host about the new log data.
fn write_log_data(
    log_level: LogLevel,
    message: &str,
    source: &str,
    caller: &str,
    source_file: &str,
    line: u32,
) {
    let guest_log_data = GuestLogData::new(
        message.to_string(),
        source.to_string(),
        log_level,
        caller.to_string(),
        source_file.to_string(),
        line,
    );

    let bytes: Vec<u8> = guest_log_data
        .try_into()
        .expect("Failed to convert GuestLogData to bytes");

    push_shared_output_data(bytes).expect("Unable to push log data to shared output data");
}

/// Sends a log message from the guest to the host system.
///
/// This function creates a structured log message with metadata and sends it to the host
/// for processing through the shared output buffer. The host can then display, store, or
/// process this log message according to its logging configuration.
///
/// # Parameters
///
/// * `log_level` - The severity level of the log message (e.g., Trace, Debug, Info, Error)
/// * `message` - The actual log message text
/// * `source` - The source identifier for the log (e.g., module or component name)
/// * `caller` - The name of the function that generated the log
/// * `source_file` - The source file containing the logging call
/// * `line` - The line number in the source file where the logging call occurs
///
/// # Example
///
/// ```no_run
/// use hyperlight_guest::logging::log_message;
/// use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
///
/// // Log an informational message
/// log_message(
///     LogLevel::Info,
///     "Processing started",
///     "payment_module",
///     "process_payment",
///     file!(),
///     line!()
/// );
///
/// // Log an error message
/// log_message(
///     LogLevel::Error,
///     "Invalid transaction ID",
///     "payment_module",
///     "validate_transaction",
///     file!(),
///     line!()
/// );
/// ```
///
/// # Note
///
/// This function serializes the log data and sends it to the host via the shared output
/// buffer and I/O port mechanism. If the buffer is full or another error occurs, this
/// function will panic.
pub fn log_message(
    log_level: LogLevel,
    message: &str,
    source: &str,
    caller: &str,
    source_file: &str,
    line: u32,
) {
    write_log_data(log_level, message, source, caller, source_file, line);
    outb(OutBAction::Log as u16, 0);
}
