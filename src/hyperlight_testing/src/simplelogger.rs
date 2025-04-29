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

// this is a non threadsafe logger for testing purposes, to test the log messages emitted by the guest.
// it will only log messages from the hyperlight_guest target. It will not log messages from other targets.
// this target is only used when handling an outb log request from the guest, so this logger will only capture those messages.

use std::sync::Once;
use std::thread::current;

use log::{set_logger, set_max_level, Level, Log, Metadata, Record};

pub static LOGGER: SimpleLogger = SimpleLogger {};
static INITLOGGER: Once = Once::new();
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct LogCall {
    pub level: Level,
    pub args: String,
    pub target: String,
    pub line: Option<u32>,
    pub file: Option<String>,
    pub module_path: Option<String>,
}

static mut LOGCALLS: Vec<LogCall> = Vec::<LogCall>::new();
static mut NUMBER_OF_ENABLED_CALLS: usize = 0;

pub struct SimpleLogger {}

impl SimpleLogger {
    /// Initializes the test logger for the current process.
    /// 
    /// This function sets up a global logger that captures log messages specifically 
    /// from the "hyperlight_guest" target. It uses a thread-safe initialization mechanism 
    /// to ensure the logger is only set up once, even if called multiple times.
    /// 
    /// The logger is configured to capture messages at all log levels (Trace and above).
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::simplelogger::SimpleLogger;
    /// 
    /// SimpleLogger::initialize_test_logger();
    /// // Now log messages will be captured for testing
    /// ```
    pub fn initialize_test_logger() {
        INITLOGGER.call_once(|| {
            set_logger(&LOGGER).unwrap();
            set_max_level(log::LevelFilter::Trace);
        });
    }

    /// Returns the number of times logging was enabled for the "hyperlight_guest" target.
    /// 
    /// This counter is incremented each time the logger checks if a log message should be 
    /// processed for the "hyperlight_guest" target, regardless of whether the message's log 
    /// level meets the current filter level.
    /// 
    /// # Returns
    /// 
    /// The count of enabled calls for the "hyperlight_guest" target.
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::simplelogger::{SimpleLogger, LOGGER};
    /// use log::info;
    /// 
    /// SimpleLogger::initialize_test_logger();
    /// let before = LOGGER.num_enabled_calls();
    /// 
    /// // Log a message that will be processed by our logger
    /// log::info!(target: "hyperlight_guest", "test message");
    /// 
    /// assert_eq!(LOGGER.num_enabled_calls(), before + 1);
    /// ```
    pub fn num_enabled_calls(&self) -> usize {
        unsafe { NUMBER_OF_ENABLED_CALLS }
    }

    /// Returns the total number of log messages that have been captured.
    /// 
    /// This count represents all log messages that have passed both the target 
    /// filter ("hyperlight_guest") and the level filter.
    /// 
    /// # Returns
    /// 
    /// The number of log messages captured since the last clear operation.
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::simplelogger::{SimpleLogger, LOGGER};
    /// 
    /// SimpleLogger::initialize_test_logger();
    /// LOGGER.clear_log_calls();
    /// 
    /// // Log a message that will be captured
    /// log::info!(target: "hyperlight_guest", "test message");
    /// 
    /// assert_eq!(LOGGER.num_log_calls(), 1);
    /// ```
    pub fn num_log_calls(&self) -> usize {
        unsafe { LOGCALLS.len() }
    }

    /// Retrieves a captured log message at the specified index.
    /// 
    /// # Parameters
    /// 
    /// * `idx` - The index of the log message to retrieve
    /// 
    /// # Returns
    /// 
    /// * `Some(LogCall)` - The log message at the specified index
    /// * `None` - If the index is out of bounds
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::simplelogger::{SimpleLogger, LOGGER};
    /// use log::Level;
    /// 
    /// SimpleLogger::initialize_test_logger();
    /// LOGGER.clear_log_calls();
    /// 
    /// log::info!(target: "hyperlight_guest", "test message");
    /// 
    /// let log_call = LOGGER.get_log_call(0).unwrap();
    /// assert_eq!(log_call.level, Level::Info);
    /// assert_eq!(log_call.args, "test message");
    /// ```
    pub fn get_log_call(&self, idx: usize) -> Option<LogCall> {
        unsafe { LOGCALLS.get(idx).cloned() }
    }

    /// Clears all captured log messages and resets the enabled calls counter.
    /// 
    /// This is useful for setting up a clean state before capturing logs for a specific test.
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::simplelogger::{SimpleLogger, LOGGER};
    /// 
    /// SimpleLogger::initialize_test_logger();
    /// 
    /// // Ensure we start with a clean state
    /// LOGGER.clear_log_calls();
    /// 
    /// // Now we can log messages for this specific test
    /// log::info!(target: "hyperlight_guest", "test message");
    /// assert_eq!(LOGGER.num_log_calls(), 1);
    /// ```
    pub fn clear_log_calls(&self) {
        unsafe {
            LOGCALLS.clear();
            NUMBER_OF_ENABLED_CALLS = 0;
        }
    }

    /// Processes the captured log messages with a provided function and then clears them.
    /// 
    /// This is a convenient way to examine all captured logs and then reset the logger state
    /// in a single call.
    /// 
    /// # Parameters
    /// 
    /// * `f` - A function that takes a reference to the vector of captured log calls
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::simplelogger::{SimpleLogger, LOGGER};
    /// use log::Level;
    /// 
    /// SimpleLogger::initialize_test_logger();
    /// LOGGER.clear_log_calls();
    /// 
    /// log::info!(target: "hyperlight_guest", "test message 1");
    /// log::error!(target: "hyperlight_guest", "test message 2");
    /// 
    /// LOGGER.test_log_records(|logs| {
    ///     assert_eq!(logs.len(), 2);
    ///     assert_eq!(logs[0].level, Level::Info);
    ///     assert_eq!(logs[1].level, Level::Error);
    /// });
    /// 
    /// // Logs are cleared after the call
    /// assert_eq!(LOGGER.num_log_calls(), 0);
    /// ```
    pub fn test_log_records<F: Fn(&Vec<LogCall>)>(&self, f: F) {
        unsafe {
            // this logger is only used for testing so unsafe is fine here
            #[allow(static_mut_refs)]
            f(&LOGCALLS);
        };
        self.clear_log_calls();
    }
}

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // This allows us to count the actual number of messages that have been logged by the guest
        // because the guest derives its log level from the host log level then the number times that enabled is called for
        // the "hyperlight_guest" target will be the same as the number of messages logged by the guest.
        // In other words this function should always return true for the "hyperlight_guest" target.
        unsafe {
            if metadata.target() == "hyperlight_guest" {
                NUMBER_OF_ENABLED_CALLS += 1;
            }
            metadata.target() == "hyperlight_guest" && metadata.level() <= log::max_level()
        }
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        unsafe {
            LOGCALLS.push(LogCall {
                level: record.level(),
                args: format!("{}", record.args()),
                target: record.target().to_string(),
                line: record.line(),
                file: match record.file() {
                    None => record.file_static().map(|file| file.to_string()),
                    Some(file) => Some(file.to_string()),
                },
                module_path: match record.module_path() {
                    None => record
                        .module_path_static()
                        .map(|module_path| module_path.to_string()),
                    Some(module_path) => Some(module_path.to_string()),
                },
            });
        };

        println!("Thread {:?} {:?}", current().id(), record);
    }

    fn flush(&self) {}
}
