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

use std::cell::RefCell;
use std::sync::Once;
use std::thread::current;

use log::{set_logger, set_max_level, Level, LevelFilter, Log, Metadata, Record};
use once_cell::sync::Lazy;
use tracing_log::LogTracer;

pub static LOGGER: Logger = Logger {};
static LOG_TRACER: Lazy<LogTracer> = Lazy::new(LogTracer::new);
static INITLOGGER: Once = Once::new();
#[derive(Clone, Eq, PartialEq)]
pub struct LogCall {
    pub level: Level,
    pub args: String,
    pub target: String,
    pub line: Option<u32>,
    pub file: Option<String>,
    pub module_path: Option<String>,
}

thread_local!(
    static LOGCALLS: RefCell<Vec<LogCall>> = const { RefCell::new(Vec::<LogCall>::new()) };
    static LOGGER_MAX_LEVEL: RefCell<LevelFilter> = const { RefCell::new(LevelFilter::Off) };
);

pub struct Logger {}

impl Logger {
    /// Initializes the test logger for the current process.
    /// 
    /// This function sets up a global thread-safe logger that captures log messages
    /// from all targets. It uses a thread-safe initialization mechanism to ensure 
    /// the logger is only set up once, even if called multiple times.
    /// 
    /// The logger is configured to capture messages at all log levels (Trace and above).
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::logger::Logger;
    /// 
    /// Logger::initialize_test_logger();
    /// // Now log messages will be captured for testing
    /// log::info!("This message will be captured");
    /// ```
    pub fn initialize_test_logger() {
        INITLOGGER.call_once(|| {
            set_logger(&LOGGER).unwrap();
            set_max_level(log::LevelFilter::Trace);
        });
    }

    /// Initializes a log tracer for tracing events.
    ///
    /// This function sets up a global LogTracer that allows log events to be captured 
    /// by the tracing system. It uses a thread-safe initialization mechanism to ensure
    /// the tracer is only set up once, even if called multiple times.
    ///
    /// This is particularly useful when you want to capture both standard logging events
    /// and tracing spans in a unified system.
    ///
    /// # Example
    ///
    /// ```
    /// use hyperlight_testing::logger::Logger;
    /// use tracing_core::Subscriber;
    /// use hyperlight_testing::tracing_subscriber::TracingSubscriber;
    /// use tracing::Level;
    ///
    /// // Set up log tracer
    /// Logger::initialize_log_tracer();
    /// 
    /// // Set up tracing subscriber
    /// let subscriber = TracingSubscriber::new(Level::INFO);
    /// tracing::subscriber::with_default(subscriber, || {
    ///     // Now both log and trace events will be captured
    ///     log::info!("Log event");
    ///     tracing::info!("Trace event");
    /// });
    /// ```
    pub fn initialize_log_tracer() {
        INITLOGGER.call_once(|| {
            set_logger(&*LOG_TRACER).unwrap();
            set_max_level(log::LevelFilter::Trace);
        });
    }

    /// Returns the total number of log messages that have been captured.
    ///
    /// # Returns
    ///
    /// The number of log messages captured since the last clear operation.
    ///
    /// # Example
    ///
    /// ```
    /// use hyperlight_testing::logger::{Logger, LOGGER};
    ///
    /// Logger::initialize_test_logger();
    /// LOGGER.clear_log_calls();
    ///
    /// log::info!("Test message");
    ///
    /// assert_eq!(LOGGER.num_log_calls(), 1);
    /// ```
    pub fn num_log_calls(&self) -> usize {
        LOGCALLS.with(|log_calls| log_calls.borrow().len())
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
    /// use hyperlight_testing::logger::{Logger, LOGGER};
    /// use log::Level;
    ///
    /// Logger::initialize_test_logger();
    /// LOGGER.clear_log_calls();
    ///
    /// log::info!("Test message");
    ///
    /// let log_call = LOGGER.get_log_call(0).unwrap();
    /// assert_eq!(log_call.level, Level::Info);
    /// assert_eq!(log_call.args, "Test message");
    /// ```
    pub fn get_log_call(&self, idx: usize) -> Option<LogCall> {
        LOGCALLS.with(|log_calls| log_calls.borrow().get(idx).cloned())
    }

    /// Clears all captured log messages.
    ///
    /// This is useful for setting up a clean state before capturing logs for a specific test.
    ///
    /// # Example
    ///
    /// ```
    /// use hyperlight_testing::logger::{Logger, LOGGER};
    ///
    /// Logger::initialize_test_logger();
    ///
    /// // Ensure we start with a clean state
    /// LOGGER.clear_log_calls();
    ///
    /// // Now we can log messages for this specific test
    /// log::info!("Test message");
    /// assert_eq!(LOGGER.num_log_calls(), 1);
    /// ```
    pub fn clear_log_calls(&self) {
        LOGCALLS.with(|log_calls| log_calls.borrow_mut().clear());
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
    /// use hyperlight_testing::logger::{Logger, LOGGER};
    /// use log::Level;
    ///
    /// Logger::initialize_test_logger();
    /// LOGGER.clear_log_calls();
    ///
    /// log::info!("Test message 1");
    /// log::error!("Test message 2");
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
        LOGCALLS.with(|log_calls| f(&log_calls.borrow()));
        self.clear_log_calls();
    }

    /// Sets the maximum log level for this logger.
    ///
    /// Only log messages with a level equal to or more severe than the specified level
    /// will be captured.
    ///
    /// # Parameters
    ///
    /// * `level` - The new maximum log level filter
    ///
    /// # Example
    ///
    /// ```
    /// use hyperlight_testing::logger::{Logger, LOGGER};
    /// use log::LevelFilter;
    ///
    /// Logger::initialize_test_logger();
    /// LOGGER.clear_log_calls();
    ///
    /// // Set to only capture warnings and above
    /// LOGGER.set_max_level(LevelFilter::Warn);
    ///
    /// log::info!("This won't be captured");
    /// log::warn!("This will be captured");
    /// log::error!("This will be captured too");
    ///
    /// assert_eq!(LOGGER.num_log_calls(), 2);
    /// ```
    pub fn set_max_level(&self, level: LevelFilter) {
        LOGGER_MAX_LEVEL.with(|max_level| {
            *max_level.borrow_mut() = level;
        });
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        LOGGER_MAX_LEVEL.with(|max_level| metadata.level() <= *max_level.borrow())
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        LOGCALLS.with(|log_calls| {
            if record.target().contains("hyperlight_guest") {
                println!("Thread {:?} {:?}", current().id(), record);
                println!("Thread {:?} {:?}", current().id(), record.metadata());
            }
            log_calls.borrow_mut().push(LogCall {
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
            })
        });

        println!("Thread {:?} {:?}", current().id(), record);
    }

    fn flush(&self) {}
}
