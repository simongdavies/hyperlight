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

use alloc::format;
use alloc::string::String;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use {anyhow, serde_json};

pub type Result<T> = core::result::Result<T, HyperlightGuestError>;

/// Error type for Hyperlight guest operations.
///
/// This struct represents errors that can occur during guest-side operations
/// in the Hyperlight runtime. It contains both an error code that categorizes
/// the error and a message providing details.
#[derive(Debug)]
pub struct HyperlightGuestError {
    /// The error code indicating the type of error
    pub kind: ErrorCode,
    /// A detailed error message 
    pub message: String,
}

impl HyperlightGuestError {
    /// Creates a new `HyperlightGuestError` with the specified error code and message.
    ///
    /// # Parameters
    ///
    /// * `kind` - The error code categorizing the type of error
    /// * `message` - A detailed message describing the error
    ///
    /// # Returns
    ///
    /// A new `HyperlightGuestError` instance
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hyperlight_guest::error::HyperlightGuestError;
    /// use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
    ///
    /// // Create a new error for a parameter type mismatch
    /// let error = HyperlightGuestError::new(
    ///     ErrorCode::GuestFunctionParameterTypeMismatch,
    ///     "Expected string parameter, but received integer".to_string()
    /// );
    /// ```
    pub fn new(kind: ErrorCode, message: String) -> Self {
        Self { kind, message }
    }
}

impl From<anyhow::Error> for HyperlightGuestError {
    /// Converts an `anyhow::Error` into a `HyperlightGuestError`.
    ///
    /// This implementation allows Hyperlight guest code to seamlessly use the `anyhow` 
    /// error handling library by automatically converting its errors to the Hyperlight
    /// error format with a general `GuestError` code.
    ///
    /// # Parameters
    ///
    /// * `error` - The `anyhow::Error` to convert
    ///
    /// # Returns
    ///
    /// A `HyperlightGuestError` with a `GuestError` code and a message containing the
    /// debug representation of the original error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use anyhow::anyhow;
    /// use hyperlight_guest::error::HyperlightGuestError;
    /// 
    /// // Create an anyhow error
    /// let anyhow_error = anyhow!("Something went wrong with the calculation");
    /// 
    /// // Convert to HyperlightGuestError (happens automatically with the ? operator)
    /// let hyperlight_error = HyperlightGuestError::from(anyhow_error);
    /// ```
    fn from(error: anyhow::Error) -> Self {
        Self {
            kind: ErrorCode::GuestError,
            message: format!("Error: {:?}", error),
        }
    }
}

impl From<serde_json::Error> for HyperlightGuestError {
    /// Converts a `serde_json::Error` into a `HyperlightGuestError`.
    ///
    /// This implementation allows Hyperlight guest code to work with JSON serialization
    /// and deserialization by automatically converting `serde_json` errors to the 
    /// Hyperlight error format with a general `GuestError` code.
    ///
    /// # Parameters
    ///
    /// * `error` - The `serde_json::Error` to convert
    ///
    /// # Returns
    ///
    /// A `HyperlightGuestError` with a `GuestError` code and a message containing the
    /// debug representation of the original JSON error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hyperlight_guest::error::HyperlightGuestError;
    /// use serde_json::from_str;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct Data {
    ///     value: i32,
    /// }
    ///
    /// // Invalid JSON will cause a serde_json::Error
    /// let result = from_str::<Data>("{invalid_json}");
    ///
    /// // The error can be converted to a HyperlightGuestError
    /// if let Err(json_err) = result {
    ///     let hyperlight_err = HyperlightGuestError::from(json_err);
    ///     // Use hyperlight_err...
    /// }
    /// ```
    fn from(error: serde_json::Error) -> Self {
        Self {
            kind: ErrorCode::GuestError,
            message: format!("Error: {:?}", error),
        }
    }
}
