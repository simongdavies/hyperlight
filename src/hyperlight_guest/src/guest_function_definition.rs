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
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::error::{HyperlightGuestError, Result};

/// The definition of a function exposed from the guest to the host.
///
/// This struct represents a guest function that can be registered with the Hyperlight
/// runtime to make it callable by the host. It contains all the metadata needed to
/// validate and execute calls to the function, including its name, parameter types,
/// return type, and a pointer to the implementation.
///
/// Guest functions must follow a specific signature pattern to be compatible with
/// the Hyperlight function calling mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestFunctionDefinition {
    /// The function name
    pub function_name: String,
    /// The type of the parameter values for the host function call.
    pub parameter_types: Vec<ParameterType>,
    /// The type of the return value from the host function call
    pub return_type: ReturnType,
    /// The function pointer to the guest function
    pub function_pointer: usize,
}

impl GuestFunctionDefinition {
    /// Creates a new guest function definition with the specified attributes.
    ///
    /// This method constructs a new `GuestFunctionDefinition` that represents a guest function
    /// that can be registered with the Hyperlight runtime and called by the host.
    ///
    /// # Parameters
    ///
    /// * `function_name` - The name of the function, used by the host to identify which function to call
    /// * `parameter_types` - A vector of parameter types that the function accepts
    /// * `return_type` - The type of value that the function returns
    /// * `function_pointer` - A pointer to the function implementation, cast to `usize`
    ///
    /// # Returns
    ///
    /// A new `GuestFunctionDefinition` instance with the specified attributes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
    /// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
    /// use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
    /// use hyperlight_guest::error::Result;
    /// use alloc::vec::Vec;
    ///
    /// // Define a guest function
    /// fn calculate_sum(call: &FunctionCall) -> Result<Vec<u8>> {
    ///     // Implementation...
    ///     # Ok(Vec::new())
    /// }
    ///
    /// // Create a function definition
    /// let function_def = GuestFunctionDefinition::new(
    ///     "CalculateSum".to_string(),
    ///     vec![ParameterType::Int, ParameterType::Int],
    ///     ReturnType::Int,
    ///     calculate_sum as usize
    /// );
    /// ```
    pub fn new(
        function_name: String,
        parameter_types: Vec<ParameterType>,
        return_type: ReturnType,
        function_pointer: usize,
    ) -> Self {
        Self {
            function_name,
            parameter_types,
            return_type,
            function_pointer,
        }
    }

    /// Verifies that the provided parameter types match this function's expected parameters.
    ///
    /// This method checks that a function call matches the expected parameter signature of
    /// this guest function. It validates both the number of parameters and their types.
    ///
    /// # Parameters
    ///
    /// * `parameter_types` - The parameter types to verify against this function's signature
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the parameters match this function's signature
    /// * `Err` - If the parameters don't match (wrong number or wrong types)
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    /// * If there are more than the maximum allowed parameters (currently 11)
    /// * If the number of parameters doesn't match what the function expects
    /// * If any parameter type doesn't match the expected type at that position
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
    /// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
    ///
    /// // Create a function definition expecting (Int, String)
    /// let function_def = GuestFunctionDefinition::new(
    ///     "ProcessData".to_string(), 
    ///     vec![ParameterType::Int, ParameterType::String],
    ///     ReturnType::String,
    ///     0 // placeholder for actual function pointer
    /// );
    ///
    /// // These parameters match the function signature
    /// let valid_params = vec![ParameterType::Int, ParameterType::String];
    /// assert!(function_def.verify_parameters(&valid_params).is_ok());
    ///
    /// // These parameters don't match (wrong number)
    /// let invalid_count = vec![ParameterType::Int];
    /// assert!(function_def.verify_parameters(&invalid_count).is_err());
    ///
    /// // These parameters don't match (wrong types)
    /// let invalid_types = vec![ParameterType::String, ParameterType::Int];
    /// assert!(function_def.verify_parameters(&invalid_types).is_err());
    /// ```
    pub fn verify_parameters(&self, parameter_types: &[ParameterType]) -> Result<()> {
        // Verify that the function does not have more than `MAX_PARAMETERS` parameters.
        const MAX_PARAMETERS: usize = 11;
        if parameter_types.len() > MAX_PARAMETERS {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!(
                    "Function {} has too many parameters: {} (max allowed is {}).",
                    self.function_name,
                    parameter_types.len(),
                    MAX_PARAMETERS
                ),
            ));
        }

        if self.parameter_types.len() != parameter_types.len() {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestFunctionIncorrecNoOfParameters,
                format!(
                    "Called function {} with {} parameters but it takes {}.",
                    self.function_name,
                    parameter_types.len(),
                    self.parameter_types.len()
                ),
            ));
        }

        for (i, parameter_type) in self.parameter_types.iter().enumerate() {
            if parameter_type != &parameter_types[i] {
                return Err(HyperlightGuestError::new(
                    ErrorCode::GuestFunctionParameterTypeMismatch,
                    format!(
                        "Expected parameter type {:?} for parameter index {} of function {} but got {:?}.",
                        parameter_type, i, self.function_name, parameter_types[i]
                    ),
                ));
            }
        }

        Ok(())
    }
}
