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

use alloc::collections::BTreeMap;
use alloc::string::String;

use super::guest_function_definition::GuestFunctionDefinition;
use crate::REGISTERED_GUEST_FUNCTIONS;

/// Represents the registry of functions that the guest exposes to the host.
///
/// This registry maintains a mapping of function names to their corresponding 
/// definitions, allowing the host to discover and call guest-implemented functions.
/// The registry is typically populated during guest initialization and then used
/// by the guest runtime to dispatch host calls to the appropriate function implementations.
///
/// # Example
///
/// ```no_run
/// use hyperlight_guest::guest_function_register::GuestFunctionRegister;
/// use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
/// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
/// 
/// // Create a new registry
/// let mut register = GuestFunctionRegister::new();
/// 
/// // Define a guest function
/// let function_def = GuestFunctionDefinition::new(
///     "MyFunction".to_string(),
///     vec![ParameterType::Int],
///     ReturnType::Int,
///     some_function_ptr as usize
/// );
/// 
/// // Register the function
/// register.register(function_def);
/// 
/// // Later, look up the function by name
/// if let Some(func_def) = register.get("MyFunction") {
///     // Use the function definition...
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct GuestFunctionRegister {
    /// Currently registered guest functions
    guest_functions: BTreeMap<String, GuestFunctionDefinition>,
}

impl GuestFunctionRegister {
    /// Creates a new empty guest function registry.
    ///
    /// This constructor initializes a fresh registry with no registered functions.
    /// Functions must be added using the `register` method before they can be called
    /// by the host.
    ///
    /// # Returns
    ///
    /// A new empty `GuestFunctionRegister` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use hyperlight_guest::guest_function_register::GuestFunctionRegister;
    ///
    /// let registry = GuestFunctionRegister::new();
    /// ```
    pub const fn new() -> Self {
        Self {
            guest_functions: BTreeMap::new(),
        }
    }

    /// Registers a new guest function in this registry.
    ///
    /// This method adds a function definition to the registry, making it available for the
    /// host to call. If a function with the same name already exists, it will be replaced
    /// with the new definition.
    ///
    /// # Parameters
    ///
    /// * `guest_function` - The function definition to register
    ///
    /// # Returns
    ///
    /// * `Some(GuestFunctionDefinition)` - If a function with the same name was previously
    ///   registered, returns the old definition that was replaced
    /// * `None` - If no function with this name was previously registered
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hyperlight_guest::guest_function_register::GuestFunctionRegister;
    /// use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
    /// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
    ///
    /// let mut registry = GuestFunctionRegister::new();
    ///
    /// // Define and register a function
    /// let func_def = GuestFunctionDefinition::new(
    ///     "AddNumbers".to_string(),
    ///     vec![ParameterType::Int, ParameterType::Int],
    ///     ReturnType::Int,
    ///     add_numbers_impl as usize
    /// );
    ///
    /// // No previous function with this name existed
    /// assert!(registry.register(func_def).is_none());
    ///
    /// // If we register a new version, the old one is returned
    /// let new_func_def = GuestFunctionDefinition::new(
    ///     "AddNumbers".to_string(),
    ///     vec![ParameterType::Int, ParameterType::Int],
    ///     ReturnType::Int,
    ///     improved_add_impl as usize
    /// );
    ///
    /// let old_def = registry.register(new_func_def);
    /// assert!(old_def.is_some());
    /// ```
    pub fn register(
        &mut self,
        guest_function: GuestFunctionDefinition,
    ) -> Option<GuestFunctionDefinition> {
        self.guest_functions
            .insert(guest_function.function_name.clone(), guest_function)
    }

    /// Retrieves a guest function definition by its name.
    ///
    /// This method looks up a function in the registry by its registered name and returns
    /// a reference to its definition if found.
    ///
    /// # Parameters
    ///
    /// * `function_name` - The name of the function to retrieve
    ///
    /// # Returns
    ///
    /// * `Some(&GuestFunctionDefinition)` - A reference to the function definition if found
    /// * `None` - If no function with the specified name is registered
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hyperlight_guest::guest_function_register::GuestFunctionRegister;
    /// use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
    /// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
    ///
    /// let mut registry = GuestFunctionRegister::new();
    ///
    /// // Register a function
    /// let func_def = GuestFunctionDefinition::new(
    ///     "CalculateTotal".to_string(),
    ///     vec![ParameterType::Int, ParameterType::Int],
    ///     ReturnType::Int,
    ///     calculate_impl as usize
    /// );
    /// registry.register(func_def);
    ///
    /// // Later, look up the function
    /// if let Some(func) = registry.get("CalculateTotal") {
    ///     // Use the function definition...
    ///     println!("Found function with {} parameters", func.parameter_types.len());
    /// } else {
    ///     println!("Function not found");
    /// }
    ///
    /// // Non-existent function
    /// assert!(registry.get("NonExistentFunction").is_none());
    /// ```
    pub fn get(&self, function_name: &str) -> Option<&GuestFunctionDefinition> {
        self.guest_functions.get(function_name)
    }
}

/// Registers a guest function to make it callable from the host.
/// 
/// This function adds a function definition to the global registry of guest functions.
/// Once registered, the host can call this function by its name. The registration 
/// must happen during guest initialization, typically in the `hyperlight_main` function.
/// 
/// # Parameters
/// 
/// * `function_definition` - The definition of the function to register, including its name,
///   parameter types, return type, and implementation function pointer
/// 
/// # Safety
/// 
/// This function uses unsafe code to access a global static variable. This is currently
/// safe because the guest is single-threaded, but may need to be revisited for
/// multi-threaded guests in the future.
/// 
/// # Example
/// 
/// ```no_run
/// use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
/// use hyperlight_guest::guest_function_register::register_function;
/// use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
/// use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
/// use hyperlight_guest::error::Result;
/// use alloc::vec::Vec;
/// 
/// // Define a function that will be callable from the host
/// fn my_guest_function(call: &FunctionCall) -> Result<Vec<u8>> {
///     // Implementation...
///     # Ok(Vec::new())
/// }
/// 
/// // Register the function during guest initialization
/// let function_def = GuestFunctionDefinition::new(
///     "MyFunction".to_string(),
///     Vec::from(&[ParameterType::Int, ParameterType::String]), 
///     ReturnType::Int,
///     my_guest_function as usize
/// );
/// 
/// register_function(function_def);
/// ```
pub fn register_function(function_definition: GuestFunctionDefinition) {
    unsafe {
        // This is currently safe, because we are single threaded, but we
        // should find a better way to do this, see issue #808
        #[allow(static_mut_refs)]
        let gfd = &mut REGISTERED_GUEST_FUNCTIONS;
        gfd.register(function_definition);
    }
}
