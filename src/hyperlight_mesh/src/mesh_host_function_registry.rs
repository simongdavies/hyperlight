use std::sync::Mutex;

use hyperlight_host::func::HyperlightFunction;
use hyperlight_host::sandbox::ExtraAllowedSyscall;
use hyperlight_host::sandbox_state::sandbox::HostFunctionRegistry;
use hyperlight_host::Result;

use crate::mesh_sandbox_builder::HostFunction;

static HOST_FUNCTIONS: Mutex<Vec<HostFunction>> = Mutex::new(Vec::new());

pub(crate) fn get_host_functions_mut() -> Result<std::sync::MutexGuard<'static, Vec<HostFunction>>>
{
    HOST_FUNCTIONS
        .lock()
        .map_err(|e| hyperlight_error::new_error!("Error locking host function registry: {:?}", e))
}

pub struct MeshHostFunctionRegistry;
impl MeshHostFunctionRegistry {
    pub fn new() -> Self {
        Self
    }
}
impl HostFunctionRegistry for MeshHostFunctionRegistry {
    fn register_host_function(
        &mut self,
        host_function_definition: hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition,
        host_function: HyperlightFunction,
    ) -> Result<()> {
        let host_function = HostFunction::new(host_function_definition, host_function, None);
        get_host_functions_mut()?.push(host_function);
        Ok(())
    }

    fn register_host_function_with_syscalls(
        &mut self,
        host_function_definition: hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition,
        host_function: HyperlightFunction,
        syscalls: Vec<ExtraAllowedSyscall>,
    ) -> Result<()> {
        let host_function =
            HostFunction::new(host_function_definition, host_function, Some(syscalls));
        get_host_functions_mut()?.push(host_function);
        Ok(())
    }
}
