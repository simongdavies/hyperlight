use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterType, ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition;
use hyperlight_error::new_error;
use hyperlight_host::func::HyperlightFunction;
#[cfg(all(feature = "seccomp", target_os = "linux"))]
use hyperlight_host::sandbox::ExtraAllowedSyscall;
use hyperlight_host::sandbox_state::sandbox::HostFunctionRegistry;
use hyperlight_host::Result;
use mesh::rpc::FailableRpc;
use mesh::MeshPayload;

#[derive(MeshPayload)]
pub(crate) struct HostFunctionWorkerParameters {
    pub rpc: mesh::Receiver<HostFunctionWorkerRpc>,
}

#[derive(MeshPayload)]
pub(crate) struct HostFunctionCall {
    pub(crate) function_name: String,
    pub(crate) function_return_type: ReturnType,
    pub(crate) function_args: Option<Vec<ParameterValue>>,
}

impl HostFunctionCall {
    pub(crate) fn new(
        function_name: String,
        function_return_type: ReturnType,
        function_args: Option<Vec<ParameterValue>>,
    ) -> Self {
        Self {
            function_name,
            function_return_type,
            function_args,
        }
    }
}

#[derive(MeshPayload)]
pub(crate) enum HostFunctionWorkerRpc {
    CallHostFunction(FailableRpc<HostFunctionCall, ReturnValue>),
}

pub(super) type HostFunctionWorkerHandler = Arc<
    Mutex<dyn Fn(Vec<ParameterValue>) -> hyperlight_host::Result<ReturnValue> + Send + 'static>,
>;

pub(super) trait RegisterHostFunctionHandler<'a, H: HostFunctionRegistry> {
    fn register(
        &self,
        host_function_registry: &mut H,
        name: &str,
        parameter_types: Option<Vec<ParameterType>>,
        return_type: ReturnType,
    ) -> Result<()>;
    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    fn register_with_extra_allowed_syscalls(
        &self,
        host_function_registry: &mut H,
        name: &str,
        parameter_types: Option<Vec<ParameterType>>,
        return_type: ReturnType,
        extra_allowed_syscalls: Vec<crate::sandbox::ExtraAllowedSyscall>,
    ) -> Result<()>;
}

impl<H> RegisterHostFunctionHandler<'_, H> for HostFunctionWorkerHandler
where
    H: HostFunctionRegistry,
{
    fn register(
        &self,
        host_function_registry: &mut H,
        name: &str,
        parameter_types: Option<Vec<ParameterType>>,
        return_type: ReturnType,
    ) -> Result<()> {
        let cloned = self.clone();
        let func = Box::new(move |args| {
            cloned
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?(
                args
            )
        });
        host_function_registry.register_host_function(
            HostFunctionDefinition::new(name.to_string(), parameter_types, return_type),
            HyperlightFunction::new(func),
        )
    }
    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    fn register_with_extra_allowed_syscalls(
        &self,
        host_function_registry: &mut H,
        name: &str,
        parameter_types: Option<Vec<ParameterType>>,
        return_type: ReturnType,
        extra_allowed_syscalls: Vec<ExtraAllowedSyscall>,
    ) -> Result<()> {
        let cloned = self.clone();
        let func = Box::new(move |args| {
            cloned
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?(
                args
            )
        });
        host_function_registry.register_host_function_with_syscalls(
            HostFunctionDefinition::new(name.to_string(), parameter_types, return_type),
            HyperlightFunction::new(func),
            extra_allowed_syscalls,
        )
    }
}
