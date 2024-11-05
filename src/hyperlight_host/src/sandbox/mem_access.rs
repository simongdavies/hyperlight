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

use std::sync::{Arc, Mutex};

use tracing::{instrument, Span};

use super::mem_mgr::MemMgrWrapper;
use crate::error::HyperlightError::StackOverflow;
use crate::hypervisor::handlers::{
    MemAccessHandler, MemAccessHandlerFunction, MemAccessHandlerWrapper,
};
use crate::mem::shared_mem::HostSharedMemory;
use crate::{log_then_return, Result};

#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
pub(super) fn handle_mem_access_impl(wrapper: &MemMgrWrapper<HostSharedMemory>) -> Result<()> {
    if !wrapper.check_stack_guard()? {
        log_then_return!(StackOverflow());
    }

    Ok(())
}

#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn mem_access_handler_wrapper(
    wrapper: MemMgrWrapper<HostSharedMemory>,
) -> MemAccessHandlerWrapper {
    let mem_access_func: MemAccessHandlerFunction =
        Box::new(move || handle_mem_access_impl(&wrapper));
    let mem_access_hdl = MemAccessHandler::from(mem_access_func);
    Arc::new(Mutex::new(mem_access_hdl))
}
