/*
Copyright 2025  The Hyperlight Authors.

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

//! HyperlightFS: Read-only filesystem for guest code.
//!
//! This module provides a simple VFS for reading files that have been
//! mapped from the host into guest memory.
//!
//! # Usage
//!
//! ```ignore
//! use hyperlight_guest::fs;
//!
//! // Initialize (called by runtime with manifest location)
//! unsafe { fs::init(manifest_ptr, manifest_len)?; }
//!
//! // Open and read a file
//! let mut file = fs::open("/config.json")?;
//! let mut buf = [0u8; 1024];
//! let n = file.read(&mut buf)?;
//! ```

mod error;
mod fd;
mod file;
mod manifest;

pub use error::FsError;
pub use file::{DirEntry, File, Stat, open, read_dir, stat};
pub use manifest::{init, is_initialized};

#[cfg(test)]
mod tests;
