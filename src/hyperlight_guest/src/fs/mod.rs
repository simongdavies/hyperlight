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

//! HyperlightFS: Filesystem for guest code.
//!
//! This module provides a VFS for reading files that have been
//! mapped from the host into guest memory, and for accessing
//! read-write FAT filesystems.
//!
//! # Usage
//!
//! ## Reading files (read-only, memory-mapped)
//!
//! ```ignore
//! use embedded_io::Read; // Required for file.read()
//! use hyperlight_guest::fs;
//!
//! // Initialize (called by runtime with manifest location)
//! unsafe { fs::init(manifest_ptr, manifest_len)?; }
//!
//! // Check file size first (optional)
//! let info = fs::stat("/config.json")?;
//! // info.size contains the file size in bytes
//!
//! // Read file contents
//! let mut file = fs::open("/config.json")?;
//! let mut buf = [0u8; 1024];
//! let bytes_read = file.read(&mut buf)?;
//! // bytes_read tells you how many bytes were actually read.
//! // If bytes_read < buf.len(), you've reached EOF.
//! // If bytes_read == buf.len(), there may be more data - call read() again.
//! ```

mod error;
pub mod fat;
mod fd;
pub mod file;
mod manifest;
pub mod vfs;

pub use error::FsError;
pub use file::{DirEntry, File, Stat, open, read_dir, stat};
pub use manifest::{init, is_initialized, vfs, vfs_mut};

#[cfg(test)]
mod tests;
