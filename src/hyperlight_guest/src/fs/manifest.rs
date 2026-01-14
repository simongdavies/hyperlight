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

//! HyperlightFS manifest parsing and inode lookup.
//!
//! This module parses the FlatBuffer manifest from the host and provides
//! path-based lookup to resolve guest paths to inodes.

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;

use hyperlight_common::flatbuffer_wrappers::hyperlight_fs::{HyperlightFSData, InodeData};

use super::error::FsError;

/// Parsed filesystem state.
struct FsState {
    /// Inode table from the manifest.
    inodes: Vec<InodeData>,
}

/// Global filesystem state.
///
/// SAFETY: Guest code is single-threaded, so this is safe.
static FS_STATE: FsStateCell = FsStateCell(UnsafeCell::new(None));

struct FsStateCell(UnsafeCell<Option<FsState>>);

// SAFETY: Guest is single-threaded.
unsafe impl Sync for FsStateCell {}

impl FsStateCell {
    fn get(&self) -> Option<&FsState> {
        // SAFETY: Guest is single-threaded.
        unsafe { (*self.0.get()).as_ref() }
    }

    fn set(&self, state: FsState) {
        // SAFETY: Guest is single-threaded.
        unsafe {
            *self.0.get() = Some(state);
        }
    }
}

/// Initialize the filesystem from a manifest.
///
/// # Arguments
///
/// * `manifest_ptr` - Pointer to the FlatBuffer manifest data
/// * `manifest_len` - Length of the manifest in bytes
///
/// # Safety
///
/// The caller must ensure:
/// - `manifest_ptr` points to valid memory containing the manifest
/// - The memory remains valid for the lifetime of the filesystem
/// - This function is only called once
pub unsafe fn init(manifest_ptr: *const u8, manifest_len: usize) -> Result<(), FsError> {
    if manifest_ptr.is_null() || manifest_len == 0 {
        return Err(FsError::InvalidManifest);
    }

    // SAFETY: Caller guarantees pointer is valid for manifest_len bytes
    let manifest_bytes = unsafe { core::slice::from_raw_parts(manifest_ptr, manifest_len) };

    let fs_data: HyperlightFSData = manifest_bytes
        .try_into()
        .map_err(|_| FsError::InvalidManifest)?;

    let state = FsState {
        inodes: fs_data.inodes,
    };

    FS_STATE.set(state);

    Ok(())
}

/// Check if the filesystem is initialized.
pub fn is_initialized() -> bool {
    FS_STATE.get().is_some()
}

/// Look up an inode by guest path.
///
/// Returns the inode index and a reference to the inode data.
pub fn lookup(path: &str) -> Result<(usize, &'static InodeData), FsError> {
    let state = FS_STATE.get().ok_or(FsError::NotInitialized)?;

    // Normalize path: must start with /
    if !path.starts_with('/') {
        return Err(FsError::InvalidPath);
    }

    // Handle root directory specially
    if path == "/" {
        for (idx, inode) in state.inodes.iter().enumerate() {
            if inode.path == "/" && inode.is_dir() {
                return Ok((idx, inode));
            }
        }
        return Err(FsError::NotFound);
    }

    // Normalize: remove trailing slash, collapse multiple slashes
    let normalized = normalize_path(path);

    // Linear search through inodes
    // TODO: Could build a hashmap for O(1) lookup if performance matters
    for (idx, inode) in state.inodes.iter().enumerate() {
        if inode.path == normalized {
            return Ok((idx, inode));
        }
    }

    Err(FsError::NotFound)
}

/// Look up a file (not directory) by guest path.
pub fn lookup_file(path: &str) -> Result<(usize, &'static InodeData), FsError> {
    let (idx, inode) = lookup(path)?;
    if inode.is_dir() {
        return Err(FsError::NotAFile);
    }
    Ok((idx, inode))
}

/// Look up a directory by guest path.
#[cfg(test)]
pub fn lookup_dir(path: &str) -> Result<(usize, &'static InodeData), FsError> {
    let (idx, inode) = lookup(path)?;
    if inode.is_file() {
        return Err(FsError::NotADirectory);
    }
    Ok((idx, inode))
}

/// List children of a directory.
pub fn list_dir(path: &str) -> Result<Vec<&'static InodeData>, FsError> {
    let (parent_idx, parent_inode) = lookup(path)?;
    if parent_inode.is_file() {
        return Err(FsError::NotADirectory);
    }

    let state = FS_STATE.get().ok_or(FsError::NotInitialized)?;

    let children: Vec<_> = state
        .inodes
        .iter()
        .filter(|inode| inode.parent == parent_idx as u32 && inode.path != parent_inode.path)
        .collect();

    Ok(children)
}

/// Normalize a path by removing trailing slashes and collapsing multiple slashes.
fn normalize_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut prev_slash = false;

    for c in path.chars() {
        if c == '/' {
            if !prev_slash {
                result.push(c);
            }
            prev_slash = true;
        } else {
            result.push(c);
            prev_slash = false;
        }
    }

    // Remove trailing slash (unless it's just "/")
    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/foo"), "/foo");
        assert_eq!(normalize_path("/foo/"), "/foo");
        assert_eq!(normalize_path("/foo/bar"), "/foo/bar");
        assert_eq!(normalize_path("/foo//bar"), "/foo/bar");
        assert_eq!(normalize_path("//foo//bar//"), "/foo/bar");
    }

    #[test]
    fn test_init_null_ptr() {
        let result = unsafe { init(core::ptr::null(), 0) };
        assert_eq!(result, Err(FsError::InvalidManifest));
    }
}
