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

//! HyperlightFS image with zero-copy memory mappings.
//!
//! This module provides the runtime representation of a HyperlightFS image,
//! with file data memory-mapped directly from the host filesystem.
//!
//! # Guest Address Assignment
//!
//! Guest addresses (GVA/GPA) are not known until sandbox creation time.
//! This image computes file offsets on-demand and generates the final FlatBuffer
//! manifest with actual guest addresses when the mapped files region base is known.

use hyperlight_common::flatbuffer_wrappers::hyperlight_fs::{HyperlightFSData, InodeData};
use hyperlight_common::mem::PAGE_SIZE_USIZE;
use tracing::info;

use super::builder::MappedFile;
use crate::Result;
use crate::error::HyperlightError;

/// A memory-mapped file with metadata for guest memory setup.
pub struct FileMapping {
    /// Guest path of the file
    guest_path: String,
    /// Size of the file in bytes
    size: u64,
    /// Pointer to the mapped memory
    #[cfg(unix)]
    mmap_ptr: *mut libc::c_void,
    /// Size of the mapping (page-aligned)
    #[cfg(unix)]
    mmap_len: usize,
}

impl FileMapping {
    /// Get the guest path of this file.
    pub fn guest_path(&self) -> &str {
        &self.guest_path
    }

    /// Get the size of the file in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }
}

#[cfg(unix)]
impl Drop for FileMapping {
    fn drop(&mut self) {
        if !self.mmap_ptr.is_null() && self.mmap_len > 0 {
            // SAFETY: mmap_ptr and mmap_len were created by mmap and are valid
            unsafe {
                libc::munmap(self.mmap_ptr, self.mmap_len);
            }
        }
    }
}

// SAFETY: FileMapping contains only a pointer to OS-managed read-only memory.
// The underlying memory is managed by the kernel and is safe to access from
// any thread.
#[cfg(unix)]
unsafe impl Send for FileMapping {}

// SAFETY: FileMapping is Sync because the underlying memory is read-only
// and managed by the kernel. Multiple threads can safely read from it.
#[cfg(unix)]
unsafe impl Sync for FileMapping {}

/// Internal representation of an inode before guest addresses are assigned.
#[derive(Debug, Clone)]
// TODO(Phase 3): Remove this allow when HyperlightFSImage is integrated with Sandbox
#[allow(dead_code)]
struct InodeEntry {
    /// Type of inode (file or directory)
    is_dir: bool,
    /// Guest path
    path: String,
    /// Parent inode index
    parent: u32,
    /// For files: size in bytes. For directories: 0
    size: u64,
}

/// A built HyperlightFS image with zero-copy file mappings.
///
/// The manifest (metadata) is generated on-demand when guest addresses are known.
/// File data is memory-mapped directly from the host filesystem using mmap.
/// This allows mapping large files (GB scale) without copying data.
///
/// # Sharing
///
/// This struct is `Send + Sync` and can be shared across multiple sandboxes.
/// The underlying mmaps share physical pages via the OS page cache.
// TODO(Phase 3): Remove this allow when HyperlightFSImage is integrated with Sandbox
#[allow(dead_code)]
pub struct HyperlightFSImage {
    /// Inode entries (files and directories)
    inode_entries: Vec<InodeEntry>,
    /// Memory-mapped files with metadata
    #[cfg(unix)]
    file_mappings: Vec<FileMapping>,
    /// Total size of the mapped files region (sum of page-aligned file sizes)
    mapped_files_region_size: usize,
}

// TODO(Phase 3): Remove this allow when HyperlightFSImage is integrated with Sandbox
#[allow(dead_code)]
impl HyperlightFSImage {
    /// Generate a manifest with final guest addresses.
    ///
    /// The `mapped_files_region_base` is the GVA/GPA where file contents will be mapped
    /// in the guest's address space. Each file's guest_address is computed by
    /// accumulating page-aligned file sizes in sorted order.
    ///
    /// # Arguments
    ///
    /// * `mapped_files_region_base` - The guest address where the mapped files region starts
    ///
    /// # Returns
    ///
    /// A FlatBuffer-serialized manifest with guest addresses.
    pub(crate) fn generate_manifest(&self, mapped_files_region_base: u64) -> Result<Vec<u8>> {
        // Compute offsets on-the-fly by accumulating page-aligned sizes
        let mut current_offset: u64 = 0;
        let inodes: Vec<InodeData> = self
            .inode_entries
            .iter()
            .map(|entry| {
                if entry.is_dir {
                    InodeData::directory(entry.path.clone(), entry.parent)
                } else {
                    // Compute the final guest address from current offset
                    let guest_address = mapped_files_region_base + current_offset;
                    // Advance offset by page-aligned size for next file
                    let aligned_size = ((entry.size as usize + PAGE_SIZE_USIZE - 1)
                        & !(PAGE_SIZE_USIZE - 1)) as u64;
                    current_offset += aligned_size;
                    InodeData::file(entry.path.clone(), entry.parent, guest_address, entry.size)
                }
            })
            .collect();

        let fs_data = HyperlightFSData::new(inodes);

        let manifest: Vec<u8> = (&fs_data).try_into().map_err(|e| {
            HyperlightError::Error(format!("Failed to serialize HyperlightFS manifest: {}", e))
        })?;

        Ok(manifest)
    }

    /// Get the total size of the mapped files region (sum of page-aligned file sizes).
    pub(crate) fn mapped_files_region_size(&self) -> usize {
        self.mapped_files_region_size
    }

    /// Get the file mappings for wiring into guest memory.
    #[cfg(unix)]
    pub(crate) fn file_mappings(&self) -> &[FileMapping] {
        &self.file_mappings
    }

    /// Get a pointer to a file's mapped data (zero-copy).
    ///
    /// Returns `None` if the index is out of bounds.
    ///
    /// # Safety
    ///
    /// The returned pointer is valid for the lifetime of this `HyperlightFSImage`.
    /// The caller must not write to this memory.
    #[cfg(all(unix, test))]
    pub fn file_data_ptr(&self, index: usize) -> Option<*const u8> {
        self.file_mappings
            .get(index)
            .map(|m| m.mmap_ptr as *const u8)
    }
}

/// Build a HyperlightFS image with zero-copy file mappings.
#[cfg(unix)]
pub(super) fn build_image(mut files: Vec<MappedFile>) -> Result<HyperlightFSImage> {
    use std::collections::HashMap;
    use std::fs::File;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

    // Sort files by guest path for consistent ordering
    files.sort_by(|a, b| a.guest_path.cmp(&b.guest_path));

    // Calculate total data size (sum of page-aligned file sizes)
    let total_data_size: usize = files
        .iter()
        .filter(|f| !f.is_dir)
        .map(|f| (f.size as usize + PAGE_SIZE_USIZE - 1) & !(PAGE_SIZE_USIZE - 1))
        .sum();

    // Build parent index map
    let mut parent_map: HashMap<String, u32> = HashMap::new();
    for (idx, file) in files.iter().enumerate() {
        parent_map.insert(file.guest_path.clone(), idx as u32);
    }

    // Create inode entries with relative offsets (guest addresses assigned later)
    let inode_entries: Vec<InodeEntry> = files
        .iter()
        .map(|file| {
            // Find parent directory
            let parent_path = file
                .guest_path
                .rsplit_once('/')
                .map(|(p, _)| p.to_string())
                .unwrap_or_default();
            let parent_idx = parent_map.get(&parent_path).copied().unwrap_or(0);

            InodeEntry {
                is_dir: file.is_dir,
                path: file.guest_path.clone(),
                parent: parent_idx,
                size: file.size,
            }
        })
        .collect();

    info!(
        inode_count = inode_entries.len(),
        mapped_files_region_size = total_data_size,
        "Built HyperlightFS inode entries"
    );

    // Memory-map file data (zero-copy!)
    let mut file_mappings: Vec<FileMapping> = Vec::new();

    for file in &files {
        if !file.is_dir && !file.host_path.as_os_str().is_empty() {
            let f = File::open(&file.host_path).map_err(|e| {
                HyperlightError::Error(format!("Failed to open {:?}: {}", file.host_path, e))
            })?;

            let file_size = f.metadata()?.size() as usize;
            if file_size == 0 {
                // Can't mmap empty files, skip
                info!(
                    guest = %file.guest_path,
                    "Skipping empty file (cannot mmap)"
                );
                continue;
            }

            let mmap_size = (file_size + PAGE_SIZE_USIZE - 1) & !(PAGE_SIZE_USIZE - 1);

            // SAFETY: mmap with MAP_PRIVATE | PROT_READ is safe for read-only access.
            // The kernel ensures the mapping is valid.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    mmap_size,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    f.as_raw_fd(),
                    0,
                )
            };

            if ptr == libc::MAP_FAILED {
                return Err(HyperlightError::Error(format!(
                    "mmap failed for {:?}: {}",
                    file.host_path,
                    std::io::Error::last_os_error()
                )));
            }

            info!(
                guest = %file.guest_path,
                host = %file.host_path.display(),
                size = file.size,
                mmap_size = mmap_size,
                "Memory-mapped file (zero-copy)"
            );

            file_mappings.push(FileMapping {
                guest_path: file.guest_path.clone(),
                size: file.size,
                mmap_ptr: ptr,
                mmap_len: mmap_size,
            });
        }
    }

    info!(
        inode_count = inode_entries.len(),
        file_count = file_mappings.len(),
        total_data_size = total_data_size,
        "HyperlightFS image built with zero-copy mmaps"
    );

    Ok(HyperlightFSImage {
        inode_entries,
        file_mappings,
        mapped_files_region_size: total_data_size,
    })
}

/// Windows stub - not yet implemented.
#[cfg(windows)]
pub(super) fn build_image(_files: Vec<MappedFile>) -> Result<HyperlightFSImage> {
    Err(HyperlightError::Error(
        "HyperlightFS is not yet supported on Windows".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_build_empty_image() {
        let files = vec![MappedFile {
            host_path: std::path::PathBuf::new(),
            guest_path: String::new(),
            size: 0,
            is_dir: true,
        }];

        let image = build_image(files).expect("Failed to build image");

        assert_eq!(image.inode_entries.len(), 1);
        assert_eq!(image.file_mappings.len(), 0); // Root dir only, no files
    }

    #[test]
    fn test_generate_manifest_with_guest_address() {
        let files = vec![
            MappedFile {
                host_path: std::path::PathBuf::new(),
                guest_path: "/".to_string(),
                size: 0,
                is_dir: true,
            },
            MappedFile {
                host_path: std::path::PathBuf::new(), // Empty path = no mmap
                guest_path: "/test.txt".to_string(),
                size: 100,
                is_dir: false,
            },
        ];

        let image = build_image(files).expect("Failed to build image");

        // Generate manifest with a specific base address
        let mapped_files_region_base: u64 = 0x1000_0000;
        let manifest = image
            .generate_manifest(mapped_files_region_base)
            .expect("Failed to generate manifest");

        // Parse the manifest back and verify guest_address
        let parsed: HyperlightFSData = manifest.as_slice().try_into().unwrap();
        assert_eq!(parsed.inodes.len(), 2);

        // Find the file inode
        let file_inode = parsed.inodes.iter().find(|i| i.is_file()).unwrap();
        assert_eq!(file_inode.guest_address, mapped_files_region_base); // First file at offset 0
        assert_eq!(file_inode.size, 100);
    }

    #[cfg(unix)]
    #[test]
    fn test_build_with_file() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let files = vec![MappedFile {
            host_path: file_path,
            guest_path: "/test.txt".to_string(),
            size: 11,
            is_dir: false,
        }];

        let image = build_image(files).expect("Failed to build image");

        assert_eq!(image.file_mappings().len(), 1);
        assert_eq!(image.file_mappings()[0].guest_path(), "/test.txt");
        assert_eq!(image.file_mappings()[0].size(), 11);

        // Verify we can read the mapped data
        let ptr = image.file_data_ptr(0).unwrap();
        let data = unsafe { std::slice::from_raw_parts(ptr, 11) };
        assert_eq!(data, b"hello world");

        // Generate manifest and verify
        let manifest = image.generate_manifest(0x2000_0000).unwrap();
        let parsed: HyperlightFSData = manifest.as_slice().try_into().unwrap();
        let file_inode = parsed.inodes.iter().find(|i| i.is_file()).unwrap();
        assert_eq!(file_inode.guest_address, 0x2000_0000);
    }
}
