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

//! FAT filesystem image management for HyperlightFS.
//!
//! This module provides [`FatImage`], a wrapper around FAT filesystem images
//! that handles:
//! - Exclusive file locking to prevent concurrent access
//! - Memory mapping with `MAP_SHARED` for write persistence
//! - FAT32 formatting for new images
//! - Automatic cleanup of temporary files
//!
//! # Zero-Copy Architecture
//!
//! FAT images use `MAP_SHARED` memory mapping, which means:
//! - Guest writes go directly to the kernel's page cache
//! - The same physical pages are shared between host and guest
//! - Durability is ensured by `msync(MS_SYNC)` called during sandbox HLT handling
//!
//! # Exclusive Locking
//!
//! Each FAT image is exclusively locked using `flock(LOCK_EX)` to prevent
//! multiple sandboxes from concurrently accessing the same backing file.
//!
//! # Example
//!
//! ```ignore
//! use hyperlight_host::hyperlight_fs::FatImage;
//!
//! // Create a new temporary FAT image (1MB)
//! let image = FatImage::create_temp(1024 * 1024)?;
//!
//! // Or open an existing image (acquires exclusive lock)
//! let image = FatImage::open("/path/to/existing.fat")?;
//!
//! // Get the mmap'd region for guest memory setup
//! let ptr = image.as_ptr();
//! let size = image.size();
//! ```

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use tracing::{debug, error, info, warn};

use crate::Result;
use crate::error::HyperlightError;

// FatImage requires 64-bit pointers for mmap of large files
#[cfg(not(target_pointer_width = "64"))]
compile_error!("FatImage requires a 64-bit target");

/// Minimum FAT image size (1MB) - FAT32 requires at least ~32KB for metadata,
/// but we use 1MB as a practical minimum.
pub const MIN_FAT_IMAGE_SIZE: usize = 1_024 * 1_024;

/// Maximum FAT image size (16GB) - practical limit to avoid excessive mmap usage.
/// FAT32 itself supports up to ~2TB with 512-byte sectors, but we cap it here
/// for sanity. The 4GB-1 limit often cited is for individual *files within*
/// a FAT32 filesystem, not the volume size.
pub const MAX_FAT_IMAGE_SIZE: usize = 16 * 1_024 * 1_024 * 1_024;

/// A FAT filesystem image backed by an mmap'd host file.
///
/// The backing file is exclusively locked (`flock`) to prevent multiple
/// sandboxes from mapping the same file concurrently. The memory mapping
/// uses `MAP_SHARED` so writes persist to the backing file automatically.
///
/// # Lifecycle
///
/// 1. **Creation**: `create_temp()` or `create_at()` creates a new file,
///    formats it as FAT32, and acquires an exclusive lock.
/// 2. **Opening**: `open()` opens an existing file and acquires an exclusive lock.
/// 3. **Usage**: `as_ptr()` and `size()` provide access for guest memory mapping.
/// 4. **Cleanup**: On `drop()`, the lock is released. For temp files, the file is deleted.
#[cfg(unix)]
#[derive(Debug)]
pub struct FatImage {
    /// The backing file (holds the exclusive lock).
    /// Kept for its Drop impl which releases the flock.
    _file: File,
    /// Memory-mapped region (MAP_SHARED for write persistence).
    mmap_ptr: *mut u8,
    /// Size of the mapped region.
    mmap_size: usize,
    /// Path to the backing file (for cleanup).
    path: PathBuf,
    /// Whether this is a temp file (delete on drop).
    is_temp: bool,
}

// SAFETY: FatImage is Send because the mmap'd region is process-local
// and the file lock ensures exclusive access.
//
// FatImage is intentionally NOT Sync. While the raw pointer could technically
// support shared reads, FatImage is designed to be owned by a single Sandbox,
// and Sandbox itself is not Sync.
#[cfg(unix)]
unsafe impl Send for FatImage {}

#[cfg(unix)]
impl FatImage {
    /// Open an existing FAT image from a file with exclusive lock.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to an existing FAT image file
    ///
    /// # Returns
    ///
    /// A `FatImage` with an exclusive lock on the file.
    ///
    /// # Errors
    ///
    /// Returns `HyperlightError::Error` if the file doesn't exist, can't be opened,
    /// is not a valid FAT image, or another process holds the lock.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        info!(path = %path.display(), "Opening FAT image");

        // Open file for read/write
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| {
                error!(path = %path.display(), error = %e, "Failed to open FAT image");
                HyperlightError::Error(format!("Failed to open FAT image {:?}: {}", path, e))
            })?;

        // Try to acquire exclusive lock (non-blocking)
        file.try_lock_exclusive().map_err(|e| {
            error!(path = %path.display(), error = %e, "FAT image is locked by another process");
            HyperlightError::Error(format!(
                "File is locked by another process {:?}: {}",
                path, e
            ))
        })?;

        // Get file size
        let metadata = file.metadata().map_err(|e| {
            error!(path = %path.display(), error = %e, "Failed to get FAT image metadata");
            HyperlightError::Error(format!("Failed to get metadata for {:?}: {}", path, e))
        })?;
        let size = metadata.len() as usize;

        Self::validate_size(size)?;

        // Memory map the file with MAP_SHARED
        let mmap_ptr = Self::mmap_file(&file, size)?;

        // Validate it's actually a FAT filesystem
        Self::validate_fat_image(mmap_ptr, size).inspect_err(|_| {
            // Unmap on validation failure. The file lock is released when `file`
            // is dropped at function exit (implicit via the returned Err).
            unsafe { libc::munmap(mmap_ptr as *mut libc::c_void, size) };
        })?;

        info!(path = %path.display(), size, "FAT image opened and locked");

        Ok(Self {
            _file: file,
            mmap_ptr,
            mmap_size: size,
            path,
            is_temp: false,
        })
    }

    /// Create a new empty FAT image at the specified path.
    ///
    /// Creates the file, extends it to the specified size (sparse if supported),
    /// formats it as FAT32, and acquires an exclusive lock.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the FAT image will be created
    /// * `size_bytes` - Size of the image (must be between 1MB and 16GB)
    ///
    /// # Errors
    ///
    /// - `HyperlightError::Error` if size is out of range or if FAT formatting fails
    /// - `HyperlightError::IOError` if file creation fails
    pub fn create_at<P: AsRef<Path>>(path: P, size_bytes: usize) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        Self::validate_size(size_bytes)?;

        info!(path = %path.display(), size = size_bytes, "Creating FAT image");

        // Create file (fails if it already exists)
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                error!(path = %path.display(), error = %e, "Failed to create FAT image");
                HyperlightError::Error(format!("Failed to create FAT image {:?}: {}", path, e))
            })?;

        // Acquire exclusive lock (shouldn't fail on newly created file, but if it does we should not try and delete it since someone else may be using it)
        file.try_lock_exclusive().map_err(|e| {
            error!(path = %path.display(), error = %e, "Failed to lock newly created FAT image");
            HyperlightError::Error(format!(
                "Failed to lock newly created file {:?}: {}",
                path, e
            ))
        })?;

        Self::initialize_image(file, path, size_bytes, false)
    }

    /// Create a new empty FAT image as a temporary file.
    ///
    /// The temp file will be deleted when the `FatImage` is dropped.
    ///
    /// # Arguments
    ///
    /// * `size_bytes` - Size of the image (must be between 1MB and 16GB)
    ///
    /// # Errors
    ///
    /// - `HyperlightError::Error` if size is out of range
    /// - `HyperlightError::IOError` if temp file creation fails
    pub fn create_temp(size_bytes: usize) -> Result<Self> {
        Self::validate_size(size_bytes)?;

        // Create temp file and persist it (so path remains valid)
        let temp_file = tempfile::NamedTempFile::new().map_err(|e| {
            error!(error = %e, "Failed to create temp file for FAT image");
            HyperlightError::Error(format!("Failed to create temp file: {}", e))
        })?;

        let path = temp_file.path().to_path_buf();

        info!(path = %path.display(), size = size_bytes, "Creating temporary FAT image");

        // persist() converts NamedTempFile to a regular File, disabling its auto-delete.
        // FatImage::Drop will delete the file since is_temp=true.
        let file = temp_file.persist(&path).map_err(|e| {
            error!(path = %path.display(), error = %e, "Failed to persist temp file");
            HyperlightError::Error(format!("Failed to persist temp file: {}", e))
        })?;

        // Acquire exclusive lock (shouldn't fail on newly created file, but if it does, leave file for debugging)
        file.try_lock_exclusive().map_err(|e| {
            error!(path = %path.display(), error = %e, "Failed to lock temp FAT image");
            HyperlightError::Error(format!("Failed to lock temp file: {}", e))
        })?;

        Self::initialize_image(file, path, size_bytes, true)
    }

    /// Get a pointer to the mmap'd region.
    ///
    /// This pointer can be used to map the FAT image into guest memory.
    /// The pointer is valid for the lifetime of this `FatImage`.
    pub fn as_ptr(&self) -> *const u8 {
        self.mmap_ptr as *const u8
    }

    /// Get a mutable pointer to the mmap'd region.
    ///
    /// This pointer can be used to map the FAT image into guest memory
    /// with write access.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.mmap_ptr
    }

    /// Get the size of the FAT image in bytes.
    pub fn size(&self) -> usize {
        self.mmap_size
    }

    /// Get the path to the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if this is a temporary file (will be deleted on drop).
    pub fn is_temp(&self) -> bool {
        self.is_temp
    }

    // ---- Private helpers ----

    /// Initialize a newly created image file: extend, format, and mmap.
    /// Cleans up the file on failure.
    fn initialize_image(file: File, path: PathBuf, size: usize, is_temp: bool) -> Result<Self> {
        // Helper to delete file on error
        let cleanup_on_err = |e| {
            warn!(path = %path.display(), "Deleting incomplete FAT image after initialization failure");
            let _ = std::fs::remove_file(&path);
            e
        };

        // Extend file to size (creates sparse file on Linux)
        Self::extend_file(&file, size).map_err(cleanup_on_err)?;

        // Format as FAT32
        Self::format_fat32(&file, size).map_err(cleanup_on_err)?;

        // Memory map the file
        let mmap_ptr = Self::mmap_file(&file, size).map_err(cleanup_on_err)?;

        debug!(path = %path.display(), size, is_temp, "FAT image initialized");

        Ok(Self {
            _file: file,
            mmap_ptr,
            mmap_size: size,
            path,
            is_temp,
        })
    }

    fn validate_size(size_bytes: usize) -> Result<()> {
        if !(MIN_FAT_IMAGE_SIZE..=MAX_FAT_IMAGE_SIZE).contains(&size_bytes) {
            error!(
                size = size_bytes,
                min = MIN_FAT_IMAGE_SIZE,
                max = MAX_FAT_IMAGE_SIZE,
                "FAT image size out of range"
            );
            return Err(HyperlightError::Error(format!(
                "FAT image size {} is out of range ({} - {})",
                size_bytes, MIN_FAT_IMAGE_SIZE, MAX_FAT_IMAGE_SIZE
            )));
        }
        Ok(())
    }

    fn extend_file(file: &File, size: usize) -> Result<()> {
        // Use ftruncate to extend the file (creates sparse file on Linux)
        file.set_len(size as u64).map_err(|e| {
            error!(size, error = %e, "Failed to extend FAT image file");
            HyperlightError::Error(format!("Failed to extend file to {} bytes: {}", size, e))
        })?;
        Ok(())
    }

    fn mmap_file(file: &File, size: usize) -> Result<*mut u8> {
        use std::os::unix::io::AsRawFd;

        // SAFETY:
        // - `file` is a valid, open file descriptor (from OpenOptions or tempfile)
        // - `size` > 0 (validated by validate_size, minimum 1MB)
        // - offset 0 is valid for any file
        // - We have exclusive access via flock, preventing concurrent modification
        // - The file has been extended to `size` bytes (extend_file called first)
        // - The returned pointer is only used while FatImage is alive (Drop does munmap)
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            error!(size, error = %err, "Failed to mmap FAT image");
            return Err(HyperlightError::Error(format!("mmap failed: {}", err)));
        }

        Ok(ptr as *mut u8)
    }

    fn format_fat32(file: &File, size: usize) -> Result<()> {
        use std::io::{Seek, SeekFrom};

        // fatfs::format_volume requires ReadWriteSeek. &File implements Read, Write, and Seek
        // via interior mutability (pread/pwrite), so we can use it directly.
        let mut file_ref = file;

        // Seek to start before formatting
        file_ref.seek(SeekFrom::Start(0)).map_err(|e| {
            error!(error = %e, "Failed to seek to start for FAT formatting");
            HyperlightError::Error(format!("Failed to seek to start: {}", e))
        })?;

        // Format as FAT32 explicitly (don't let fatfs auto-select FAT12/16 for small volumes)
        let options = fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat32);
        fatfs::format_volume(file_ref, options).map_err(|e| {
            error!(size, error = %e, "Failed to format FAT volume");
            HyperlightError::Error(format!("Failed to format FAT volume: {}", e))
        })?;

        // Ensure all data is flushed to disk
        file.sync_all().map_err(|e| {
            error!(error = %e, "Failed to sync FAT volume after formatting");
            HyperlightError::Error(format!("Failed to sync after formatting: {}", e))
        })?;

        info!(size, "FAT volume formatted");

        Ok(())
    }

    /// Validate that the mmap'd region contains a valid FAT filesystem.
    fn validate_fat_image(ptr: *mut u8, size: usize) -> Result<()> {
        // SAFETY:
        // - `ptr` is valid for `size` bytes (from successful mmap_file call)
        // - Data is initialized: either formatted by format_fat32, or read from existing file
        // - The slice lifetime is bounded by this function scope (no escape)
        // - We use a mutable slice because fatfs::FileSystem requires ReadWriteSeek,
        //   but we only read (validation doesn't modify the filesystem)
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, size) };
        let cursor = std::io::Cursor::new(slice);

        // Try to open as a FAT filesystem - this validates the boot sector
        fatfs::FileSystem::new(cursor, fatfs::FsOptions::new()).map_err(|e| {
            error!(error = %e, "File is not a valid FAT image");
            HyperlightError::Error(format!("Not a valid FAT image: {}", e))
        })?;

        Ok(())
    }
}

#[cfg(unix)]
impl Drop for FatImage {
    fn drop(&mut self) {
        // Note: msync is NOT called here. Durability is ensured by the sandbox's HLT handling
        // which calls msync before returning from sandbox.call(). Calling msync here would be:
        // 1. Redundant in the normal case (HLT already synced)
        // 2. Potentially harmful in error cases (if persisting corrupted data)

        // Unmap the memory region
        // SAFETY: mmap_ptr and mmap_size are valid from construction
        let result = unsafe { libc::munmap(self.mmap_ptr as *mut libc::c_void, self.mmap_size) };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            error!(error = %err, "Failed to munmap FAT image");
        }

        // Lock is automatically released when file is dropped

        // Delete temp file if applicable
        if self.is_temp {
            if let Err(e) = std::fs::remove_file(&self.path) {
                error!(path = %self.path.display(), error = %e, "Failed to delete temp FAT image");
            } else {
                debug!(path = %self.path.display(), "Deleted temp FAT image");
            }
        }
    }
}

/// Windows stub - not yet implemented.
#[cfg(windows)]
pub struct FatImage {
    _private: (),
}

#[cfg(windows)]
impl FatImage {
    /// Not supported on Windows.
    pub fn open<P: AsRef<Path>>(_path: P) -> Result<Self> {
        Err(HyperlightError::Error(
            "FatImage is not supported on Windows".to_string(),
        ))
    }

    /// Not supported on Windows.
    pub fn create_at<P: AsRef<Path>>(_path: P, _size_bytes: usize) -> Result<Self> {
        Err(HyperlightError::Error(
            "FatImage is not supported on Windows".to_string(),
        ))
    }

    /// Not supported on Windows.
    pub fn create_temp(_size_bytes: usize) -> Result<Self> {
        Err(HyperlightError::Error(
            "FatImage is not supported on Windows".to_string(),
        ))
    }

    /// Not supported on Windows.
    pub fn as_ptr(&self) -> *const u8 {
        unreachable!("FatImage cannot be constructed on Windows")
    }

    /// Not supported on Windows.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        unreachable!("FatImage cannot be constructed on Windows")
    }

    /// Not supported on Windows.
    pub fn size(&self) -> usize {
        unreachable!("FatImage cannot be constructed on Windows")
    }

    /// Not supported on Windows.
    pub fn path(&self) -> &Path {
        unreachable!("FatImage cannot be constructed on Windows")
    }

    /// Not supported on Windows.
    pub fn is_temp(&self) -> bool {
        unreachable!("FatImage cannot be constructed on Windows")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_fat_image_create_temp() {
        let image = FatImage::create_temp(MIN_FAT_IMAGE_SIZE).expect("Failed to create temp image");

        assert_eq!(image.size(), MIN_FAT_IMAGE_SIZE);
        assert!(image.is_temp());
        assert!(!image.as_ptr().is_null());

        // Verify the file exists
        assert!(image.path().exists());

        let path = image.path().to_path_buf();

        // Drop should delete the temp file
        drop(image);
        assert!(!path.exists());
    }

    #[test]
    fn test_fat_image_create_at() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.fat");

        let image =
            FatImage::create_at(&path, MIN_FAT_IMAGE_SIZE).expect("Failed to create image at path");

        assert_eq!(image.size(), MIN_FAT_IMAGE_SIZE);
        assert!(!image.is_temp());
        assert!(path.exists());

        drop(image);

        // File should persist after drop (not temp)
        assert!(path.exists());
    }

    #[test]
    fn test_fat_image_open() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.fat");

        // Create first
        {
            let _image = FatImage::create_at(&path, MIN_FAT_IMAGE_SIZE)
                .expect("Failed to create image at path");
        }

        // Open existing
        let image = FatImage::open(&path).expect("Failed to open existing image");

        assert_eq!(image.size(), MIN_FAT_IMAGE_SIZE);
        assert!(!image.is_temp());
    }

    #[test]
    fn test_fat_image_exclusive_lock() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.fat");

        // Create and hold lock
        let _image1 =
            FatImage::create_at(&path, MIN_FAT_IMAGE_SIZE).expect("Failed to create image");

        // Second open should fail with lock error
        let result = FatImage::open(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("locked"), "Expected lock error, got: {}", err);
    }

    #[test]
    fn test_fat_image_lock_released_on_drop() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.fat");

        // Create and drop
        {
            let _image =
                FatImage::create_at(&path, MIN_FAT_IMAGE_SIZE).expect("Failed to create image");
        }

        // Should be able to open now
        let image = FatImage::open(&path).expect("Failed to open after drop");
        assert_eq!(image.size(), MIN_FAT_IMAGE_SIZE);
    }

    #[test]
    fn test_fat_image_size_validation() {
        // Too small
        let result = FatImage::create_temp(MIN_FAT_IMAGE_SIZE - 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("out of range"));

        // Too large (for open - create a sparse file that reports oversized)
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("oversized.fat");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_FAT_IMAGE_SIZE as u64 + 1).unwrap();
        drop(file);

        let result = FatImage::open(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("out of range"),
            "Expected 'out of range' error, got: {}",
            err
        );
    }

    #[test]
    fn test_fat_image_create_at_fails_if_exists() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("existing.fat");

        // Create file first time - should succeed
        {
            let _image = FatImage::create_at(&path, MIN_FAT_IMAGE_SIZE)
                .expect("Failed to create image first time");
        }

        // Create again at same path - should fail
        let result = FatImage::create_at(&path, MIN_FAT_IMAGE_SIZE);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exists") || err.contains("Failed to create"),
            "Expected 'already exists' error, got: {}",
            err
        );
    }

    #[test]
    fn test_fat_image_open_rejects_non_fat_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("not_a_fat.img");

        // Create a file with garbage content (not a FAT image)
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MIN_FAT_IMAGE_SIZE as u64).unwrap();
        drop(file);

        // Opening should fail with validation error
        let result = FatImage::open(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("valid FAT"),
            "Expected 'valid FAT' error, got: {}",
            err
        );
    }
}
