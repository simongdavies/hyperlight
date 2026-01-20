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

//! Unified file handle with VFS routing.
//!
//! This module provides a [`File`] type that transparently works with both:
//! - **Read-only files**: Memory-mapped from the host manifest
//! - **FAT files**: Read-write files on FAT filesystem mounts
//!
//! The VFS automatically routes operations to the correct backend based on
//! which mount point the file path resolves to.
//!
//! # Opening Files
//!
//! Use [`open()`] for simple read-only access, or [`OpenOptions`] for more control:
//!
//! ```ignore
//! use hyperlight_guest::fs::{self, OpenOptions};
//!
//! // Simple read-only open (works for both RO and FAT files)
//! let file = fs::open("/config.json")?;
//!
//! // Open with specific options (FAT files support all options)
//! let file = OpenOptions::new()
//!     .read(true)
//!     .write(true)
//!     .create(true)
//!     .open("/data/output.txt")?;
//! ```
//!
//! # File Operations
//!
//! [`File`] implements [`embedded_io::Read`], [`embedded_io::Seek`], and
//! [`embedded_io::Write`]. Write operations return [`FsError::ReadOnly`]
//! for read-only files.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_io::{ErrorType, Read, Seek, SeekFrom, Write};

use super::error::FsError;
use super::fat::GuestFatFile;
use super::fd::{self, OpenFile};
use super::manifest;

/// Builder for opening files with specific access options.
///
/// This provides a readable, builder-pattern API for specifying file open modes
/// instead of multiple boolean parameters. For FAT files, all options are
/// supported. For read-only files, only `read(true)` is valid.
///
/// # Default Behavior
///
/// If you call `open()` without setting any options, it defaults to read-only
/// mode (equivalent to `.read(true)`).
///
/// # Examples
///
/// ```ignore
/// use hyperlight_guest::fs::OpenOptions;
///
/// // Open for reading (explicit)
/// let file = OpenOptions::new()
///     .read(true)
///     .open("/config.txt")?;
///
/// // Open for reading (implicit - same as above)
/// let file = OpenOptions::new().open("/config.txt")?;
///
/// // Create a new file for writing (FAT only)
/// let file = OpenOptions::new()
///     .write(true)
///     .create(true)
///     .open("/data/output.txt")?;
///
/// // Open existing file for read-write (FAT only)
/// let file = OpenOptions::new()
///     .read(true)
///     .write(true)
///     .open("/data/existing.txt")?;
///
/// // Truncate existing file on open (FAT only)
/// let file = OpenOptions::new()
///     .write(true)
///     .truncate(true)
///     .open("/data/existing.txt")?;
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    create: bool,
    truncate: bool,
}

impl OpenOptions {
    /// Create a new `OpenOptions` with all options set to false.
    ///
    /// Note: You must set at least `read(true)` or `write(true)` for a valid open.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            read: false,
            write: false,
            create: false,
            truncate: false,
        }
    }

    /// Sets the option for read access.
    ///
    /// When true, the file will be openable for reading.
    #[must_use]
    pub const fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Sets the option for write access.
    ///
    /// When true, the file will be openable for writing.
    /// Only supported for FAT filesystems.
    #[must_use]
    pub const fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Sets the option to create a new file if it doesn't exist.
    ///
    /// Only supported for FAT filesystems.
    #[must_use]
    pub const fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    /// Sets the option to truncate the file to zero length on open.
    ///
    /// Requires `write(true)`. Only supported for FAT filesystems.
    #[must_use]
    pub const fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }

    /// Opens the file at the specified path with the configured options.
    ///
    /// If neither `read` nor `write` is set, defaults to `read(true)`.
    ///
    /// # Errors
    ///
    /// - [`FsError::NotInitialized`] if the filesystem hasn't been initialized
    /// - [`FsError::NotFound`] if the path doesn't exist and `create` is false
    /// - [`FsError::NotAFile`] if the path refers to a directory
    /// - [`FsError::ReadOnly`] if write/create/truncate on a read-only mount
    /// - [`FsError::InvalidArgument`] if `truncate` is set without `write`
    pub fn open(self, path: &str) -> Result<File, FsError> {
        // Validate: truncate requires write
        if self.truncate && !self.write {
            return Err(FsError::InvalidArgument);
        }

        // Default to read if neither read nor write specified
        let read = if !self.read && !self.write {
            true
        } else {
            self.read
        };

        open_with_options(path, read, self.write, self.create, self.truncate)
    }
}
use super::vfs::MountBackend;

// ============================================================================
// Unified File Handle
// ============================================================================

/// An open file handle.
///
/// This is a unified type that works with both read-only memory-mapped files
/// and read-write FAT filesystem files. The VFS routes operations to the
/// appropriate backend based on the file's mount point.
///
/// Implements [`embedded_io::Read`], [`embedded_io::Seek`], and
/// [`embedded_io::Write`] (write only works for FAT files).
///
/// # Lifetime
///
/// The `'static` lifetime on the FAT variant is safe because:
/// - The guest environment is single-threaded
/// - FAT filesystems live for the program's entire lifetime
/// - The backing memory is mapped by the host before guest execution
///
/// # Example
///
/// ```ignore
/// use embedded_io::{Read, Write};
/// use hyperlight_guest::fs::{self, OpenOptions};
///
/// // Read from a read-only file
/// let mut file = fs::open("/config.json")?;
/// let mut buf = [0u8; 256];
/// let bytes_read = file.read(&mut buf)?;
///
/// // Write to a FAT file (if mounted) using OpenOptions builder
/// let mut fat_file = OpenOptions::new()
///     .read(true)
///     .write(true)
///     .create(true)
///     .open("/data/output.txt")?;
/// fat_file.write(b"Hello, FAT!")?;
/// fat_file.flush()?;
/// ```
pub enum File {
    /// Read-only memory-mapped file from the manifest.
    ReadOnly(RoFile),
    /// Read-write file on a FAT filesystem.
    ///
    /// The `'static` lifetime is valid because the FAT filesystem backing
    /// memory is mapped by the host and lives for the guest's entire execution.
    Fat(GuestFatFile<'static>),
}

impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            File::ReadOnly(ro) => f.debug_tuple("ReadOnly").field(ro).finish(),
            File::Fat(fat) => f.debug_tuple("Fat").field(fat).finish(),
        }
    }
}

impl File {
    /// Returns true if this file is read-only.
    pub fn is_readonly(&self) -> bool {
        matches!(self, File::ReadOnly(_))
    }

    /// Returns true if this file supports writing.
    pub fn is_writable(&self) -> bool {
        match self {
            File::ReadOnly(_) => false,
            File::Fat(f) => f.can_write(),
        }
    }

    /// Get the file descriptor for read-only files.
    ///
    /// Returns `Some(fd)` for read-only memory-mapped files, `None` for FAT files.
    /// FAT files use a different internal representation and don't have fds.
    pub fn fd(&self) -> Option<i32> {
        match self {
            File::ReadOnly(f) => Some(f.fd()),
            File::Fat(_) => None,
        }
    }

    /// Create a read-only File from a file descriptor.
    ///
    /// This is only valid for read-only memory-mapped files. The fd must have
    /// been obtained from a previous call to `File::fd()` on a read-only file.
    ///
    /// # Warning
    ///
    /// This creates a read-only file wrapper. Do NOT use this with file descriptors
    /// that weren't obtained from `File::fd()` on a read-only file. FAT files
    /// cannot be reconstructed from file descriptors.
    ///
    /// Note: This does not validate that the fd is valid. Using an invalid fd
    /// will cause errors on subsequent operations.
    ///
    /// # Intended Use
    ///
    /// This is primarily for the C API (`hyperlight_guest_capi`) which needs to
    /// reconstruct File handles from integer descriptors passed by C code.
    /// Rust code should prefer holding onto the `File` directly.
    pub fn from_fd(fd: i32) -> Self {
        File::ReadOnly(RoFile::from_fd(fd))
    }

    /// Get the current position in the file.
    pub fn position(&mut self) -> Result<u64, FsError> {
        match self {
            File::ReadOnly(f) => f.position(),
            File::Fat(f) => f.seek(fatfs::SeekFrom::Current(0)),
        }
    }

    /// Get the size of the file in bytes.
    pub fn size(&mut self) -> Result<u64, FsError> {
        match self {
            File::ReadOnly(f) => f.size(),
            File::Fat(f) => f.len(),
        }
    }

    /// Get the remaining bytes from current position to end of file.
    pub fn remaining(&mut self) -> Result<u64, FsError> {
        match self {
            File::ReadOnly(f) => f.remaining(),
            File::Fat(f) => {
                let pos = f.seek(fatfs::SeekFrom::Current(0))?;
                let size = f.len()?;
                Ok(size.saturating_sub(pos))
            }
        }
    }

    /// Flush any buffered data to the underlying storage.
    ///
    /// For read-only files, this is a no-op.
    /// For FAT files, this flushes the fatfs buffer.
    pub fn flush(&mut self) -> Result<(), FsError> {
        match self {
            File::ReadOnly(_) => Ok(()), // No-op for RO
            File::Fat(f) => f.flush(),
        }
    }

    /// Read the entire file into a newly allocated Vec.
    ///
    /// Seeks to the beginning first, then reads until EOF.
    pub fn read_to_vec(&mut self) -> Result<Vec<u8>, FsError> {
        use alloc::vec;

        use embedded_io::ReadExactError;

        // Get file size by seeking to end (1 seek)
        let size = self.seek(SeekFrom::End(0))? as usize;

        // Rewind to beginning for reading (1 seek)
        self.rewind()?;

        let mut buf = vec![0u8; size];
        self.read_exact(&mut buf).map_err(|e| match e {
            ReadExactError::UnexpectedEof => FsError::IoError,
            ReadExactError::Other(err) => err,
        })?;
        Ok(buf)
    }
}

impl ErrorType for File {
    type Error = FsError;
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self {
            File::ReadOnly(f) => f.read(buf),
            File::Fat(f) => f.read(buf),
        }
    }
}

impl Seek for File {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        match self {
            File::ReadOnly(f) => f.seek(pos),
            File::Fat(f) => {
                // Convert embedded_io::SeekFrom to fatfs::SeekFrom
                let fatfs_pos = match pos {
                    SeekFrom::Start(n) => fatfs::SeekFrom::Start(n),
                    SeekFrom::End(n) => fatfs::SeekFrom::End(n),
                    SeekFrom::Current(n) => fatfs::SeekFrom::Current(n),
                };
                f.seek(fatfs_pos)
            }
        }
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match self {
            File::ReadOnly(_) => Err(FsError::ReadOnly),
            File::Fat(f) => f.write(buf),
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        File::flush(self)
    }
}

// ============================================================================
// Read-Only File Handle
// ============================================================================

/// A read-only file handle for memory-mapped files.
///
/// This type is exposed through the [`File::ReadOnly`] variant. While you can
/// pattern-match to extract it, prefer using the unified [`File`] API which
/// works transparently with both read-only and FAT files.
///
/// This type must be `pub` because it appears in a public enum variant.
#[derive(Debug, PartialEq, Eq)]
pub struct RoFile {
    /// File descriptor index.
    fd: i32,
}

impl RoFile {
    /// Create a new RoFile from a file descriptor.
    pub(crate) fn from_fd(fd: i32) -> Self {
        Self { fd }
    }

    /// Get the file descriptor number.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Get the current position in the file.
    pub fn position(&self) -> Result<u64, FsError> {
        let entry = fd::get_fd(self.fd)?;
        Ok(entry.position)
    }

    /// Get the size of the file in bytes.
    pub fn size(&self) -> Result<u64, FsError> {
        let entry = fd::get_fd(self.fd)?;
        Ok(entry.size)
    }

    /// Get the remaining bytes from current position to end of file.
    pub fn remaining(&self) -> Result<u64, FsError> {
        let entry = fd::get_fd(self.fd)?;
        Ok(entry.size.saturating_sub(entry.position))
    }
}

impl Drop for RoFile {
    fn drop(&mut self) {
        // Ignore errors on close - nothing we can do about them
        let _ = fd::free_fd(self.fd);
    }
}

impl ErrorType for RoFile {
    type Error = FsError;
}

impl Read for RoFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        let entry = fd::get_fd(self.fd)?;

        // Calculate how many bytes we can read
        let remaining = entry.size.saturating_sub(entry.position) as usize;
        if remaining == 0 {
            return Ok(0); // EOF
        }

        let to_read = buf.len().min(remaining);

        // Calculate the source address in guest memory
        let src_addr = entry.guest_address + entry.position;

        // SAFETY: The host has mapped file data at guest_address.
        // We trust that the manifest contains valid addresses and sizes.
        // If these are corrupted then the guest may crash or read invalid data but it cannot
        // access data in the host that hasn't been explicitly mapped and we don't allow
        // dynamic allocations so this is safe.
        // The guest is single-threaded so no data races.
        unsafe {
            let src_ptr = src_addr as *const u8;
            core::ptr::copy_nonoverlapping(src_ptr, buf.as_mut_ptr(), to_read);
        }

        // Update position
        entry.position += to_read as u64;

        Ok(to_read)
    }
}

impl Seek for RoFile {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        let entry = fd::get_fd(self.fd)?;

        let new_pos: i64 = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => entry.size as i64 + n,
            SeekFrom::Current(n) => entry.position as i64 + n,
        };

        if new_pos < 0 {
            return Err(FsError::InvalidSeek);
        }

        // Clamp to file size (seeking past EOF is allowed but reads return 0)
        let new_pos = (new_pos as u64).min(entry.size);
        entry.position = new_pos;

        Ok(new_pos)
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Result of resolving a path through the VFS.
enum ResolvedPath {
    /// Path resolves to a read-only mount.
    ReadOnly {
        /// The full path (for inode lookup).
        full_path: String,
    },
    /// Path resolves to a FAT mount.
    Fat {
        /// Index of the mount in the VFS.
        mount_idx: usize,
        /// Path relative to the mount point.
        relative_path: String,
    },
}

/// Resolve a path through the VFS to determine which backend handles it.
fn resolve_path(path: &str) -> Result<ResolvedPath, FsError> {
    let vfs = manifest::vfs()?;
    let (mount_idx, relative_path) = vfs.resolve(path)?;

    let mount = vfs.get_mount(mount_idx).ok_or(FsError::NotFound)?;

    match mount.backend() {
        MountBackend::ReadOnly => Ok(ResolvedPath::ReadOnly {
            full_path: String::from(path),
        }),
        MountBackend::Fat(_) => Ok(ResolvedPath::Fat {
            mount_idx,
            relative_path,
        }),
    }
}

/// Open a file by path for reading.
///
/// Routes through the VFS to the appropriate backend (read-only or FAT).
/// For read-only files, opens for reading only. For FAT files, opens for
/// reading only (use [`open_with_options`] for write access).
///
/// # Errors
///
/// - [`FsError::NotInitialized`] if the filesystem hasn't been initialized
/// - [`FsError::NotFound`] if the path doesn't exist
/// - [`FsError::NotAFile`] if the path refers to a directory
pub fn open(path: &str) -> Result<File, FsError> {
    open_with_options(path, true, false, false, false)
}

/// Internal implementation for opening files with specific options.
///
/// Use [`OpenOptions`] for the public API.
fn open_with_options(
    path: &str,
    read: bool,
    write: bool,
    create: bool,
    truncate: bool,
) -> Result<File, FsError> {
    match resolve_path(path)? {
        ResolvedPath::ReadOnly { full_path } => {
            // RO only supports read-only access
            if write || create || truncate {
                return Err(FsError::ReadOnly);
            }

            let (_idx, inode) = manifest::lookup_file(&full_path)?;

            let open_file = OpenFile {
                position: 0,
                size: inode.size,
                guest_address: inode.guest_address,
            };

            let fd = fd::alloc_fd(open_file);
            Ok(File::ReadOnly(RoFile::from_fd(fd)))
        }
        ResolvedPath::Fat {
            mount_idx,
            relative_path,
        } => {
            // SAFETY: Single-threaded guest, no other VFS refs held.
            // We resolved the path above and now need mutable access to open the file.
            let vfs = unsafe { manifest::vfs_mut()? };
            let mount = vfs.get_mount_mut(mount_idx).ok_or(FsError::NotFound)?;

            if let MountBackend::Fat(fat) = mount.backend_mut() {
                let fat_file = fat.open(&relative_path, read, write, create, truncate)?;
                Ok(File::Fat(fat_file))
            } else {
                // Should never happen - resolve_path already confirmed it's Fat
                Err(FsError::IoError)
            }
        }
    }
}

/// File metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// Size of the file in bytes (0 for directories).
    pub size: u64,
    /// Whether this is a directory.
    pub is_dir: bool,
}

/// Get file metadata without opening the file.
///
/// Routes through VFS to the appropriate backend.
///
/// # Errors
///
/// - [`FsError::NotInitialized`] if the filesystem hasn't been initialized
/// - [`FsError::NotFound`] if the path doesn't exist
pub fn stat(path: &str) -> Result<Stat, FsError> {
    match resolve_path(path)? {
        ResolvedPath::ReadOnly { full_path } => {
            let (_idx, inode) = manifest::lookup(&full_path)?;
            Ok(Stat {
                size: inode.size,
                is_dir: inode.is_dir(),
            })
        }
        ResolvedPath::Fat {
            mount_idx,
            relative_path,
        } => {
            // Handle root of mount specially
            if relative_path.is_empty() {
                return Ok(Stat {
                    size: 0,
                    is_dir: true,
                });
            }

            let vfs = manifest::vfs()?;
            let mount = vfs.get_mount(mount_idx).ok_or(FsError::NotFound)?;

            if let MountBackend::Fat(fat) = mount.backend() {
                let fat_stat = fat.stat(&relative_path)?;
                Ok(Stat {
                    size: fat_stat.size,
                    is_dir: fat_stat.is_dir,
                })
            } else {
                Err(FsError::IoError)
            }
        }
    }
}

/// Directory entry returned by [`read_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Name of the entry (just the filename, not full path).
    pub name: String,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Size in bytes (0 for directories).
    pub size: u64,
}

/// List the contents of a directory.
///
/// Routes through VFS to the appropriate backend.
/// Returns a vector of directory entries (direct children only, not recursive).
///
/// # Errors
///
/// - [`FsError::NotInitialized`] if the filesystem hasn't been initialized
/// - [`FsError::NotFound`] if the path doesn't exist
/// - [`FsError::NotADirectory`] if the path is a file
pub fn read_dir(path: &str) -> Result<Vec<DirEntry>, FsError> {
    use alloc::string::ToString;

    match resolve_path(path)? {
        ResolvedPath::ReadOnly { full_path } => {
            let children = manifest::list_dir(&full_path)?;

            let entries: Vec<DirEntry> = children
                .into_iter()
                .map(|inode| {
                    let name = inode
                        .path
                        .rsplit('/')
                        .next()
                        .unwrap_or(&inode.path)
                        .to_string();

                    DirEntry {
                        name,
                        is_dir: inode.is_dir(),
                        size: inode.size,
                    }
                })
                .collect();

            Ok(entries)
        }
        ResolvedPath::Fat {
            mount_idx,
            relative_path,
        } => {
            let vfs = manifest::vfs()?;
            let mount = vfs.get_mount(mount_idx).ok_or(FsError::NotFound)?;

            if let MountBackend::Fat(fat) = mount.backend() {
                // Use "." for mount root
                let fat_path = if relative_path.is_empty() {
                    "."
                } else {
                    &relative_path
                };

                let fat_entries = fat.read_dir(fat_path)?;

                let entries: Vec<DirEntry> = fat_entries
                    .into_iter()
                    .map(|e| DirEntry {
                        name: e.name,
                        is_dir: e.is_dir,
                        size: e.size,
                    })
                    .collect();

                Ok(entries)
            } else {
                Err(FsError::IoError)
            }
        }
    }
}
