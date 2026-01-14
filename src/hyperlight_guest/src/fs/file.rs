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

//! File handle with `embedded-io` trait implementations.
//!
//! Provides a `File` struct that implements `Read` and `Seek` for reading
//! from memory-mapped file data in the guest address space.

use embedded_io::{ErrorType, Read, Seek, SeekFrom};

use super::error::FsError;
use super::fd::{self, OpenFile};

/// An open file handle.
///
/// Implements [`embedded_io::Read`] and [`embedded_io::Seek`] for reading
/// file data from guest memory.
///
/// # Example
///
/// ```ignore
/// let mut file = fs::open("/config.json")?;
/// let mut buf = [0u8; 256];
/// let bytes_read = file.read(&mut buf)?;
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct File {
    /// File descriptor index.
    fd: i32,
}

impl File {
    /// Create a new File from a file descriptor.
    ///
    /// # Safety
    /// The caller must ensure `fd` is a valid file descriptor obtained
    /// from `fs::open()` or equivalent. Using an invalid fd may lead
    /// to undefined behavior when reading.
    ///
    /// This is primarily for C API interop where file descriptors are
    /// passed as integers.
    pub fn from_fd(fd: i32) -> Self {
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

    /// Read the entire file into a newly allocated Vec.
    ///
    /// Seeks to the beginning first, then reads until EOF.
    pub fn read_to_vec(&mut self) -> Result<alloc::vec::Vec<u8>, FsError> {
        use alloc::vec;

        use embedded_io::ReadExactError;

        self.rewind()?;
        let size = self.size()? as usize;
        let mut buf = vec![0u8; size];
        self.read_exact(&mut buf).map_err(|e| match e {
            ReadExactError::UnexpectedEof => FsError::NotFound, // Shouldn't happen
            ReadExactError::Other(err) => err,
        })?;
        Ok(buf)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        // Ignore errors on close - nothing we can do about them
        let _ = fd::free_fd(self.fd);
    }
}

impl ErrorType for File {
    type Error = FsError;
}

impl Read for File {
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
        // If these are corrupted then the guest may crash or read invalid data but it cannot access data in
        //the host that hasn't been explicitly mapped and we dont allow dynamic allocations so this is safe.
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

impl Seek for File {
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

/// Open a file by path.
///
/// Returns a [`File`] handle that can be used for reading.
///
/// # Errors
///
/// - [`FsError::NotInitialized`] if the filesystem hasn't been initialized
/// - [`FsError::NotFound`] if the path doesn't exist
/// - [`FsError::NotAFile`] if the path refers to a directory
pub fn open(path: &str) -> Result<File, FsError> {
    let (_idx, inode) = super::manifest::lookup_file(path)?;

    let open_file = OpenFile {
        position: 0,
        size: inode.size,
        guest_address: inode.guest_address,
    };

    let fd = fd::alloc_fd(open_file);
    Ok(File::from_fd(fd))
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
/// # Errors
///
/// - [`FsError::NotInitialized`] if the filesystem hasn't been initialized
/// - [`FsError::NotFound`] if the path doesn't exist
pub fn stat(path: &str) -> Result<Stat, FsError> {
    let (_idx, inode) = super::manifest::lookup(path)?;

    Ok(Stat {
        size: inode.size,
        is_dir: inode.is_dir(),
    })
}

/// Directory entry returned by [`read_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Name of the entry (just the filename, not full path).
    pub name: alloc::string::String,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Size in bytes (0 for directories).
    pub size: u64,
}

/// List the contents of a directory.
///
/// Returns a vector of directory entries. Only returns direct children,
/// not recursive.
///
/// # Errors
///
/// - [`FsError::NotInitialized`] if the filesystem hasn't been initialized
/// - [`FsError::NotFound`] if the path doesn't exist
/// - [`FsError::NotADirectory`] if the path is a file
pub fn read_dir(path: &str) -> Result<alloc::vec::Vec<DirEntry>, FsError> {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    let children = super::manifest::list_dir(path)?;

    let entries: Vec<DirEntry> = children
        .into_iter()
        .map(|inode| {
            // Extract just the filename from the full path
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
