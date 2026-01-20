/*
Copyright 2025 The Hyperlight Authors.

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

//! C API for HyperlightFS - libc-style file operations.
//!
//! Provides POSIX-like file operations for C guests.

use core::ffi::c_char;

use hyperlight_guest::fs;

/// SEEK_SET - seek relative to beginning of file
pub const HL_SEEK_SET: i32 = 0;
/// SEEK_CUR - seek relative to current position
pub const HL_SEEK_CUR: i32 = 1;
/// SEEK_END - seek relative to end of file
pub const HL_SEEK_END: i32 = 2;

/// O_RDONLY - open for reading only (the only supported mode)
pub const HL_O_RDONLY: i32 = 0;

/// File status information (similar to struct stat).
/// Exported as `Stat` in C.
#[repr(C)]
pub struct Stat {
    /// Size of the file in bytes.
    pub size: u64,
    /// 1 if this is a directory, 0 if a file.
    pub is_dir: i32,
    /// Reserved for future use.
    pub _reserved: [u32; 4],
}

/// Check if HyperlightFS is initialized.
///
/// Returns 1 if initialized, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn hl_fs_initialized() -> i32 {
    if fs::is_initialized() { 1 } else { 0 }
}

/// Open a file for reading.
///
/// # Arguments
/// * `path` - Null-terminated path string (e.g., "/config.json")
/// * `flags` - Must be O_RDONLY (0). Other flags will return -1.
///
/// # Returns
/// * File descriptor (>= 0) on success
/// * -1 on error (file not found, invalid flags, FS not initialized, etc.)
///
/// # Example
/// ```c
/// int fd = open("/config.json", O_RDONLY);
/// if (fd < 0) {
///     // handle error
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn hl_fs_open(path: *const c_char, flags: i32) -> i32 {
    if path.is_null() {
        return -1;
    }

    // Only O_RDONLY is supported - HyperlightFS is read-only
    if flags != HL_O_RDONLY {
        return -1;
    }

    let path_str = match unsafe { core::ffi::CStr::from_ptr(path).to_str() } {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match fs::open(path_str) {
        Ok(file) => {
            // CAPI only supports read-only files (which have fds)
            // FAT files return None and are not supported via CAPI
            match file.fd() {
                Some(fd) => {
                    // Don't run destructor - we're transferring ownership to C code
                    core::mem::forget(file);
                    fd
                }
                None => {
                    // FAT file - not supported via CAPI, drop and return error
                    drop(file);
                    -1
                }
            }
        }
        Err(_) => -1,
    }
}

/// Close a file descriptor.
///
/// # Arguments
/// * `fd` - File descriptor returned by `hl_fs_open`
///
/// # Returns
/// * 0 on success
/// * -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn hl_fs_close(fd: i32) -> i32 {
    if fd < 0 {
        return -1;
    }

    // Create a File from the fd so it gets properly closed on drop
    let file = fs::File::from_fd(fd);
    drop(file);
    0
}

/// Read from a file.
///
/// # Arguments
/// * `fd` - File descriptor
/// * `buf` - Buffer to read into
/// * `count` - Maximum number of bytes to read
///
/// # Returns
/// * Number of bytes read (0 at EOF)
/// * -1 on error
///
/// # Example
/// ```c
/// char buf[256];
/// ssize_t n = hl_fs_read(fd, buf, sizeof(buf));
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn hl_fs_read(fd: i32, buf: *mut u8, count: u64) -> i64 {
    if fd < 0 || buf.is_null() || count == 0 {
        return if count == 0 { 0 } else { -1 };
    }

    // Create a temporary File wrapper (we won't drop it - just use for reading)
    let mut file = fs::File::from_fd(fd);

    let slice = unsafe { core::slice::from_raw_parts_mut(buf, count as usize) };

    use hyperlight_guest::Read;
    match file.read(slice) {
        Ok(n) => {
            // Don't close the fd - forget the wrapper
            core::mem::forget(file);
            n as i64
        }
        Err(_) => {
            core::mem::forget(file);
            -1
        }
    }
}

/// Seek to a position in the file.
///
/// # Arguments
/// * `fd` - File descriptor
/// * `offset` - Offset in bytes
/// * `whence` - HL_SEEK_SET (0), HL_SEEK_CUR (1), or HL_SEEK_END (2)
///
/// # Returns
/// * New position in file on success
/// * -1 on error
///
/// # Example
/// ```c
/// // Seek to beginning
/// hl_fs_lseek(fd, 0, HL_SEEK_SET);
/// // Seek to end
/// hl_fs_lseek(fd, 0, HL_SEEK_END);
/// // Seek relative to current
/// hl_fs_lseek(fd, 100, HL_SEEK_CUR);
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn hl_fs_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    if fd < 0 {
        return -1;
    }

    use hyperlight_guest::{Seek, SeekFrom};

    let seek_from = match whence {
        HL_SEEK_SET => SeekFrom::Start(offset as u64),
        HL_SEEK_CUR => SeekFrom::Current(offset),
        HL_SEEK_END => SeekFrom::End(offset),
        _ => return -1,
    };

    let mut file = fs::File::from_fd(fd);

    match file.seek(seek_from) {
        Ok(pos) => {
            core::mem::forget(file);
            pos as i64
        }
        Err(_) => {
            core::mem::forget(file);
            -1
        }
    }
}

/// Get file status by file descriptor.
///
/// # Arguments
/// * `fd` - File descriptor
/// * `stat` - Pointer to Stat struct to fill
///
/// # Returns
/// * 0 on success
/// * -1 on error
#[unsafe(no_mangle)]
pub extern "C" fn hl_fs_fstat(fd: i32, stat: *mut Stat) -> i32 {
    if fd < 0 || stat.is_null() {
        return -1;
    }

    let mut file = fs::File::from_fd(fd);

    match file.size() {
        Ok(size) => {
            unsafe {
                (*stat).size = size;
                (*stat).is_dir = 0; // Files opened via hl_fs_open are always files
                (*stat)._reserved = [0; 4];
            }
            core::mem::forget(file);
            0
        }
        Err(_) => {
            core::mem::forget(file);
            -1
        }
    }
}

/// Get file status by path.
///
/// # Arguments
/// * `path` - Null-terminated path string
/// * `stat` - Pointer to Stat struct to fill
///
/// # Returns
/// * 0 on success
/// * -1 on error (file not found, etc.)
#[unsafe(no_mangle)]
pub extern "C" fn hl_fs_stat(path: *const c_char, stat: *mut Stat) -> i32 {
    if path.is_null() || stat.is_null() {
        return -1;
    }

    let path_str = match unsafe { core::ffi::CStr::from_ptr(path).to_str() } {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match fs::stat(path_str) {
        Ok(s) => {
            unsafe {
                (*stat).size = s.size;
                (*stat).is_dir = if s.is_dir { 1 } else { 0 };
                (*stat)._reserved = [0; 4];
            }
            0
        }
        Err(_) => -1,
    }
}
