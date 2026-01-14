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

//! File descriptor table for HyperlightFS.
//!
//! Manages open files dynamically. Each open file tracks:
//! - The current read position within the file
//! - The file size and guest memory address

use alloc::vec::Vec;
use core::cell::UnsafeCell;

use super::error::FsError;

/// First file descriptor available for allocation.
/// FDs 0-2 are reserved for stdin/stdout/stderr (POSIX compatibility).
const FIRST_AVAILABLE_FD: usize = 3;

/// An open file entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFile {
    /// Current read position within the file.
    pub position: u64,
    /// Size of the file (cached from inode).
    pub size: u64,
    /// Guest address where file data is mapped.
    pub guest_address: u64,
}

/// File descriptor table.
struct FdTable {
    /// Slots for open files. None = slot is free, Some = open file.
    /// Freed slots are reused on subsequent allocations.
    slots: Vec<Option<OpenFile>>,
}

impl FdTable {
    fn new() -> Self {
        // Pre-allocate reserved slots (0=stdin, 1=stdout, 2=stderr)
        Self {
            slots: alloc::vec![None; FIRST_AVAILABLE_FD],
        }
    }
}

/// Global file descriptor table.
///
/// SAFETY: Guest code is single-threaded, so this is safe.
/// Initialized lazily on first access.
static FD_TABLE: FdTableCell = FdTableCell(UnsafeCell::new(None));

struct FdTableCell(UnsafeCell<Option<FdTable>>);

// SAFETY: Guest is single-threaded.
unsafe impl Sync for FdTableCell {}

impl FdTableCell {
    #[allow(clippy::mut_from_ref)] // SAFETY: Guest is single-threaded, interior mutability is intentional
    fn get(&self) -> &mut FdTable {
        // SAFETY: Guest is single-threaded.
        let inner = unsafe { &mut *self.0.get() };
        inner.get_or_insert_with(FdTable::new)
    }
}

/// Allocate a new file descriptor for an open file.
///
/// Returns the file descriptor number. Reuses freed slots when available,
/// otherwise appends to the table.
pub fn alloc_fd(open_file: OpenFile) -> i32 {
    let table = FD_TABLE.get();

    // Try to reuse a freed slot (skip reserved 0-2)
    for (idx, slot) in table.slots.iter_mut().enumerate().skip(FIRST_AVAILABLE_FD) {
        if slot.is_none() {
            *slot = Some(open_file);
            return idx as i32;
        }
    }

    // No free slot, append new entry
    let fd = table.slots.len() as i32;
    table.slots.push(Some(open_file));
    fd
}

/// Get an open file by file descriptor.
///
/// Returns a mutable reference to the OpenFile entry.
pub fn get_fd(fd: i32) -> Result<&'static mut OpenFile, FsError> {
    if (fd as usize) < FIRST_AVAILABLE_FD {
        return Err(FsError::InvalidFd);
    }

    let table = FD_TABLE.get();
    table
        .slots
        .get_mut(fd as usize)
        .and_then(|slot| slot.as_mut())
        .ok_or(FsError::InvalidFd)
}

/// Close a file descriptor, freeing the slot for reuse.
pub fn free_fd(fd: i32) -> Result<(), FsError> {
    if (fd as usize) < FIRST_AVAILABLE_FD {
        return Err(FsError::InvalidFd);
    }

    let table = FD_TABLE.get();
    match table.slots.get_mut(fd as usize) {
        Some(slot @ Some(_)) => {
            *slot = None;
            Ok(())
        }
        _ => Err(FsError::InvalidFd),
    }
}

/// Check if a file descriptor is valid (open).
#[cfg(test)]
pub fn is_valid_fd(fd: i32) -> bool {
    if (fd as usize) < FIRST_AVAILABLE_FD {
        return false;
    }

    let table = FD_TABLE.get();
    table
        .slots
        .get(fd as usize)
        .is_some_and(|slot| slot.is_some())
}

/// Get the number of currently open files.
#[cfg(test)]
pub fn open_count() -> usize {
    let table = FD_TABLE.get();
    table.slots.iter().filter(|s| s.is_some()).count()
}

/// Reset the file descriptor table (for testing).
#[cfg(test)]
pub fn reset() {
    let table = FD_TABLE.get();
    table.slots.clear();
    table.slots.resize(FIRST_AVAILABLE_FD, None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_and_free() {
        reset();

        let file = OpenFile {
            position: 0,
            size: 100,
            guest_address: 0x1000,
        };

        // Allocate (first available is fd 3, since 0-2 are reserved)
        let fd = alloc_fd(file);
        assert_eq!(fd, 3);
        assert!(is_valid_fd(fd));
        assert_eq!(open_count(), 1);

        // Get and verify
        let entry = get_fd(fd).unwrap();
        assert_eq!(entry.size, 100);

        // Free
        free_fd(fd).unwrap();
        assert!(!is_valid_fd(fd));
        assert_eq!(open_count(), 0);

        // Double free should fail
        assert_eq!(free_fd(fd), Err(FsError::InvalidFd));
    }

    #[test]
    fn test_invalid_fd() {
        reset();

        assert_eq!(get_fd(-1), Err(FsError::InvalidFd));
        assert_eq!(get_fd(1000), Err(FsError::InvalidFd)); // Out of bounds
        assert_eq!(get_fd(0), Err(FsError::InvalidFd)); // Reserved (stdin)
        assert_eq!(get_fd(1), Err(FsError::InvalidFd)); // Reserved (stdout)
        assert_eq!(get_fd(2), Err(FsError::InvalidFd)); // Reserved (stderr)
        assert_eq!(get_fd(3), Err(FsError::InvalidFd)); // Not open yet
    }

    #[test]
    fn test_slot_reuse() {
        reset();

        let file = OpenFile {
            position: 0,
            size: 0,
            guest_address: 0,
        };

        // Allocate three fds (starting from 3 since 0-2 are reserved)
        let fd0 = alloc_fd(file);
        let fd1 = alloc_fd(file);
        let fd2 = alloc_fd(file);
        assert_eq!(fd0, 3);
        assert_eq!(fd1, 4);
        assert_eq!(fd2, 5);
        assert_eq!(open_count(), 3);

        // Free the middle one
        free_fd(fd1).unwrap();
        assert_eq!(open_count(), 2);

        // Next alloc should reuse slot 4
        let fd3 = alloc_fd(file);
        assert_eq!(fd3, 4);
        assert_eq!(open_count(), 3);

        reset();
    }

    #[test]
    fn test_position_update() {
        reset();

        let file = OpenFile {
            position: 0,
            size: 100,
            guest_address: 0x1000,
        };

        let fd = alloc_fd(file);
        assert_eq!(fd, 3); // First available after reserved

        // Update position
        {
            let entry = get_fd(fd).unwrap();
            entry.position = 50;
        }

        // Verify update persisted
        {
            let entry = get_fd(fd).unwrap();
            assert_eq!(entry.position, 50);
        }

        reset();
    }
}
