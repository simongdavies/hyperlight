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

//! Error types for the HyperlightFS guest VFS.

use core::fmt;

use embedded_io::ErrorKind;

/// Filesystem errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// File or directory not found.
    NotFound,
    /// Path refers to a directory, not a file.
    NotAFile,
    /// Path refers to a file, not a directory.
    NotADirectory,
    /// Invalid file descriptor.
    InvalidFd,
    /// Invalid path (empty, contains null bytes, etc.).
    InvalidPath,
    /// Filesystem not initialized.
    NotInitialized,
    /// Seek to invalid position.
    InvalidSeek,
    /// Manifest parsing failed.
    InvalidManifest,
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::NotFound => write!(f, "file or directory not found"),
            FsError::NotAFile => write!(f, "path is a directory, not a file"),
            FsError::NotADirectory => write!(f, "path is a file, not a directory"),
            FsError::InvalidFd => write!(f, "invalid file descriptor"),
            FsError::InvalidPath => write!(f, "invalid path"),
            FsError::NotInitialized => write!(f, "filesystem not initialized"),
            FsError::InvalidSeek => write!(f, "invalid seek position"),
            FsError::InvalidManifest => write!(f, "invalid filesystem manifest"),
        }
    }
}

impl core::error::Error for FsError {}

impl embedded_io::Error for FsError {
    fn kind(&self) -> ErrorKind {
        match self {
            FsError::NotFound => ErrorKind::NotFound,
            FsError::NotAFile => ErrorKind::InvalidInput,
            FsError::NotADirectory => ErrorKind::InvalidInput,
            FsError::InvalidFd => ErrorKind::InvalidInput,
            FsError::InvalidPath => ErrorKind::InvalidInput,
            FsError::NotInitialized => ErrorKind::NotFound,
            FsError::InvalidSeek => ErrorKind::InvalidInput,
            FsError::InvalidManifest => ErrorKind::InvalidData,
        }
    }
}
