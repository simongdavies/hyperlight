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

//! Builder for HyperlightFS images.
//!
//! This module provides a fluent API for specifying which files to map
//! into the guest filesystem.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use glob::Pattern;
use tracing::info;

use super::fat_image::FatImage;
use super::image::HyperlightFSImage;
use crate::Result;
use crate::error::HyperlightError;

/// Validate a host path.
///
/// Rules:
/// - Must be absolute
/// - Must not contain `..` components (to avoid confusion about what file is being mapped)
fn validate_host_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(HyperlightError::Error(format!(
            "Invalid host path {:?}: must be absolute",
            path
        )));
    }

    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(HyperlightError::Error(format!(
            "Invalid host path {:?}: '..' components are not allowed",
            path
        )));
    }

    Ok(())
}

/// Validate and normalize a guest file path.
///
/// Rules:
/// - Must be absolute (start with `/`)
/// - Must not contain `..` components
/// - Must not contain null bytes
/// - Must not be just `/` (root)
fn validate_guest_file_path(path: &str) -> Result<String> {
    if path.contains('\0') {
        return Err(HyperlightError::Error(format!(
            "Invalid guest path {:?}: contains null byte",
            path
        )));
    }

    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(HyperlightError::Error(format!(
            "Invalid guest path {:?}: must be absolute (start with '/')",
            path
        )));
    }

    let mut parts = Vec::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                return Err(HyperlightError::Error(format!(
                    "Invalid guest path {:?}: '..' components are not allowed",
                    path
                )));
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().to_string()),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }

    if parts.is_empty() {
        return Err(HyperlightError::Error(format!(
            "Invalid guest path {:?}: cannot be root directory",
            path
        )));
    }

    Ok(format!("/{}", parts.join("/")))
}

/// Validate and normalize a guest directory prefix.
///
/// Same rules as file path, but `/` (root) is allowed.
fn validate_guest_dir_prefix(path: &str) -> Result<String> {
    if path.contains('\0') {
        return Err(HyperlightError::Error(format!(
            "Invalid guest prefix {:?}: contains null byte",
            path
        )));
    }

    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(HyperlightError::Error(format!(
            "Invalid guest prefix {:?}: must be absolute (start with '/')",
            path
        )));
    }

    let mut parts = Vec::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                return Err(HyperlightError::Error(format!(
                    "Invalid guest prefix {:?}: '..' components are not allowed",
                    path
                )));
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().to_string()),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }

    if parts.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", parts.join("/")))
    }
}

/// Normalize a guest path by removing duplicate slashes and `.` components.
///
/// This is used for paths built via Path::join which may not be clean.
/// Does not validate - use validate_guest_file_path for user input.
fn normalize_guest_path(path: &str) -> String {
    let p = Path::new(path);
    let parts: Vec<_> = p
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Internal representation of a file to be mapped.
#[derive(Debug, Clone)]
pub(super) struct MappedFile {
    /// Path on the host filesystem
    pub host_path: PathBuf,
    /// Path in the guest filesystem
    pub guest_path: String,
    /// File size in bytes
    pub size: u64,
    /// Whether this is a directory
    pub is_dir: bool,
}

/// A manifest entry for preview/dry-run.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    /// Path on the host filesystem
    pub host_path: PathBuf,
    /// Path in the guest filesystem  
    pub guest_path: String,
    /// File size in bytes
    pub size: u64,
    /// Whether this is a directory
    pub is_dir: bool,
}

/// Result of a dry-run list operation.
#[derive(Debug)]
pub struct BuildManifest {
    /// Files that would be mapped
    pub files: Vec<ManifestEntry>,
    /// Total size of all files
    pub total_size: u64,
}

/// Internal representation of a FAT mount.
// TODO(Phase 3): Remove this allow when FAT mounts are integrated with HyperlightFSImage
#[allow(dead_code)]
#[derive(Debug)]
struct FatMountEntry {
    /// The FAT image
    image: FatImage,
    /// Mount point in the guest filesystem (e.g., "/data")
    mount_point: String,
}

/// Builder for HyperlightFS images.
///
/// Supports two types of filesystem content:
/// - **Read-only files**: Host files mapped into the guest via [`add_file`](Self::add_file)
///   or [`add_dir`](Self::add_dir)
/// - **FAT mounts**: Read-write FAT filesystems via [`add_fat_image`](Self::add_fat_image)
///   or [`add_empty_fat_mount`](Self::add_empty_fat_mount)
///
/// Empty by default - content must be explicitly added (no implicit mappings).
#[derive(Debug)]
pub struct HyperlightFSBuilder {
    /// Files collected so far (read-only mappings from host to guest)
    files: Vec<MappedFile>,
    /// Guest paths seen so far (for duplicate detection)
    guest_paths_seen: HashSet<String>,
    /// FAT mounts collected so far (read-write filesystems)
    fat_mounts: Vec<FatMountEntry>,
}

impl HyperlightFSBuilder {
    /// Create a new empty builder.
    ///
    /// No content is mapped by default. Use:
    /// - [`add_file`](Self::add_file) or [`add_dir`](Self::add_dir) for read-only files
    /// - [`add_fat_image`](Self::add_fat_image) or [`add_empty_fat_mount`](Self::add_empty_fat_mount)
    ///   for read-write FAT filesystems
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            guest_paths_seen: HashSet::new(),
            fat_mounts: Vec::new(),
        }
    }

    /// Add a single file to the filesystem.
    ///
    /// # Arguments
    ///
    /// * `host_path` - Path to the file on the host filesystem (must be absolute, no `..`)
    /// * `guest_path` - Path where the file will appear in the guest (must be absolute, no `..`)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The host path is not absolute or contains `..` components
    /// - The file doesn't exist, isn't a regular file, or is a symlink
    /// - The guest path is invalid (not absolute, contains `..`, is just `/`)
    /// - The guest path is already in use
    pub fn add_file<P: AsRef<Path>>(
        mut self,
        host_path: P,
        guest_path: impl Into<String>,
    ) -> Result<Self> {
        let host_path = host_path.as_ref().to_path_buf();
        validate_host_path(&host_path)?;
        let guest_path = validate_guest_file_path(&guest_path.into())?;

        // Check for duplicate guest paths
        if self.guest_paths_seen.contains(&guest_path) {
            return Err(HyperlightError::Error(format!(
                "Duplicate guest path {:?}: already mapped",
                guest_path
            )));
        }

        // Check for conflicts with existing FAT mounts
        self.check_file_path_conflicts(&guest_path)?;

        // Fail immediately if file doesn't exist
        // Use symlink_metadata to avoid following symlinks
        let metadata = std::fs::symlink_metadata(&host_path).map_err(|e| {
            HyperlightError::Error(format!("Cannot add file {:?}: {}", host_path, e))
        })?;

        if metadata.file_type().is_symlink() {
            return Err(HyperlightError::Error(format!(
                "Cannot add {:?}: symlinks are not supported",
                host_path
            )));
        }

        if !metadata.is_file() {
            return Err(HyperlightError::Error(format!(
                "Cannot add {:?}: not a regular file (use add_dir for directories)",
                host_path
            )));
        }

        info!(
            host = %host_path.display(),
            guest = %guest_path,
            size = metadata.len(),
            "Adding file to HyperlightFS"
        );

        self.guest_paths_seen.insert(guest_path.clone());
        self.files.push(MappedFile {
            host_path,
            guest_path,
            size: metadata.len(),
            is_dir: false,
        });

        Ok(self)
    }

    /// Start adding a directory with pattern matching.
    ///
    /// Returns a [`DirectoryBuilder`] that must have at least one `include`
    /// pattern before calling `done()`.
    ///
    /// # Arguments
    ///
    /// * `host_path` - Path to the directory on the host filesystem (must be absolute, no `..`)
    /// * `guest_prefix` - Path prefix for files in the guest (e.g., "/data", must be absolute)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The host path is not absolute or contains `..` components
    /// - The path doesn't exist or isn't a directory
    /// - The guest prefix is invalid (not absolute, contains `..`)
    pub fn add_dir<P: AsRef<Path>>(
        self,
        host_path: P,
        guest_prefix: impl Into<String>,
    ) -> Result<DirectoryBuilder> {
        let host_path = host_path.as_ref().to_path_buf();
        validate_host_path(&host_path)?;
        let guest_prefix = validate_guest_dir_prefix(&guest_prefix.into())?;

        // Fail immediately if directory doesn't exist
        let metadata = std::fs::metadata(&host_path).map_err(|e| {
            HyperlightError::Error(format!("Cannot add directory {:?}: {}", host_path, e))
        })?;

        if !metadata.is_dir() {
            return Err(HyperlightError::Error(format!(
                "Cannot add {:?}: not a directory",
                host_path
            )));
        }

        Ok(DirectoryBuilder {
            parent: self,
            host_path,
            guest_prefix,
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
        })
    }

    /// Preview what files would be mapped (dry run).
    ///
    /// This logs all files at INFO level and returns a manifest
    /// without creating any memory mappings.
    pub fn list(&self) -> Result<BuildManifest> {
        let mut entries = Vec::new();
        let mut total_size = 0u64;

        for file in &self.files {
            info!(
                host = %file.host_path.display(),
                guest = %file.guest_path,
                size = file.size,
                is_dir = file.is_dir,
                "Would map"
            );

            total_size += file.size;
            entries.push(ManifestEntry {
                host_path: file.host_path.clone(),
                guest_path: file.guest_path.clone(),
                size: file.size,
                is_dir: file.is_dir,
            });
        }

        info!(
            file_count = entries.len(),
            total_size = total_size,
            "HyperlightFS manifest preview"
        );

        Ok(BuildManifest {
            files: entries,
            total_size,
        })
    }

    /// Create a builder from a TOML configuration.
    ///
    /// This applies all file and directory mappings from the config
    /// to a new builder.
    ///
    /// # Arguments
    ///
    /// * `config` - The parsed TOML configuration
    ///
    /// # Errors
    ///
    /// Returns an error if any mapping in the config is invalid (e.g.,
    /// host file doesn't exist, invalid paths, duplicate guest paths).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hyperlight_host::hyperlight_fs::{HyperlightFSBuilder, HyperlightFsConfig};
    ///
    /// let config = HyperlightFsConfig::from_toml_file("hyperlight-fs.toml")?;
    /// let fs = HyperlightFSBuilder::from_config(&config)?.build()?;
    /// ```
    pub fn from_config(config: &super::config::HyperlightFsConfig) -> Result<Self> {
        let mut builder = Self::new();

        // Add individual file mappings
        for file in &config.file {
            builder = builder.add_file(&file.host, &file.guest)?;
        }

        // Add directory mappings
        for dir in &config.directory {
            let mut dir_builder = builder.add_dir(&dir.host, &dir.guest)?;

            // Add include patterns (default to "**/*" if none specified)
            if dir.include.is_empty() {
                dir_builder = dir_builder.include("**/*");
            } else {
                for pattern in &dir.include {
                    dir_builder = dir_builder.include(pattern);
                }
            }

            // Add exclude patterns
            for pattern in &dir.exclude {
                dir_builder = dir_builder.exclude(pattern);
            }

            builder = dir_builder.done()?;
        }

        Ok(builder)
    }

    /// Create a builder from a TOML string.
    ///
    /// Convenience method that parses the TOML and creates a builder.
    ///
    /// # Arguments
    ///
    /// * `toml_content` - TOML configuration as a string
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The TOML is malformed
    /// - Any mapping in the config is invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;
    ///
    /// let toml = r#"
    /// [[file]]
    /// host = "/etc/config.json"
    /// guest = "/config.json"
    /// "#;
    ///
    /// let fs = HyperlightFSBuilder::from_toml(toml)?.build()?;
    /// ```
    pub fn from_toml(toml_content: &str) -> Result<Self> {
        let config = super::config::HyperlightFsConfig::from_toml(toml_content)
            .map_err(|e| HyperlightError::Error(format!("Failed to parse TOML config: {}", e)))?;
        Self::from_config(&config)
    }

    /// Create a builder from a TOML file.
    ///
    /// Convenience method that reads and parses a TOML file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read
    /// - The TOML is malformed
    /// - Any mapping in the config is invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;
    ///
    /// let fs = HyperlightFSBuilder::from_toml_file("/path/to/hyperlight-fs.toml")?.build()?;
    /// ```
    pub fn from_toml_file(path: &str) -> Result<Self> {
        let config = super::config::HyperlightFsConfig::from_toml_file(path).map_err(|e| {
            HyperlightError::Error(format!("Failed to load config file '{}': {}", path, e))
        })?;
        Self::from_config(&config)
    }

    /// Mount an existing FAT image from a host file.
    ///
    /// The FAT image file will be opened with an exclusive lock to prevent
    /// concurrent modifications.
    ///
    /// # Arguments
    ///
    /// * `host_path` - Path to the FAT image file on the host
    /// * `mount_point` - Where the FAT filesystem will be mounted in the guest (e.g., "/data")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The host path doesn't exist or isn't a valid FAT image
    /// - The mount point is invalid (not absolute, contains `..`, etc.)
    /// - The mount point conflicts with existing files or mounts
    /// - The FAT image is already locked by another process
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;
    ///
    /// let fs = HyperlightFSBuilder::new()
    ///     .add_fat_image("/host/path/to/data.fat", "/data")?
    ///     .build()?;
    /// ```
    #[cfg(unix)]
    pub fn add_fat_image<P: AsRef<Path>>(
        mut self,
        host_path: P,
        mount_point: &str,
    ) -> Result<Self> {
        let host_path = host_path.as_ref();
        let mount_point = self.validate_mount_point(mount_point)?;

        // Check for conflicts with existing files and mounts
        self.check_mount_conflicts(&mount_point)?;

        // Open the FAT image (acquires exclusive lock)
        let image = FatImage::open(host_path)?;

        info!(
            host = %host_path.display(),
            mount_point = %mount_point,
            size = image.size(),
            "Adding FAT image to HyperlightFS"
        );

        self.fat_mounts.push(FatMountEntry { image, mount_point });

        Ok(self)
    }

    /// Windows stub - FAT mounts are not supported on Windows.
    #[cfg(windows)]
    pub fn add_fat_image<P: AsRef<Path>>(self, _host_path: P, _mount_point: &str) -> Result<Self> {
        Err(HyperlightError::Error(
            "FAT mounts are not supported on Windows".to_string(),
        ))
    }

    /// Create an empty FAT filesystem at a mount point.
    ///
    /// Creates a temporary FAT image file on the host with the specified size.
    /// The temp file is deleted when the `HyperlightFSImage` is dropped.
    ///
    /// # Arguments
    ///
    /// * `mount_point` - Where the FAT filesystem will be mounted in the guest
    /// * `size_bytes` - Size of the FAT image (min: 1MB, max: 16GB)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The mount point is invalid or conflicts with existing files/mounts
    /// - The size is out of range
    /// - Failed to create or format the FAT image
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;
    ///
    /// // Create a 10MB scratch space for the guest
    /// let fs = HyperlightFSBuilder::new()
    ///     .add_empty_fat_mount("/scratch", 10 * 1024 * 1024)?
    ///     .build()?;
    /// ```
    #[cfg(unix)]
    pub fn add_empty_fat_mount(mut self, mount_point: &str, size_bytes: usize) -> Result<Self> {
        let mount_point = self.validate_mount_point(mount_point)?;

        // Check for conflicts with existing files and mounts
        self.check_mount_conflicts(&mount_point)?;

        // Create a temp FAT image
        let image = FatImage::create_temp(size_bytes)?;

        info!(
            mount_point = %mount_point,
            size = size_bytes,
            temp_path = %image.path().display(),
            "Creating empty FAT mount in HyperlightFS"
        );

        self.fat_mounts.push(FatMountEntry { image, mount_point });

        Ok(self)
    }

    /// Windows stub - FAT mounts are not supported on Windows.
    #[cfg(windows)]
    pub fn add_empty_fat_mount(self, _mount_point: &str, _size_bytes: usize) -> Result<Self> {
        Err(HyperlightError::Error(
            "FAT mounts are not supported on Windows".to_string(),
        ))
    }

    /// Create an empty FAT filesystem backed by a specified host file.
    ///
    /// Like [`add_empty_fat_mount`](Self::add_empty_fat_mount), but the backing
    /// file is created at the specified path and persists after drop. Useful for
    /// debugging, inspection, or reusing the filesystem across runs.
    ///
    /// # Arguments
    ///
    /// * `host_path` - Where to create the FAT image file on the host
    /// * `mount_point` - Where the FAT filesystem will be mounted in the guest
    /// * `size_bytes` - Size of the FAT image (min: 1MB, max: 16GB)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The host path already exists
    /// - The mount point is invalid or conflicts with existing files/mounts
    /// - The size is out of range
    /// - Failed to create or format the FAT image
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;
    ///
    /// // Create a persistent 50MB data volume
    /// let fs = HyperlightFSBuilder::new()
    ///     .add_empty_fat_mount_at("/host/data.fat", "/data", 50 * 1024 * 1024)?
    ///     .build()?;
    /// // After drop, /host/data.fat still exists and can be inspected or reused
    /// ```
    #[cfg(unix)]
    pub fn add_empty_fat_mount_at<P: AsRef<Path>>(
        mut self,
        host_path: P,
        mount_point: &str,
        size_bytes: usize,
    ) -> Result<Self> {
        let host_path = host_path.as_ref();
        let mount_point = self.validate_mount_point(mount_point)?;

        // Check for conflicts with existing files and mounts
        self.check_mount_conflicts(&mount_point)?;

        // Create a FAT image at the specified path
        let image = FatImage::create_at(host_path, size_bytes)?;

        info!(
            host = %host_path.display(),
            mount_point = %mount_point,
            size = size_bytes,
            "Creating FAT mount at path in HyperlightFS"
        );

        self.fat_mounts.push(FatMountEntry { image, mount_point });

        Ok(self)
    }

    /// Windows stub - FAT mounts are not supported on Windows.
    #[cfg(windows)]
    pub fn add_empty_fat_mount_at<P: AsRef<Path>>(
        self,
        _host_path: P,
        _mount_point: &str,
        _size_bytes: usize,
    ) -> Result<Self> {
        Err(HyperlightError::Error(
            "FAT mounts are not supported on Windows".to_string(),
        ))
    }

    /// Validate and normalize a mount point.
    ///
    /// Mount points must be:
    /// - Absolute (start with `/`)
    /// - Not contain `..` components
    /// - Not contain null bytes
    fn validate_mount_point(&self, mount_point: &str) -> Result<String> {
        if mount_point.contains('\0') {
            return Err(HyperlightError::Error(format!(
                "Invalid mount point {:?}: contains null byte",
                mount_point
            )));
        }

        let p = Path::new(mount_point);
        if !p.is_absolute() {
            return Err(HyperlightError::Error(format!(
                "Invalid mount point {:?}: must be absolute (start with '/')",
                mount_point
            )));
        }

        let mut parts = Vec::new();
        for comp in p.components() {
            match comp {
                Component::ParentDir => {
                    return Err(HyperlightError::Error(format!(
                        "Invalid mount point {:?}: '..' components are not allowed",
                        mount_point
                    )));
                }
                Component::Normal(s) => parts.push(s.to_string_lossy().to_string()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }

        // Root mount "/" is allowed
        if parts.is_empty() {
            Ok("/".to_string())
        } else {
            Ok(format!("/{}", parts.join("/")))
        }
    }

    /// Check for conflicts between a new mount point and existing files/mounts.
    ///
    /// Conflicts occur when:
    /// - The mount point is a prefix of an existing RO file path
    /// - An existing RO file path is a prefix of the mount point
    /// - Two mounts have the same or overlapping mount points
    /// - Root mount ("/") is used with other files or mounts
    fn check_mount_conflicts(&self, mount_point: &str) -> Result<()> {
        let mount_with_slash = if mount_point == "/" {
            "/".to_string()
        } else {
            format!("{}/", mount_point)
        };

        // If mounting at root, no other files or mounts allowed
        if mount_point == "/" {
            if !self.guest_paths_seen.is_empty() {
                return Err(HyperlightError::Error(
                    "Cannot mount at root '/': RO files already added. \
                     Root mount must be the only filesystem content."
                        .to_string(),
                ));
            }
            if !self.fat_mounts.is_empty() {
                return Err(HyperlightError::Error(
                    "Cannot mount at root '/': other mounts already added. \
                     Root mount must be the only filesystem content."
                        .to_string(),
                ));
            }
        }

        // Check if any existing RO file would be under this mount point
        for guest_path in &self.guest_paths_seen {
            // Check if guest_path starts with mount_point
            if guest_path == mount_point || guest_path.starts_with(&mount_with_slash) {
                return Err(HyperlightError::Error(format!(
                    "Mount point '{}' conflicts with existing file '{}'. \
                     Cannot mount over existing RO files.",
                    mount_point, guest_path
                )));
            }

            // Check if mount_point would be under an existing file's directory
            // (This shouldn't normally happen since we don't allow mounting files at non-leaf paths,
            // but check anyway for safety)
            let guest_with_slash = format!("{}/", guest_path);
            if mount_point.starts_with(&guest_with_slash) {
                return Err(HyperlightError::Error(format!(
                    "Mount point '{}' conflicts with existing file '{}'. \
                     Mount point would be under an existing file path.",
                    mount_point, guest_path
                )));
            }
        }

        // Check if any existing FAT mount would conflict
        for existing in &self.fat_mounts {
            // Check if this is trying to add root mount when others exist
            if existing.mount_point == "/" {
                return Err(HyperlightError::Error(format!(
                    "Cannot add mount at '{}': root mount already exists. \
                     Root mount must be the only filesystem content.",
                    mount_point
                )));
            }

            let existing_with_slash = if existing.mount_point == "/" {
                "/".to_string()
            } else {
                format!("{}/", existing.mount_point)
            };

            // Same mount point
            if mount_point == existing.mount_point {
                return Err(HyperlightError::Error(format!(
                    "Mount point '{}' already in use",
                    mount_point
                )));
            }

            // New mount is under existing mount
            if mount_point.starts_with(&existing_with_slash) {
                return Err(HyperlightError::Error(format!(
                    "Mount point '{}' conflicts with existing mount '{}'. \
                     Cannot create nested mounts.",
                    mount_point, existing.mount_point
                )));
            }

            // Existing mount is under new mount
            if existing.mount_point.starts_with(&mount_with_slash) {
                return Err(HyperlightError::Error(format!(
                    "Mount point '{}' conflicts with existing mount '{}'. \
                     Cannot create nested mounts.",
                    mount_point, existing.mount_point
                )));
            }
        }

        Ok(())
    }

    /// Check if a file path conflicts with existing mounts.
    ///
    /// This is called when adding RO files (via `add_file` or `add_dir`) to ensure
    /// they don't fall under an existing mount point.
    ///
    /// # Arguments
    ///
    /// * `guest_path` - The guest path of the file being added
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A root mount exists (no RO files allowed)
    /// - The file path would be under an existing mount point
    fn check_file_path_conflicts(&self, guest_path: &str) -> Result<()> {
        for mount in &self.fat_mounts {
            // Root mount means no RO files allowed
            if mount.mount_point == "/" {
                return Err(HyperlightError::Error(format!(
                    "Cannot add file '{}': root mount exists. \
                     Root mount must be the only filesystem content.",
                    guest_path
                )));
            }

            let mount_with_slash = format!("{}/", mount.mount_point);

            // Check if file path is exactly the mount point or under it
            if guest_path == mount.mount_point || guest_path.starts_with(&mount_with_slash) {
                return Err(HyperlightError::Error(format!(
                    "Cannot add file '{}': conflicts with mount at '{}'. \
                     RO files cannot be placed under mount points.",
                    guest_path, mount.mount_point
                )));
            }
        }

        Ok(())
    }

    /// Build the HyperlightFS image.
    ///
    /// This creates memory mappings for all configured content:
    /// - **Read-only files**: mmap'd with `MAP_PRIVATE | PROT_READ`
    /// - **FAT mounts**: mmap'd with `MAP_SHARED` for write persistence
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any file cannot be opened
    /// - mmap fails
    /// - Platform is not supported (Windows)
    ///
    /// # Note
    ///
    /// FAT mount integration is not yet implemented (Phase 3). Currently only
    /// read-only files are included in the built image.
    pub fn build(self) -> Result<HyperlightFSImage> {
        super::image::build_image(self.files)
    }
}

impl Default for HyperlightFSBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for adding a directory with include/exclude patterns.
///
/// At least one `include` pattern must be specified before calling `done()`.
#[derive(Debug)]
pub struct DirectoryBuilder {
    parent: HyperlightFSBuilder,
    host_path: PathBuf,
    guest_prefix: String,
    include_patterns: Vec<Pattern>,
    exclude_patterns: Vec<Pattern>,
}

impl DirectoryBuilder {
    /// Add a glob pattern for files to include.
    ///
    /// Patterns use gitignore-style syntax:
    /// - `*` matches any sequence of characters except `/`
    /// - `**` matches any sequence of characters including `/`
    /// - `?` matches any single character
    ///
    /// # Examples
    ///
    /// ```ignore
    /// builder
    ///     .include("**/*.json")    // All JSON files
    ///     .include("config/*")     // Direct children of config/
    ///     .include("data/**")      // Everything under data/
    /// ```
    pub fn include(mut self, pattern: &str) -> Self {
        match Pattern::new(pattern) {
            Ok(p) => self.include_patterns.push(p),
            Err(e) => {
                // Log warning but don't fail - pattern just won't match anything
                tracing::warn!(pattern = pattern, error = %e, "Invalid include pattern");
            }
        }
        self
    }

    /// Add a glob pattern for files to exclude.
    ///
    /// Exclude patterns are applied after include patterns. A file that
    /// matches both an include and exclude pattern will be excluded.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// builder
    ///     .include("**/*")
    ///     .exclude("**/secret/*")    // Exclude secret directories
    ///     .exclude("**/*.tmp")       // Exclude temp files
    /// ```
    pub fn exclude(mut self, pattern: &str) -> Self {
        match Pattern::new(pattern) {
            Ok(p) => self.exclude_patterns.push(p),
            Err(e) => {
                tracing::warn!(pattern = pattern, error = %e, "Invalid exclude pattern");
            }
        }
        self
    }

    /// Finish configuring the directory and return to the parent builder.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No include patterns were specified
    /// - Any generated guest path would conflict with an existing path
    /// - Any generated guest path would conflict with an existing FAT mount
    pub fn done(mut self) -> Result<HyperlightFSBuilder> {
        if self.include_patterns.is_empty() {
            return Err(HyperlightError::Error(format!(
                "Directory {:?} has no include patterns. Use .include() to specify what to map.",
                self.host_path
            )));
        }

        // Walk the directory and apply patterns
        let files = self.collect_files()?;

        // Check for duplicates against existing guest paths
        for file in &files {
            if self.parent.guest_paths_seen.contains(&file.guest_path) {
                return Err(HyperlightError::Error(format!(
                    "Duplicate guest path {:?}: already mapped (from directory {:?})",
                    file.guest_path, self.host_path
                )));
            }
        }

        // Check for conflicts with existing FAT mounts
        for file in &files {
            self.parent.check_file_path_conflicts(&file.guest_path)?;
        }

        // Add all guest paths to the seen set
        for file in &files {
            self.parent.guest_paths_seen.insert(file.guest_path.clone());
        }

        self.parent.files.extend(files);
        Ok(self.parent)
    }

    /// Walk the directory and collect matching files.
    fn collect_files(&self) -> Result<Vec<MappedFile>> {
        let mut results = Vec::new();
        let mut dirs_seen: HashSet<PathBuf> = HashSet::new();

        self.walk_dir(&self.host_path, &mut results, &mut dirs_seen)?;

        Ok(results)
    }

    /// Recursively walk a directory.
    fn walk_dir(
        &self,
        dir: &Path,
        results: &mut Vec<MappedFile>,
        dirs_seen: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            HyperlightError::Error(format!("Cannot read directory {:?}: {}", dir, e))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                HyperlightError::Error(format!("Cannot read directory entry: {}", e))
            })?;

            let path = entry.path();
            // Use symlink_metadata to avoid following symlinks
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|e| HyperlightError::Error(format!("Cannot stat {:?}: {}", path, e)))?;

            // Skip symlinks - they are not supported
            if metadata.file_type().is_symlink() {
                tracing::debug!(path = %path.display(), "Skipping symlink");
                continue;
            }

            // Get relative path for pattern matching
            let rel_path = path.strip_prefix(&self.host_path).unwrap_or(&path);

            // Safety check: reject paths with .. components (shouldn't happen from fs traversal)
            if rel_path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            {
                tracing::warn!(path = %path.display(), "Skipping path with .. component");
                continue;
            }

            let rel_path_str = rel_path.to_string_lossy();

            if metadata.is_dir() {
                // Recurse into directories
                self.walk_dir(&path, results, dirs_seen)?;
            } else if metadata.is_file() {
                // Check if file matches patterns
                if self.matches(&rel_path_str) {
                    let guest_path = normalize_guest_path(
                        &Path::new(&self.guest_prefix)
                            .join(rel_path)
                            .to_string_lossy(),
                    );

                    info!(
                        host = %path.display(),
                        guest = %guest_path,
                        size = metadata.len(),
                        "Adding file from directory"
                    );

                    // Ensure parent directories exist in the mapping
                    self.ensure_parent_dirs(&guest_path, results, dirs_seen);

                    results.push(MappedFile {
                        host_path: path,
                        guest_path,
                        size: metadata.len(),
                        is_dir: false,
                    });
                }
            }
        }

        Ok(())
    }

    /// Check if a relative path matches the include/exclude patterns.
    fn matches(&self, rel_path: &str) -> bool {
        // Must match at least one include pattern
        let included = self.include_patterns.iter().any(|p| p.matches(rel_path));
        if !included {
            return false;
        }

        // Must not match any exclude pattern
        let excluded = self.exclude_patterns.iter().any(|p| p.matches(rel_path));
        !excluded
    }

    /// Ensure parent directories are added to the results.
    fn ensure_parent_dirs(
        &self,
        guest_path: &str,
        results: &mut Vec<MappedFile>,
        dirs_seen: &mut HashSet<PathBuf>,
    ) {
        let path = Path::new(guest_path);

        // Collect ancestors we haven't seen (skip the file itself and root)
        let new_dirs: Vec<_> = path
            .ancestors()
            .skip(1) // skip the file itself
            .filter(|p| !p.as_os_str().is_empty() && *p != Path::new("/"))
            .filter(|p| dirs_seen.insert(p.to_path_buf()))
            .map(|p| p.to_path_buf())
            .collect();

        // Add directories in reverse order (root first)
        for dir_path in new_dirs.into_iter().rev() {
            results.push(MappedFile {
                host_path: PathBuf::new(), // No host path for synthetic dirs
                guest_path: normalize_guest_path(&dir_path.to_string_lossy()),
                size: 0,
                is_dir: true,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    // ==================== validate_host_path tests ====================

    #[test]
    fn test_host_path_valid() {
        assert!(validate_host_path(Path::new("/foo")).is_ok());
        assert!(validate_host_path(Path::new("/foo/bar")).is_ok());
        assert!(validate_host_path(Path::new("/a/b/c")).is_ok());
    }

    #[test]
    fn test_host_path_rejects_relative() {
        assert!(validate_host_path(Path::new("foo")).is_err());
        assert!(validate_host_path(Path::new("foo/bar")).is_err());
        assert!(validate_host_path(Path::new("./foo")).is_err());
    }

    #[test]
    fn test_host_path_rejects_parent_dir() {
        assert!(validate_host_path(Path::new("/foo/..")).is_err());
        assert!(validate_host_path(Path::new("/foo/../bar")).is_err());
        assert!(validate_host_path(Path::new("/../foo")).is_err());
    }

    // ==================== validate_guest_file_path tests ====================

    #[test]
    fn test_file_path_valid() {
        assert_eq!(validate_guest_file_path("/foo").unwrap(), "/foo");
        assert_eq!(validate_guest_file_path("/foo/bar").unwrap(), "/foo/bar");
        assert_eq!(validate_guest_file_path("/a/b/c/d").unwrap(), "/a/b/c/d");
    }

    #[test]
    fn test_file_path_normalizes_double_slashes() {
        assert_eq!(validate_guest_file_path("//foo").unwrap(), "/foo");
        assert_eq!(validate_guest_file_path("/foo//bar").unwrap(), "/foo/bar");
        assert_eq!(validate_guest_file_path("/a///b").unwrap(), "/a/b");
    }

    #[test]
    fn test_file_path_normalizes_trailing_slash() {
        assert_eq!(validate_guest_file_path("/foo/").unwrap(), "/foo");
        assert_eq!(validate_guest_file_path("/foo/bar/").unwrap(), "/foo/bar");
    }

    #[test]
    fn test_file_path_normalizes_dot_components() {
        assert_eq!(validate_guest_file_path("/./foo").unwrap(), "/foo");
        assert_eq!(validate_guest_file_path("/foo/./bar").unwrap(), "/foo/bar");
    }

    #[test]
    fn test_file_path_rejects_relative() {
        assert!(validate_guest_file_path("foo").is_err());
        assert!(validate_guest_file_path("foo/bar").is_err());
        assert!(validate_guest_file_path("./foo").is_err());
    }

    #[test]
    fn test_file_path_rejects_parent_dir() {
        assert!(validate_guest_file_path("/foo/..").is_err());
        assert!(validate_guest_file_path("/foo/../bar").is_err());
        assert!(validate_guest_file_path("/../foo").is_err());
        assert!(validate_guest_file_path("/..").is_err());
    }

    #[test]
    fn test_file_path_rejects_null_byte() {
        assert!(validate_guest_file_path("/foo\0bar").is_err());
        assert!(validate_guest_file_path("/foo/\0").is_err());
    }

    #[test]
    fn test_file_path_rejects_root() {
        assert!(validate_guest_file_path("/").is_err());
        assert!(validate_guest_file_path("//").is_err());
        assert!(validate_guest_file_path("///").is_err());
    }

    #[test]
    fn test_file_path_rejects_empty() {
        assert!(validate_guest_file_path("").is_err());
    }

    // ==================== validate_guest_dir_prefix tests ====================

    #[test]
    fn test_dir_prefix_valid() {
        assert_eq!(validate_guest_dir_prefix("/foo").unwrap(), "/foo");
        assert_eq!(validate_guest_dir_prefix("/foo/bar").unwrap(), "/foo/bar");
    }

    #[test]
    fn test_dir_prefix_allows_root() {
        assert_eq!(validate_guest_dir_prefix("/").unwrap(), "/");
        assert_eq!(validate_guest_dir_prefix("//").unwrap(), "/");
        assert_eq!(validate_guest_dir_prefix("///").unwrap(), "/");
    }

    #[test]
    fn test_dir_prefix_normalizes_double_slashes() {
        assert_eq!(validate_guest_dir_prefix("//foo").unwrap(), "/foo");
        assert_eq!(validate_guest_dir_prefix("/foo//bar").unwrap(), "/foo/bar");
    }

    #[test]
    fn test_dir_prefix_normalizes_trailing_slash() {
        assert_eq!(validate_guest_dir_prefix("/foo/").unwrap(), "/foo");
    }

    #[test]
    fn test_dir_prefix_normalizes_dot_components() {
        assert_eq!(validate_guest_dir_prefix("/./foo").unwrap(), "/foo");
        assert_eq!(validate_guest_dir_prefix("/foo/./bar").unwrap(), "/foo/bar");
    }

    #[test]
    fn test_dir_prefix_rejects_relative() {
        assert!(validate_guest_dir_prefix("foo").is_err());
        assert!(validate_guest_dir_prefix("foo/bar").is_err());
        assert!(validate_guest_dir_prefix("./foo").is_err());
    }

    #[test]
    fn test_dir_prefix_rejects_parent_dir() {
        assert!(validate_guest_dir_prefix("/foo/..").is_err());
        assert!(validate_guest_dir_prefix("/foo/../bar").is_err());
        assert!(validate_guest_dir_prefix("/../foo").is_err());
    }

    #[test]
    fn test_dir_prefix_rejects_null_byte() {
        assert!(validate_guest_dir_prefix("/foo\0bar").is_err());
    }

    #[test]
    fn test_dir_prefix_rejects_empty() {
        assert!(validate_guest_dir_prefix("").is_err());
    }

    // ==================== Builder integration tests ====================

    #[test]
    fn test_builder_new_is_empty() {
        let builder = HyperlightFSBuilder::new();
        let manifest = builder.list().unwrap();
        assert!(manifest.files.is_empty());
        assert_eq!(manifest.total_size, 0);
    }

    #[test]
    fn test_add_file_nonexistent() {
        let result =
            HyperlightFSBuilder::new().add_file("/nonexistent/path/to/file.txt", "/guest/file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_file_success() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let builder = HyperlightFSBuilder::new()
            .add_file(&file_path, "/guest/test.txt")
            .unwrap();

        let manifest = builder.list().unwrap();
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].guest_path, "/guest/test.txt");
        assert_eq!(manifest.files[0].size, 5);
    }

    #[test]
    fn test_add_file_rejects_relative_host_path() {
        let result = HyperlightFSBuilder::new().add_file("relative/path.txt", "/guest/file.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be absolute"));
    }

    #[test]
    fn test_add_file_rejects_host_path_traversal() {
        let result =
            HyperlightFSBuilder::new().add_file("/some/../path/file.txt", "/guest/file.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'..'"));
    }

    #[test]
    fn test_add_dir_rejects_relative_host_path() {
        let result = HyperlightFSBuilder::new().add_dir("relative/dir", "/guest");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be absolute"));
    }

    #[test]
    fn test_add_dir_rejects_host_path_traversal() {
        let result = HyperlightFSBuilder::new().add_dir("/some/../path/dir", "/guest");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'..'"));
    }

    #[test]
    fn test_add_file_rejects_invalid_guest_path() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        // Relative path
        assert!(
            HyperlightFSBuilder::new()
                .add_file(&file_path, "guest/test.txt")
                .is_err()
        );

        // Path traversal
        assert!(
            HyperlightFSBuilder::new()
                .add_file(&file_path, "/guest/../test.txt")
                .is_err()
        );

        // Root only
        assert!(
            HyperlightFSBuilder::new()
                .add_file(&file_path, "/")
                .is_err()
        );
    }

    #[test]
    fn test_add_file_rejects_duplicate_guest_path() {
        let tmp = TempDir::new().unwrap();
        let file1 = tmp.path().join("file1.txt");
        let file2 = tmp.path().join("file2.txt");
        std::fs::write(&file1, b"one").unwrap();
        std::fs::write(&file2, b"two").unwrap();

        let result = HyperlightFSBuilder::new()
            .add_file(&file1, "/same/path.txt")
            .unwrap()
            .add_file(&file2, "/same/path.txt");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate"));
    }

    #[test]
    fn test_add_file_rejects_symlink() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("real.txt");
        let link_path = tmp.path().join("link.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&file_path, &link_path).unwrap();
            let result = HyperlightFSBuilder::new().add_file(&link_path, "/guest/link.txt");
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("symlink"));
        }
    }

    #[test]
    fn test_add_file_rejects_directory() {
        let tmp = TempDir::new().unwrap();
        let result = HyperlightFSBuilder::new().add_file(tmp.path(), "/guest/dir");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not a regular file")
        );
    }

    #[test]
    fn test_add_dir_no_include_fails() {
        let tmp = TempDir::new().unwrap();

        let result = HyperlightFSBuilder::new()
            .add_dir(tmp.path(), "/guest")
            .unwrap()
            .done();

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no include patterns")
        );
    }

    #[test]
    fn test_add_dir_rejects_invalid_prefix() {
        let tmp = TempDir::new().unwrap();

        // Relative prefix
        assert!(
            HyperlightFSBuilder::new()
                .add_dir(tmp.path(), "guest")
                .is_err()
        );

        // Path traversal
        assert!(
            HyperlightFSBuilder::new()
                .add_dir(tmp.path(), "/guest/../data")
                .is_err()
        );
    }

    #[test]
    fn test_add_dir_with_patterns() {
        let tmp = TempDir::new().unwrap();

        // Create test files
        let data_dir = tmp.path().join("data");
        std::fs::create_dir(&data_dir).unwrap();
        std::fs::write(data_dir.join("file.json"), b"{}").unwrap();
        std::fs::write(data_dir.join("file.txt"), b"text").unwrap();
        std::fs::write(data_dir.join("file.bin"), b"binary").unwrap();

        // Create secret directory with files that match include patterns
        // but should be excluded by the exclude pattern
        let secret_dir = tmp.path().join("secret");
        std::fs::create_dir(&secret_dir).unwrap();
        std::fs::write(
            secret_dir.join("credentials.json"),
            b"{\"key\": \"secret\"}",
        )
        .unwrap();
        std::fs::write(secret_dir.join("password.txt"), b"hunter2").unwrap();

        let builder = HyperlightFSBuilder::new()
            .add_dir(tmp.path(), "/guest")
            .unwrap()
            .include("**/*.json")
            .include("**/*.txt")
            .exclude("**/secret/*")
            .done()
            .unwrap();

        let manifest = builder.list().unwrap();

        let file_names: Vec<_> = manifest
            .files
            .iter()
            .filter(|f| !f.is_dir)
            .map(|f| f.guest_path.clone())
            .collect();

        // Should have json and txt from data/
        assert!(file_names.iter().any(|p| p.ends_with("data/file.json")));
        assert!(file_names.iter().any(|p| p.ends_with("data/file.txt")));

        // Should NOT have bin (not in include patterns)
        assert!(!file_names.iter().any(|p| p.ends_with(".bin")));

        // Should NOT have files from secret/ (excluded)
        assert!(!file_names.iter().any(|p| p.contains("secret")));
        assert!(!file_names.iter().any(|p| p.contains("credentials")));
        assert!(!file_names.iter().any(|p| p.contains("password")));
    }

    #[test]
    fn test_from_config_single_file() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("config.json");
        std::fs::write(&file_path, b"{\"key\": \"value\"}").unwrap();

        let toml = format!(
            r#"
[[file]]
host = "{}"
guest = "/config.json"
"#,
            file_path.display()
        );

        let builder = HyperlightFSBuilder::from_toml(&toml).unwrap();
        let manifest = builder.list().unwrap();

        assert_eq!(manifest.files.iter().filter(|f| !f.is_dir).count(), 1);
        assert_eq!(manifest.files[0].guest_path, "/config.json");
    }

    #[test]
    fn test_from_config_multiple_files() {
        let tmp = TempDir::new().unwrap();
        let file1 = tmp.path().join("file1.txt");
        let file2 = tmp.path().join("file2.txt");
        std::fs::write(&file1, b"one").unwrap();
        std::fs::write(&file2, b"two").unwrap();

        let toml = format!(
            r#"
[[file]]
host = "{}"
guest = "/a/file1.txt"

[[file]]
host = "{}"
guest = "/b/file2.txt"
"#,
            file1.display(),
            file2.display()
        );

        let builder = HyperlightFSBuilder::from_toml(&toml).unwrap();
        let manifest = builder.list().unwrap();

        let file_count = manifest.files.iter().filter(|f| !f.is_dir).count();
        assert_eq!(file_count, 2);
    }

    #[test]
    fn test_from_config_directory_default_include() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"aaa").unwrap();
        std::fs::write(tmp.path().join("b.json"), b"{}").unwrap();

        // No include patterns = default to **/*
        let toml = format!(
            r#"
[[directory]]
host = "{}"
guest = "/data"
"#,
            tmp.path().display()
        );

        let builder = HyperlightFSBuilder::from_toml(&toml).unwrap();
        let manifest = builder.list().unwrap();

        let file_names: Vec<_> = manifest
            .files
            .iter()
            .filter(|f| !f.is_dir)
            .map(|f| f.guest_path.clone())
            .collect();

        // Should include all files
        assert!(file_names.iter().any(|p| p.ends_with("a.txt")));
        assert!(file_names.iter().any(|p| p.ends_with("b.json")));
    }

    #[test]
    fn test_from_config_directory_with_patterns() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("include.txt"), b"yes").unwrap();
        std::fs::write(tmp.path().join("exclude.txt"), b"no").unwrap();
        std::fs::write(tmp.path().join("other.bin"), b"binary").unwrap();

        let toml = format!(
            r#"
[[directory]]
host = "{}"
guest = "/assets"
include = ["**/*.txt"]
exclude = ["**/exclude*"]
"#,
            tmp.path().display()
        );

        let builder = HyperlightFSBuilder::from_toml(&toml).unwrap();
        let manifest = builder.list().unwrap();

        let file_names: Vec<_> = manifest
            .files
            .iter()
            .filter(|f| !f.is_dir)
            .map(|f| f.guest_path.clone())
            .collect();

        // Should include .txt files except excluded ones
        assert!(file_names.iter().any(|p| p.ends_with("include.txt")));
        assert!(!file_names.iter().any(|p| p.contains("exclude")));
        assert!(!file_names.iter().any(|p| p.ends_with(".bin")));
    }

    #[test]
    fn test_from_config_mixed() {
        let tmp = TempDir::new().unwrap();
        let single_file = tmp.path().join("single.json");
        std::fs::write(&single_file, b"{}").unwrap();

        let dir = tmp.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("nested.txt"), b"nested").unwrap();

        let toml = format!(
            r#"
[[file]]
host = "{}"
guest = "/config.json"

[[directory]]
host = "{}"
guest = "/data"
"#,
            single_file.display(),
            dir.display()
        );

        let builder = HyperlightFSBuilder::from_toml(&toml).unwrap();
        let manifest = builder.list().unwrap();

        let file_names: Vec<_> = manifest
            .files
            .iter()
            .filter(|f| !f.is_dir)
            .map(|f| f.guest_path.clone())
            .collect();

        assert!(file_names.iter().any(|p| p == "/config.json"));
        assert!(file_names.iter().any(|p| p.ends_with("nested.txt")));
    }

    #[test]
    fn test_from_config_invalid_toml() {
        let result = HyperlightFSBuilder::from_toml("not valid toml {{{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_config_invalid_host_path() {
        let toml = r#"
[[file]]
host = "/nonexistent/path/file.txt"
guest = "/file.txt"
"#;
        let result = HyperlightFSBuilder::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_toml_file_not_found() {
        let result = HyperlightFSBuilder::from_toml_file("/nonexistent/config.toml");
        assert!(result.is_err());
    }

    // ---- FAT Mount Tests ----

    #[cfg(unix)]
    mod fat_mount_tests {
        use super::*;
        use crate::hyperlight_fs::fat_image::MIN_FAT_IMAGE_SIZE;

        #[test]
        fn test_builder_add_fat_image() {
            let tmp = TempDir::new().unwrap();
            let fat_path = tmp.path().join("test.fat");

            // Create a FAT image first
            {
                let _img = crate::hyperlight_fs::FatImage::create_at(&fat_path, MIN_FAT_IMAGE_SIZE)
                    .expect("Failed to create FAT image");
            }

            // Now open it via the builder
            let builder = HyperlightFSBuilder::new()
                .add_fat_image(&fat_path, "/data")
                .expect("Failed to add FAT image");

            assert_eq!(builder.fat_mounts.len(), 1);
            assert_eq!(builder.fat_mounts[0].mount_point, "/data");
        }

        #[test]
        fn test_builder_add_empty_fat() {
            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/scratch", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add empty FAT mount");

            assert_eq!(builder.fat_mounts.len(), 1);
            assert_eq!(builder.fat_mounts[0].mount_point, "/scratch");
            assert!(builder.fat_mounts[0].image.is_temp());
        }

        #[test]
        fn test_builder_add_empty_fat_at() {
            let tmp = TempDir::new().unwrap();
            let fat_path = tmp.path().join("persistent.fat");

            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount_at(&fat_path, "/data", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add FAT mount at path");

            assert_eq!(builder.fat_mounts.len(), 1);
            assert_eq!(builder.fat_mounts[0].mount_point, "/data");
            assert!(!builder.fat_mounts[0].image.is_temp());

            // File should exist
            assert!(fat_path.exists());

            // Drop builder and verify file persists
            drop(builder);
            assert!(fat_path.exists());
        }

        #[test]
        fn test_builder_fat_conflict_with_file() {
            let tmp = TempDir::new().unwrap();
            let file_path = tmp.path().join("file.txt");
            std::fs::write(&file_path, b"content").unwrap();

            // Add a file at /data/file.txt
            let builder = HyperlightFSBuilder::new()
                .add_file(&file_path, "/data/file.txt")
                .expect("Failed to add file");

            // Try to mount FAT at /data (parent of the file) - should fail
            let result = builder.add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("conflicts"),
                "Expected conflict error, got: {}",
                err
            );
        }

        #[test]
        fn test_builder_fat_conflict_with_fat() {
            // Add first FAT mount
            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add first FAT mount");

            // Try to add another FAT at the same mount point - should fail
            let result = builder.add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("already in use"),
                "Expected 'already in use' error, got: {}",
                err
            );
        }

        #[test]
        fn test_builder_fat_conflict_nested_mounts() {
            // Add FAT at /data
            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add FAT mount");

            // Try to add nested FAT at /data/nested - should fail
            let result = builder.add_empty_fat_mount("/data/nested", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("nest"),
                "Expected nesting conflict error, got: {}",
                err
            );
        }

        #[test]
        fn test_builder_root_fat_exclusive() {
            // Add FAT at root
            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add root FAT mount");

            // Try to add another mount - should fail
            let result = builder.add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("root"),
                "Expected root exclusivity error, got: {}",
                err
            );
        }

        #[test]
        fn test_builder_root_fat_blocks_files() {
            let tmp = TempDir::new().unwrap();
            let file_path = tmp.path().join("file.txt");
            std::fs::write(&file_path, b"content").unwrap();

            // Add a file first
            let builder = HyperlightFSBuilder::new()
                .add_file(&file_path, "/config.txt")
                .expect("Failed to add file");

            // Try to mount root FAT - should fail because files exist
            let result = builder.add_empty_fat_mount("/", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("root") && err.contains("RO files"),
                "Expected root + files conflict error, got: {}",
                err
            );
        }

        #[test]
        fn test_builder_invalid_mount_point() {
            let builder = HyperlightFSBuilder::new();

            // Relative path
            let result = builder.add_empty_fat_mount("relative/path", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());

            let builder = HyperlightFSBuilder::new();

            // Path with ..
            let result = builder.add_empty_fat_mount("/foo/../bar", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());

            let builder = HyperlightFSBuilder::new();

            // Null byte
            let result = builder.add_empty_fat_mount("/foo\0bar", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());
        }

        #[test]
        fn test_builder_multiple_fat_mounts() {
            // Multiple non-conflicting FAT mounts should work
            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add first FAT mount")
                .add_empty_fat_mount("/scratch", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add second FAT mount")
                .add_empty_fat_mount("/logs", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add third FAT mount");

            assert_eq!(builder.fat_mounts.len(), 3);
        }

        #[test]
        fn test_builder_fat_and_ro_files_coexist() {
            let tmp = TempDir::new().unwrap();
            let file_path = tmp.path().join("config.json");
            std::fs::write(&file_path, b"{}").unwrap();

            // RO file at /config.json and FAT at /data should coexist
            let builder = HyperlightFSBuilder::new()
                .add_file(&file_path, "/config.json")
                .expect("Failed to add file")
                .add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add FAT mount");

            assert_eq!(builder.files.len(), 1);
            assert_eq!(builder.fat_mounts.len(), 1);
        }

        #[test]
        fn test_file_after_fat_mount_conflict() {
            // This is the critical bug test: adding a file AFTER a FAT mount
            // at a path under the mount point should fail
            let tmp = TempDir::new().unwrap();
            let file_path = tmp.path().join("data.txt");
            std::fs::write(&file_path, b"data").unwrap();

            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add FAT mount");

            // This should fail - file is under mount point
            let result = builder.add_file(&file_path, "/data/file.txt");
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("conflicts with mount"),
                "Expected mount conflict error, got: {}",
                err
            );
        }

        #[test]
        fn test_file_after_root_fat_mount() {
            // No files allowed when root mount exists
            let tmp = TempDir::new().unwrap();
            let file_path = tmp.path().join("config.json");
            std::fs::write(&file_path, b"{}").unwrap();

            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add root FAT mount");

            let result = builder.add_file(&file_path, "/config.json");
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("root mount exists"),
                "Expected root mount error, got: {}",
                err
            );
        }

        #[test]
        fn test_dir_after_fat_mount_conflict() {
            // Adding directory files under mount point should fail
            let tmp = TempDir::new().unwrap();

            // Create a directory structure that will map under /data
            let data_dir = tmp.path().join("hostdir");
            std::fs::create_dir_all(&data_dir).unwrap();
            std::fs::write(data_dir.join("file.txt"), b"content").unwrap();

            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add FAT mount");

            // This should fail - directory would map files under mount point
            let result = builder
                .add_dir(&data_dir, "/data")
                .unwrap()
                .include("**/*")
                .done();
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("conflicts with mount"),
                "Expected mount conflict error, got: {}",
                err
            );
        }

        #[test]
        fn test_dir_after_root_fat_mount() {
            // Adding directory files with root mount should fail
            let tmp = TempDir::new().unwrap();

            let src_dir = tmp.path().join("src");
            std::fs::create_dir_all(&src_dir).unwrap();
            std::fs::write(src_dir.join("main.rs"), b"fn main() {}").unwrap();

            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add root FAT mount");

            let result = builder
                .add_dir(&src_dir, "/src")
                .unwrap()
                .include("**/*")
                .done();
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("root mount exists"),
                "Expected root mount error, got: {}",
                err
            );
        }

        #[test]
        fn test_nested_fat_mounts_rejected() {
            // Cannot have /data and /data/nested as separate mounts
            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add first FAT mount");

            let result = builder.add_empty_fat_mount("/data/nested", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("nested mounts"),
                "Expected nested mount error, got: {}",
                err
            );
        }

        #[test]
        fn test_nested_fat_mounts_reverse_order() {
            // Cannot have /data/nested and then /data as parent
            let builder = HyperlightFSBuilder::new()
                .add_empty_fat_mount("/data/nested", MIN_FAT_IMAGE_SIZE)
                .expect("Failed to add nested FAT mount");

            let result = builder.add_empty_fat_mount("/data", MIN_FAT_IMAGE_SIZE);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("nested mounts"),
                "Expected nested mount error, got: {}",
                err
            );
        }
    }
}
