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

/// Builder for HyperlightFS images.
///
/// Empty by default - files must be explicitly added (no implicit mappings).
#[derive(Debug)]
pub struct HyperlightFSBuilder {
    /// Files collected so far
    files: Vec<MappedFile>,
    /// Guest paths seen so far (for duplicate detection)
    guest_paths_seen: HashSet<String>,
}

impl HyperlightFSBuilder {
    /// Create a new empty builder.
    ///
    /// No files are mapped by default. Use [`add_file`](Self::add_file) or
    /// [`add_dir`](Self::add_dir) to specify what to include.
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            guest_paths_seen: HashSet::new(),
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

    /// Build the HyperlightFS image.
    ///
    /// This creates memory mappings for all files. On Linux, files are
    /// mmap'd with `MAP_PRIVATE | PROT_READ`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any file cannot be opened
    /// - mmap fails
    /// - Platform is not supported (Windows)
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
}
