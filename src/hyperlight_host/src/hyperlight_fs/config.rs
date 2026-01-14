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

//! TOML configuration support for HyperlightFS.
//!
//! This module provides serde-deserializable configuration structures for
//! defining filesystem mappings in TOML format.
//!
//! # Example TOML Configuration
//!
//! ```toml
//! # Single file mappings
//! [[file]]
//! host = "/etc/app/config.json"
//! guest = "/config.json"
//!
//! [[file]]
//! host = "/var/data/model.bin"
//! guest = "/models/model.bin"
//!
//! # Directory mapping with glob patterns
//! [[directory]]
//! host = "/opt/app/assets"
//! guest = "/assets"
//! include = ["**/*.json", "**/*.txt"]
//! exclude = ["**/secret/*", "**/.git/**"]
//! ```
//!
//! # Usage
//!
//! ## From a TOML file on disk
//!
//! ```ignore
//! use hyperlight_host::hyperlight_fs::{HyperlightFSBuilder, HyperlightFsConfig};
//!
//! // Load config from a file
//! let config = HyperlightFsConfig::from_toml_file("/path/to/hyperlight-fs.toml")?;
//! let fs = HyperlightFSBuilder::from_config(&config)?.build()?;
//! ```
//!
//! ## From a TOML string
//!
//! ```ignore
//! use hyperlight_host::hyperlight_fs::{HyperlightFSBuilder, HyperlightFsConfig};
//!
//! let toml_content = r#"
//! [[file]]
//! host = "/etc/app/config.json"
//! guest = "/config.json"
//! "#;
//!
//! let config = HyperlightFsConfig::from_toml(toml_content)?;
//! let fs = HyperlightFSBuilder::from_config(&config)?.build()?;
//! ```

use serde::Deserialize;

/// Root configuration structure for HyperlightFS TOML files.
///
/// Contains lists of individual file mappings and directory mappings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HyperlightFsConfig {
    /// Individual file mappings.
    #[serde(default)]
    pub file: Vec<FileMapping>,

    /// Directory mappings with optional glob patterns.
    #[serde(default)]
    pub directory: Vec<DirectoryMapping>,
}

/// A single file mapping from host to guest path.
///
/// # Example
///
/// ```toml
/// [[file]]
/// host = "/etc/app/config.json"
/// guest = "/config.json"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMapping {
    /// Absolute path to the file on the host filesystem.
    pub host: String,

    /// Path where the file will appear in the guest's virtual filesystem.
    pub guest: String,
}

/// A directory mapping with optional include/exclude glob patterns.
///
/// # Example
///
/// ```toml
/// [[directory]]
/// host = "/opt/app/assets"
/// guest = "/assets"
/// include = ["**/*.json", "**/*.txt"]
/// exclude = ["**/secret/*"]
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryMapping {
    /// Absolute path to the directory on the host filesystem.
    pub host: String,

    /// Path where the directory will appear in the guest's virtual filesystem.
    pub guest: String,

    /// Glob patterns for files to include (default: `["**/*"]` - all files).
    #[serde(default)]
    pub include: Vec<String>,

    /// Glob patterns for files to exclude (default: empty - exclude nothing).
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl HyperlightFsConfig {
    /// Parse a TOML configuration string into a `HyperlightFsConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML is malformed or contains unknown fields.
    ///
    /// # Example
    ///
    /// ```
    /// use hyperlight_host::hyperlight_fs::HyperlightFsConfig;
    ///
    /// let toml = r#"
    /// [[file]]
    /// host = "/etc/config.json"
    /// guest = "/config.json"
    /// "#;
    ///
    /// let config = HyperlightFsConfig::from_toml(toml).unwrap();
    /// assert_eq!(config.file.len(), 1);
    /// ```
    pub fn from_toml(toml_content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_content)
    }

    /// Load a TOML configuration from a file path.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read
    /// - The TOML is malformed or contains unknown fields
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hyperlight_host::hyperlight_fs::HyperlightFsConfig;
    ///
    /// let config = HyperlightFsConfig::from_toml_file("/path/to/hyperlight-fs.toml")?;
    /// ```
    pub fn from_toml_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
            path: path.to_string(),
            source: e,
        })?;
        Self::from_toml(&content).map_err(|e| ConfigError::ParseError {
            path: path.to_string(),
            source: e,
        })
    }

    /// Returns the total number of mappings (files + directories).
    pub fn mapping_count(&self) -> usize {
        self.file.len() + self.directory.len()
    }

    /// Returns true if the configuration has no mappings.
    pub fn is_empty(&self) -> bool {
        self.file.is_empty() && self.directory.is_empty()
    }
}

/// Errors that can occur when loading a TOML configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read the configuration file.
    #[error("failed to read config file '{path}': {source}")]
    IoError {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse the TOML content.
    #[error("failed to parse config file '{path}': {source}")]
    ParseError {
        /// The path that could not be parsed.
        path: String,
        /// The underlying TOML parse error.
        #[source]
        source: toml::de::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_config() {
        let config = HyperlightFsConfig::from_toml("").unwrap();
        assert!(config.is_empty());
        assert_eq!(config.mapping_count(), 0);
    }

    #[test]
    fn test_parse_single_file() {
        let toml = r#"
[[file]]
host = "/etc/config.json"
guest = "/config.json"
"#;
        let config = HyperlightFsConfig::from_toml(toml).unwrap();
        assert_eq!(config.file.len(), 1);
        assert_eq!(config.file[0].host, "/etc/config.json");
        assert_eq!(config.file[0].guest, "/config.json");
        assert_eq!(config.mapping_count(), 1);
    }

    #[test]
    fn test_parse_multiple_files() {
        let toml = r#"
[[file]]
host = "/etc/config.json"
guest = "/config.json"

[[file]]
host = "/var/data/model.bin"
guest = "/models/model.bin"
"#;
        let config = HyperlightFsConfig::from_toml(toml).unwrap();
        assert_eq!(config.file.len(), 2);
        assert_eq!(config.file[1].guest, "/models/model.bin");
    }

    #[test]
    fn test_parse_directory_minimal() {
        let toml = r#"
[[directory]]
host = "/opt/app/assets"
guest = "/assets"
"#;
        let config = HyperlightFsConfig::from_toml(toml).unwrap();
        assert_eq!(config.directory.len(), 1);
        assert_eq!(config.directory[0].host, "/opt/app/assets");
        assert_eq!(config.directory[0].guest, "/assets");
        assert!(config.directory[0].include.is_empty());
        assert!(config.directory[0].exclude.is_empty());
    }

    #[test]
    fn test_parse_directory_with_patterns() {
        let toml = r#"
[[directory]]
host = "/opt/app/assets"
guest = "/assets"
include = ["**/*.json", "**/*.txt"]
exclude = ["**/secret/*", "**/.git/**"]
"#;
        let config = HyperlightFsConfig::from_toml(toml).unwrap();
        assert_eq!(config.directory[0].include.len(), 2);
        assert_eq!(config.directory[0].exclude.len(), 2);
        assert_eq!(config.directory[0].include[0], "**/*.json");
        assert_eq!(config.directory[0].exclude[0], "**/secret/*");
    }

    #[test]
    fn test_parse_mixed_config() {
        let toml = r#"
[[file]]
host = "/etc/config.json"
guest = "/config.json"

[[directory]]
host = "/opt/assets"
guest = "/assets"
include = ["**/*.png"]

[[file]]
host = "/var/data.bin"
guest = "/data.bin"
"#;
        let config = HyperlightFsConfig::from_toml(toml).unwrap();
        assert_eq!(config.file.len(), 2);
        assert_eq!(config.directory.len(), 1);
        assert_eq!(config.mapping_count(), 3);
    }

    #[test]
    fn test_reject_unknown_fields() {
        let toml = r#"
[[file]]
host = "/etc/config.json"
guest = "/config.json"
unknown_field = "bad"
"#;
        let result = HyperlightFsConfig::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_unknown_top_level() {
        let toml = r#"
[[unknown_section]]
foo = "bar"
"#;
        let result = HyperlightFsConfig::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_fields() {
        // Missing 'guest' field
        let toml = r#"
[[file]]
host = "/etc/config.json"
"#;
        let result = HyperlightFsConfig::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_toml_file_not_found() {
        let result = HyperlightFsConfig::from_toml_file("/nonexistent/path/config.toml");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::IoError { .. }));
    }
}
