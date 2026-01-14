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

//! HyperlightFS configuration validator.
//!
//! This tool validates a HyperlightFS TOML configuration file and displays
//! what files would be mapped into the guest filesystem.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example hyperlight_fs_validate -- /path/to/hyperlight-fs.toml
//! ```
//!
//! # Example Output
//!
//! ```text
//! ✓ Config valid: hyperlight-fs.toml
//!
//! Files to be mapped:
//!   /config.json (1.2 KB) <- /etc/app/config.json
//!   /assets/logo.png (45.0 KB) <- /opt/app/assets/logo.png
//!   /assets/data.json (892 B) <- /opt/app/assets/data.json
//!
//! Summary:
//!   Files: 3
//!   Directories: 2
//!   Total size: 47.1 KB
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use hyperlight_host::hyperlight_fs::{HyperlightFSBuilder, HyperlightFsConfig};

/// HyperlightFS configuration validator.
///
/// Validates a HyperlightFS TOML configuration file and displays
/// what files would be mapped into the guest filesystem.
#[derive(Parser, Debug)]
#[command(name = "hyperlight_fs_validate")]
#[command(about = "Validate a HyperlightFS TOML configuration file")]
#[command(version)]
struct Args {
    /// Path to the HyperlightFS TOML configuration file.
    #[arg(value_name = "CONFIG")]
    config: PathBuf,

    /// Show only errors, no file listing.
    #[arg(short, long)]
    quiet: bool,

    /// Show detailed information including directory entries.
    #[arg(short, long)]
    verbose: bool,
}

/// Format a byte size in human-readable form.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn run(args: Args) -> Result<(), String> {
    let config_path = args.config.display().to_string();

    // Step 1: Load and parse the TOML config
    if !args.quiet {
        println!("Loading config: {}", config_path);
        println!();
    }

    let config = HyperlightFsConfig::from_toml_file(&config_path)
        .map_err(|e| format!("Failed to load config: {}", e))?;

    if config.is_empty() {
        return Err("Config is empty - no file or directory mappings defined".to_string());
    }

    if !args.quiet {
        println!(
            "✓ Config parsed: {} file mapping(s), {} directory mapping(s)",
            config.file.len(),
            config.directory.len()
        );
        println!();
    }

    // Step 2: Build the manifest (dry-run)
    let builder = HyperlightFSBuilder::from_config(&config)
        .map_err(|e| format!("Failed to process config: {}", e))?;

    let manifest = builder
        .list()
        .map_err(|e| format!("Failed to list files: {}", e))?;

    // Step 3: Display results
    let files: Vec<_> = manifest.files.iter().filter(|f| !f.is_dir).collect();
    let dirs: Vec<_> = manifest.files.iter().filter(|f| f.is_dir).collect();

    if !args.quiet {
        if files.is_empty() {
            println!("⚠ Warning: No files matched the configuration patterns");
            println!();
        } else {
            println!("Files to be mapped:");
            println!();

            for entry in &files {
                println!(
                    "  {} ({}) <- {}",
                    entry.guest_path,
                    format_size(entry.size),
                    entry.host_path.display()
                );
            }
            println!();
        }

        if args.verbose && !dirs.is_empty() {
            println!("Directories:");
            println!();
            for entry in &dirs {
                println!("  {}", entry.guest_path);
            }
            println!();
        }

        // Summary
        println!("Summary:");
        println!("  Files: {}", files.len());
        println!("  Directories: {}", dirs.len());
        println!("  Total size: {}", format_size(manifest.total_size));
        println!();
    }

    println!("✓ Configuration is valid!");

    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();

    match run(args) {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("✗ Error: {}", e);
            ExitCode::from(1)
        }
    }
}
