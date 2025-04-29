/*
Copyright 2024 The Hyperlight Authors.

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

// This crate contains testing utilities which need to be shared across multiple
// crates in this project.
use std::env;
use std::path::PathBuf;

use anyhow::{anyhow, Result};

pub const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
pub mod logger;
pub mod simplelogger;
pub mod tracing_subscriber;

/// Join all the `&str`s in the `v` parameter as a path with appropriate
/// path separators, then prefix it with `start`, again with the appropriate
/// path separator
fn join_to_path(start: &str, v: Vec<&str>) -> PathBuf {
    let fold_start: PathBuf = {
        let mut pb = PathBuf::new();
        pb.push(start);
        pb
    };
    let fold_closure = |mut agg: PathBuf, cur: &&str| {
        agg.push(cur);
        agg
    };
    v.iter().fold(fold_start, fold_closure)
}

/// Get a new `PathBuf` to a specified Rust guest binary.
/// 
/// This function constructs a path to a Rust guest binary in the test directory structure.
/// It automatically selects the appropriate build directory (debug/release) based on 
/// whether the code is compiled with debug assertions enabled.
/// 
/// # Parameters
/// 
/// * `guest` - The name of the guest binary to locate
/// 
/// # Returns
/// 
/// A `PathBuf` pointing to the location of the specified guest binary
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::rust_guest_as_pathbuf;
/// use std::path::PathBuf;
/// 
/// // Get path to the simpleguest binary
/// let guest_path: PathBuf = rust_guest_as_pathbuf("simpleguest");
/// ```
pub fn rust_guest_as_pathbuf(guest: &str) -> PathBuf {
    let build_dir_selector = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    join_to_path(
        MANIFEST_DIR,
        vec![
            "..",
            "tests",
            "rust_guests",
            "bin",
            build_dir_selector,
            guest,
        ],
    )
}

/// Get a fully qualified OS-specific path to the simpleguest ELF binary.
/// 
/// This function returns the absolute path to the simpleguest ELF binary as a string,
/// automatically selecting the appropriate build directory (debug/release).
/// 
/// # Returns
/// 
/// * `Ok(String)` - The path to the simpleguest ELF binary
/// * `Err` - If the path couldn't be converted to a string
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::simple_guest_as_string;
/// 
/// match simple_guest_as_string() {
///     Ok(path) => println!("Simple guest path: {}", path),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn simple_guest_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("simpleguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert simple guest PathBuf to string"))
}

/// Get a fully qualified OS-specific path to the simpleguest.exe PE binary.
/// 
/// This function returns the absolute path to the simpleguest.exe PE binary as a string,
/// automatically selecting the appropriate build directory (debug/release).
/// 
/// # Returns
/// 
/// * `Ok(String)` - The path to the simpleguest.exe PE binary
/// * `Err` - If the path couldn't be converted to a string
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::simple_guest_exe_as_string;
/// 
/// match simple_guest_exe_as_string() {
///     Ok(path) => println!("Simple guest EXE path: {}", path),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn simple_guest_exe_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("simpleguest.exe");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert simple guest PathBuf to string"))
}

/// Get a fully qualified OS-specific path to the callbackguest ELF binary.
/// 
/// This function returns the absolute path to the callbackguest ELF binary as a string,
/// automatically selecting the appropriate build directory (debug/release).
/// 
/// # Returns
/// 
/// * `Ok(String)` - The path to the callbackguest ELF binary
/// * `Err` - If the path couldn't be converted to a string
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::callback_guest_as_string;
/// 
/// match callback_guest_as_string() {
///     Ok(path) => println!("Callback guest path: {}", path),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn callback_guest_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("callbackguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert callback guest PathBuf to string"))
}

/// Get a fully qualified OS-specific path to the callbackguest.exe PE binary.
/// 
/// This function returns the absolute path to the callbackguest.exe PE binary as a string,
/// automatically selecting the appropriate build directory (debug/release).
/// 
/// # Returns
/// 
/// * `Ok(String)` - The path to the callbackguest.exe PE binary
/// * `Err` - If the path couldn't be converted to a string
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::callback_guest_exe_as_string;
/// 
/// match callback_guest_exe_as_string() {
///     Ok(path) => println!("Callback guest EXE path: {}", path),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn callback_guest_exe_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("callbackguest.exe");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert callback guest PathBuf to string"))
}

/// Get a fully qualified OS-specific path to the dummyguest ELF binary.
/// 
/// This function returns the absolute path to the dummyguest ELF binary as a string,
/// automatically selecting the appropriate build directory (debug/release).
/// 
/// # Returns
/// 
/// * `Ok(String)` - The path to the dummyguest ELF binary
/// * `Err` - If the path couldn't be converted to a string
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::dummy_guest_as_string;
/// 
/// match dummy_guest_as_string() {
///     Ok(path) => println!("Dummy guest path: {}", path),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn dummy_guest_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("dummyguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert dummy guest PathBuf to string"))
}

/// Get a new `PathBuf` to a specified C guest binary.
/// 
/// This function constructs a path to a C guest binary in the test directory structure.
/// It automatically selects the appropriate build directory (debug/release) based on 
/// whether the code is compiled with debug assertions enabled.
/// 
/// # Parameters
/// 
/// * `guest` - The name of the C guest binary to locate
/// 
/// # Returns
/// 
/// A `PathBuf` pointing to the location of the specified C guest binary
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::c_guest_as_pathbuf;
/// use std::path::PathBuf;
/// 
/// // Get path to the C simpleguest binary
/// let guest_path: PathBuf = c_guest_as_pathbuf("simpleguest");
/// ```
pub fn c_guest_as_pathbuf(guest: &str) -> PathBuf {
    let build_dir_selector = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    join_to_path(
        MANIFEST_DIR,
        vec!["..", "tests", "c_guests", "bin", build_dir_selector, guest],
    )
}

/// Get a fully qualified OS-specific path to the C simpleguest binary.
/// 
/// This function returns the absolute path to the C simpleguest binary as a string,
/// automatically selecting the appropriate build directory (debug/release).
/// 
/// # Returns
/// 
/// * `Ok(String)` - The path to the C simpleguest binary
/// * `Err` - If the path couldn't be converted to a string
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::c_simple_guest_as_string;
/// 
/// match c_simple_guest_as_string() {
///     Ok(path) => println!("C simple guest path: {}", path),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn c_simple_guest_as_string() -> Result<String> {
    let buf = c_guest_as_pathbuf("simpleguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert simple guest PathBuf to string"))

}

/// Get a fully qualified OS-specific path to the C callbackguest binary.
/// 
/// This function returns the absolute path to the C callbackguest binary as a string,
/// automatically selecting the appropriate build directory (debug/release).
/// 
/// # Returns
/// 
/// * `Ok(String)` - The path to the C callbackguest binary
/// * `Err` - If the path couldn't be converted to a string
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::c_callback_guest_as_string;
/// 
/// match c_callback_guest_as_string() {
///     Ok(path) => println!("C callback guest path: {}", path),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn c_callback_guest_as_string() -> Result<String> {
    let buf = c_guest_as_pathbuf("callbackguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert callback guest PathBuf to string"))
}

/// Get a fully qualified path to a simple guest binary for fuzzing purposes.
/// 
/// This function first attempts to find a simpleguest binary in the same directory
/// as the current executable. If found, it returns that path. Otherwise, it falls
/// back to the standard test directory structure.
/// 
/// This is particularly useful in fuzzing scenarios where pre-built binaries are
/// built and submitted to a fuzzing framework.
/// 
/// # Returns
/// 
/// * `Ok(String)` - The path to the simpleguest binary to use for fuzzing
/// * `Err` - If the path couldn't be converted to a string
/// 
/// # Example
/// 
/// ```
/// use hyperlight_testing::simple_guest_for_fuzzing_as_string;
/// 
/// match simple_guest_for_fuzzing_as_string() {
///     Ok(path) => println!("Simple guest for fuzzing path: {}", path),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn simple_guest_for_fuzzing_as_string() -> Result<String> {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|p| p.to_path_buf()));

    if let Some(exe_dir) = exe_dir {
        let guest_path = exe_dir.join("simpleguest");

        if guest_path.exists() {
            return Ok(guest_path
                .to_str()
                .ok_or(anyhow!("Invalid path string"))?
                .to_string());
        }
    }

    simple_guest_as_string()
}
