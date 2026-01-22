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

//! Integration tests for HyperlightFS - FAT filesystem support.
//!
//! These tests verify the full FAT filesystem lifecycle including:
//! - Creating empty FAT mounts
//! - Loading existing FAT images
//! - CRUD operations (create, read, update, delete)
//! - Directory operations (mkdir, rmdir, list)
//! - Mixed ReadOnly + FAT configurations

#![cfg(unix)]
#![allow(clippy::disallowed_macros)]

use std::path::PathBuf;

use hyperlight_host::GuestBinary;
use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;
use hyperlight_host::sandbox::{MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::{c_simple_guest_as_string, simple_guest_by_env};
use tempfile::TempDir;

/// Default FAT image size for tests (1 MiB).
/// This is sufficient for most test scenarios.
const DEFAULT_TEST_FAT_SIZE: usize = 1024 * 1024;

/// Larger FAT image size for tests that need more space (2 MiB).
const LARGE_TEST_FAT_SIZE: usize = 2 * 1024 * 1024;

/// Returns true if we should skip C-only tests (i.e., GUEST=rust is set).
///
/// C-only tests exercise C API functions that only exist in the C guest.
/// When running with GUEST=rust, these tests should be skipped.
fn skip_c_only_tests() -> bool {
    std::env::var("GUEST")
        .map(|v| v.eq_ignore_ascii_case("rust"))
        .unwrap_or(false)
}

/// Helper to create a sandbox with FAT support.
fn create_fat_sandbox(
    fs_image: hyperlight_host::hyperlight_fs::HyperlightFSImage,
) -> MultiUseSandbox {
    let guest_path = simple_guest_by_env();
    UninitializedSandbox::new(GuestBinary::FilePath(guest_path), None)
        .unwrap()
        .with_hyperlight_fs(fs_image)
        .evolve()
        .unwrap()
}

/// Helper to create a temp directory with an empty FAT mount sandbox.
///
/// Returns the TempDir (must be kept alive for the duration of the test)
/// and the initialized sandbox with an empty FAT mount at `/data`.
fn create_empty_fat_test_sandbox() -> (TempDir, MultiUseSandbox) {
    create_empty_fat_test_sandbox_with_size(DEFAULT_TEST_FAT_SIZE)
}

/// Helper to create a temp directory with an empty FAT mount sandbox of specific size.
///
/// Returns the TempDir (must be kept alive for the duration of the test)
/// and the initialized sandbox with an empty FAT mount at `/data`.
fn create_empty_fat_test_sandbox_with_size(size: usize) -> (TempDir, MultiUseSandbox) {
    let temp_dir = TempDir::new().unwrap();
    let fat_path = temp_dir.path().join("test.fat");

    let fs_image = HyperlightFSBuilder::new()
        .add_empty_fat_mount_at(&fat_path, "/data", size)
        .unwrap()
        .build()
        .unwrap();

    (temp_dir, create_fat_sandbox(fs_image))
}

// =============================================================================
// CRUD Operations Tests
// =============================================================================

/// Integration test: Guest CRUD operations on empty FAT mount.
///
/// Tests the full lifecycle of FAT filesystem operations:
/// 1. Create directory
/// 2. Write file
/// 3. Read file back
/// 4. List directory
/// 5. Delete file
/// 6. Remove directory
#[test]
fn test_guest_fat_crud_operations() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Verify FS is initialized
    let is_init: i32 = sandbox.call("IsFsInitialized", ()).unwrap();
    assert_eq!(is_init, 1, "HyperlightFS should be initialized");

    // 1. Create a directory
    let mkdir_result: bool = sandbox
        .call("MkdirFat", "/data/testdir".to_string())
        .unwrap();
    assert!(mkdir_result, "mkdir should succeed");

    // 2. Write a file
    let test_content = b"Hello from FAT filesystem!".to_vec();
    let write_result: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/testdir/hello.txt".to_string(), test_content.clone()),
        )
        .unwrap();
    assert!(write_result, "write should succeed");

    // 3. Read the file back
    let read_content: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/testdir/hello.txt".to_string())
        .unwrap();
    assert_eq!(
        read_content, test_content,
        "read content should match written content"
    );

    // 4. List directory contents
    let dir_listing: String = sandbox
        .call("ListDirFat", "/data/testdir".to_string())
        .unwrap();
    assert!(
        dir_listing.to_lowercase().contains("hello.txt"),
        "directory listing should contain hello.txt, got: {}",
        dir_listing
    );

    // 5. Delete the file
    let delete_result: bool = sandbox
        .call("DeleteFatFile", "/data/testdir/hello.txt".to_string())
        .unwrap();
    assert!(delete_result, "delete should succeed");

    // Verify file is gone
    let read_deleted: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/testdir/hello.txt".to_string())
        .unwrap();
    assert!(read_deleted.is_empty(), "deleted file should return empty");

    // 6. Remove the directory
    let rmdir_result: bool = sandbox
        .call("RmdirFat", "/data/testdir".to_string())
        .unwrap();
    assert!(rmdir_result, "rmdir should succeed");

    // 7. Test write-then-read at root level (no subdirectory)
    let root_content = b"Root level file!".to_vec();
    let root_write: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/root_file.txt".to_string(), root_content.clone()),
        )
        .unwrap();
    assert!(root_write, "write to root should succeed");

    let root_read: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/root_file.txt".to_string())
        .unwrap();
    assert_eq!(
        root_read, root_content,
        "root-level write-then-read should work"
    );
}

// =============================================================================
// Existing FAT Image Tests
// =============================================================================

/// Integration test: Load existing FAT image and perform mixed operations.
///
/// Tests loading a pre-seeded FAT image:
/// 1. Read pre-existing files from the image
/// 2. Write new files
/// 3. Verify both old and new files accessible
#[test]
fn test_guest_fat_existing_image() {
    // Path to the pre-seeded test FAT image
    let original_fat_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/assets/test_fat.img");

    // Skip test if the asset doesn't exist
    if !original_fat_path.exists() {
        eprintln!(
            "Skipping test: test FAT image not found at {:?}",
            original_fat_path
        );
        return;
    }

    // Copy to temp location so test doesn't modify the original asset
    let temp_dir = TempDir::new().unwrap();
    let test_fat_path = temp_dir.path().join("test_fat.img");
    std::fs::copy(&original_fat_path, &test_fat_path).unwrap();

    let fs_image = HyperlightFSBuilder::new()
        .add_fat_image(&test_fat_path, "/mnt")
        .unwrap()
        .build()
        .unwrap();

    let mut sandbox = create_fat_sandbox(fs_image);

    // Read pre-existing file from the image
    let hello_content: Vec<u8> = sandbox
        .call("ReadFatFile", "/mnt/hello.txt".to_string())
        .unwrap();
    assert_eq!(
        hello_content, b"Hello from the host!\n",
        "pre-seeded hello.txt content should match"
    );

    // Read nested file
    let nested_content: Vec<u8> = sandbox
        .call("ReadFatFile", "/mnt/subdir/nested.txt".to_string())
        .unwrap();
    assert_eq!(
        nested_content, b"File in subdirectory\n",
        "pre-seeded nested.txt content should match"
    );

    // List root directory
    let root_listing: String = sandbox.call("ListDirFat", "/mnt".to_string()).unwrap();
    assert!(
        root_listing.contains("hello.txt"),
        "root should contain hello.txt, got: {}",
        root_listing
    );
    assert!(
        root_listing.contains("subdir"),
        "root should contain subdir, got: {}",
        root_listing
    );

    // Write a new file
    let new_content = b"Written by the guest!".to_vec();
    let write_result: bool = sandbox
        .call(
            "WriteFatFile",
            ("/mnt/guest_output.txt".to_string(), new_content.clone()),
        )
        .unwrap();
    assert!(write_result, "write to existing image should succeed");

    // Read the new file back
    let read_new: Vec<u8> = sandbox
        .call("ReadFatFile", "/mnt/guest_output.txt".to_string())
        .unwrap();
    assert_eq!(read_new, new_content, "newly written content should match");

    // Verify both old and new files are in listing
    let final_listing: String = sandbox.call("ListDirFat", "/mnt".to_string()).unwrap();
    assert!(
        final_listing.contains("hello.txt"),
        "original file should still exist"
    );
    assert!(
        final_listing.contains("guest_output.txt"),
        "new file should appear in listing, got: {}",
        final_listing
    );
}

// =============================================================================
// Root Level Write Tests
// =============================================================================

/// Minimal test: Root-level FAT write with add_empty_fat_mount_at
#[test]
fn test_guest_fat_root_level_minimal() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // ONLY do a root-level write, nothing else first
    let content = b"Root level test".to_vec();
    let write_result: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/root.txt".to_string(), content.clone()),
        )
        .unwrap();
    assert!(write_result, "root-level write should succeed");

    let read_result: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/root.txt".to_string())
        .unwrap();
    assert_eq!(
        read_result, content,
        "root-level write-then-read should work"
    );
}

/// Test: Root-level write after mkdir/rmdir sequence
#[test]
fn test_guest_fat_root_after_mkdir_rmdir() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Do mkdir then rmdir
    let mkdir_result: bool = sandbox
        .call("MkdirFat", "/data/testdir".to_string())
        .unwrap();
    assert!(mkdir_result, "mkdir should succeed");

    let rmdir_result: bool = sandbox
        .call("RmdirFat", "/data/testdir".to_string())
        .unwrap();
    assert!(rmdir_result, "rmdir should succeed");

    // NOW do a root-level write
    let content = b"After mkdir/rmdir".to_vec();
    let write_result: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/root.txt".to_string(), content.clone()),
        )
        .unwrap();
    assert!(
        write_result,
        "root-level write after mkdir/rmdir should succeed"
    );

    let read_result: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/root.txt".to_string())
        .unwrap();
    assert_eq!(
        read_result, content,
        "root-level read after mkdir/rmdir should work"
    );
}

// =============================================================================
// Mixed RO and FAT Tests
// =============================================================================

/// Integration test: Mixed RO and FAT mounts.
#[test]
fn test_guest_mixed_ro_and_fat() {
    use std::io::Write;

    let temp_dir = TempDir::new().unwrap();

    // Create a read-only config file
    let config_path = temp_dir.path().join("config.json");
    let config_content = b"{\"setting\": \"readonly\"}";
    {
        let mut f = std::fs::File::create(&config_path).unwrap();
        f.write_all(config_content).unwrap();
    }

    // Build FS with both RO file and FAT mount
    let fs_image = HyperlightFSBuilder::new()
        .add_file(&config_path, "/config.json")
        .unwrap()
        .add_empty_fat_mount("/data", DEFAULT_TEST_FAT_SIZE)
        .unwrap()
        .build()
        .unwrap();

    let mut sandbox = create_fat_sandbox(fs_image);

    // Read the RO config file
    let read_config: Vec<u8> = sandbox
        .call("ReadFile", "/config.json".to_string())
        .unwrap();
    assert_eq!(read_config, config_content, "RO config should be readable");

    // Write to the FAT mount
    let output_content = b"Processing results".to_vec();
    let write_result: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/output.txt".to_string(), output_content.clone()),
        )
        .unwrap();
    assert!(write_result, "writing to FAT mount should succeed");

    // Read back from FAT
    let read_output: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/output.txt".to_string())
        .unwrap();
    assert_eq!(read_output, output_content, "FAT content should match");
}

// =============================================================================
// File Operation Tests
// =============================================================================

/// Test: File overwrite/update operations.
#[test]
fn test_guest_fat_file_overwrite() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Write initial content
    let content_v1 = b"Version 1 content here".to_vec();
    let write1: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/test.txt".to_string(), content_v1.clone()),
        )
        .unwrap();
    assert!(write1, "initial write should succeed");

    let read1: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/test.txt".to_string())
        .unwrap();
    assert_eq!(read1, content_v1, "initial content should match");

    // Overwrite with new content (shorter)
    let content_v2 = b"V2".to_vec();
    let write2: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/test.txt".to_string(), content_v2.clone()),
        )
        .unwrap();
    assert!(write2, "overwrite should succeed");

    let read2: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/test.txt".to_string())
        .unwrap();
    assert_eq!(read2, content_v2, "overwritten content should match");
    assert_ne!(read2.len(), content_v1.len(), "file should be truncated");

    // Overwrite with longer content
    let content_v3 = b"Version 3 with much longer content than before!".to_vec();
    let write3: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/test.txt".to_string(), content_v3.clone()),
        )
        .unwrap();
    assert!(write3, "second overwrite should succeed");

    let read3: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/test.txt".to_string())
        .unwrap();
    assert_eq!(read3, content_v3, "longer overwrite content should match");
}

/// Test: Nested directory operations.
#[test]
fn test_guest_fat_nested_dirs() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create nested directories (must create parent first)
    let mkdir1: bool = sandbox
        .call("MkdirFat", "/data/level1".to_string())
        .unwrap();
    assert!(mkdir1, "mkdir level1 should succeed");

    let mkdir2: bool = sandbox
        .call("MkdirFat", "/data/level1/level2".to_string())
        .unwrap();
    assert!(mkdir2, "mkdir level2 should succeed");

    let mkdir3: bool = sandbox
        .call("MkdirFat", "/data/level1/level2/level3".to_string())
        .unwrap();
    assert!(mkdir3, "mkdir level3 should succeed");

    // Write file at deepest level
    let deep_content = b"Deep nested file".to_vec();
    let write_deep: bool = sandbox
        .call(
            "WriteFatFile",
            (
                "/data/level1/level2/level3/deep.txt".to_string(),
                deep_content.clone(),
            ),
        )
        .unwrap();
    assert!(write_deep, "write to deep path should succeed");

    // Read back
    let read_deep: Vec<u8> = sandbox
        .call(
            "ReadFatFile",
            "/data/level1/level2/level3/deep.txt".to_string(),
        )
        .unwrap();
    assert_eq!(read_deep, deep_content, "deep file content should match");

    // List intermediate directory
    let list_level2: String = sandbox
        .call("ListDirFat", "/data/level1/level2".to_string())
        .unwrap();
    assert!(
        list_level2.contains("level3"),
        "level2 should contain level3, got: {}",
        list_level2
    );
}

// =============================================================================
// Error Handling Tests
// =============================================================================

/// Test: Error cases for FAT operations.
#[test]
fn test_guest_fat_error_cases() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Read non-existent file should return empty
    let read_missing: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/nonexistent.txt".to_string())
        .unwrap();
    assert!(
        read_missing.is_empty(),
        "reading missing file should return empty"
    );

    // Delete non-existent file should fail
    let delete_missing: bool = sandbox
        .call("DeleteFatFile", "/data/nonexistent.txt".to_string())
        .unwrap();
    assert!(!delete_missing, "deleting missing file should fail");

    // rmdir non-existent dir should fail
    let rmdir_missing: bool = sandbox
        .call("RmdirFat", "/data/nonexistent".to_string())
        .unwrap();
    assert!(!rmdir_missing, "rmdir missing dir should fail");

    // Create dir and file, then try rmdir on non-empty dir
    let _: bool = sandbox
        .call("MkdirFat", "/data/nonempty".to_string())
        .unwrap();
    let _: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/nonempty/file.txt".to_string(), b"data".to_vec()),
        )
        .unwrap();

    let rmdir_nonempty: bool = sandbox
        .call("RmdirFat", "/data/nonempty".to_string())
        .unwrap();
    assert!(!rmdir_nonempty, "rmdir non-empty dir should fail");

    // mkdir on existing dir - verify it doesn't crash
    let _: bool = sandbox
        .call("MkdirFat", "/data/existing".to_string())
        .unwrap();
    let _: bool = sandbox
        .call("MkdirFat", "/data/existing".to_string())
        .unwrap();

    // List non-existent dir should return empty
    let list_missing: String = sandbox
        .call("ListDirFat", "/data/nonexistent".to_string())
        .unwrap();
    assert!(
        list_missing.is_empty(),
        "listing missing dir should return empty"
    );
}

// =============================================================================
// Rename Tests
// =============================================================================

/// Test: File rename operations.
#[test]
fn test_guest_fat_rename() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create and rename a file
    let content = b"Rename me!".to_vec();
    let _: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/original.txt".to_string(), content.clone()),
        )
        .unwrap();

    let rename_result: bool = sandbox
        .call(
            "RenameFat",
            (
                "/data/original.txt".to_string(),
                "/data/renamed.txt".to_string(),
            ),
        )
        .unwrap();
    assert!(rename_result, "rename should succeed");

    // Old name should not exist
    let read_old: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/original.txt".to_string())
        .unwrap();
    assert!(
        read_old.is_empty(),
        "old name should not exist after rename"
    );

    // New name should have content
    let read_new: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/renamed.txt".to_string())
        .unwrap();
    assert_eq!(read_new, content, "renamed file should have same content");

    // Rename non-existent file should fail
    let rename_missing: bool = sandbox
        .call(
            "RenameFat",
            ("/data/missing.txt".to_string(), "/data/new.txt".to_string()),
        )
        .unwrap();
    assert!(!rename_missing, "rename non-existent should fail");
}

// =============================================================================
// Stat Tests
// =============================================================================

/// Test: File stat operations.
#[test]
fn test_guest_fat_stat() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create a file with known content
    let content = b"Hello, stat test!".to_vec();
    let _: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/sized.txt".to_string(), content.clone()),
        )
        .unwrap();

    // Check file size
    let size: i64 = sandbox
        .call("StatFatSize", "/data/sized.txt".to_string())
        .unwrap();
    assert_eq!(
        size,
        content.len() as i64,
        "stat size should match content length"
    );

    // Check non-existent file size
    let missing_size: i64 = sandbox
        .call("StatFatSize", "/data/missing.txt".to_string())
        .unwrap();
    assert_eq!(missing_size, -1, "stat on missing file should return -1");

    // Create a directory
    let _: bool = sandbox.call("MkdirFat", "/data/mydir".to_string()).unwrap();

    // Check existence: file
    let exists_file: i32 = sandbox
        .call("ExistsFat", "/data/sized.txt".to_string())
        .unwrap();
    assert_eq!(exists_file, 1, "existing file should return 1");

    // Check existence: directory
    let exists_dir: i32 = sandbox
        .call("ExistsFat", "/data/mydir".to_string())
        .unwrap();
    assert_eq!(exists_dir, 2, "existing directory should return 2");

    // Check existence: missing
    let exists_missing: i32 = sandbox.call("ExistsFat", "/data/nope".to_string()).unwrap();
    assert_eq!(exists_missing, 0, "missing path should return 0");
}

// =============================================================================
// Large File Tests
// =============================================================================

/// Test: Large file operations.
#[test]
fn test_guest_fat_large_file() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox_with_size(LARGE_TEST_FAT_SIZE);

    // Create a ~10KB file with a pattern (keeping within buffer limits)
    let pattern = b"ABCDEFGHIJ";
    let repeat_count = 1_000;
    let large_content: Vec<u8> = pattern
        .iter()
        .cycle()
        .take(pattern.len() * repeat_count)
        .copied()
        .collect();

    let write_result: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/large.bin".to_string(), large_content.clone()),
        )
        .unwrap();
    assert!(write_result, "large file write should succeed");

    let read_result: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/large.bin".to_string())
        .unwrap();
    assert_eq!(
        read_result.len(),
        large_content.len(),
        "large file length should match"
    );
    assert_eq!(
        read_result, large_content,
        "large file content should match"
    );

    let size: i64 = sandbox
        .call("StatFatSize", "/data/large.bin".to_string())
        .unwrap();
    assert_eq!(
        size,
        large_content.len() as i64,
        "stat size should match large file"
    );
}

// =============================================================================
// CWD Tests
// =============================================================================

/// Test: Current working directory operations.
#[test]
fn test_guest_fat_cwd_operations() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Initial CWD should be "/"
    let initial_cwd: String = sandbox.call("GetCwd", ()).unwrap();
    assert_eq!(initial_cwd, "/", "initial CWD should be /");

    // Create a directory structure
    let _: bool = sandbox
        .call("MkdirFat", "/data/workdir".to_string())
        .unwrap();

    // Change to /data/workdir
    let chdir_result: bool = sandbox.call("Chdir", "/data/workdir".to_string()).unwrap();
    assert!(chdir_result, "chdir should succeed");

    // Verify CWD changed
    let new_cwd: String = sandbox.call("GetCwd", ()).unwrap();
    assert_eq!(new_cwd, "/data/workdir", "CWD should be /data/workdir");

    // Write using relative path (regular WriteFatFile handles relative paths via VFS)
    let content = b"Relative path content".to_vec();
    let write_result: bool = sandbox
        .call(
            "WriteFatFile",
            ("relative.txt".to_string(), content.clone()),
        )
        .unwrap();
    assert!(write_result, "write with relative path should succeed");

    // Read using relative path (regular ReadFatFile handles relative paths via VFS)
    let read_result: Vec<u8> = sandbox
        .call("ReadFatFile", "relative.txt".to_string())
        .unwrap();
    assert_eq!(read_result, content, "relative read should match");

    // Verify file exists at absolute path too
    let abs_read: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/workdir/relative.txt".to_string())
        .unwrap();
    assert_eq!(abs_read, content, "absolute path should find same file");

    // Change to parent directory using ".."
    let chdir_parent: bool = sandbox.call("Chdir", "..".to_string()).unwrap();
    assert!(chdir_parent, "chdir to .. should succeed");

    let parent_cwd: String = sandbox.call("GetCwd", ()).unwrap();
    assert_eq!(parent_cwd, "/data", "CWD should be /data after chdir ..");

    // Verify we can still read the file with relative path from new CWD
    let read_from_parent: Vec<u8> = sandbox
        .call("ReadFatFile", "workdir/relative.txt".to_string())
        .unwrap();
    assert_eq!(
        read_from_parent, content,
        "relative path from parent should work"
    );
}

// =============================================================================
// Sandbox Filesystem API Tests
// =============================================================================

/// Test: fs_write_file and fs_read_file for host ↔ FAT data exchange.
#[test]
fn test_sandbox_fs_write_and_read_file() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Host writes data to FAT mount
    let input_data = b"Host injected data for guest";
    sandbox
        .fs_write_file("/data/input.txt", input_data)
        .unwrap();

    // Guest reads it back
    let guest_read: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/input.txt".to_string())
        .unwrap();
    assert_eq!(
        guest_read,
        input_data.to_vec(),
        "guest should read host-written data"
    );

    // Guest writes data
    let guest_output = b"Guest generated output".to_vec();
    let _: bool = sandbox
        .call(
            "WriteFatFile",
            ("/data/output.txt".to_string(), guest_output.clone()),
        )
        .unwrap();

    // Host reads it back
    let host_read = sandbox.fs_read_file("/data/output.txt").unwrap();
    assert_eq!(
        host_read, guest_output,
        "host should read guest-written data"
    );
}

/// Test: fs_stat returns correct metadata.
#[test]
fn test_sandbox_fs_stat() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Write a file with known content
    let content = b"Hello, stat test!";
    sandbox
        .fs_write_file("/data/statfile.txt", content)
        .unwrap();

    // Create a directory
    sandbox.fs_mkdir("/data/statdir").unwrap();

    // Stat the file
    let file_stat = sandbox.fs_stat("/data/statfile.txt").unwrap();
    assert_eq!(
        file_stat.size,
        content.len() as u64,
        "file size should match"
    );
    assert!(!file_stat.is_dir, "file should not be a directory");

    // Stat the directory
    let dir_stat = sandbox.fs_stat("/data/statdir").unwrap();
    assert!(dir_stat.is_dir, "directory should be a directory");
    assert_eq!(dir_stat.size, 0, "directory size should be 0");
}

/// Test: fs_read_dir lists directory contents.
#[test]
fn test_sandbox_fs_read_dir() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create some files and directories with known content
    let file1_content = b"content1"; // 8 bytes
    let file2_content = b"content2"; // 8 bytes

    sandbox
        .fs_write_file("/data/file1.txt", file1_content)
        .unwrap();
    sandbox
        .fs_write_file("/data/file2.txt", file2_content)
        .unwrap();
    sandbox.fs_mkdir("/data/subdir").unwrap();

    // List directory
    let entries = sandbox.fs_read_dir("/data").unwrap();

    // Should have 3 entries
    assert_eq!(entries.len(), 3, "should list 3 entries");

    // Check names
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"file1.txt"), "should contain file1.txt");
    assert!(names.contains(&"file2.txt"), "should contain file2.txt");
    assert!(names.contains(&"subdir"), "should contain subdir");

    // Check types
    let subdir_entry = entries.iter().find(|e| e.name == "subdir").unwrap();
    assert!(subdir_entry.stat.is_dir, "subdir should be a directory");

    let file1_entry = entries.iter().find(|e| e.name == "file1.txt").unwrap();
    assert!(
        !file1_entry.stat.is_dir,
        "file1.txt should not be a directory"
    );
    assert_eq!(
        file1_entry.stat.size,
        file1_content.len() as u64,
        "file1.txt size should match content length"
    );
}

/// Test: fs_mkdir creates directories.
#[test]
fn test_sandbox_fs_mkdir() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create a directory
    sandbox.fs_mkdir("/data/newdir").unwrap();

    // Verify it exists and is a directory
    let stat = sandbox.fs_stat("/data/newdir").unwrap();
    assert!(stat.is_dir, "should be a directory");

    // Create nested directory
    sandbox.fs_mkdir("/data/newdir/nested").unwrap();
    let nested_stat = sandbox.fs_stat("/data/newdir/nested").unwrap();
    assert!(nested_stat.is_dir, "nested should be a directory");

    // Write a file inside to verify it's usable
    sandbox
        .fs_write_file("/data/newdir/nested/file.txt", b"nested content")
        .unwrap();
    let content = sandbox
        .fs_read_file("/data/newdir/nested/file.txt")
        .unwrap();
    assert_eq!(content, b"nested content");
}

/// Test: fs_remove_file deletes files.
#[test]
fn test_sandbox_fs_remove_file() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create and verify file
    sandbox
        .fs_write_file("/data/todelete.txt", b"delete me")
        .unwrap();
    assert!(sandbox.fs_exists("/data/todelete.txt").unwrap());

    // Delete file
    sandbox.fs_remove_file("/data/todelete.txt").unwrap();

    // Verify it's gone
    assert!(!sandbox.fs_exists("/data/todelete.txt").unwrap());
}

/// Test: fs_remove_dir deletes empty directories.
#[test]
fn test_sandbox_fs_remove_dir() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create and verify directory
    sandbox.fs_mkdir("/data/emptydir").unwrap();
    assert!(sandbox.fs_exists("/data/emptydir").unwrap());

    // Delete directory
    sandbox.fs_remove_dir("/data/emptydir").unwrap();

    // Verify it's gone
    assert!(!sandbox.fs_exists("/data/emptydir").unwrap());
}

/// Test: fs_remove_dir fails on non-empty directory.
#[test]
fn test_sandbox_fs_remove_dir_not_empty_fails() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create directory with content
    sandbox.fs_mkdir("/data/nonempty").unwrap();
    sandbox
        .fs_write_file("/data/nonempty/file.txt", b"content")
        .unwrap();

    // Attempt to delete non-empty directory should fail
    let result = sandbox.fs_remove_dir("/data/nonempty");
    assert!(result.is_err(), "removing non-empty directory should fail");
}

/// Test: fs_rename renames files.
#[test]
fn test_sandbox_fs_rename_file() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create file
    let content = b"rename me";
    sandbox.fs_write_file("/data/oldname.txt", content).unwrap();

    // Rename file (paths must be relative within the FAT mount)
    sandbox
        .fs_rename("/data/oldname.txt", "/data/newname.txt")
        .unwrap();

    // Old name should not exist
    assert!(!sandbox.fs_exists("/data/oldname.txt").unwrap());

    // New name should exist with same content
    assert!(sandbox.fs_exists("/data/newname.txt").unwrap());
    let read_content = sandbox.fs_read_file("/data/newname.txt").unwrap();
    assert_eq!(read_content, content.to_vec());
}

/// Test: fs_rename moves files to subdirectories.
#[test]
fn test_sandbox_fs_rename_move_to_subdir() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create file and target directory
    let content = b"move me";
    sandbox.fs_write_file("/data/moveme.txt", content).unwrap();
    sandbox.fs_mkdir("/data/subdir").unwrap();

    // Move file
    sandbox
        .fs_rename("/data/moveme.txt", "/data/subdir/moveme.txt")
        .unwrap();

    // Verify move
    assert!(!sandbox.fs_exists("/data/moveme.txt").unwrap());
    assert!(sandbox.fs_exists("/data/subdir/moveme.txt").unwrap());
    let read_content = sandbox.fs_read_file("/data/subdir/moveme.txt").unwrap();
    assert_eq!(read_content, content.to_vec());
}

/// Test: fs_rename renames directories.
#[test]
fn test_sandbox_fs_rename_directory() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create directory with contents
    sandbox.fs_mkdir("/data/olddir").unwrap();
    sandbox
        .fs_write_file("/data/olddir/file.txt", b"content")
        .unwrap();

    // Rename directory (paths must be guest paths)
    sandbox.fs_rename("/data/olddir", "/data/newdir").unwrap();

    // Verify old name gone, new name exists
    assert!(!sandbox.fs_exists("/data/olddir").unwrap());
    assert!(sandbox.fs_exists("/data/newdir").unwrap());
    assert!(sandbox.fs_exists("/data/newdir/file.txt").unwrap());
}

/// Test: fs_exists returns correct results.
#[test]
fn test_sandbox_fs_exists() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Non-existent path
    assert!(!sandbox.fs_exists("/data/noexist.txt").unwrap());

    // Create file
    sandbox
        .fs_write_file("/data/exists.txt", b"I exist")
        .unwrap();
    assert!(sandbox.fs_exists("/data/exists.txt").unwrap());

    // Create directory
    sandbox.fs_mkdir("/data/existsdir").unwrap();
    assert!(sandbox.fs_exists("/data/existsdir").unwrap());

    // Root of mount always exists
    assert!(sandbox.fs_exists("/data").unwrap());
}

/// Test: fs_open_file provides streaming read access.
#[test]
fn test_sandbox_fs_open_file_streaming() {
    use std::io::{Read, Seek, SeekFrom};

    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create file with known content
    let content = b"0123456789ABCDEFGHIJ";
    sandbox.fs_write_file("/data/stream.txt", content).unwrap();

    // Open for streaming read
    let mut reader = sandbox.fs_open_file("/data/stream.txt").unwrap();

    // Read first 5 bytes
    let mut buf = [0u8; 5];
    reader.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"01234");

    // Seek to position 10
    reader.seek(SeekFrom::Start(10)).unwrap();
    reader.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ABCDE");

    // Seek from end
    reader.seek(SeekFrom::End(-5)).unwrap();
    reader.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"FGHIJ");
}

/// Test: fs_create_file provides streaming write access.
#[test]
fn test_sandbox_fs_create_file_streaming() {
    use std::io::Write;

    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create file via streaming write
    {
        let mut writer = sandbox.fs_create_file("/data/streamed.txt").unwrap();
        writer.write_all(b"Part 1, ").unwrap();
        writer.write_all(b"Part 2, ").unwrap();
        writer.write_all(b"Part 3").unwrap();
        writer.flush().unwrap();
    } // writer dropped here, releasing borrow

    // Read back via simple method
    let content = sandbox.fs_read_file("/data/streamed.txt").unwrap();
    assert_eq!(content, b"Part 1, Part 2, Part 3");

    // Verify guest can also read it
    let guest_read: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/streamed.txt".to_string())
        .unwrap();
    assert_eq!(guest_read, b"Part 1, Part 2, Part 3".to_vec());
}

/// Test: Error when path is not in a FAT mount.
#[test]
fn test_sandbox_fs_path_not_in_mount_error() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Try to access a path not in any FAT mount
    let result = sandbox.fs_read_file("/notamount/file.txt");
    assert!(result.is_err(), "should error for path not in FAT mount");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not within a FAT mount"),
        "error should mention FAT mount: {}",
        err
    );
}

/// Test: Error when no HyperlightFS is configured.
#[test]
fn test_sandbox_fs_no_hyperlight_fs_error() {
    // Create sandbox WITHOUT HyperlightFS
    let guest_path = simple_guest_by_env();
    let uninit = UninitializedSandbox::new(GuestBinary::FilePath(guest_path), None).unwrap();
    let mut sandbox: MultiUseSandbox = uninit.evolve().unwrap();

    // All fs_* methods should fail
    let result = sandbox.fs_read_file("/any/path");
    assert!(result.is_err(), "should error when no HyperlightFS");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("No HyperlightFS"),
        "error should mention no HyperlightFS: {}",
        err
    );
}

/// Test: Full workflow - host injects, guest processes, host extracts.
#[test]
fn test_sandbox_fs_full_workflow() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Step 1: Host creates directory structure
    sandbox.fs_mkdir("/data/input").unwrap();
    sandbox.fs_mkdir("/data/output").unwrap();

    // Step 2: Host injects input data
    sandbox
        .fs_write_file("/data/input/data.txt", b"Process this data")
        .unwrap();

    // Step 3: Verify input is visible to guest (by reading it)
    let guest_read: Vec<u8> = sandbox
        .call("ReadFatFile", "/data/input/data.txt".to_string())
        .unwrap();
    assert_eq!(
        guest_read,
        b"Process this data".to_vec(),
        "guest should read host-written input"
    );

    // Step 4: Guest writes output (simulated)
    let _: bool = sandbox
        .call(
            "WriteFatFile",
            (
                "/data/output/result.txt".to_string(),
                b"Processed result".to_vec(),
            ),
        )
        .unwrap();

    // Step 5: Host extracts output
    let result = sandbox.fs_read_file("/data/output/result.txt").unwrap();
    assert_eq!(result, b"Processed result");

    // Step 6: Host lists output directory
    let entries = sandbox.fs_read_dir("/data/output").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "result.txt");

    // Step 7: Host cleans up
    sandbox.fs_remove_file("/data/output/result.txt").unwrap();
    sandbox.fs_remove_file("/data/input/data.txt").unwrap();
    sandbox.fs_remove_dir("/data/output").unwrap();
    sandbox.fs_remove_dir("/data/input").unwrap();

    // Verify cleanup
    assert!(!sandbox.fs_exists("/data/input").unwrap());
    assert!(!sandbox.fs_exists("/data/output").unwrap());
}

/// Test: fs_rename fails when renaming to existing file.
#[test]
fn test_sandbox_fs_rename_to_existing_fails() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create two files
    sandbox
        .fs_write_file("/data/source.txt", b"source content")
        .unwrap();
    sandbox
        .fs_write_file("/data/target.txt", b"target content")
        .unwrap();

    // Attempt to rename source to existing target should fail
    let result = sandbox.fs_rename("/data/source.txt", "/data/target.txt");
    assert!(
        result.is_err(),
        "renaming to existing file should fail: {:?}",
        result
    );
}

/// Test: fs_rename fails when paths are in different FAT mounts.
#[test]
fn test_sandbox_fs_rename_cross_mount_fails() {
    // Create sandbox with TWO FAT mounts
    let temp_dir = TempDir::new().unwrap();
    let fat1_path = temp_dir.path().join("fat1.fat");
    let fat2_path = temp_dir.path().join("fat2.fat");
    let guest_path = simple_guest_by_env();

    let fs = HyperlightFSBuilder::new()
        .add_empty_fat_mount_at(&fat1_path, "/data1", 1024 * 1024) // 1MB minimum
        .expect("first FAT mount")
        .add_empty_fat_mount_at(&fat2_path, "/data2", 1024 * 1024) // 1MB minimum
        .expect("second FAT mount")
        .build()
        .expect("build fs");

    let mut sandbox: MultiUseSandbox =
        UninitializedSandbox::new(GuestBinary::FilePath(guest_path), None)
            .unwrap()
            .with_hyperlight_fs(fs)
            .evolve()
            .unwrap();

    // Create file in first mount
    sandbox
        .fs_write_file("/data1/file.txt", b"content")
        .unwrap();

    // Attempt to rename across mounts should fail
    let result = sandbox.fs_rename("/data1/file.txt", "/data2/file.txt");
    assert!(result.is_err(), "cross-mount rename should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("different FAT mounts"),
        "error should mention different mounts: {}",
        err
    );

    drop(sandbox);
    drop(temp_dir);
}

/// Test: fs_rename fails when trying to rename root.
#[test]
fn test_sandbox_fs_rename_root_fails() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Attempt to rename root (mount point) should fail
    // We use "/data/" renamed to "/data/newroot" - the source is the root of the mount
    let result = sandbox.fs_rename("/data/", "/data/newroot");
    assert!(result.is_err(), "renaming root should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("root") || err.contains("Cannot rename"),
        "error should mention root directory: {}",
        err
    );
}

/// Test: read_dir size reflects actual content size.
#[test]
fn test_sandbox_fs_read_dir_file_sizes() {
    let (_temp_dir, mut sandbox) = create_empty_fat_test_sandbox();

    // Create files with known content sizes
    let content_a = b"hello"; // 5 bytes
    let content_b = b"goodbye world"; // 13 bytes

    sandbox.fs_write_file("/data/a.txt", content_a).unwrap();
    sandbox.fs_write_file("/data/b.txt", content_b).unwrap();

    // List and verify sizes match content lengths
    let entries = sandbox.fs_read_dir("/data").unwrap();

    let a_entry = entries.iter().find(|e| e.name == "a.txt").unwrap();
    assert_eq!(
        a_entry.stat.size,
        content_a.len() as u64,
        "a.txt size should match content length"
    );

    let b_entry = entries.iter().find(|e| e.name == "b.txt").unwrap();
    assert_eq!(
        b_entry.stat.size,
        content_b.len() as u64,
        "b.txt size should match content length"
    );
}

// =============================================================================
// C Guest Only Tests - Testing C API bindings (opendir, access, fcntl, etc.)
// =============================================================================
//
// These tests exercise C-specific API bindings that don't have Rust equivalents.
// They use c_simple_guest_as_string() directly rather than the GUEST env var.

/// Helper to create a C guest sandbox with FAT support.
fn create_c_guest_fat_sandbox(
    fs_image: hyperlight_host::hyperlight_fs::HyperlightFSImage,
) -> MultiUseSandbox {
    let guest_path = c_simple_guest_as_string().expect("C guest binary not found");
    UninitializedSandbox::new(GuestBinary::FilePath(guest_path), None)
        .unwrap()
        .with_hyperlight_fs(fs_image)
        .evolve()
        .unwrap()
}

/// Helper to create a C guest sandbox with an empty FAT mount at /data.
fn create_c_guest_empty_fat_sandbox() -> (TempDir, MultiUseSandbox) {
    let temp_dir = TempDir::new().unwrap();
    let fat_path = temp_dir.path().join("test.fat");

    let fs = HyperlightFSBuilder::new()
        .add_empty_fat_mount_at(&fat_path, "/data", DEFAULT_TEST_FAT_SIZE)
        .expect("create FAT mount")
        .build()
        .expect("build fs");

    let sandbox = create_c_guest_fat_sandbox(fs);
    (temp_dir, sandbox)
}

/// Test: C API opendir/readdir/closedir returns correct entry count.
#[test]
fn test_c_api_opendir_readdir_count() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create some files and directories
    sandbox.fs_mkdir("/data/subdir").unwrap();
    sandbox.fs_write_file("/data/file1.txt", b"one").unwrap();
    sandbox.fs_write_file("/data/file2.txt", b"two").unwrap();

    // Call C guest function to count entries via opendir/readdir
    let count: i32 = sandbox
        .call("TestOpendirReaddir", "/data".to_string())
        .unwrap();

    // Should have 3 entries: subdir, file1.txt, file2.txt
    assert_eq!(count, 3, "opendir/readdir should return 3 entries");
}

/// Test: C API opendir/readdir returns entries with type prefixes.
#[test]
fn test_c_api_opendir_list_with_types() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create a directory and a file
    sandbox.fs_mkdir("/data/mydir").unwrap();
    sandbox
        .fs_write_file("/data/myfile.txt", b"content")
        .unwrap();

    // Call C guest function to list entries with D:/F: prefixes
    let listing: String = sandbox
        .call("TestOpendirList", "/data".to_string())
        .unwrap();

    // Should contain "D:mydir" and "F:myfile.txt"
    assert!(
        listing.contains("D:mydir"),
        "listing should contain 'D:mydir': {}",
        listing
    );
    assert!(
        listing.contains("F:myfile.txt"),
        "listing should contain 'F:myfile.txt': {}",
        listing
    );
}

/// Test: C API access() with F_OK checks file existence.
#[test]
fn test_c_api_access_f_ok() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create a file
    sandbox.fs_write_file("/data/exists.txt", b"hi").unwrap();

    // F_OK = 0 - check existence
    let result: i32 = sandbox
        .call("TestAccess", ("/data/exists.txt".to_string(), 0_i32))
        .unwrap();
    assert_eq!(result, 0, "access(F_OK) should return 0 for existing file");

    // Check non-existent file
    let result: i32 = sandbox
        .call("TestAccess", ("/data/noexist.txt".to_string(), 0_i32))
        .unwrap();
    assert!(result < 0, "access(F_OK) should fail for non-existent file");
}

/// Test: C API access() with R_OK checks read permission.
#[test]
fn test_c_api_access_r_ok() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create a file
    sandbox
        .fs_write_file("/data/readable.txt", b"data")
        .unwrap();

    // R_OK = 4 - check read permission
    let result: i32 = sandbox
        .call("TestAccess", ("/data/readable.txt".to_string(), 4_i32))
        .unwrap();
    assert_eq!(result, 0, "access(R_OK) should return 0 for readable file");
}

/// Test: C API access() with W_OK checks write permission.
#[test]
fn test_c_api_access_w_ok() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create a file (FAT files are writable)
    sandbox
        .fs_write_file("/data/writable.txt", b"data")
        .unwrap();

    // W_OK = 2 - check write permission
    let result: i32 = sandbox
        .call("TestAccess", ("/data/writable.txt".to_string(), 2_i32))
        .unwrap();
    assert_eq!(result, 0, "access(W_OK) should return 0 for writable file");
}

/// Test: C API openat with AT_FDCWD works like open().
#[test]
fn test_c_api_openat_with_at_fdcwd() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create a file
    sandbox
        .fs_write_file("/data/openat_test.txt", b"test")
        .unwrap();

    // O_RDONLY = 0
    let result: i32 = sandbox
        .call(
            "TestOpenatCwd",
            ("/data/openat_test.txt".to_string(), 0_i32),
        )
        .unwrap();
    assert_eq!(result, 1, "openat(AT_FDCWD) should succeed with O_RDONLY");
}

/// Test: C API fcntl F_GETFL/F_SETFL works.
#[test]
fn test_c_api_fcntl_flags() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create a file
    sandbox
        .fs_write_file("/data/fcntl_test.txt", b"test")
        .unwrap();

    // TestFcntlFlags opens with O_RDONLY, gets flags, sets them back
    // Returns the flags on success, negative on error
    let flags: i32 = sandbox
        .call("TestFcntlFlags", "/data/fcntl_test.txt".to_string())
        .unwrap();

    assert!(
        flags >= 0,
        "fcntl F_GETFL/F_SETFL should succeed, got: {}",
        flags
    );
}

/// Test: C API dup works for FAT files.
///
/// Tests that dup() correctly creates a duplicate file descriptor that
/// can be used to read from the same file.
#[test]
fn test_c_api_dup_works() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create a file with some content
    sandbox
        .fs_write_file("/data/dup_test.txt", b"test content for dup")
        .unwrap();

    // TestDup returns true if dup() works correctly
    let result: bool = sandbox
        .call("TestDup", "/data/dup_test.txt".to_string())
        .unwrap();

    assert!(
        result,
        "dup() should work for FAT files (Rc<RefCell<>> implemented)"
    );
}

/// Test: C API dup2 works for FAT files.
///
/// Tests that dup2() correctly creates a duplicate file descriptor at
/// a specific fd number.
#[test]
fn test_c_api_dup2_works() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create a file with some content
    sandbox
        .fs_write_file("/data/dup2_test.txt", b"test content for dup2")
        .unwrap();

    // TestDup2 returns true if dup2() works correctly
    let result: bool = sandbox
        .call("TestDup2", "/data/dup2_test.txt".to_string())
        .unwrap();

    assert!(
        result,
        "dup2() should work for FAT files (Rc<RefCell<>> implemented)"
    );
}

/// Test: C API dup creates fd that shares file position (POSIX semantics).
///
/// This tests the critical POSIX requirement that dup'd file descriptors
/// share the file offset. When fd1 reads 2 bytes, fd2's position also
/// advances, so the next read from fd2 continues where fd1 left off.
#[test]
fn test_c_api_dup_shared_position() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create a file with specific content for position tracking
    sandbox
        .fs_write_file("/data/shared_pos.txt", b"ABCDEFGH")
        .unwrap();

    // TestDupSharedPosition:
    // 1. Opens file, gets fd1
    // 2. Dups to fd2
    // 3. Reads 2 bytes from fd1 (should get "AB")
    // 4. Reads 2 bytes from fd2 (should get "CD" if position shared, "AB" if not)
    // Returns true if position is properly shared
    let result: bool = sandbox
        .call("TestDupSharedPosition", "/data/shared_pos.txt".to_string())
        .unwrap();

    assert!(
        result,
        "dup'd file descriptors should share file position (POSIX semantics)"
    );
}

/// Test: C API mkdirat with AT_FDCWD works like mkdir().
#[test]
fn test_c_api_mkdirat_with_at_fdcwd() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // TestMkdiratCwd creates a dir, verifies it, then removes it
    // Returns 1 on success, negative on error
    let result: i32 = sandbox
        .call("TestMkdiratCwd", "/data/mkdirat_test".to_string())
        .unwrap();

    assert_eq!(result, 1, "mkdirat(AT_FDCWD) should succeed");
}

/// Test: C API opendir on empty directory returns 0 entries.
#[test]
fn test_c_api_opendir_empty_dir() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Create an empty directory
    sandbox.fs_mkdir("/data/emptydir").unwrap();

    // Count entries
    let count: i32 = sandbox
        .call("TestOpendirReaddir", "/data/emptydir".to_string())
        .unwrap();

    assert_eq!(count, 0, "empty directory should have 0 entries");
}

/// Test: C API opendir on non-existent path returns -1.
#[test]
fn test_c_api_opendir_nonexistent() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    // Try to open non-existent directory
    let count: i32 = sandbox
        .call("TestOpendirReaddir", "/data/nonexistent".to_string())
        .unwrap();

    assert_eq!(count, -1, "opendir on non-existent path should return -1");
}

// =============================================================================
// Open Flag Tests - Testing O_TRUNC, O_EXCL, O_APPEND, O_CREAT, O_RDWR
// =============================================================================

/// Test: O_TRUNC flag truncates existing file content.
///
/// Opens file with O_TRUNC, writes shorter content than original,
/// verifies only new content remains (old content is gone).
#[test]
fn test_c_api_o_trunc() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestOTrunc", "/data/trunc_test.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "O_TRUNC test should succeed (got error code {})",
        result
    );
}

/// Test: O_EXCL flag rejects opening existing file.
///
/// O_CREAT | O_EXCL should fail with error if file already exists.
/// This is the atomic "create if not exists" pattern.
#[test]
fn test_c_api_o_excl_existing() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestOExcl", "/data/excl_test.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "O_EXCL test should succeed (got error code {})",
        result
    );
}

/// Test: O_EXCL flag allows creating new file.
///
/// O_CREAT | O_EXCL should succeed when file doesn't exist.
#[test]
fn test_c_api_o_excl_new_file() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestOExclNewFile", "/data/excl_new.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "O_EXCL new file test should succeed (got error code {})",
        result
    );
}

/// Test: O_EXCL without O_CREAT returns EINVAL.
///
/// Per POSIX, O_EXCL without O_CREAT is undefined behavior.
/// We choose to return EINVAL to catch bugs in guest code.
#[test]
fn test_c_api_o_excl_no_creat() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestOExclNoCreat", "/data/excl_no_creat.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "O_EXCL without O_CREAT should return EINVAL (got error code {})",
        result
    );
}

/// Test: O_APPEND flag ensures writes go to end of file.
///
/// Opens file with O_APPEND, writes additional content,
/// verifies original + new content are concatenated.
#[test]
fn test_c_api_o_append() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestOAppend", "/data/append_test.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "O_APPEND test should succeed (got error code {})",
        result
    );
}

/// Test: O_CREAT flag creates file if it doesn't exist.
#[test]
fn test_c_api_o_creat() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestOCreat", "/data/creat_test.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "O_CREAT test should succeed (got error code {})",
        result
    );
}

/// Test: O_RDWR flag allows both reading and writing.
#[test]
fn test_c_api_o_rdwr() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestORdwr", "/data/rdwr_test.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "O_RDWR test should succeed (got error code {})",
        result
    );
}
// =============================================================================
// POSIX Compliance Tests
// =============================================================================

/// Test: O_APPEND after lseek - writes should still go to end.
///
/// POSIX requires that O_APPEND causes each write to seek to EOF first,
/// even if lseek was called in between.
#[test]
fn test_c_api_o_append_after_lseek() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call(
            "TestOAppendAfterLseek",
            "/data/append_lseek.txt".to_string(),
        )
        .unwrap();

    assert_eq!(
        result, 1,
        "O_APPEND after lseek test should succeed (got error code {})",
        result
    );
}

/// Test: fcntl F_GETFL returns accurate flags including O_APPEND.
#[test]
fn test_c_api_fcntl_getfl_accuracy() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestFcntlGetflAccuracy", "/data/getfl_test.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "F_GETFL accuracy test should succeed (got error code {})",
        result
    );
}

/// Test: fcntl F_SETFL can enable O_APPEND after open.
#[test]
fn test_c_api_fcntl_setfl_append() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestFcntlSetflAppend", "/data/setfl_test.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "F_SETFL O_APPEND test should succeed (got error code {})",
        result
    );
}

/// Test: openat with non-AT_FDCWD dirfd returns ENOTSUP.
#[test]
fn test_c_api_openat_real_dirfd() {
    if skip_c_only_tests() {
        return;
    }
    let (_temp_dir, mut sandbox) = create_c_guest_empty_fat_sandbox();

    let result: i32 = sandbox
        .call("TestOpenatRealDirfd", "/data/openat_test.txt".to_string())
        .unwrap();

    assert_eq!(
        result, 1,
        "openat with real dirfd should return ENOTSUP (got error code {})",
        result
    );
}
