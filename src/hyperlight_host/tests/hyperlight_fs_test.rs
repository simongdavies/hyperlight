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
use hyperlight_testing::simple_guest_as_string;
use tempfile::TempDir;

/// Default FAT image size for tests (1 MiB).
/// This is sufficient for most test scenarios.
const DEFAULT_TEST_FAT_SIZE: usize = 1024 * 1024;

/// Larger FAT image size for tests that need more space (2 MiB).
const LARGE_TEST_FAT_SIZE: usize = 2 * 1024 * 1024;

/// Helper to get the guest binary path.
fn guest_binary_path() -> String {
    simple_guest_as_string().expect("Guest binary not found")
}

/// Helper to create a sandbox with FAT support.
fn create_fat_sandbox(
    fs_image: hyperlight_host::hyperlight_fs::HyperlightFSImage,
) -> MultiUseSandbox {
    let guest_path = guest_binary_path();
    let mut uninit = UninitializedSandbox::new(GuestBinary::FilePath(guest_path), None).unwrap();
    uninit.set_hyperlight_fs(fs_image);
    uninit.evolve().unwrap()
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

    // Write using relative path
    let content = b"Relative path content".to_vec();
    let write_result: bool = sandbox
        .call(
            "WriteFatFileRelative",
            ("relative.txt".to_string(), content.clone()),
        )
        .unwrap();
    assert!(write_result, "write with relative path should succeed");

    // Read using relative path
    let read_result: Vec<u8> = sandbox
        .call("ReadFatFileRelative", "relative.txt".to_string())
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
        .call("ReadFatFileRelative", "workdir/relative.txt".to_string())
        .unwrap();
    assert_eq!(
        read_from_parent, content,
        "relative path from parent should work"
    );
}
