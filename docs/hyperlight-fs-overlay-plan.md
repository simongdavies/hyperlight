# HyperlightFS Overlay & Extraction Implementation Plan

> **Status**: Planning  
> **Branch**: `hyperlight-fs-with-fat-overlay`  
> **Spec**: [hyperlight-fs-fat-spec.md](./hyperlight-fs-fat-spec.md) §15-17

## Overview

This document tracks the implementation plan for FAT overlay filesystem and host extraction APIs. Each phase is designed to be independently reviewable and testable.

## Scope

### In Scope (This Implementation)

| Feature | Description |
|---------|-------------|
| Guest FAT Extraction | Extract guest-created FAT mounts back to host |
| FAT-on-FAT Overlay | Copy-on-write overlay on FAT base images |
| Block-level COW | 4KB block granularity for efficient storage |
| Whiteout deletions | Track deleted files without modifying base |
| Overlay diff extraction | Get structured diff of changes |
| Merge to new FAT | Apply overlay to produce v2 (base unchanged) |
| Memory-backed overlay | Overlay stored in guest heap |

### Out of Scope (Deferred)

| Feature | Reason |
|---------|--------|
| RO mmap overlay | Complexity - requires virtual FAT or hybrid VFS |
| Host-backed persistent overlay | Memory-backed sufficient for initial use cases |
| Antivirus integration | Users scan extracted content with own tools |
| Nested overlays | Complexity vs benefit |
| Overlay-on-overlay | Single level only |
| Guest-created + host overlay | Host overlay is host-only |

---

## Phase 1: Guest FAT Extraction (Foundation)

**Goal**: Extract guest-created FAT mounts back to host

**Branch**: `hyperlight-fs-overlay-phase1` (from `hyperlight-fs-with-fat-overlay`)

### Deliverables

```rust
// New types
pub struct MountInfo {
    pub mount_point: String,
    pub mount_type: MountType,
    pub size_bytes: u64,
    pub used_bytes: Option<u64>,
    pub is_guest_created: bool,
    pub has_overlay: bool,
}

pub struct ExtractionReport {
    pub files_extracted: usize,
    pub directories_created: usize,
    pub total_bytes: u64,
    pub warnings: Vec<String>,
    pub skipped_count: usize,
}

// New Sandbox methods
impl Sandbox {
    fn fs_list_mounts(&self) -> Result<Vec<MountInfo>>;
    fn fs_extract_fat(&self, mount_point: &str) -> Result<Vec<u8>>;
    fn fs_extract_fat_to_file(&self, mount_point: &str, path: &Path) -> Result<()>;
    fn fs_extract_to_dir(&self, mount_point: &str, host_dir: &Path) -> Result<ExtractionReport>;
}
```

### Tasks

- [ ] **1.1** Design guest-to-host mount enumeration mechanism
  - Option A: Guest updates shared memory region
  - Option B: Host call triggers guest to report mounts
  - **Decision**: TBD during implementation
  
- [ ] **1.2** Add FlatBuffer schema for mount enumeration response
  - `MountInfo` table
  - Response message type
  
- [ ] **1.3** Implement `fs_list_mounts()` on Sandbox
  - Enumerate host-configured mounts
  - Query guest for guest-created mounts
  - Combine into single list
  
- [ ] **1.4** Implement `fs_extract_fat()` 
  - Locate FAT region in guest memory
  - Copy bytes to Vec
  - Validate FAT structure
  
- [ ] **1.5** Implement `fs_extract_fat_to_file()`
  - Use `fs_extract_fat()` internally
  - Write to file
  - Validate output file is valid FAT
  
- [ ] **1.6** Implement `fs_extract_to_dir()`
  - Parse FAT structure on host
  - Walk directory tree
  - Sanitize filenames (security!)
  - Create directories and files
  - Generate ExtractionReport
  
- [ ] **1.7** Add security documentation
  - Big scary warning box
  - Path sanitization details
  - Recommendations for users
  
- [ ] **1.8** Unit tests
  - Mock guest-created mounts
  - Extraction validation
  - Path sanitization tests
  
- [ ] **1.9** Integration tests
  - Guest creates mount, writes files
  - Host extracts and validates

### Files to Create/Modify

| File | Change |
|------|--------|
| `src/hyperlight_host/src/sandbox/fs_extraction.rs` | New - extraction APIs |
| `src/hyperlight_host/src/sandbox/mod.rs` | Export new module |
| `src/schema/hyperlight_fs.fbs` | Mount enumeration schema |
| `src/hyperlight_guest/src/fs/mod.rs` | Mount enumeration support |
| `src/hyperlight_host/tests/fs_extraction_test.rs` | New - integration tests |
| `docs/hyperlight-fs.md` | User-facing extraction docs |

### Estimated Size

- **Lines**: 400-600
- **Risk**: 🟢 Low
- **Dependencies**: None

### Review Checklist

- [ ] Security: Path sanitization tested
- [ ] Security: Warning documentation added
- [ ] FAT validation on extraction
- [ ] Tests pass
- [ ] Docs updated
- [ ] `just fmt-apply` clean
- [ ] `just clippy debug` clean
- [ ] `just clippy release` clean

---

## Phase 2: COW Block Store Infrastructure

**Goal**: Internal copy-on-write tracking structure (no VFS integration yet)

**Branch**: `hyperlight-fs-overlay-phase2` (from phase1)

### Deliverables

```rust
/// Block-level copy-on-write tracker
pub(crate) struct CowBlockStore {
    block_size: usize,  // 4096
    base_size: u64,
    modified_bitmap: BitVec,
    modified_blocks: Vec<u8>,
    max_overlay_size: u64,
    whiteouts: HashSet<PathBuf>,
}

pub struct CowStats {
    pub blocks_modified: usize,
    pub bytes_in_overlay: u64,
    pub whiteout_count: usize,
    pub max_overlay_size: u64,
    pub overlay_utilization: f64,
}

pub struct OverlayFullError {
    pub requested_bytes: u64,
    pub available_bytes: u64,
}

impl CowBlockStore {
    fn new(base_size: u64, max_overlay_size: u64) -> Self;
    fn read_block(&self, block_num: u64) -> Option<&[u8]>;
    fn write_block(&mut self, block_num: u64, data: &[u8]) -> Result<(), OverlayFullError>;
    fn is_block_modified(&self, block_num: u64) -> bool;
    fn add_whiteout(&mut self, path: &Path);
    fn remove_whiteout(&mut self, path: &Path);
    fn is_whiteout(&self, path: &Path) -> bool;
    fn stats(&self) -> CowStats;
}
```

### Tasks

- [ ] **2.1** Add `bitvec` dependency (or implement simple bitmap)
  
- [ ] **2.2** Implement `CowBlockStore::new()`
  - Calculate number of blocks from base_size
  - Initialize empty bitmap
  - Pre-allocate modified_blocks with capacity estimate
  
- [ ] **2.3** Implement block read/write
  - `read_block()`: Return data if modified, None otherwise
  - `write_block()`: Copy to overlay, update bitmap
  - Check size limits before write
  
- [ ] **2.4** Implement whiteout tracking
  - `HashSet<PathBuf>` for deleted paths
  - add/remove/is_whiteout methods
  
- [ ] **2.5** Implement `stats()`
  - Count modified blocks
  - Calculate utilization
  
- [ ] **2.6** Unit tests
  - Block operations
  - Size limit enforcement
  - Whiteout semantics
  - Edge cases (first block, last block, etc.)

### Files to Create/Modify

| File | Change |
|------|--------|
| `src/hyperlight_guest/src/fs/cow.rs` | New - COW block store |
| `src/hyperlight_guest/src/fs/mod.rs` | Export (crate-internal) |
| `src/hyperlight_guest/Cargo.toml` | Maybe bitvec dep |

### Estimated Size

- **Lines**: 300-400
- **Risk**: 🟢 Low  
- **Dependencies**: None (pure data structure)

### Review Checklist

- [ ] Block operations correct
- [ ] Size limits enforced
- [ ] No panics on edge cases
- [ ] Tests comprehensive
- [ ] `just fmt-apply` clean
- [ ] `just clippy debug` clean
- [ ] `just clippy release` clean

---

## Phase 3: FAT Overlay Mount

**Goal**: Mount FAT with overlay, transparent to guest

**Branch**: `hyperlight-fs-overlay-phase3` (from phase2)

### Deliverables

```rust
// Host-side
pub struct OverlayConfig {
    pub max_size: u64,
}

impl OverlayConfig {
    pub fn memory_only(max_size: u64) -> Self;
}

impl HyperlightFSBuilder {
    fn with_overlay(self, mount_point: &str, config: OverlayConfig) -> Result<Self>;
}

// Guest-side: FAT backend routes through COW layer
```

### Tasks

- [ ] **3.1** Add `OverlayConfig` struct to host
  
- [ ] **3.2** Implement `with_overlay()` builder method
  - Validate mount_point exists and is FAT
  - Store overlay config in builder state
  - Error if already has overlay
  
- [ ] **3.3** Update FlatBuffer manifest
  - Add `has_overlay: bool`
  - Add `overlay_max_size: uint64`
  
- [ ] **3.4** Update guest manifest parsing
  - Detect overlay config
  - Initialize COW store for mount
  
- [ ] **3.5** Integrate COW into FAT backend
  - Wrap FAT read operations: check COW first
  - Wrap FAT write operations: write to COW
  - Handle whiteouts in path resolution
  
- [ ] **3.6** Handle file deletion with whiteouts
  - `unlink()` on base file creates whiteout
  - `open()` checks whiteouts before base
  
- [ ] **3.7** Integration tests
  - Mount with overlay
  - Write to existing file (COW)
  - Create new file (overlay only)
  - Delete file (whiteout)
  - Read sees merged view

### Files to Create/Modify

| File | Change |
|------|--------|
| `src/hyperlight_host/src/hyperlight_fs/builder.rs` | with_overlay() |
| `src/hyperlight_host/src/hyperlight_fs/overlay.rs` | New - OverlayConfig |
| `src/schema/hyperlight_fs.fbs` | Overlay fields |
| `src/hyperlight_guest/src/fs/fat.rs` | COW integration |
| `src/hyperlight_guest/src/fs/vfs.rs` | Whiteout checks |
| `src/hyperlight_host/tests/fs_overlay_test.rs` | New - integration tests |

### Estimated Size

- **Lines**: 500-700
- **Risk**: 🟡 Medium (VFS integration)
- **Dependencies**: Phase 2

### Review Checklist

- [ ] COW operations work correctly
- [ ] Whiteouts prevent access to deleted files
- [ ] Guest API unchanged (transparent)
- [ ] Base image never modified
- [ ] Tests comprehensive
- [ ] `just fmt-apply` clean
- [ ] `just clippy debug` clean
- [ ] `just clippy release` clean

---

## Phase 4: Overlay Diff Extraction

**Goal**: Extract just the overlay changes as structured diff

**Branch**: `hyperlight-fs-overlay-phase4` (from phase3)

### Deliverables

```rust
pub struct OverlayDiff {
    pub added: Vec<DiffFileEntry>,
    pub modified: Vec<DiffFileEntry>,
    pub deleted: Vec<PathBuf>,
}

pub struct DiffFileEntry {
    pub path: PathBuf,
    pub content: Vec<u8>,
    pub is_directory: bool,
}

impl Sandbox {
    fn fs_extract_overlay_diff(&self, mount_point: &str) -> Result<OverlayDiff>;
}
```

### Tasks

- [ ] **4.1** Add `OverlayDiff` and `DiffFileEntry` types
  
- [ ] **4.2** Implement diff computation
  - Walk overlay blocks to find modified ranges
  - Determine which files were modified
  - Collect whiteouts as deleted entries
  - Identify new files (in overlay, not in base)
  
- [ ] **4.3** Implement `fs_extract_overlay_diff()`
  - Validate mount has overlay
  - Compute diff
  - Return structured result
  
- [ ] **4.4** Unit tests
  - Empty overlay → empty diff
  - Modified file appears in modified
  - New file appears in added
  - Deleted file appears in deleted
  
- [ ] **4.5** Integration tests
  - Guest modifies files
  - Extract diff, verify contents

### Files to Create/Modify

| File | Change |
|------|--------|
| `src/hyperlight_host/src/sandbox/fs_extraction.rs` | Add diff extraction |
| `src/hyperlight_host/src/hyperlight_fs/diff.rs` | New - OverlayDiff types |
| `src/hyperlight_host/tests/fs_overlay_test.rs` | Diff tests |

### Estimated Size

- **Lines**: 300-400
- **Risk**: 🟢 Low
- **Dependencies**: Phase 3

### Review Checklist

- [ ] Diff correctly identifies added/modified/deleted
- [ ] Content extraction correct
- [ ] Tests comprehensive
- [ ] `just fmt-apply` clean
- [ ] `just clippy debug` clean
- [ ] `just clippy release` clean

---

## Phase 5: Merge to New FAT Image

**Goal**: Apply overlay to base, produce new FAT image (v2)

**Branch**: `hyperlight-fs-overlay-phase5` (from phase4)

### Deliverables

```rust
pub struct MergeReport {
    pub base_path: PathBuf,
    pub output_path: PathBuf,
    pub files_added: usize,
    pub files_modified: usize,
    pub files_deleted: usize,
    pub output_size: u64,
}

impl Sandbox {
    fn fs_merge_overlay(&self, mount_point: &str, output_path: &Path) -> Result<MergeReport>;
    fn fs_merge_overlay_to_bytes(&self, mount_point: &str) -> Result<Vec<u8>>;
}
```

### Tasks

- [ ] **5.1** Add `MergeReport` type
  
- [ ] **5.2** Implement merge algorithm
  - Create new FAT image (copy of base)
  - Apply modified blocks from overlay
  - Skip whited-out files
  - Add new files from overlay
  
- [ ] **5.3** Implement `fs_merge_overlay_to_bytes()`
  - Perform merge in memory
  - Return byte vector
  - Validate output is valid FAT
  
- [ ] **5.4** Implement `fs_merge_overlay()`
  - Use `fs_merge_overlay_to_bytes()`
  - Write to file
  - Generate MergeReport
  
- [ ] **5.5** Integration tests
  - Merge produces valid FAT
  - Merged image contains expected files
  - Base image unchanged
  - Report accurate

### Files to Create/Modify

| File | Change |
|------|--------|
| `src/hyperlight_host/src/sandbox/fs_extraction.rs` | Add merge |
| `src/hyperlight_host/src/hyperlight_fs/merge.rs` | New - merge logic |
| `src/hyperlight_host/tests/fs_overlay_test.rs` | Merge tests |

### Estimated Size

- **Lines**: 400-500
- **Risk**: 🟡 Medium (FAT manipulation)
- **Dependencies**: Phase 3, Phase 4

### Review Checklist

- [ ] Merge produces valid FAT
- [ ] Base image NOT modified
- [ ] Whiteouts correctly applied
- [ ] Report statistics accurate
- [ ] Tests comprehensive
- [ ] `just fmt-apply` clean
- [ ] `just clippy debug` clean
- [ ] `just clippy release` clean

---

## Summary

| Phase | Feature | Est. Lines | Risk | Dependencies | Status |
|-------|---------|------------|------|--------------|--------|
| 1 | Guest FAT Extraction | 400-600 | 🟢 Low | None | ⬜ Not Started |
| 2 | COW Block Store | 300-400 | 🟢 Low | None | ⬜ Not Started |
| 3 | FAT Overlay Mount | 500-700 | 🟡 Medium | Phase 2 | ⬜ Not Started |
| 4 | Overlay Diff Extract | 300-400 | 🟢 Low | Phase 3 | ⬜ Not Started |
| 5 | Merge to New FAT | 400-500 | 🟡 Medium | Phase 3, 4 | ⬜ Not Started |

**Total Estimated**: 1900-2600 lines across 5 reviewable PRs

---

## Open Questions

### Q1: Guest Mount Enumeration Mechanism (Phase 1)

How does host learn about guest-created mounts?

- **Option A**: Guest updates shared memory region (manifest)
- **Option B**: Host call triggers guest to report mounts

**Decision**: TBD - will decide when implementing Phase 1

### Q2: FAT Parsing Library (Phase 1)

For `fs_extract_to_dir()`, need to parse FAT on host side:

- **Option A**: Use `fatfs` crate (already a dependency)
- **Option B**: Minimal custom parser (just for reading)

**Leaning**: Option A - reuse existing dependency

---

## Changelog

| Date | Change |
|------|--------|
| 2026-01-27 | Initial plan created |

