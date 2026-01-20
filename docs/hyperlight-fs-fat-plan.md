# HyperlightFS FAT Integration - Implementation Plan

## Document Status

| Field | Value |
|-------|-------|
| Status | **In Progress** |
| Created | 2026-01-19 |
| Last Updated | 2026-01-19 |
| Specification | [hyperlight-fs-fat-spec.md](./hyperlight-fs-fat-spec.md) |

## Progress Summary

| Phase | Status | Progress |
|-------|--------|----------|
| Phase 1: Host-Side Foundation | 🟡 In Progress | 5/6 |
| Phase 2: Guest-Side Foundation | ⬜ Not Started | 0/5 |
| Phase 3: Host-Guest Integration | ⬜ Not Started | 0/4 |
| Phase 4: C API Implementation | ⬜ Not Started | 0/4 |
| Phase 5: Host Extraction APIs | ⬜ Not Started | 0/3 |
| Phase 6: Testing & Documentation | ⬜ Not Started | 0/4 |

**Overall: 5/26 steps complete**

---

## Design Reference

All architecture, design decisions, and constraints are documented in the **[HyperlightFS Specification](./hyperlight-fs-fat-spec.md)**. Key sections:

- **§2**: Architecture and MAP_SHARED flow (including page fault handling)
- **§3**: File system types (RO vs FAT), comparison, data persistence guarantees
- **§12**: Security considerations and file locking strategy
- **§13**: Limitations, platform support, resource limits

This plan focuses on **implementation tasks only**.

---

## Platform Constraints

**Windows (WHP)**: Not supported - see Spec §13.1. All HyperlightFS methods return `FsError::PlatformNotSupported` on Windows.

---

## Phase 1: Host-Side Foundation

Build the host-side infrastructure for FAT filesystem support.

### Step 1.1: Add fatfs Dependencies

**Status:** ✅ Complete

**Goal:** Add fatfs, fscommon, and file locking crates to hyperlight-host.

**Files to modify:**
- `src/hyperlight_host/Cargo.toml`

**Changes:**
```toml
[dependencies]
fatfs = "0.3"
fscommon = "0.1"
fs2 = "0.4"  # For cross-platform file locking
```

**Acceptance criteria:**
- [ ] Dependencies added to Cargo.toml
- [ ] `cargo check` passes
- [ ] No version conflicts with existing dependencies

**Notes:**
- fscommon provides `BufStream` for buffered I/O over FAT images
- fatfs 0.3.6 is latest stable
- fs2 provides `flock()` equivalent via `FileExt::lock_exclusive()`

---

### Step 1.2: Create FatImage Wrapper Type with Exclusive Locking

**Status:** ✅ Complete

**Goal:** Create a type to manage FAT filesystem images on the host with exclusive file locking.

**Files to create:**
- `src/hyperlight_host/src/hyperlight_fs/fat_image.rs`

**Files to modify:**
- `src/hyperlight_host/src/hyperlight_fs/mod.rs` (add module)

**Types to implement:**
```rust
use std::fs::File;
use fs2::FileExt;

/// A FAT filesystem image backed by an mmap'd host file.
/// 
/// The backing file is exclusively locked (flock) to prevent
/// multiple sandboxes from mapping the same file concurrently.
pub struct FatImage {
    /// The backing file (holds the exclusive lock)
    file: File,
    /// Memory-mapped region (MAP_SHARED for write persistence)
    mmap: memmap2::MmapMut,
    /// Mount point in guest namespace
    mount_point: String,
    /// Whether this is a temp file (delete on drop)
    is_temp: bool,
}

impl FatImage {
    /// Open an existing FAT image from a file with exclusive lock.
    /// 
    /// Returns `FsError::FileLocked` if file is already locked by another process.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self>;
    
    /// Create a new empty FAT image with specified fixed size.
    /// Creates a backing temp file on the host (potentially sparse).
    /// Size cannot be changed after creation - ENOSPC when full.
    pub fn create_temp(size_bytes: usize) -> Result<Self>;
    
    /// Create a new empty FAT image at specified path with exclusive lock.
    pub fn create_at<P: AsRef<Path>>(path: P, size_bytes: usize) -> Result<Self>;
    
    /// Get the mmap'd region for guest memory mapping.
    pub fn as_mut_ptr(&mut self) -> *mut u8;
    
    /// Get size of image.
    pub fn size(&self) -> usize;
}

impl Drop for FatImage {
    fn drop(&mut self) {
        // Lock is automatically released when file is dropped
        // If is_temp, delete the backing file
    }
}
```

**Acceptance criteria:**
- [ ] FatImage struct implemented with mmap + exclusive lock
- [ ] open() acquires lock, returns FileLocked if already held
- [ ] create_temp() creates temp file, formats FAT32, acquires lock
- [ ] create_at() creates file at path, formats FAT32, acquires lock
- [ ] Lock released on drop
- [ ] Temp files deleted on drop
- [ ] Unit tests pass

**Tests to add:**
- `test_fat_image_create_temp` - create temp image, verify formatted
- `test_fat_image_create_at` - create at path, verify persists after drop
- `test_fat_image_open` - open existing image
- `test_fat_image_exclusive_lock` - second open fails with FileLocked
- `test_fat_image_lock_released_on_drop` - drop first, second can open

---

### Step 1.3: Host FAT File Operations

**Status:** ✅ Complete

**Goal:** Add methods to read/write files within a FAT image.

**Files to modify:**
- `src/hyperlight_host/src/hyperlight_fs/fat_image.rs`

**Methods to implement:**
```rust
impl FatImage {
    /// List directory contents.
    pub fn read_dir(&self, path: &str) -> Result<Vec<FatDirEntry>>;
    
    /// Read a file's contents.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    
    /// Write data to a file (creates or overwrites).
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()>;
    
    /// Create a directory.
    pub fn create_dir(&mut self, path: &str) -> Result<()>;
    
    /// Delete a file.
    pub fn delete_file(&mut self, path: &str) -> Result<()>;
    
    /// Delete an empty directory.
    pub fn delete_dir(&mut self, path: &str) -> Result<()>;
    
    /// Get file/directory metadata.
    pub fn stat(&self, path: &str) -> Result<FatStat>;
    
    /// Check if path exists.
    pub fn exists(&self, path: &str) -> bool;
}

pub struct FatDirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

pub struct FatStat {
    pub size: u64,
    pub is_dir: bool,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
}
```

**Acceptance criteria:**
- [ ] All methods implemented
- [ ] Proper error handling for not-found, permission errors
- [ ] Path validation (no `..`, must be absolute)
- [ ] Unit tests pass

**Tests to add:**
- `test_fat_write_read_file`
- `test_fat_create_delete_dir`
- `test_fat_list_dir`
- `test_fat_nested_dirs`
- `test_fat_overwrite_file`

---

### Step 1.4: Extend HyperlightFSBuilder for FAT Mounts

**Status:** ✅ Complete

**Goal:** Add methods to mount FAT images in the builder.

**Files to modify:**
- `src/hyperlight_host/src/hyperlight_fs/builder.rs`

**Methods to add:**
```rust
impl HyperlightFSBuilder {
    /// Mount a FAT image from a host file.
    pub fn add_fat_image<P: AsRef<Path>>(
        self,
        host_path: P,
        mount_point: &str
    ) -> Result<Self>;
    
    /// Create an empty FAT filesystem at a mount point.
    /// 
    /// Creates a backing host temp file of the specified size (sparse)
    /// and formats it as FAT32. Size is fixed - ENOSPC when full.
    /// Temp file is deleted when HyperlightFSImage is dropped.
    pub fn add_empty_fat_mount(
        self,
        mount_point: &str,
        size_bytes: usize
    ) -> Result<Self>;
    
    /// Create an empty FAT filesystem backed by a specified host file.
    /// 
    /// Like add_empty_fat_mount(), but the file persists after drop.
    /// Useful for debugging, inspection, or reuse across runs.
    pub fn add_empty_fat_mount_at<P: AsRef<Path>>(
        self,
        host_path: P,
        mount_point: &str,
        size_bytes: usize
    ) -> Result<Self>;
}
```

**Internal changes:**
- Add `fat_mounts: Vec<FatMountEntry>` to builder state
- Add conflict detection between:
  - FAT mounts and RO files
  - FAT mounts and other FAT mounts
  - Root mount exclusivity check
- Validate mount points (absolute, no `..`, no null bytes)

**Acceptance criteria:**
- [x] add_fat_image() loads and validates FAT image
- [x] add_empty_fat_mount() creates formatted FAT
- [x] add_empty_fat_mount_at() creates FAT at specified path
- [x] Conflict detection works for all cases
- [x] Root mount (`/`) prevents other additions
- [x] Unit tests pass

**Tests to add:**
- [x] `test_builder_add_fat_image`
- [x] `test_builder_add_empty_fat`
- [x] `test_builder_add_empty_fat_at` - verify file persists after drop
- [x] `test_builder_fat_conflict_with_file`
- [x] `test_builder_fat_conflict_with_fat`
- [x] `test_builder_root_fat_exclusive`

**Additional tests added:**
- [x] `test_file_after_fat_mount_conflict` - RO file under existing mount
- [x] `test_file_after_root_fat_mount` - RO file with root mount
- [x] `test_dir_after_fat_mount_conflict` - directory under mount
- [x] `test_dir_after_root_fat_mount` - directory with root mount
- [x] `test_nested_fat_mounts_rejected` - /data then /data/nested
- [x] `test_nested_fat_mounts_reverse_order` - /data/nested then /data
- [x] `test_builder_multiple_fat_mounts` - non-conflicting mounts
- [x] `test_builder_fat_and_ro_files_coexist` - valid coexistence
- [x] `test_builder_invalid_mount_point` - path validation
- [x] `test_builder_root_fat_blocks_files` - files then root mount
- [x] `test_builder_fat_conflict_nested_mounts` - nested mount detection

**Deferred:** FsLimits and shared locks for RO files (see Appendix D)

---

### Step 1.5: TOML Config Support for FAT Mounts

**Status:** ✅ Complete

**Goal:** Extend the TOML configuration parser to support FAT mount declarations.

**Files to modify:**
- `src/hyperlight_host/src/hyperlight_fs/config.rs`

**Config format:**
```toml
# Mount an existing FAT image file
[[fat_image]]
host_path = "/host/path/to/data.fat"
mount_point = "/data"

# Create an empty FAT mount (temp file, deleted on drop)
[[fat_mount]]
mount_point = "/scratch"
size = "10MB"

# Create an empty FAT mount at a specific host path (persists after drop)
[[fat_mount]]
host_path = "/host/path/to/persistent.fat"
mount_point = "/logs"
size = "50MB"
```

**Types to add:**
```rust
/// Configuration for mounting an existing FAT image.
#[derive(Debug, Clone, Deserialize)]
pub struct FatImageConfig {
    /// Path to the FAT image file on the host
    pub host_path: String,
    /// Mount point in the guest filesystem
    pub mount_point: String,
}

/// Configuration for creating an empty FAT mount.
#[derive(Debug, Clone, Deserialize)]
pub struct FatMountConfig {
    /// Optional path for persistent FAT image (temp if omitted)
    pub host_path: Option<String>,
    /// Mount point in the guest filesystem
    pub mount_point: String,
    /// Size of the FAT image (e.g., "10MB", "1GB", or bytes as integer)
    pub size: SizeValue,
}

/// Size value that can be parsed from string ("10MB") or integer (bytes).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum SizeValue {
    Bytes(usize),
    Human(String),
}
```

**Changes to HyperlightFsConfig:**
```rust
pub struct HyperlightFsConfig {
    #[serde(default)]
    pub file: Vec<FileMapping>,
    #[serde(default)]
    pub directory: Vec<DirectoryMapping>,
    #[serde(default)]
    pub fat_image: Vec<FatImageConfig>,    // NEW
    #[serde(default)]
    pub fat_mount: Vec<FatMountConfig>,    // NEW
}
```

**Changes to from_config():**
- Process `fat_image` entries via `add_fat_image()`
- Process `fat_mount` entries via `add_empty_fat_mount()` or `add_empty_fat_mount_at()`
- Parse human-readable sizes ("10MB", "1GB", etc.)

**Acceptance criteria:**
- [x] `FatImageConfig` struct implemented
- [x] `FatMountConfig` struct implemented  
- [x] `SizeValue` parses both bytes and human-readable sizes
- [x] `from_config()` processes FAT entries
- [x] Conflict detection works via builder
- [x] Unit tests pass

**Tests added:**
- [x] `test_from_config_fat_image`
- [x] `test_from_config_fat_mount_temp`
- [x] `test_from_config_fat_mount_persistent`
- [x] `test_from_config_fat_size_bytes`
- [x] `test_from_config_fat_size_human`
- [x] `test_from_config_fat_conflict_with_file`
- [x] `test_from_config_mixed_ro_and_fat`
- [x] `test_from_config_fat_invalid_size`
- [x] `test_from_config_multiple_fat_mounts`

**Implementation notes:**
- Renamed `host` field to `host_path` in all config structs for clarity
- Added support for size suffixes: B, KB, KiB, MB, MiB, GB, GiB
- Size parsing supports decimal values (e.g., "1.5GB")

---

### Step 1.6: Update FlatBuffer Schema

**Status:** ⬜ Not Started

**Goal:** Extend the manifest schema to support FAT mount metadata.

**Files to modify:**
- `src/schema/hyperlight_fs.fbs`
- `src/hyperlight_common/src/flatbuffer_wrappers/hyperlight_fs.rs`

**Schema changes:**
```flatbuffers
enum InodeType : ubyte {
    File = 0,
    Directory = 1,
    FatMount = 2,    // NEW
}

table Inode {
    inode_type: InodeType;
    path: string (required);
    parent: uint32;
    guest_address: uint64;
    size: uint64;     // CHANGED: was int32 (~2GB limit), now uint64 (no practical limit)
    mount_id: uint32;  // NEW: identifies mount for extraction
}

table HyperlightFS {
    version: uint16;  // Bump to 2
    inodes: [Inode] (required);
}
```

**Wrapper changes:**
- Add `InodeType::FatMount`
- Add `mount_id` field to `InodeData`
- Change `size` field from `i32` to `u64`
- Add `InodeData::fat_mount()` constructor
- Update `HYPERLIGHT_FS_VERSION` to 2
- Add backward compatibility for v1 manifests
- Remove 2GB file size limit check in builder

**Acceptance criteria:**
- [ ] Schema updated
- [ ] `just flatc` regenerates bindings
- [ ] Wrapper types updated
- [ ] Roundtrip serialization works
- [ ] v1 manifests still parseable

**Tests to add:**
- `test_manifest_fat_mount_roundtrip`
- `test_manifest_v1_compatibility`

---

## Phase 2: Guest-Side Foundation

Build the guest-side VFS infrastructure.

### Step 2.1: Add fatfs to Guest

**Status:** ⬜ Not Started

**Goal:** Add fatfs crate to hyperlight-guest with no_std support.

**Files to modify:**
- `src/hyperlight_guest/Cargo.toml`

**Changes:**
```toml
[dependencies]
fatfs = { version = "0.3", default-features = false, features = ["alloc"] }
```

**Note:** The `core_io` feature may require nightly. Need to verify compatibility with hyperlight's toolchain.

**Acceptance criteria:**
- [ ] Dependency added
- [ ] `cargo build --target x86_64-unknown-none` succeeds
- [ ] No_std compatibility verified

**Risks:**
- fatfs `core_io` feature requires specific nightly
- May need to use `lfn` feature for long filenames
- Custom `TimeProvider` implementation needed (see below)

**TimeProvider for FAT timestamps:**

FAT requires timestamps for file creation/modification. Options:
1. **Fixed timestamp** (1980-01-01): Default when no time source available
2. **Integration with `guest_time` feature** ([PR #1173](https://github.com/hyperlight-dev/hyperlight/pull/1173)): When enabled, use `clock_gettime(CLOCK_REALTIME)` for real timestamps

```rust
struct HyperlightTimeProvider;

impl fatfs::TimeProvider for HyperlightTimeProvider {
    fn get_current_date_time(&self) -> fatfs::DateTime {
        #[cfg(feature = "guest_time")]
        {
            // Use paravirtualized clock for real timestamps
            let now = time::now_utc();
            fatfs::DateTime::new(now.year, now.month, now.day, 
                                 now.hour, now.minute, now.second)
        }
        #[cfg(not(feature = "guest_time"))]
        {
            // Fall back to FAT epoch
            fatfs::DateTime::new(1980, 1, 1, 0, 0, 0)
        }
    }
}
```

---

### Step 2.2: Create Guest Memory Block Device

**Status:** ⬜ Not Started

**Goal:** Create a block device adapter for in-memory FAT access.

**Files to create:**
- `src/hyperlight_guest/src/fs/fat_backend.rs`

**Types to implement:**
```rust
/// Block device backed by guest memory region.
pub struct MemoryBlockDevice {
    /// Pointer to start of FAT image in guest memory
    base: *mut u8,
    /// Size of the image
    size: usize,
    /// Current position for Read/Write/Seek
    position: usize,
}

impl MemoryBlockDevice {
    /// Create from a memory region.
    /// 
    /// # Safety
    /// Caller must ensure the memory region is valid and accessible.
    pub unsafe fn new(base: *mut u8, size: usize) -> Self;
}

// Implement traits required by fatfs
impl Read for MemoryBlockDevice { ... }
impl Write for MemoryBlockDevice { ... }
impl Seek for MemoryBlockDevice { ... }
```

**Acceptance criteria:**
- [ ] Implements fatfs::ReadWriteSeek trait
- [ ] Proper bounds checking
- [ ] Works with fatfs::FileSystem

---

### Step 2.3: Create Guest VFS Mount Table

**Status:** ⬜ Not Started

**Goal:** Create the mount table for routing paths to backends.

**Files to modify:**
- `src/hyperlight_guest/src/fs/manifest.rs`
- Create: `src/hyperlight_guest/src/fs/vfs.rs`

**Types to implement:**
```rust
/// A mounted filesystem.
pub enum MountBackend {
    /// Read-only memory-mapped files from host
    ReadOnly,
    /// Read-write FAT filesystem
    Fat(FatFs),
}

/// Mount table entry.
struct Mount {
    /// Mount point path (e.g., "/data")
    path: String,
    /// Backend handling this mount
    backend: MountBackend,
}

/// Virtual filesystem state.
pub struct Vfs {
    /// Mounts sorted by path length (longest first)
    mounts: Vec<Mount>,
    /// Current working directory
    cwd: String,
}

impl Vfs {
    /// Resolve a path to a mount and relative path within it.
    pub fn resolve(&self, path: &str) -> Result<(&Mount, &str), FsError>;
    
    /// Get current working directory.
    pub fn getcwd(&self) -> &str;
    
    /// Change current working directory.
    pub fn chdir(&mut self, path: &str) -> Result<(), FsError>;
}
```

**Acceptance criteria:**
- [ ] Longest-prefix matching works
- [ ] Relative path resolution with cwd
- [ ] Mount conflict detection
- [ ] cwd validation (must exist, must be directory)

**Tests to add:**
- `test_vfs_resolve_longest_prefix`
- `test_vfs_resolve_relative`
- `test_vfs_chdir`

---

### Step 2.4: Parse FAT Mounts from Manifest

**Status:** ⬜ Not Started

**Goal:** Initialize FAT filesystems from manifest during guest startup.

**Files to modify:**
- `src/hyperlight_guest/src/fs/manifest.rs`

**Changes:**
- Parse `InodeType::FatMount` entries
- Create `MemoryBlockDevice` for each FAT mount
- Initialize `fatfs::FileSystem` for each
- Register in VFS mount table

**Acceptance criteria:**
- [ ] FAT mounts detected in manifest
- [ ] fatfs initialized for each mount
- [ ] VFS populated with mounts
- [ ] RO files still work as before

---

### Step 2.5: Unified File Operations

**Status:** ⬜ Not Started

**Goal:** Route file operations through VFS to appropriate backend.

**Files to modify:**
- `src/hyperlight_guest/src/fs/file.rs`
- `src/hyperlight_guest/src/fs/mod.rs`

**Changes to open():**
```rust
pub fn open(path: &str, mode: OpenMode) -> Result<File, FsError> {
    let (mount, rel_path) = VFS.resolve(path)?;
    
    match mount.backend {
        MountBackend::ReadOnly => {
            // Existing RO logic
            if mode.contains(OpenMode::WRITE) {
                return Err(FsError::ReadOnly);
            }
            // ... open from manifest
        }
        MountBackend::Fat(ref fs) => {
            // FAT logic
            // ... open via fatfs
        }
    }
}
```

**File struct changes:**
```rust
pub struct File {
    fd: i32,
    backend: FileBackend,
}

enum FileBackend {
    /// Read-only memory-mapped
    ReadOnly(RoFileHandle),
    /// FAT file
    Fat(FatFileHandle),
}
```

**Acceptance criteria:**
- [ ] open() routes to correct backend
- [ ] read() works for both backends
- [ ] write() works for FAT, returns EROFS for RO
- [ ] seek() works for both backends
- [ ] stat() works for both backends

---

## Phase 3: Host-Guest Integration

Wire FAT images into sandbox memory.

### Step 3.1: Update HyperlightFSImage for FAT

**Status:** ⬜ Not Started

**Goal:** Include FAT image data in the built filesystem image.

**Files to modify:**
- `src/hyperlight_host/src/hyperlight_fs/image.rs`

**Changes:**
- Store `Vec<FatImage>` in HyperlightFSImage
- Compute memory layout including FAT regions
- Generate manifest with FAT mount inodes

**Acceptance criteria:**
- [ ] FAT images stored in HyperlightFSImage
- [ ] manifest_size() includes FAT mount inodes
- [ ] mapped_files_region_size() includes FAT images
- [ ] generate_manifest() produces correct FAT mount entries

---

### Step 3.2: Map FAT Data into Guest Memory (Linux Only)

**Status:** ⬜ Not Started

**Goal:** Map FAT image data into guest address space using MAP_SHARED mmap.

**Files to modify:**
- `src/hyperlight_host/src/sandbox/uninitialized_evolve.rs`
- `src/hyperlight_host/src/sandbox/initialized_multi_use.rs` (extend `map_region` for WRITE)
- `src/hyperlight_host/src/hypervisor/hyperlight_vm.rs`
- `src/hyperlight_host/src/mem/layout.rs` (if needed)
- `src/hyperlight_host/src/sandbox/mod.rs` (add msync on HLT)

**Changes:**

1. **Enable writable mappings in `map_region`:**
   - Remove the TODO check that rejects `MemoryRegionFlags::WRITE`
   - Handle snapshot/restore implications (or disable snapshot for RW regions)

2. **Map FAT images:**
   - Use `mmap(MAP_SHARED)` on the backing file (already done in FatImage)
   - Map into guest via hypervisor's `map_memory` with RW flags
   - Set guest_address in manifest for each FAT mount

3. **Platform check:**
   - Return `FsError::PlatformNotSupported` on Windows/WHP
   - Only proceed on Linux (KVM/MSHV)

**Memory layout:**
```
[Manifest] [RO Files (PROT_READ)...] [FAT Image 1 (RW)] [FAT Image 2 (RW)] ...
                                      ^                  ^
                                      MAP_SHARED mmap    MAP_SHARED mmap
                                      (writes persist)   (writes persist)
```

**Hypervisor-specific handling:**
- **KVM**: Use `kvm_userspace_memory_region` with flags=0 (not KVM_MEM_READONLY)
- **MSHV**: Use `mshv_user_mem_region` with `MSHV_SET_MEM_BIT_WRITABLE`
- **WHP**: Return error (TODO)

**msync on HLT (Spec §3.5):**

When the sandbox halts (HLT), automatically sync dirty FAT pages to disk:

```rust
// In sandbox halt/exit path
impl Sandbox {
    fn on_halt(&mut self) -> Result<()> {
        // Only if we have RW FAT mounts
        if let Some(ref fs_image) = self.hyperlight_fs {
            if fs_image.has_rw_fat_mounts() {
                // msync each dirty FAT region
                for fat_region in fs_image.fat_regions() {
                    if fat_region.is_dirty() {
                        // SAFETY: region is valid mmap'd memory
                        unsafe {
                            libc::msync(
                                fat_region.ptr() as *mut libc::c_void,
                                fat_region.len(),
                                libc::MS_SYNC  // Synchronous - blocks until complete
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
```

**Dirty tracking:**
- Track dirty state per FAT region in `FatImage`
- Set dirty on first map with WRITE (conservative) OR
- Use `/proc/self/pagemap` to check dirty bits (complex, future optimization)
- Initially: assume dirty if mapped RW

**Acceptance criteria:**
- [ ] FAT regions mapped with RW permissions
- [ ] Addresses correct in manifest
- [ ] Page-aligned regions
- [ ] Guest can read/write FAT data
- [ ] Writes persist to backing file
- [ ] Returns PlatformNotSupported on Windows
- [ ] msync() called on HLT for dirty RW FAT regions
- [ ] msync() NOT called if no RW FAT mounts (no overhead for RO-only)

---

### Step 3.3: Guest FAT Mount Initialization

**Status:** ⬜ Not Started

**Goal:** Initialize FAT filesystems in guest during startup.

**Files to modify:**
- `src/hyperlight_guest/src/fs/manifest.rs`
- `src/hyperlight_guest_bin/src/guest_entry.rs` (if initialization needed)

**Changes:**
- After parsing manifest, initialize FAT mounts
- Create block devices pointing to mapped regions
- Initialize fatfs::FileSystem for each

**Acceptance criteria:**
- [ ] FAT mounts initialized during fs::init()
- [ ] VFS populated with FAT backends
- [ ] Files in FAT mounts accessible

---

### Step 3.4: Guest-Created FAT Mounts

**Status:** ⬜ Not Started

**Goal:** Allow guests to create new FAT filesystems dynamically.

**Files to modify:**
- `src/hyperlight_guest/src/fs/mod.rs`
- `src/hyperlight_guest/src/fs/vfs.rs`

**Functions to add:**
```rust
/// Create a new FAT filesystem in guest memory.
pub fn create_fat_mount(mount_point: &str, size_bytes: usize) -> Result<(), FsError>;

/// Unmount a guest-created FAT filesystem.
pub fn unmount(mount_point: &str) -> Result<(), FsError>;
```

**Implementation:**
- Allocate memory from guest heap
- Format as FAT32 using fatfs
- Add to VFS mount table
- Track as "guest-created" for unmount validation

**Acceptance criteria:**
- [ ] create_fat_mount() allocates and formats
- [ ] New mount appears in VFS
- [ ] Files can be created in new mount
- [ ] unmount() works for guest-created mounts
- [ ] unmount() fails for host-provided mounts

---

## Phase 4: C API Implementation

Implement libc-compatible C API.

### Step 4.1: Core File Operations

**Status:** ⬜ Not Started

**Goal:** Implement open, close, read, write, lseek.

**Files to modify:**
- `src/hyperlight_guest_capi/src/fs.rs`
- `src/hyperlight_guest_capi/cbindgen.toml`

**Functions to implement:**
```rust
#[no_mangle]
pub extern "C" fn open(path: *const c_char, flags: c_int) -> c_int;

#[no_mangle]
pub extern "C" fn open(path: *const c_char, flags: c_int, mode: mode_t) -> c_int;

#[no_mangle]
pub extern "C" fn close(fd: c_int) -> c_int;

#[no_mangle]
pub extern "C" fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t;

#[no_mangle]
pub extern "C" fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;

#[no_mangle]
pub extern "C" fn lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t;
```

**Existing functions to update:**
- `hl_fs_open` → add write mode support
- Add `hl_fs_write` function

**Acceptance criteria:**
- [ ] All flags handled (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND, O_EXCL)
- [ ] mode parameter accepted (ignored)
- [ ] Correct error return codes
- [ ] C guest can read/write files

---

### Step 4.2: Directory Operations

**Status:** ⬜ Not Started

**Goal:** Implement opendir, readdir, closedir, mkdir, rmdir.

**Files to modify:**
- `src/hyperlight_guest_capi/src/fs.rs`

**Types to add:**
```rust
/// Opaque directory stream handle.
pub struct hl_DIR {
    entries: Vec<DirEntry>,
    position: usize,
}

/// Directory entry.
#[repr(C)]
pub struct hl_dirent_t {
    d_ino: u64,
    d_type: u8,
    d_name: [c_char; 256],
}
```

**Functions to implement:**
```rust
#[no_mangle]
pub extern "C" fn opendir(path: *const c_char) -> *mut hl_DIR;

#[no_mangle]
pub extern "C" fn readdir(dirp: *mut hl_DIR) -> *mut hl_dirent_t;

#[no_mangle]
pub extern "C" fn closedir(dirp: *mut hl_DIR) -> c_int;

#[no_mangle]
pub extern "C" fn mkdir(path: *const c_char, mode: mode_t) -> c_int;

#[no_mangle]
pub extern "C" fn rmdir(path: *const c_char) -> c_int;
```

**Acceptance criteria:**
- [ ] opendir/readdir/closedir work
- [ ] d_type set correctly (DT_REG, DT_DIR)
- [ ] mkdir creates directories in FAT mounts
- [ ] rmdir removes empty directories
- [ ] Error codes correct

---

### Step 4.3: Stat and Working Directory

**Status:** ⬜ Not Started

**Goal:** Implement stat, fstat, getcwd, chdir.

**Files to modify:**
- `src/hyperlight_guest_capi/src/fs.rs`

**Types to update:**
```rust
#[repr(C)]
pub struct hl_stat_t {
    st_size: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_atime: u64,
    st_mtime: u64,
    st_ctime: u64,
    _reserved: [u64; 4],
}
```

**Functions to implement:**
```rust
#[no_mangle]
pub extern "C" fn stat(path: *const c_char, statbuf: *mut hl_stat_t) -> c_int;

#[no_mangle]
pub extern "C" fn fstat(fd: c_int, statbuf: *mut hl_stat_t) -> c_int;

#[no_mangle]
pub extern "C" fn getcwd(buf: *mut c_char, size: size_t) -> *mut c_char;

#[no_mangle]
pub extern "C" fn chdir(path: *const c_char) -> c_int;
```

**st_mode values:**
- `S_IFREG | 0644` = `0100644` for files
- `S_IFDIR | 0755` = `0040755` for directories

**Acceptance criteria:**
- [ ] stat() returns correct metadata
- [ ] fstat() works on open fds
- [ ] st_mode set correctly
- [ ] getcwd() returns current directory
- [ ] chdir() changes directory

---

### Step 4.4: Advanced Operations

**Status:** ⬜ Not Started

**Goal:** Implement openat, fcntl, unlink, rename.

**Files to modify:**
- `src/hyperlight_guest_capi/src/fs.rs`

**Functions to implement:**
```rust
#[no_mangle]
pub extern "C" fn openat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;

#[no_mangle]
pub extern "C" fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;

#[no_mangle]
pub extern "C" fn unlink(path: *const c_char) -> c_int;

#[no_mangle]
pub extern "C" fn rename(oldpath: *const c_char, newpath: *const c_char) -> c_int;
```

**fcntl commands to support:**
- `F_DUPFD` - duplicate fd (return new fd with same file)
- `F_GETFD` - return 0 (no FD_CLOEXEC in guest)
- `F_SETFD` - accept but ignore
- `F_GETFL` - return open flags
- `F_SETFL` - accept but may ignore most flags

**openat behavior:**
- `AT_FDCWD` (-100) uses cwd
- Directory fd opens relative to that directory

**Acceptance criteria:**
- [ ] openat with AT_FDCWD works
- [ ] openat with directory fd works
- [ ] fcntl F_DUPFD duplicates fd
- [ ] fcntl F_GETFL returns flags
- [ ] unlink deletes files
- [ ] rename moves files/directories

---

## Phase 5: Host Extraction APIs

APIs for host to extract data after sandbox execution.

### Step 5.1: Sandbox File Access APIs

**Status:** ⬜ Not Started

**Goal:** Allow host to read/write files while sandbox is paused.

**Files to modify:**
- `src/hyperlight_host/src/sandbox/mod.rs` or appropriate sandbox file

**Methods to add:**
```rust
impl Sandbox {
    /// Read a file from the guest filesystem (VM must be paused).
    pub fn fs_read_file(&self, guest_path: &str) -> Result<Vec<u8>>;
    
    /// Write a file to a FAT mount (VM must be paused).
    pub fn fs_write_file(&self, guest_path: &str, data: &[u8]) -> Result<()>;
    
    /// Get file metadata.
    pub fn fs_stat(&self, guest_path: &str) -> Result<FileStat>;
    
    /// List directory contents.
    pub fn fs_read_dir(&self, guest_path: &str) -> Result<Vec<DirEntry>>;
}
```

**Implementation:**
- Check sandbox state (must be paused or finished)
- Parse manifest to find file/mount
- For RO files: read directly from mmap
- For FAT files: create temporary fatfs over guest memory region

**Acceptance criteria:**
- [ ] Read works for RO files
- [ ] Read works for FAT files
- [ ] Write works for FAT files
- [ ] Write fails for RO files
- [ ] Error if VM is running

---

### Step 5.2: FAT Image Extraction

**Status:** ⬜ Not Started

**Goal:** Allow host to extract entire FAT images after execution.

**Files to modify:**
- `src/hyperlight_host/src/sandbox/mod.rs`

**Methods to add:**
```rust
impl Sandbox {
    /// Get raw FAT image data for a mount point.
    pub fn get_fat_image_data(&self, mount_point: &str) -> Result<Vec<u8>>;
    
    /// Save FAT image to a host file.
    pub fn save_fat_image<P: AsRef<Path>>(
        &self,
        mount_point: &str,
        host_path: P
    ) -> Result<()>;
}
```

**Implementation:**
- Look up mount point in manifest
- Copy guest memory region containing FAT image
- Write to file

**Acceptance criteria:**
- [ ] get_fat_image_data returns valid FAT image
- [ ] save_fat_image writes to file
- [ ] Extracted image contains guest modifications
- [ ] Works for host-provided and guest-created mounts

---

### Step 5.3: Selective File/Directory Extraction

**Status:** ⬜ Not Started

**Goal:** Allow extracting specific files or directories from FAT mounts.

**Files to modify:**
- `src/hyperlight_host/src/sandbox/mod.rs`

**Methods to add:**
```rust
impl Sandbox {
    /// Save a specific file from FAT mount to host.
    pub fn save_guest_file<P: AsRef<Path>>(
        &self,
        guest_path: &str,
        host_path: P
    ) -> Result<()>;
    
    /// Save a directory tree from FAT mount to host.
    pub fn save_guest_dir<P: AsRef<Path>>(
        &self,
        guest_path: &str,
        host_path: P
    ) -> Result<()>;
}
```

**Implementation:**
- Read file via FAT
- Write to host filesystem
- For directories: recursive copy

**Acceptance criteria:**
- [ ] Single files extracted correctly
- [ ] Directories extracted recursively
- [ ] Preserves directory structure
- [ ] Handles nested directories

---

## Phase 6: Testing & Documentation

### Step 6.1: Integration Tests

**Status:** ⬜ Not Started

**Goal:** Comprehensive integration tests for all features.

**Files to create:**
- Test functions in `src/hyperlight_host/src/sandbox/uninitialized_evolve.rs`
- Test guest code in `tests/rust_guests/`

**Tests to add:**

1. **Basic FAT mount test**
   - Create sandbox with FAT mount
   - Guest reads/writes files
   - Host extracts results

2. **Mixed RO and FAT test**
   - Sandbox with RO files and FAT mounts
   - Guest accesses both
   - Verify isolation

3. **Guest-created mount test**
   - Guest creates FAT mount at runtime
   - Guest writes files
   - Host extracts

4. **C guest test**
   - C guest uses all libc functions
   - Verify compatibility

5. **Large file test**
   - Files near FAT32 limit
   - Many small files
   - Deep directory nesting

**Acceptance criteria:**
- [ ] All integration tests pass
- [ ] Tests work with both Rust and C guests
- [ ] Tests cover error conditions

---

### Step 6.2: C Guest Test Code

**Status:** ⬜ Not Started

**Goal:** C test guest for validating C API.

**Files to create/modify:**
- `tests/c_guests/simpleguest/main.c` (add FS test functions)
- Or create new `tests/c_guests/fsguest/`

**Functions to add:**
```c
// Test all file operations
int TestFatReadWrite(const char *path);
int TestFatDir(const char *dir_path);
int TestFatStat(const char *path);
int TestChdir(const char *path);
int TestOpenat(int dirfd, const char *path);
```

**Acceptance criteria:**
- [ ] C guest builds
- [ ] All C APIs exercised
- [ ] Tests callable from host

---

### Step 6.3: Update Documentation

**Status:** ⬜ Not Started

**Goal:** Update all documentation for FAT support.

**Files to modify:**
- `docs/hyperlight-fs.md` - main user documentation
- `docs/hyperlight-fs-fat-spec.md` - already created, may need updates
- Code comments throughout

**Documentation updates:**
- Add FAT mount section to user guide
- Update API reference
- Add examples for common use cases
- Document limitations
- Update TOML config format

**Acceptance criteria:**
- [ ] User guide covers FAT mounts
- [ ] API reference complete
- [ ] Examples compile and work
- [ ] Limitations documented

---

### Step 6.4: Validation Tool Update

**Status:** ⬜ Not Started

**Goal:** Update hyperlight_fs_validate for FAT configuration.

**Files to modify:**
- `src/hyperlight_host/examples/hyperlight_fs_validate.rs`

**Changes:**
- Parse `[[fat_image]]` and `[[fat_mount]]` sections
- Validate FAT images exist and are valid
- Report mount point conflicts
- Show FAT contents in verbose mode
- Check for exclusive lock conflicts

**Acceptance criteria:**
- [ ] Validates FAT image paths
- [ ] Reports invalid FAT images
- [ ] Shows mount conflicts
- [ ] Verbose mode lists FAT contents
- [ ] Reports locked files

---

## Appendix A: File Change Summary

### New Files

| File | Purpose |
|------|---------|
| `src/hyperlight_host/src/hyperlight_fs/fat_image.rs` | Host FAT image wrapper with mmap + exclusive lock |
| `src/hyperlight_guest/src/fs/fat_backend.rs` | Guest memory block device |
| `src/hyperlight_guest/src/fs/vfs.rs` | Guest VFS mount table |

### Modified Files

| File | Changes |
|------|---------|
| `src/hyperlight_host/Cargo.toml` | Add fatfs, fscommon, fs2, memmap2 deps |
| `src/hyperlight_host/src/hyperlight_fs/mod.rs` | Export fat_image module |
| `src/hyperlight_host/src/hyperlight_fs/builder.rs` | Add FAT mount methods with platform check |
| `src/hyperlight_host/src/hyperlight_fs/image.rs` | Include FAT images |
| `src/hyperlight_host/src/sandbox/initialized_multi_use.rs` | Enable WRITE flag in map_region |
| `src/hyperlight_guest/Cargo.toml` | Add fatfs dep |
| `src/hyperlight_guest/src/fs/mod.rs` | Add create_fat_mount, unified API |
| `src/hyperlight_guest/src/fs/manifest.rs` | Parse FAT mounts |
| `src/hyperlight_guest/src/fs/file.rs` | Dual backend support |
| `src/hyperlight_guest_capi/src/fs.rs` | All new C functions |
| `src/hyperlight_guest_capi/cbindgen.toml` | New macro definitions |
| `src/schema/hyperlight_fs.fbs` | FatMount inode type |
| `src/hyperlight_common/src/flatbuffer_wrappers/hyperlight_fs.rs` | FatMount support |
| `src/hyperlight_host/src/sandbox/uninitialized_evolve.rs` | Map FAT data with RW |
| `docs/hyperlight-fs.md` | User documentation |

---

## Appendix B: Implementation Risks

Risks specific to implementation that may require investigation or workarounds:

| Risk | Impact | Mitigation |
|------|--------|------------|
| fatfs no_std compatibility | High | Test early in Phase 2.1; may need fork or patches |
| fatfs `core_io` requires nightly | Medium | Verify with hyperlight's toolchain before starting |
| Snapshot/restore with RW regions | High | May need to disable snapshot for FAT mounts; investigate in Phase 3 |

For design limitations and constraints, see **Spec §13**.

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| GPA | Guest Physical Address |
| VFS | Virtual file system (abstraction layer in guest) |
| HLT | x86 halt instruction; triggers VM exit |

For complete glossary, see **Spec Appendix**.

---

## Appendix D: Deferred Items

Items intentionally deferred from initial implementation. Review before considering the feature complete.

| Item | Spec Reference | Reason Deferred | Review Trigger |
|------|----------------|-----------------|----------------|
| `FsLimits` struct | §13.4 | No guest-side code yet to hit limits | Before Phase 2 (guest-side) |
| `with_limits()` builder method | §13.4 | YAGNI until limits are enforced | Before Phase 2 |
| `max_file_count` enforcement | §13.4 | Manifest size not a concern yet | When manifest exceeds ~1MB |
| `max_mount_count` enforcement | §13.4 | 64 mounts unlikely to be hit | When mount count > 10 |
| `max_path_length` enforcement | §13.4 | Stack allocation not yet an issue | Guest VFS implementation |
| `max_open_files` enforcement | §13.4 | Guest FD table not implemented | Guest file handle implementation |
| Shared locks (`LOCK_SH`) for RO files | §12 | Prevents FAT exclusive lock conflicts | When mixing RO + FAT on same files |

**When to revisit:** Before declaring Phase 2 complete, review this table and implement any items that become relevant.

---

*End of Plan*
