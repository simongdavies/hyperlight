# HyperlightFS Specification

## Document Status

| Version | Date | Author | Status |
|---------|------|--------|--------|
| 1.0 | 2026-01-19 | Hyperlight Team | Draft |

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [File System Types](#file-system-types)
   - [Data Persistence Guarantees](#35-data-persistence-guarantees)
4. [Host APIs](#host-apis)
5. [Guest APIs](#guest-apis)
6. [C API Reference](#c-api-reference)
7. [Mount Points and Namespace](#mount-points-and-namespace)
8. [Data Serialization](#data-serialization)
9. [Memory Layout](#memory-layout)
10. [Permissions and Metadata](#permissions-and-metadata)
11. [Error Handling](#error-handling)
12. [Security Considerations](#security-considerations)
13. [Limitations](#limitations)

---

## 1. Overview

HyperlightFS is the filesystem subsystem for Hyperlight sandboxes. It provides a unified interface for guests to access files through two distinct backing storage mechanisms:

### 1.1 Read-Only Memory-Mapped Files 

- **Zero-copy**: Host files are memory-mapped (`mmap`) directly into guest address space
- **Read-only**: Enforced at kernel level via `PROT_READ`
- **Demand-paged**: File pages loaded on-demand via page faults
- **Shareable**: Multiple sandboxes can share the same mappings via OS page cache

### 1.2 Read-Write FAT Filesystems

- **Mutable**: Full read/write access to files and directories
- **FAT32 format**: Industry-standard filesystem via `fatfs` crate
- **Zero-copy via MAP_SHARED**: Host file is mmap'd with `MAP_SHARED`, then the same physical pages are mapped into guest address space
- **Auto-persist**: Guest writes go to page cache → OS flushes to backing file asynchronously
- **Exclusive**: Each backing file locked to one sandbox at a time

### 1.3 Design Goals

1. **Unified guest API**: Same functions work for both RO and RW files
2. **Explicit mapping**: Nothing exposed unless explicitly configured
3. **Type safety**: Clear distinction between mutable and immutable content
4. **Minimal overhead**: Zero-copy for both RO and RW paths
5. **POSIX compatibility**: C API follows libc conventions

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              HOST PROCESS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ HyperlightFSBuilder                                                   │   │
│  │   ├── add_file("/host/config.json", "/config.json")     [RO mmap]    │   │
│  │   ├── add_dir("/host/assets", "/assets")                [RO mmap]    │   │
│  │   ├── add_fat_image("/host/data.fat", "/data")          [RW FAT]     │   │
│  │   ├── add_empty_fat_mount("/tmp", 1MB)                  [RW FAT]     │   │
│  │   ├── add_empty_fat_mount_at("out.fat", "/out", 1MB)    [RW FAT]     │   │
│  │   └── build() → HyperlightFSImage                                    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ HyperlightFSImage                                                     │   │
│  │   ├── Manifest (FlatBuffer serialized metadata)                      │   │
│  │   ├── RO file mappings (mmap PROT_READ pointers + metadata)          │   │
│  │   ├── FAT image mappings (mmap MAP_SHARED, exclusive lock)           │   │
│  │   └── Host file access APIs (read/write/list)                        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Sandbox                                                               │   │
│  │   ├── Guest memory with FS regions mapped                            │   │
│  │   ├── File access APIs (read/write during pause)                     │   │
│  │   └── Extraction APIs (get FAT data after execution)                 │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                              GUEST VM                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Guest Memory Layout                                                   │   │
│  │   ├── Manifest region (FlatBuffer with file/mount metadata)          │   │
│  │   ├── RO files region (demand-paged from host mmap)                  │   │
│  │   ├── Host FAT regions (MAP_SHARED from host backing file)           │   │
│  │   └── Guest FAT regions (allocated from guest heap via create_fat_mount)│
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Unified VFS Layer (hyperlight_guest::fs)                             │   │
│  │   ├── Mount table (mount_point → backend)                            │   │
│  │   ├── File descriptor table                                          │   │
│  │   ├── Current working directory                                      │   │
│  │   └── Path resolution (longest-prefix mount matching)                │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────┐     ┌─────────────────────────────────────────┐   │
│  │ RO Backend          │     │ FAT Backend                              │   │
│  │   └── Direct memory │     │   └── fatfs crate over memory buffer    │   │
│  │       read from     │     │       with Read/Write/Seek              │   │
│  │       mapped region │     │                                         │   │
│  └─────────────────────┘     └─────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 How FAT RW Mounting Works (MAP_SHARED Flow)

The key aspect of this design is that **the same physical memory pages** are shared between the host process and guest VM. Here's the complete flow:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 1: Builder opens/creates backing file                                   │
│                                                                              │
│   For add_fat_image("/host/data.fat", "/data"):                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. Open existing file: /host/data.fat                               │   │
│   │ 2. Validate FAT32 format                                            │   │
│   │ 3. Acquire exclusive lock: flock(fd, LOCK_EX)                       │   │
│   │ 4. mmap(fd, MAP_SHARED, PROT_READ|PROT_WRITE) → host_ptr            │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   For add_empty_fat_mount("/tmp", 1MB):                                     │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. Create temp file: /tmp/hyperlight-fat-{sandbox_id}-{random} (1MB)│   │
│   │ 2. Format as FAT32 using fatfs crate                                │   │
│   │ 3. Acquire exclusive lock: flock(fd, LOCK_EX)                       │   │
│   │ 4. mmap(fd, MAP_SHARED, PROT_READ|PROT_WRITE) → host_ptr            │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Result: host_ptr points to pages backed by the file                       │
│   The OS kernel manages the mapping: file ↔ page cache ↔ host_ptr          │
├─────────────────────────────────────────────────────────────────────────────┤
│ STEP 2: Sandbox evolution maps into guest                                    │
│                                                                              │
│   sandbox.evolve()                                                          │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. Choose guest physical address (GPA) for FAT region               │   │
│   │ 2. Tell hypervisor to map host_ptr → GPA with RW permissions:       │   │
│   │    • KVM:  kvm_userspace_memory_region { userspace_addr: host_ptr } │   │
│   │    • MSHV: mshv_user_mem_region { userspace_addr: host_ptr }        │   │
│   │ 3. Update manifest with guest_address = GPA                         │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Result: Guest sees FAT image at GPA, backed by SAME pages as host_ptr    │
├─────────────────────────────────────────────────────────────────────────────┤
│ STEP 3: Guest writes to FAT                                                  │
│                                                                              │
│   guest: open("/tmp/foo.txt", O_CREAT|O_WRONLY); write(fd, "hello", 5);    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. VFS resolves /tmp → FAT mount at GPA                             │   │
│   │ 2. fatfs computes target address within FAT image region            │   │
│   │ 3. Guest CPU executes store instruction to GPA                      │   │
│   │ 4. If page not present: #PF → hypervisor handles by mapping page    │   │
│   │ 5. Store completes → page marked dirty in host page cache           │   │
│   │ 6. Kernel writeback daemon eventually flushes to backing file       │   │
│   │    (or immediately on msync/HLT - see §3.5)                         │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Result: Write goes to shared page → persists to backing file              │
├─────────────────────────────────────────────────────────────────────────────┤
│ STEP 4: Cleanup on drop                                                      │
│                                                                              │
│   drop(HyperlightFSImage)                                                   │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. munmap(host_ptr) - unmap from host                               │   │
│   │ 2. Hypervisor unmaps from guest (sandbox already dropped)           │   │
│   │ 3. close(fd) - releases exclusive lock                              │   │
│   │ 4. For temp files: unlink() deletes the file                        │   │
│   │    For add_empty_fat_mount_at(): file PERSISTS on disk              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Why this is zero-copy:**
- No `memcpy()` between host and guest
- Guest CPU writes directly to pages that are also mapped into host process
- Same physical RAM, two virtual address mappings (host + guest)

**Why exclusive locking:**
- Two sandboxes writing to same backing file = data corruption
- `flock(LOCK_EX)` ensures one sandbox per file
- Lock released on drop, then another sandbox can use the file

---

## 3. File System Types

### 3.1 Read-Only Memory-Mapped (RO)

| Property | Value |
|----------|-------|
| Backing | Host file via `mmap(PROT_READ)` |
| Access | Read-only |
| Consistency | Static snapshot at build time |
| Sharing | Shared across sandboxes via page cache |
| Performance | Zero-copy, demand-paged |
| Locking | Shared lock (`flock(LOCK_SH)`) blocks external writers |
| Platform | Linux (KVM/MSHV) initially; Windows (WHP) is TODO |

**Use cases:**
- Configuration files
- Static assets (images, templates)
- Model weights / large data files
- Shared libraries

### 3.2 FAT Filesystem (RW)

| Property | Value |
|----------|-------|
| Backing | Host file mmap'd with `MAP_SHARED` (writes persist automatically) |
| Access | Read-write |
| Format | FAT32 (via `fatfs` crate) |
| Source | Host file, programmatic creation, or guest allocation |
| Size | Fixed at creation time (cannot grow) |
| Exclusivity | Each backing file can only be mapped to one sandbox at a time |
| Platform | Linux (KVM/MSHV) initially; Windows (WHP) is TODO |

**Use cases:**
- Temporary files
- Output data
- Caches
- Writable configuration

### 3.3 Comparison

| Feature | RO (mmap) | RW (FAT) |
|---------|-----------|----------|
| Read | ✅ | ✅ |
| Write | ❌ | ✅ |
| Create file | ❌ | ✅ |
| Delete file | ❌ | ✅ |
| Create directory | ❌ | ✅ |
| Zero-copy | ✅ | ✅ (via MAP_SHARED) |
| Auto-persist | N/A | ✅ (writes go to host file) |
| Guest creation | ❌ | ✅ |
| Multi-sandbox | ✅ (shared) | ❌ (exclusive) |
| Max file size | uint64 (no practical limit) | ~4GB (FAT32 limit) |
| Guest memory used | None (zero-copy) | None for host FAT; heap for guest-created |

### 3.4 Future Enhancement: Read-Only FAT Mounts

A future version will support mounting FAT images as **read-only**. This would:
- Use `mmap(MAP_SHARED, PROT_READ)` for zero-copy RO access
- Allow sharing across sandboxes via shared lock (`flock(LOCK_SH)`)
- Shared lock allows multiple readers, blocks external writers
- Provide directory structure and metadata that RO mmap files lack
- Enable mounting pre-built data archives in FAT format

### 3.5 Data Persistence Guarantees

When using `MAP_SHARED` for FAT mounts, writes made by the guest are written to the kernel's page cache. The kernel asynchronously flushes dirty pages to the backing file. This has important implications:

**Normal operation:**
- Guest writes → page cache → kernel writeback → backing file
- Typical writeback latency: seconds (controlled by `vm.dirty_writeback_centisecs`)
- Normal process termination flushes all dirty pages

**Crash scenarios:**
- If the host process crashes, some recent writes may not have reached disk
- If the host machine loses power, recent writes may be lost

**Hyperlight's guarantee:**

When a sandbox with RW FAT mounts halts (HLT), the host automatically calls `msync(MS_SYNC)` on all dirty FAT regions before returning control to the caller. This ensures:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Sandbox Halt Sequence                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Guest executes HLT instruction                                          │
│  2. VM exits to host                                                        │
│  3. Host checks: has_rw_fat_mounts && dirty_pages?                          │
│  4. If yes: msync(fat_region, MS_SYNC) for each FAT mount                   │
│  5. Return to caller                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

**What this means for users:**
- When `sandbox.call()` returns normally, all FAT writes are durably persisted to disk
- No need for explicit `fsync()` or `msync()` in user code
- Safe to read the backing file immediately after sandbox execution

**Data loss warning:**
- If the sandbox terminates abnormally (e.g., guest crash, timeout, host error), `msync()` is NOT called
- In these cases, recent writes may be lost or the FAT image may be in an inconsistent state
- This is intentional: we do not want to persist potentially corrupted data from a failed execution
- Users should treat the FAT image as potentially invalid after any error

**Implementation notes:**
- `msync()` is only called if `has_rw_fat_mounts` is true (no overhead for RO-only)
- The host tracks dirty state per FAT region (set on first guest write via dirty bit)
- `MS_SYNC` ensures synchronous flush (blocks until I/O complete)
- This is a host-side operation; guests cannot call `msync()`

**Performance consideration:**
- `msync()` can be slow for large dirty regions
- For latency-sensitive use cases, consider smaller FAT images
- The `MS_ASYNC` variant (non-blocking) may be offered as an opt-in in future

---

## 4. Host APIs

### 4.1 HyperlightFSBuilder

Builder for constructing a filesystem image before sandbox creation.

```rust
/// Resource limits for filesystem operations.
/// 
/// These limits only apply to resources that consume guest memory or
/// have fixed overhead. Host-provided files and FAT images use zero-copy
/// MAP_SHARED and have no size limits.
pub struct FsLimits {
    /// Max number of files/directories in manifest (default: 100,000)
    /// 
    /// Each entry adds ~100 bytes to the serialized manifest.
    pub max_file_count: usize,
    
    /// Max number of mount points (default: 64)
    pub max_mount_count: usize,
    
    /// Max path length in bytes (default: 4096)
    pub max_path_length: usize,
    
    /// Max open file descriptors per guest (default: 256)
    pub max_open_files: usize,
}

impl Default for FsLimits {
    fn default() -> Self {
        Self {
            max_file_count: 100_000,
            max_mount_count: 64,
            max_path_length: 4096,
            max_open_files: 256,
        }
    }
}

impl HyperlightFSBuilder {
    /// Create a new empty builder with default limits.
    pub fn new() -> Self;
    
    /// Create a new builder with custom resource limits.
    /// 
    /// Note: Size limits are NOT needed for host-provided files or FAT images
    /// since they use zero-copy MAP_SHARED and don't consume guest memory.
    /// Limits only apply to metadata overhead and runtime resources.
    pub fn with_limits(limits: FsLimits) -> Self;
    
    /// Add a single read-only file (mmap'd from host).
    /// 
    /// # Arguments
    /// * `host_path` - Absolute path on host filesystem
    /// * `guest_path` - Path where file appears in guest
    /// 
    /// # Errors
    /// * Host path doesn't exist or is not a regular file
    /// * Guest path conflicts with existing mapping or mount
    /// * Guest path is under a FAT mount point
    pub fn add_file<P: AsRef<Path>>(
        self, 
        host_path: P, 
        guest_path: &str
    ) -> Result<Self>;
    
    /// Add a directory of read-only files with pattern matching.
    /// 
    /// Returns a `DirectoryBuilder` that allows configuring include/exclude
    /// patterns before finalizing with `.done()`.
    pub fn add_dir<P: AsRef<Path>>(
        self,
        host_path: P,
        guest_prefix: &str
    ) -> Result<DirectoryBuilder>;
}

/// Builder for configuring directory mappings with glob patterns.
pub struct DirectoryBuilder {
    // ... internal fields
}

impl DirectoryBuilder {
    /// Include files matching a glob pattern.
    /// 
    /// Patterns use gitignore-style syntax:
    /// - `**/*.json` - all JSON files recursively
    /// - `*.txt` - text files in root only
    /// - `data/**` - everything under data/
    pub fn include(self, pattern: &str) -> Self;
    
    /// Exclude files matching a glob pattern.
    /// 
    /// Exclusions are applied after inclusions.
    /// - `**/secret/*` - exclude secret directories
    /// - `**/.git/**` - exclude .git folders
    pub fn exclude(self, pattern: &str) -> Self;
    
    /// Finalize the directory mapping and return to the parent builder.
    pub fn done(self) -> Result<HyperlightFSBuilder>;
}

impl HyperlightFSBuilder {
    /// Mount a FAT image from a host file.
    /// 
    /// The file is mmap'd with `MAP_SHARED` so writes persist automatically.
    /// An exclusive lock is acquired on the file - attempting to map the same
    /// file into another sandbox will fail until this sandbox releases it.
    /// 
    /// # Arguments
    /// * `host_path` - Path to FAT image file on host
    /// * `mount_point` - Directory path in guest namespace
    /// 
    /// # Errors
    /// * Host path doesn't exist or is not a valid FAT image
    /// * Mount point conflicts with existing mapping or mount
    /// * File is already mapped into another sandbox (exclusive lock held)
    /// * Platform not supported (Windows/WHP - TODO)
    pub fn add_fat_image<P: AsRef<Path>>(
        self,
        host_path: P,
        mount_point: &str
    ) -> Result<Self>;
    
    /// Create an empty FAT filesystem at a mount point.
    /// 
    /// Creates a temporary host file of the specified size and formats it as FAT32.
    /// The file is mmap'd with `MAP_SHARED` so writes persist automatically.
    /// This provides consistency with `add_fat_image()` - both methods create a
    /// backing host file. The temp file is deleted when the HyperlightFSImage is dropped.
    /// 
    /// The size is fixed at creation time. If the guest fills the filesystem,
    /// subsequent writes will fail with ENOSPC. Consider using sparse files on
    /// the host for efficient storage when the full size may not be used.
    /// 
    /// # Arguments
    /// * `mount_point` - Directory path in guest namespace  
    /// * `size_bytes` - Size of the filesystem (rounded up to sector boundary)
    /// 
    /// # Errors
    /// * Mount point conflicts with existing mapping or mount
    /// * Size is too small (minimum 1MB) or too large (maximum 16GB)
    /// * Failed to create temp file
    /// * Platform not supported (Windows/WHP - TODO)
    pub fn add_empty_fat_mount(
        self,
        mount_point: &str,
        size_bytes: usize
    ) -> Result<Self>;
    
    /// Create an empty FAT filesystem at a mount point, backed by a specified host file.
    /// 
    /// Similar to `add_empty_fat_mount()`, but the backing file is created at the
    /// specified host path and **persists after the HyperlightFSImage is dropped**.
    /// The file is mmap'd with `MAP_SHARED` so writes persist automatically.
    /// This is useful for debugging, inspection, or reusing images across runs.
    /// 
    /// The file is created (or truncated if it exists) and formatted as FAT32.
    /// An exclusive lock is acquired - same file cannot be used by another sandbox.
    /// 
    /// # Arguments
    /// * `host_path` - Path where backing file will be created on host
    /// * `mount_point` - Directory path in guest namespace  
    /// * `size_bytes` - Size of the filesystem (rounded up to sector boundary)
    /// 
    /// # Errors
    /// * Mount point conflicts with existing mapping or mount
    /// * Size is too small (minimum 1MB) or too large (maximum 16GB)
    /// * Failed to create file at host_path
    /// * File already in use by another sandbox (exclusive lock)
    /// * Platform not supported (Windows/WHP - TODO)
    pub fn add_empty_fat_mount_at<P: AsRef<Path>>(
        self,
        host_path: P,
        mount_point: &str,
        size_bytes: usize
    ) -> Result<Self>;
    
    /// Preview what would be built without creating mappings.
    pub fn list(&self) -> Result<BuildManifest>;
    
    /// Build the filesystem image.
    pub fn build(self) -> Result<HyperlightFSImage>;
    
    /// Build from TOML configuration.
    pub fn from_toml(toml: &str) -> Result<Self>;
    
    /// Build from TOML configuration file.
    pub fn from_config(config: &HyperlightFsConfig) -> Result<Self>;
}
```

### 4.2 HyperlightFSImage

Represents a built filesystem image with file access APIs.

```rust
impl HyperlightFSImage {
    // === Metadata ===
    
    /// Get total size of all mapped regions.
    pub fn total_size(&self) -> usize;
    
    /// List all mount points.
    pub fn list_mounts(&self) -> Vec<MountInfo>;
    
    /// List all file mappings (RO files and FAT mount contents).
    pub fn list_files(&self) -> Vec<FileInfo>;
    
    // === FAT Image Access (before sandbox) ===
    
    /// Read a file from a FAT mount.
    /// 
    /// # Errors
    /// * Path is not under a FAT mount
    /// * Path not found
    /// * Path is a directory
    pub fn read_file(&self, guest_path: &str) -> Result<Vec<u8>>;
    
    /// Write a file to a FAT mount.
    /// 
    /// # Errors
    /// * Path is not under a FAT mount (RO files cannot be modified)
    /// * Parent directory doesn't exist
    /// * Filesystem is full
    pub fn write_file(&self, guest_path: &str, data: &[u8]) -> Result<()>;
    
    /// Delete a file from a FAT mount.
    pub fn delete_file(&self, guest_path: &str) -> Result<()>;
    
    /// Create a directory in a FAT mount.
    pub fn create_dir(&self, guest_path: &str) -> Result<()>;
    
    /// Delete an empty directory from a FAT mount.
    pub fn delete_dir(&self, guest_path: &str) -> Result<()>;
    
    /// Get file/directory metadata.
    /// 
    /// Works for both RO files and FAT files.
    pub fn stat(&self, guest_path: &str) -> Result<FileStat>;
    
    /// List directory contents.
    /// 
    /// Works for both RO directories and FAT directories.
    pub fn read_dir(&self, guest_path: &str) -> Result<Vec<DirEntry>>;
    
    // === FAT Image Extraction ===
    
    /// Get raw FAT image data for a mount point.
    pub fn get_fat_image_data(&self, mount_point: &str) -> Result<&[u8]>;
    
    /// Write FAT image to a file.
    pub fn save_fat_image<P: AsRef<Path>>(
        &self, 
        mount_point: &str, 
        path: P
    ) -> Result<()>;
}
```

### 4.3 Sandbox File Access

File access during sandbox lifecycle (when VM is paused).

```rust
impl Sandbox {
    // === During Execution (VM must be paused) ===
    
    /// Read a file from the guest filesystem.
    /// 
    /// # Errors
    /// * VM is running (not paused)
    /// * Path not found
    pub fn fs_read_file(&self, guest_path: &str) -> Result<Vec<u8>>;
    
    /// Write a file to a FAT mount in guest filesystem.
    /// 
    /// # Errors
    /// * VM is running (not paused)
    /// * Path is RO (not under FAT mount)
    pub fn fs_write_file(&self, guest_path: &str, data: &[u8]) -> Result<()>;
    
    /// Get file metadata.
    pub fn fs_stat(&self, guest_path: &str) -> Result<FileStat>;
    
    /// List directory contents.
    pub fn fs_read_dir(&self, guest_path: &str) -> Result<Vec<DirEntry>>;
    
    // === Post-Execution Extraction ===
    
    /// Get raw FAT image data for a mount point.
    /// 
    /// Returns the current state of the FAT filesystem including
    /// any modifications made by the guest.
    pub fn get_fat_image_data(&self, mount_point: &str) -> Result<Vec<u8>>;
    
    /// Save a specific file from FAT mount to host filesystem.
    pub fn save_guest_file<P: AsRef<Path>>(
        &self,
        guest_path: &str,
        host_path: P
    ) -> Result<()>;
    
    /// Save entire FAT image to host filesystem.
    pub fn save_fat_image<P: AsRef<Path>>(
        &self,
        mount_point: &str,
        host_path: P
    ) -> Result<()>;
    
    /// Save a directory tree from FAT mount to host filesystem.
    pub fn save_guest_dir<P: AsRef<Path>>(
        &self,
        guest_path: &str,
        host_path: P
    ) -> Result<()>;
}
```

### 4.4 Host Data Types

```rust
/// Information about a mount point.
pub struct MountInfo {
    /// Guest path where mounted (e.g., "/data")
    pub mount_point: String,
    /// Type of mount
    pub mount_type: MountType,
    /// Total size in bytes
    pub size: u64,
    /// Used space (FAT only, 0 for RO)
    pub used: u64,
}

pub enum MountType {
    /// Read-only memory-mapped files
    ReadOnly,
    /// Read-write FAT filesystem from host image
    FatFromHost,
    /// Read-write FAT filesystem created empty
    FatEmpty,
    /// Read-write FAT filesystem created by guest
    FatGuest,
}

/// File metadata.
pub struct FileStat {
    /// Size in bytes
    pub size: u64,
    /// Is this a directory?
    pub is_dir: bool,
    /// Is this read-only?
    pub is_readonly: bool,
    /// Creation time (FAT only)
    pub created: Option<DateTime>,
    /// Modification time (FAT only)
    pub modified: Option<DateTime>,
    /// Access time (FAT only)
    pub accessed: Option<DateTime>,
}

/// Directory entry.
pub struct DirEntry {
    /// Entry name (not full path)
    pub name: String,
    /// Is this a directory?
    pub is_dir: bool,
    /// Size in bytes (0 for directories)
    pub size: u64,
}
```

---

## 5. Guest APIs

### 5.1 Rust API (hyperlight_guest::fs)

```rust
// === Initialization ===

/// Check if filesystem is initialized.
pub fn is_initialized() -> bool;

/// Get current working directory.
pub fn getcwd() -> Result<String, FsError>;

/// Change current working directory.
pub fn chdir(path: &str) -> Result<(), FsError>;

// === File Operations ===

/// Open a file.
/// 
/// # Arguments
/// * `path` - Absolute or relative path
/// * `mode` - Open mode flags
pub fn open(path: &str, mode: OpenMode) -> Result<File, FsError>;

/// Create and open a new file (O_CREAT | O_WRONLY | O_TRUNC).
pub fn create(path: &str) -> Result<File, FsError>;

/// Get file metadata by path.
pub fn stat(path: &str) -> Result<Stat, FsError>;

/// Delete a file.
pub fn unlink(path: &str) -> Result<(), FsError>;

/// Rename/move a file or directory.
pub fn rename(old_path: &str, new_path: &str) -> Result<(), FsError>;

// === Directory Operations ===

/// Create a directory.
pub fn mkdir(path: &str) -> Result<(), FsError>;

/// Remove an empty directory.
pub fn rmdir(path: &str) -> Result<(), FsError>;

/// Read directory contents.
pub fn read_dir(path: &str) -> Result<Vec<DirEntry>, FsError>;

// === FAT Mount Creation (Guest) ===

/// Create a new FAT filesystem and mount it.
/// 
/// # Arguments
/// * `mount_point` - Where to mount (must not conflict)
/// * `size_bytes` - Size to allocate from guest heap
/// 
/// # Errors
/// * Insufficient memory
/// * Mount point already in use
/// * Size too small for FAT32
pub fn create_fat_mount(mount_point: &str, size_bytes: usize) -> Result<(), FsError>;

/// Unmount a guest-created FAT filesystem.
/// 
/// Only works for mounts created by this guest via create_fat_mount().
pub fn unmount(mount_point: &str) -> Result<(), FsError>;
```

### 5.2 File Handle

```rust
pub struct File {
    // ... internal fields
}

impl File {
    /// Get file descriptor number (for C interop).
    pub fn fd(&self) -> i32;
    
    /// Get current position.
    pub fn position(&self) -> Result<u64, FsError>;
    
    /// Get file size.
    pub fn size(&self) -> Result<u64, FsError>;
    
    /// Get remaining bytes from position to EOF.
    pub fn remaining(&self) -> Result<u64, FsError>;
    
    /// Read entire file into a Vec.
    pub fn read_to_vec(&mut self) -> Result<Vec<u8>, FsError>;
    
    /// Truncate file to current position (RW files only).
    pub fn truncate(&mut self) -> Result<(), FsError>;
    
    /// Sync data to underlying storage (RW files only).
    pub fn sync(&mut self) -> Result<(), FsError>;
    
    /// Get file metadata.
    pub fn stat(&self) -> Result<Stat, FsError>;
}

// Implements embedded_io traits
impl embedded_io::Read for File { ... }
impl embedded_io::Write for File { ... }  // RW files only
impl embedded_io::Seek for File { ... }
```

### 5.3 Open Modes

```rust
bitflags! {
    pub struct OpenMode: u32 {
        /// Open for reading.
        const READ = 0x01;
        /// Open for writing.
        const WRITE = 0x02;
        /// Create file if it doesn't exist.
        const CREATE = 0x04;
        /// Truncate file to zero length.
        const TRUNCATE = 0x08;
        /// Append to end of file.
        const APPEND = 0x10;
        /// Fail if file already exists (with CREATE).
        const EXCLUSIVE = 0x20;
        
        // Convenience combinations
        const READ_ONLY = Self::READ.bits();
        const WRITE_ONLY = Self::WRITE.bits();
        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();
        const CREATE_NEW = Self::WRITE.bits() | Self::CREATE.bits() | Self::EXCLUSIVE.bits();
    }
}
```

### 5.4 Guest Data Types

```rust
/// File metadata.
#[derive(Debug, Clone, Copy)]
pub struct Stat {
    /// Size in bytes.
    pub size: u64,
    /// Is this a directory?
    pub is_dir: bool,
    /// Is this read-only?
    pub is_readonly: bool,
    /// Permission mode (faked for FAT).
    pub mode: u32,
}

/// Directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name.
    pub name: String,
    /// Is this a directory?
    pub is_dir: bool,
    /// Size in bytes.
    pub size: u64,
}
```

---

## 6. C API Reference

### 6.1 Constants

```c
// Open flags
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_EXCL      0x0080
#define O_TRUNC     0x0200
#define O_APPEND    0x0400

// Seek whence
#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

// Directory entry types (for d_type)
#define DT_UNKNOWN  0
#define DT_REG      8   // Regular file
#define DT_DIR      4   // Directory

// fcntl commands
#define F_DUPFD     0
#define F_GETFD     1
#define F_SETFD     2
#define F_GETFL     3
#define F_SETFL     4

// AT_* constants for openat
#define AT_FDCWD    -100
```

### 6.2 Data Structures

```c
// File status (stat/fstat)
typedef struct {
    uint64_t st_size;       // File size in bytes
    uint32_t st_mode;       // File mode (S_IFREG, S_IFDIR, permissions)
    uint32_t st_nlink;      // Number of hard links (always 1)
    uint32_t st_uid;        // User ID (always 0)
    uint32_t st_gid;        // Group ID (always 0)
    uint64_t st_atime;      // Access time (Unix timestamp, FAT only)
    uint64_t st_mtime;      // Modification time (Unix timestamp, FAT only)
    uint64_t st_ctime;      // Creation time (Unix timestamp, FAT only)
    uint64_t _reserved[4];  // Reserved for future use
} hl_stat_t;

// Directory entry (readdir)
typedef struct {
    uint64_t d_ino;         // Inode number (synthetic)
    uint8_t  d_type;        // Entry type (DT_REG or DT_DIR)
    char     d_name[256];   // Entry name (null-terminated)
} hl_dirent_t;

// Directory stream (opaque)
typedef struct hl_DIR hl_DIR;
```

### 6.3 Functions

```c
// === File Operations ===

/// Open a file.
/// Returns file descriptor >= 0 on success, -1 on error.
int open(const char *path, int flags);
int open(const char *path, int flags, mode_t mode);  // mode ignored

/// Open relative to directory fd.
/// dirfd can be AT_FDCWD or a directory file descriptor.
int openat(int dirfd, const char *path, int flags);
int openat(int dirfd, const char *path, int flags, mode_t mode);

/// Close a file descriptor.
int close(int fd);

/// Read from file.
/// Returns bytes read, 0 at EOF, -1 on error.
ssize_t read(int fd, void *buf, size_t count);

/// Write to file.
/// Returns bytes written, -1 on error.
ssize_t write(int fd, const void *buf, size_t count);

/// Seek in file.
/// Returns new offset, -1 on error.
off_t lseek(int fd, off_t offset, int whence);

/// Get file status by fd.
int fstat(int fd, hl_stat_t *statbuf);

/// Get file status by path.
int stat(const char *path, hl_stat_t *statbuf);

/// File control operations.
int fcntl(int fd, int cmd, ...);

// === Directory Operations ===

/// Open a directory for reading.
hl_DIR *opendir(const char *path);

/// Read next directory entry.
/// Returns pointer to static dirent, NULL at end or on error.
hl_dirent_t *readdir(hl_DIR *dirp);

/// Close directory stream.
int closedir(hl_DIR *dirp);

/// Create a directory.
int mkdir(const char *path, mode_t mode);  // mode ignored

/// Remove an empty directory.
int rmdir(const char *path);

// === File Manipulation ===

/// Delete a file.
int unlink(const char *path);

/// Rename a file or directory.
int rename(const char *oldpath, const char *newpath);

// === Working Directory ===

/// Get current working directory.
/// Returns buf on success, NULL on error.
char *getcwd(char *buf, size_t size);

/// Change current working directory.
int chdir(const char *path);

// === HyperlightFS Extensions ===

/// Check if filesystem is initialized.
int hl_fs_initialized(void);

/// Create a new FAT mount from guest memory.
/// Returns 0 on success, -1 on error.
int hl_fs_create_mount(const char *mount_point, size_t size_bytes);

/// Unmount a guest-created FAT filesystem.
int hl_fs_unmount(const char *mount_point);
```

### 6.4 Error Handling

All C functions return negative values on error. The specific error is **not** set in a global `errno` variable (documented limitation). Instead, the following conventions apply:

| Return Value | Meaning |
|--------------|---------|
| `-1` | Generic error (ENOENT, EACCES, etc.) |
| `-2` | Not implemented (ENOTSUP) |
| `-3` | Read-only filesystem (EROFS) |
| `-4` | No space left (ENOSPC) |
| `-5` | File exists (EEXIST) |
| `-6` | Not a directory (ENOTDIR) |
| `-7` | Is a directory (EISDIR) |
| `-8` | Directory not empty (ENOTEMPTY) |
| `-9` | Invalid argument (EINVAL) |
| `-10` | Too many open files (EMFILE) |
| `-11` | Bad file descriptor (EBADF) |

**Future enhancement:** May add `hl_fs_errno()` function to retrieve last error code.

### 6.5 Unsupported Operations

The following operations return `-2` (ENOTSUP):

| Operation | Reason |
|-----------|--------|
| Symlink creation/reading | FAT32 doesn't support symlinks |
| Hard link creation | FAT32 doesn't support hard links |
| chmod/chown | FAT32 has no Unix permissions |
| mknod | No device files |
| File locking (fcntl F_SETLK) | Not implemented |

---

## 7. Mount Points and Namespace

### 7.1 Mount Point Rules

1. **Absolute paths only**: Mount points must be absolute (start with `/`)
2. **No `..` components**: Parent directory traversal not allowed in mount paths
3. **No overlapping mounts**: Cannot mount at paths that would overlap
4. **Root mount exclusivity**: If `/` is a mount point, no other mounts or files allowed

### 7.2 Conflict Detection

```
Scenario 1: Valid - Non-overlapping mounts
  Mount: /data (FAT)
  Mount: /tmp (FAT)
  File:  /config.json (RO)
  ✅ OK - no conflicts

Scenario 2: Invalid - Overlapping mounts
  Mount: /data (FAT)
  Mount: /data/cache (FAT)
  ❌ ERROR - /data/cache is under /data

Scenario 3: Invalid - File under mount
  Mount: /data (FAT)
  File:  /data/file.txt (RO)
  ❌ ERROR - /data/file.txt is under FAT mount /data

Scenario 4: Invalid - Mount under file's directory
  File:  /config/app.json (RO)
  Mount: /config (FAT)
  ❌ ERROR - Mount /config would hide RO file

Scenario 5: Valid - Root FAT mount (exclusive)
  Mount: / (FAT)
  ✅ OK - but no other mounts/files allowed

Scenario 6: Invalid - Root mount with other content
  Mount: / (FAT)
  File:  /config.json (RO)
  ❌ ERROR - Cannot have RO files with root FAT mount
```

### 7.3 Path Resolution

Guest path resolution uses **longest-prefix matching**:

```
Mounts:
  /data → FAT image A
  /data/cache → FAT image B

Resolution:
  /data/file.txt → FAT image A, path "file.txt"
  /data/cache/temp.dat → FAT image B, path "temp.dat"
  /config.json → RO file (no mount prefix matches)
```

### 7.4 Current Working Directory

- Initial cwd: `/`
- `chdir()` changes cwd for subsequent relative path resolution
- Relative paths resolved against cwd before mount matching
- cwd must exist and be a directory

---

## 8. Data Serialization

### 8.1 FlatBuffer Schema

```flatbuffers
namespace Hyperlight.Generated;

enum InodeType : ubyte {
    File = 0,        // RO memory-mapped file
    Directory = 1,   // RO directory (container)
    FatMount = 2,    // RW FAT filesystem mount
}

table Inode {
    inode_type: InodeType;
    path: string (required);
    parent: uint32;
    
    // For File: address and size of mmap'd data
    // For FatMount: address and size of FAT image data
    guest_address: uint64;
    size: uint64;
    
    // For FatMount: identifies the mount for extraction
    mount_id: uint32;
}

table HyperlightFS {
    version: uint16;       // Schema version (2 for FAT support)
    inodes: [Inode] (required);
}

root_type HyperlightFS;
```

### 8.2 Version History

| Version | Changes |
|---------|---------|
| 1 | Initial release - RO files only |
| 2 | Added FatMount inode type, mount_id field |

---

## 9. Memory Layout

### 9.1 Guest Address Space

```
┌─────────────────────────────────────────────┐ High Address
│                                             │
│  Guest Heap (grows down)                    │
│    └── Guest-created FAT images allocated   │
│        here via guest allocator             │
│                                             │
├─────────────────────────────────────────────┤
│                                             │
│  HyperlightFS Region                        │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │ Manifest (FlatBuffer, page-aligned) │    │
│  │   - File metadata                   │    │
│  │   - Mount metadata                  │    │
│  │   - Guest addresses                 │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │ RO Files Region                     │    │
│  │   - Memory-mapped from host files   │    │
│  │   - Each file page-aligned          │    │
│  │   - Demand-paged via page faults    │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │ FAT Image Regions (host-provided)   │    │
│  │   - mmap'd from host with MAP_SHARED│    │
│  │   - One region per mount            │    │
│  │   - Page-aligned, RW access         │    │
│  │   - Writes persist to host file     │    │
│  └─────────────────────────────────────┘    │
│                                             │
├─────────────────────────────────────────────┤
│                                             │
│  Guest Stack                                │
│                                             │
├─────────────────────────────────────────────┤
│                                             │
│  Guest Code                                 │
│                                             │
└─────────────────────────────────────────────┘ Low Address
```

### 9.2 FAT Image Structure

Each FAT image (host-provided or guest-created) follows standard FAT32 layout:

```
┌────────────────────────────┐
│ Boot Sector (512 bytes)    │
├────────────────────────────┤
│ FS Info Sector (512 bytes) │
├────────────────────────────┤
│ Reserved Sectors           │
├────────────────────────────┤
│ FAT #1                     │
├────────────────────────────┤
│ FAT #2 (backup)            │
├────────────────────────────┤
│ Data Region                │
│   - Directory entries      │
│   - File data clusters     │
└────────────────────────────┘
```

---

## 10. Permissions and Metadata

### 10.1 Faked Unix Permissions

Since FAT32 doesn't support Unix permissions, HyperlightFS fakes them:

| Entry Type | st_mode | Octal |
|------------|---------|-------|
| Regular file | `S_IFREG \| 0644` | 0100644 |
| Directory | `S_IFDIR \| 0755` | 0040755 |

### 10.2 Ownership

All files appear owned by:
- `st_uid = 0` (root)
- `st_gid = 0` (root)

### 10.3 Timestamps

| Timestamp | RO Files | FAT Files |
|-----------|----------|-----------|
| st_atime | 0 (not tracked) | From FAT metadata |
| st_mtime | 0 (not tracked) | From FAT metadata |
| st_ctime | 0 (not tracked) | From FAT metadata |

**Guest timestamp source**: By default, Hyperlight guests have no real-time clock (RTC). Files created or modified by the guest use a fixed timestamp (FAT epoch: 1980-01-01 00:00:00). Pre-existing files in FAT images loaded via `add_fat_image()` retain their original timestamps.

**Future**: When paravirtualized clock support is enabled (see [PR #1173](https://github.com/hyperlight-dev/hyperlight/pull/1173)), guests will have access to wall-clock time and file timestamps will reflect actual creation/modification times. The `guest_time` feature provides `clock_gettime()` and related APIs that HyperlightFS can use for accurate FAT timestamps.

### 10.4 mode Parameter Handling

The `mode` parameter in `open(..., O_CREAT, mode)` and `mkdir(path, mode)` is **ignored**. Files are always created with the default permissions above.

**Documented limitation**: This matches Linux behavior when mounting FAT with `umask=022`.

---

## 11. Error Handling

### 11.1 Rust Errors

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// Filesystem not initialized
    NotInitialized,
    /// Path not found
    NotFound,
    /// Not a file (is a directory)
    NotAFile,
    /// Not a directory (is a file)
    NotADirectory,
    /// Path is read-only
    ReadOnly,
    /// File already exists
    AlreadyExists,
    /// Directory not empty
    NotEmpty,
    /// No space left
    NoSpace,
    /// Invalid path (null bytes, empty, etc.)
    InvalidPath,
    /// Invalid seek position
    InvalidSeek,
    /// Too many open files
    TooManyOpenFiles,
    /// Bad file descriptor
    BadFd,
    /// Invalid manifest data
    InvalidManifest,
    /// Operation not supported
    NotSupported,
    /// I/O error
    IoError,
    /// Insufficient memory
    OutOfMemory,
    /// File is locked by another process/sandbox
    FileLocked,
    /// Platform does not support this operation (e.g., FAT RW on Windows)
    PlatformNotSupported,
}
```

### 11.2 Error Mapping

| FsError | C Return | POSIX Equivalent |
|---------|----------|------------------|
| NotInitialized | -1 | ENXIO |
| NotFound | -1 | ENOENT |
| NotAFile | -7 | EISDIR |
| NotADirectory | -6 | ENOTDIR |
| ReadOnly | -3 | EROFS |
| AlreadyExists | -5 | EEXIST |
| NotEmpty | -8 | ENOTEMPTY |
| NoSpace | -4 | ENOSPC |
| InvalidPath | -9 | EINVAL |
| InvalidSeek | -9 | EINVAL |
| TooManyOpenFiles | -10 | EMFILE |
| BadFd | -11 | EBADF |
| InvalidManifest | -1 | EIO |
| NotSupported | -2 | ENOTSUP |
| IoError | -1 | EIO |
| OutOfMemory | -1 | ENOMEM |
| FileLocked | -1 | EAGAIN |
| PlatformNotSupported | -2 | ENOTSUP |

---

## 12. Security Considerations

### 12.1 Host-Side Security

| Concern | Mitigation |
|---------|------------|
| Path traversal | All paths validated, no `..` allowed |
| Symlink attacks | Symlinks rejected during mapping |
| TOCTOU | Logical lock during sandbox execution |
| File modification during mmap | Shared lock (`flock(LOCK_SH)`) blocks external writers |
| Arbitrary host file access | Only explicitly mapped files accessible |
| Concurrent FAT access | Exclusive file lock prevents multi-sandbox corruption |

### 12.2 Guest-Side Security

| Concern | Mitigation |
|---------|------------|
| RO file modification | Write operations fail with EROFS |
| Escape to host FS | Guest has no access to host paths |
| Memory corruption | FAT data in separate guest regions |
| Resource exhaustion | Guest memory is bounded |

### 12.3 Isolation Properties

- Guest cannot access unmapped host files
- Guest cannot modify RO files
- Guest cannot see host file paths
- Guest-created filesystems are isolated
- FAT images are exclusively locked: one sandbox per backing file

**Multi-sandbox sharing constraints:**

When the same `HyperlightFSImage` is used by multiple sandboxes (via `Arc<HyperlightFSImage>`):
- The image **must only contain RO file mappings** (no FAT mounts)
- Attempting to evolve a sandbox with a shared image containing FAT mounts returns an error
- Guest `create_fat_mount()` is **disabled** when using a shared image
- This is enforced at `sandbox.evolve()` time by checking `Arc::strong_count() > 1`

```rust
// Valid: Shared RO-only image
let fs = Arc::new(HyperlightFSBuilder::new()
    .add_file("/etc/config.json", "/config")?
    .add_dir("/opt/assets", "/assets")?.include("**/*").done()?
    .build()?);

let sandbox1 = UninitializedSandbox::new(guest, None)?
    .set_hyperlight_fs(Arc::clone(&fs))
    .evolve(host_funcs)?;  // ✅ OK

let sandbox2 = UninitializedSandbox::new(guest, None)?
    .set_hyperlight_fs(Arc::clone(&fs))
    .evolve(host_funcs)?;  // ✅ OK - RO sharing allowed

// Invalid: Shared image with FAT mount
let fs = Arc::new(HyperlightFSBuilder::new()
    .add_file("/etc/config.json", "/config")?
    .add_empty_fat_mount("/tmp", 1024 * 1024)?  // FAT mount
    .build()?);

let sandbox1 = UninitializedSandbox::new(guest, None)?
    .set_hyperlight_fs(Arc::clone(&fs))
    .evolve(host_funcs)?;  // ✅ OK - first use

let sandbox2 = UninitializedSandbox::new(guest, None)?
    .set_hyperlight_fs(Arc::clone(&fs))
    .evolve(host_funcs)?;  // ❌ ERROR: Cannot share HyperlightFSImage with FAT mounts
```

### 12.4 File Locking Strategy

All mapped files use advisory locks (`flock`) to prevent external interference:

**RO Files - Shared Lock (`LOCK_SH`)**:
- Acquired during `add_file()` / `add_dir()` when files are mmap'd
- Multiple sandboxes can hold shared locks on the same file (concurrent reads OK)
- Blocks external processes from acquiring exclusive locks (prevents writes)
- Released when `HyperlightFSImage` is dropped

**FAT Images - Exclusive Lock (`LOCK_EX`)**:
- Acquired during `add_fat_image()` / `add_empty_fat_mount_at()` / `add_empty_fat_mount()`
- Only one sandbox can hold the lock (prevents concurrent RW access)
- Blocks both shared and exclusive lock attempts by others
- Released when `HyperlightFSImage` is dropped
- Attempting to map an already-locked file returns `FsError::FileLocked`

**Lock compatibility matrix**:

| Existing Lock | New LOCK_SH | New LOCK_EX |
|---------------|-------------|-------------|
| None | ✅ Granted | ✅ Granted |
| LOCK_SH | ✅ Granted | ❌ Blocked |
| LOCK_EX | ❌ Blocked | ❌ Blocked |

This ensures:
- RO files cannot be modified externally while mmap'd
- FAT backing files are used by at most one sandbox at a time
- Multiple sandboxes can safely share RO file mappings

---

## 13. Limitations

### 13.1 Platform Support

| Platform | Hypervisor | RO Files | FAT RW Mounts | Notes |
|----------|------------|----------|---------------|-------|
| Linux | KVM | ✅ | ✅ | Full support |
| Linux | MSHV | ✅ | ✅ | Full support |
| Windows | WHP | ❌ **TODO** | ❌ **TODO** | Requires surrogate process changes |

**Windows/WHP Support**: The Windows hypervisor (WHP) uses a surrogate process model that currently blocks memory mappings. HyperlightFS (both RO and FAT) is not yet implemented on Windows and is tracked as a TODO.

### 13.2 FAT32 Limitations

| Limitation | Value | Impact |
|------------|-------|--------|
| Fixed size | Cannot grow after creation | Must specify size upfront; ENOSPC when full |
| Min image size | 1 MB | Implementation practical minimum |
| Max image size | 16 GB | Implementation limit (FAT32 itself supports ~2TB) |
| Max file size | 4 GB - 1 byte | Large individual files not supported |
| Max filename | 255 chars (LFN) | Long names supported |
| Max path | ~260 chars | Deep nesting limited |
| Timestamps | 2-second resolution | Not precise; requires `guest_time` feature for real timestamps |
| Permissions | None | Faked as 644/755 |
| Symlinks | None | ENOTSUP |
| Hard links | None | ENOTSUP |

### 13.3 Implementation Limitations

| Limitation | Status |
|------------|--------|
| Global errno | Not implemented (negative returns instead) |
| File locking | Not implemented |
| Async I/O | Not supported |
| Memory-mapped files (guest mmap) | Not supported |
| Sparse files | Not supported |
| Extended attributes | Not supported |
| Multi-sandbox FAT sharing | Not supported (exclusive lock) |
| Read-only FAT mounts | Future enhancement (see §3.4) |

### 13.4 Resource Limits

HyperlightFS enforces limits on resources that consume guest memory or have fixed overhead. **Host-provided files and FAT images have no size limits** since they use zero-copy `MAP_SHARED` and don't consume guest memory.

| Resource | Default Limit | Configurable | Reason |
|----------|---------------|--------------|--------|
| Max files in manifest | 100,000 | ✅ `FsLimits` | Manifest size (~100 bytes/entry) |
| Max mount points | 64 | ✅ `FsLimits` | Mount table overhead |
| Max path length | 4,096 bytes | ✅ `FsLimits` | Stack allocation in path resolution |
| Max open file descriptors | 256 | ✅ `FsLimits` | FD table size |
| Max single RO file size | **No limit** | N/A | Zero-copy, no guest memory used |
| Max total RO file size | **No limit** | N/A | Zero-copy, shared via page cache |
| Min FAT image size (host) | 1 MB | ❌ | FAT32 metadata + practical minimum |
| Max FAT image size (host) | 16 GB | ❌ | Practical mmap limit (FAT32 supports ~2TB) |
| Max guest-created FAT size | Guest heap size | N/A | Allocated from guest heap |

### 13.5 Known Issues

1. **SIGBUS on RO file modification**: If host modifies mmap'd file during sandbox execution, SIGBUS may occur
2. **FAT fragmentation**: Long-running guests with many create/delete cycles may fragment
3. **no_std fatfs**: Requires specific Rust nightly for `core_io` feature

---

## 14. Dependencies and Risks

### 14.1 fatfs Crate Status

The FAT filesystem implementation depends on the [`fatfs`](https://crates.io/crates/fatfs) crate.

| Metric | Value | Assessment |
|--------|-------|------------|
| Downloads | ~900K | Moderate adoption |
| Last release | 0.3.6 (June 2019) | ⚠️ Stale |
| Last commit | March 2025 | Active development |
| Unreleased version | 0.4.0 | Breaking API changes pending |

**Current situation**: The crate is actively maintained with 154+ commits since 0.3.6, including important bug fixes. However, these fixes are unreleased because 0.4.0 includes breaking API changes.

**Unreleased bug fixes (on master) that may affect us**:
- Fill FAT32 root directory clusters with zeros (avoids interpreting garbage as entries)
- Fix `.` and `..` directory entries (fixes fsck errors)
- Fix `..` cluster number for first-level directories
- Don't create LFN entries for `.` and `..`
- Time encoding/decoding fixes

### 14.2 Dependency Configuration

**Initial approach**: Use published 0.3.6
```toml
fatfs = "0.3"
```

### 14.3 Mitigation Options

If we encounter bugs fixed in unreleased master, we have several options:

#### Option 1: Pin to Git Commit
```toml
fatfs = { git = "https://github.com/rafalh/rust-fatfs.git", rev = "4eccb50" }
```
- **Pros**: Get all fixes, minimal effort
- **Cons**: Breaking 0.4.0 API requires code changes, not on crates.io

#### Option 2: Vendor the Crate
Copy the crate source into `src/hyperlight_host/vendor/fatfs/`.
- **Pros**: Full control, can cherry-pick fixes, no external dependency
- **Cons**: Maintenance burden, need to track upstream

#### Option 3: Fork and Publish
Fork to `hyperlight-dev/fatfs`, apply fixes, publish as `hyperlight-fatfs`.
- **Pros**: Control + crates.io availability, community can benefit
- **Cons**: Ongoing maintenance, version coordination

#### Option 4: Implement Minimal FAT
Write our own minimal FAT32 implementation.
- **Pros**: Tailored to our needs, no external dependency
- **Cons**: Significant effort (~2-4 weeks), potential for bugs, reinventing wheel

### 14.4 Decision Record

| Date | Decision | Rationale |
|------|----------|----------|
| 2026-01-19 | Start with fatfs 0.3.6 | Published, stable API; switch if we hit known bugs |

---

## Appendix A: TOML Configuration Format

```toml
# hyperlight-fs.toml

# Read-only file mappings
[[file]]
host = "/etc/app/config.json"
guest = "/config.json"

[[file]]
host = "/var/data/model.bin"
guest = "/models/model.bin"

# Read-only directory mapping with patterns
[[directory]]
host = "/opt/app/assets"
guest = "/assets"
include = ["**/*.json", "**/*.txt"]
exclude = ["**/secret/*"]

# FAT image from host file
[[fat_image]]
host = "/var/lib/app/data.fat"
mount = "/data"

# Empty FAT filesystem
[[fat_mount]]
mount = "/tmp"
size = "10MB"  # Supports KB, MB, GB suffixes
```

---

## Appendix B: Example Usage

### Host: Create and Populate FAT Image

```rust
use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;

// Build filesystem with RO files and FAT mount
// Note: add_fat_image() acquires exclusive lock on the file
let fs_image = HyperlightFSBuilder::new()
    .add_file("/etc/config.json", "/config.json")?
    .add_fat_image("/var/data/storage.fat", "/data")?  // Exclusive lock acquired
    .add_empty_fat_mount("/tmp", 1024 * 1024)?  // 1MB temp space (auto-deleted)
    .add_empty_fat_mount_at("/var/out/output.fat", "/out", 2 * 1024 * 1024)?  // Persists
    .build()?;

// Pre-populate FAT mount with files (via mmap)
fs_image.write_file("/data/initial.txt", b"Hello from host")?;
fs_image.create_dir("/data/subdir")?;

// Create sandbox and execute
let mut sandbox = UninitializedSandbox::new(guest, None)?;
sandbox.set_hyperlight_fs(Arc::new(fs_image));
let mut sandbox = sandbox.evolve(NoopHostFunctions)?;

// Execute guest code - writes go directly to backing files via MAP_SHARED
let result: Vec<u8> = sandbox.call("ProcessData", ())?;

// After execution: /var/data/storage.fat and /var/out/output.fat contain guest's changes
// No explicit extraction needed - writes persisted automatically via mmap!

// Can still read files if needed:
let output = sandbox.fs_read_file("/data/output.txt")?;
```

### Guest (Rust): Unified File Access

```rust
use hyperlight_guest::fs;

// Read RO file (mmap'd from host)
let config = fs::open("/config.json", OpenMode::READ_ONLY)?;
let data = config.read_to_vec()?;

// Write to FAT mount - writes persist to host file automatically
let mut output = fs::create("/data/output.txt")?;
output.write_all(b"Results: ...")?;  // Goes directly to /var/data/storage.fat

// Create guest filesystem (in guest heap, not persisted)
fs::create_fat_mount("/workspace", 512 * 1024)?;  // 512KB
let mut temp = fs::create("/workspace/temp.dat")?;
temp.write_all(&processed_data)?;

// Both use same API
for entry in fs::read_dir("/")? {
    println!("{}: {} bytes", entry.name, entry.size);
}
```

### Guest (C): POSIX-Style Access

```c
#include "hyperlight_guest.h"

void process_files(void) {
    // Read RO config
    int fd = open("/config.json", O_RDONLY);
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    
    // Write to FAT mount - persists to host automatically via MAP_SHARED
    fd = open("/data/output.txt", O_WRONLY | O_CREAT | O_TRUNC);
    write(fd, "Results", 7);
    close(fd);
    
    // Create temp filesystem (in guest memory, not persisted)
    hl_fs_create_mount("/scratch", 256 * 1024);
    
    // List directory
    hl_DIR *dir = opendir("/data");
    hl_dirent_t *entry;
    while ((entry = readdir(dir)) != NULL) {
        printf("%s\n", entry->d_name);
    }
    closedir(dir);
    
    // Change directory
    chdir("/data");
    char cwd[256];
    getcwd(cwd, sizeof(cwd));  // Returns "/data"
}
```

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| GPA | Guest Physical Address - address in the VM's physical address space |
| HLT | x86 halt instruction; causes VM exit to hypervisor |
| MAP_SHARED | mmap flag that shares pages with backing file; writes persist automatically |
| RO | Read-only (memory-mapped files from host) |
| RW | Read-write (FAT filesystem) |
| VFS | Virtual File System - abstraction layer routing paths to backends |
| Mount point | Directory path where a filesystem is attached (e.g., `/data`) |
| flock | POSIX advisory file locking mechanism |
| LOCK_SH | Shared lock - allows concurrent readers, blocks writers |
| LOCK_EX | Exclusive lock - blocks all other lock attempts |
| Page cache | Kernel's cache of file-backed memory pages |
| Dirty page | Page modified in memory but not yet written to backing storage |
| msync | System call to flush dirty pages to backing storage |

---

*End of Specification*
