# HyperlightFS

HyperlightFS is a zero-copy filesystem passthrough mechanism for Hyperlight. It allows host files to be mapped into guest sandboxes with minimal overhead by using memory-mapped I/O (mmap).

## Overview

HyperlightFS provides a way to expose host filesystem content to guest code running inside Hyperlight sandboxes. Unlike traditional file sharing approaches that copy data, HyperlightFS uses `mmap` to create read-only memory mappings, allowing guests to access file contents directly from the host's page cache.

### Key Features

- **Zero-copy**: Files are memory-mapped, not copied. The guest reads directly from the host's page cache.
- **Read-only**: All mappings are read-only (`PROT_READ`). Guests cannot modify host files.
- **Explicit mapping**: No files are exposed by default. Every file must be explicitly added.
- **Path validation**: Both host and guest paths are validated to prevent path traversal attacks.
- **Pattern matching**: Directories can be added with gitignore-style include/exclude patterns.

## How It Works

1. **Build phase**: Use `HyperlightFSBuilder` to specify which host files to map and where they should appear in the guest's virtual filesystem.

2. **mmap phase**: When `build()` is called, each file is opened and memory-mapped with `MAP_PRIVATE | PROT_READ`.

3. **Serialization**: File metadata (paths, sizes, offsets) is serialized using FlatBuffers into a header that the guest can parse.

4. **Guest access**: The guest receives pointers to the memory-mapped regions and can read file contents directly.

## Usage

### Adding Individual Files

```rust
use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;

let fs = HyperlightFSBuilder::new()
    .add_file("/etc/config.json", "/config.json")?
    .add_file("/opt/app/data.bin", "/data/app.bin")?
    .build()?;
```

### Adding Directories with Patterns

```rust
use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;

let fs = HyperlightFSBuilder::new()
    .add_dir("/opt/app/assets", "/assets")?
        .include("**/*.json")       // All JSON files recursively
        .include("**/*.txt")        // All text files recursively
        .exclude("**/secret/*")     // Exclude anything in secret/ directories
        .exclude("**/*.tmp")        // Exclude temp files
        .done()?
    .build()?;
```

### Preview Before Building

Use `list()` to see what would be mapped without creating any memory mappings:

```rust
let builder = HyperlightFSBuilder::new()
    .add_file("/etc/config.json", "/config.json")?
    .add_dir("/opt/app/data", "/data")?
        .include("**/*")
        .done()?;

let manifest = builder.list()?;
println!("Would map {} files, {} bytes total", 
    manifest.files.len(), 
    manifest.total_size);

// Actually build only if satisfied
let fs = builder.build()?;
```

## Path Requirements

### Host Paths

| Requirement | Example Valid | Example Invalid |
|-------------|---------------|-----------------|
| Must be absolute | `/etc/config.json` | `config.json` |
| No `..` components | `/opt/app/file.txt` | `/opt/../etc/passwd` |

### Guest Paths

| Requirement | Example Valid | Example Invalid |
|-------------|---------------|-----------------|
| Must be absolute | `/config.json` | `config.json` |
| No `..` components | `/data/file.txt` | `/data/../secret` |
| Cannot be just `/` (for files) | `/file.txt` | `/` |
| No null bytes | `/file.txt` | `/file\0.txt` |

Guest paths are normalized:
- Double slashes collapsed: `//foo//bar` → `/foo/bar`
- Trailing slashes removed: `/foo/` → `/foo`
- Dot components removed: `/./foo` → `/foo`

## Limitations

### Platform Support

| Platform | Status |
|----------|--------|
| Linux | ✅ Fully supported |
| Windows | ❌ Not yet implemented |

### File Types

| Type | Supported |
|------|-----------|
| Regular files | ✅ Yes |
| Directories | ✅ Yes (as containers, no content) |
| Symlinks | ❌ No - explicitly rejected |
| Device files | ❌ No |
| Sockets | ❌ No |
| FIFOs | ❌ No |

### Access Mode

- **Read-only only**: All mappings use `PROT_READ`. There is no write support.
- **No file creation**: Guests cannot create new files.
- **No modification**: Guests cannot modify existing files.

### Memory Considerations

- Each mapped file consumes virtual address space
- Files are mapped with `MAP_PRIVATE` - writes by the guest would trigger copy-on-write (but writes are blocked by `PROT_READ`)
- If a host file is modified while mapped, behavior depends on the filesystem:
  - On most filesystems: guest sees the new content
  - If file is truncated: accessing beyond new size may cause `SIGBUS`

### SIGBUS Risk

If a mapped file is truncated or deleted while the guest is running, accessing the now-invalid region will cause a `SIGBUS` signal. This is an inherent limitation of memory-mapped I/O.

**Mitigation**: Ensure mapped files are not modified during sandbox execution.

## Security Considerations

1. **No implicit mappings**: Nothing is exposed unless explicitly added.

2. **Path validation**: Both host and guest paths are validated:
   - Must be absolute (no ambiguity about which file)
   - No `..` components (no path traversal)

3. **Symlink rejection**: Symlinks are rejected to prevent TOCTOU attacks where a symlink could be changed between validation and use.

4. **Read-only**: Even if a vulnerability allowed writes, the mapping is `PROT_READ` at the kernel level.

5. **No directory listings by default**: Adding a directory doesn't expose its contents - you must specify include patterns.

## Error Handling

All errors are returned as `HyperlightError`. Common error cases:

```rust
// File doesn't exist
let result = HyperlightFSBuilder::new()
    .add_file("/nonexistent", "/file");
// Error: Cannot add file "/nonexistent": No such file or directory

// Symlink rejected
let result = HyperlightFSBuilder::new()
    .add_file("/path/to/symlink", "/file");
// Error: Cannot add "/path/to/symlink": symlinks are not supported

// Relative host path
let result = HyperlightFSBuilder::new()
    .add_file("relative/path", "/file");
// Error: Invalid host path "relative/path": must be absolute

// Path traversal in guest path
let result = HyperlightFSBuilder::new()
    .add_file("/real/file", "/guest/../escape");
// Error: Invalid guest path "/guest/../escape": '..' components are not allowed

// Duplicate guest path
let result = HyperlightFSBuilder::new()
    .add_file("/file1", "/same")
    .add_file("/file2", "/same");
// Error: Duplicate guest path "/same": already mapped

// No include patterns
let result = HyperlightFSBuilder::new()
    .add_dir("/some/dir", "/guest")?
    .done();
// Error: Directory "/some/dir" has no include patterns
```

## Implementation Status

### Phase 1: Host-Side Builder (Complete)

| Component | Status | Notes |
|-----------|--------|-------|
| `HyperlightFSBuilder` | ✅ Complete | Fluent builder API |
| `DirectoryBuilder` | ✅ Complete | Pattern matching for directories |
| Host path validation | ✅ Complete | Absolute paths, no `..` |
| Guest path validation | ✅ Complete | Absolute paths, no `..`, no null bytes |
| File type validation | ✅ Complete | Regular files only, symlinks rejected |
| Duplicate detection | ✅ Complete | Guest paths must be unique |
| Pattern matching | ✅ Complete | gitignore-style globs via `glob` crate |
| `list()` dry-run | ✅ Complete | Preview without mmap |
| mmap on Linux | ✅ Complete | `MAP_PRIVATE \| PROT_READ` |
| FlatBuffer schema | ✅ Complete | `hyperlight_fs.fbs` |
| Wrapper types | ✅ Complete | `flatbuffer_wrappers/hyperlight_fs.rs` |
| Unit tests | ✅ Complete | 35 tests covering validation |
| Documentation | ✅ Complete | This document |

### Phase 2: Guest-Side VFS (Not Started)

| Component | Status | Notes |
|-----------|--------|-------|
| Guest VFS module | 🚧 Not started | Read-only filesystem abstraction |
| FlatBuffer parsing in guest | 🚧 Not started | Parse header from shared memory |
| `open()` / `read()` / `close()` | 🚧 Not started | Basic file operations |
| `stat()` / `fstat()` | 🚧 Not started | File metadata |
| `readdir()` | 🚧 Not started | Directory listing |
| Path lookup | 🚧 Not started | Resolve guest path to inode |

### Phase 3: Sandbox Integration (Not Started)

| Component | Status | Notes |
|-----------|--------|-------|
| `SandboxConfig` integration | 🚧 Not started | Add HyperlightFS to sandbox config |
| Memory region setup | 🚧 Not started | Map HyperlightFS into guest address space |
| Host function for FS ops | 🚧 Not started | Guest calls host to read files |
| Example: guest reading file | 🚧 Not started | End-to-end demo |

### Phase 4: Enhancements (Not Started)

| Component | Status | Notes |
|-----------|--------|-------|
| Windows support | 🚧 Not started | `CreateFileMapping`/`MapViewOfFile` |
| TOML configuration | 🚧 Not started | Load mappings from config file |
| Async file loading | 🚧 Not started | Background mmap for large files |
| Metrics | 🚧 Not started | Track file access patterns |

## Future Work

### Guest VFS Design

The guest will need a minimal VFS layer that can:

1. **Parse the FlatBuffer header** from a known memory location
2. **Resolve paths** by walking the inode table
3. **Provide POSIX-like APIs**: `open()`, `read()`, `close()`, `stat()`
4. **Handle errors** gracefully (file not found, permission denied, etc.)

```rust
// Proposed guest API (not yet implemented)
use hyperlight_guest::fs;

let fd = fs::open("/config.json", fs::O_RDONLY)?;
let mut buf = [0u8; 1024];
let n = fs::read(fd, &mut buf)?;
fs::close(fd)?;
```

### Sandbox Integration Design

The HyperlightFS image needs to be:

1. **Passed to sandbox creation** as part of `SandboxConfig`
2. **Mapped into guest memory** at a known address
3. **Accessible via host functions** or direct memory access

```rust
// Proposed sandbox API (not yet implemented)
let fs = HyperlightFSBuilder::new()
    .add_file("/etc/config.json", "/config.json")?
    .build()?;

let config = SandboxConfig::new()
    .with_filesystem(fs)
    .build();

let sandbox = Sandbox::new(config)?;
```

### TOML Configuration Design

Support loading file mappings from a config file:

```toml
# hyperlight-fs.toml (proposed format)
[[file]]
host = "/etc/app/config.json"
guest = "/config.json"

[[directory]]
host = "/opt/app/assets"
guest = "/assets"
include = ["**/*.json", "**/*.txt"]
exclude = ["**/secret/*"]
```

### Windows Support

Windows requires different APIs:
- `CreateFileW` to open files
- `CreateFileMappingW` to create mapping objects
- `MapViewOfFile` to map into address space
- `UnmapViewOfFile` / `CloseHandle` for cleanup

The builder API remains the same; only the `build()` implementation differs.
