# HyperlightFS

HyperlightFS is a zero-copy, read-only filesystem for Hyperlight sandboxes. It allows you to map host files into guest virtual machines without copying data—guests read directly from the host's page cache via memory-mapped I/O.

## Key Features

- **Zero-copy**: Files are memory-mapped (`mmap`), not copied. Guests read directly from the host's page cache.
- **Read-only**: All mappings are read-only at the kernel level. Guests cannot modify host files.
- **Explicit mapping**: Nothing is exposed by default. Every file must be explicitly added.
- **Demand paging**: File pages are loaded on-demand when accessed, minimizing memory overhead.
- **TOML configuration**: Define mappings in a config file or programmatically.
- **Pattern matching**: Map entire directories with gitignore-style include/exclude patterns.

## Quick Start

### 1. Build a filesystem image

```rust
use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;

let fs = HyperlightFSBuilder::new()
    .add_file("/etc/config.json", "/config.json")?
    .add_dir("/opt/app/assets", "/assets")?
        .include("**/*.json")
        .include("**/*.txt")
        .exclude("**/secret/*")
        .done()?
    .build()?;
```

### 2. Attach to a sandbox

```rust
use std::sync::Arc;
use hyperlight_host::sandbox::UninitializedSandbox;

let mut sandbox = UninitializedSandbox::new(guest_binary, None)?;
sandbox.set_hyperlight_fs(Arc::new(fs));

let mut sandbox = sandbox.evolve(hyperlight_host::func::NoopHostFunctions)?;
```

### 3. Read files in the guest

```rust
// In guest code
use hyperlight_guest::fs;

let mut file = fs::open("/config.json")?;
let content = file.read_to_vec()?;
```

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Host Process                                 │
├─────────────────────────────────────────────────────────────────────┤
│  HyperlightFSBuilder                                                │
│    ├── mmap(/etc/config.json) → 0x7f0000001000                      │
│    ├── mmap(/opt/app/data.bin) → 0x7f0000002000                     │
│    └── Serialize manifest (FlatBuffer)                              │
├─────────────────────────────────────────────────────────────────────┤
│                         Guest VM                                     │
├─────────────────────────────────────────────────────────────────────┤
│  Shared Memory                                                      │
│    ├── Manifest: file paths, sizes, addresses                       │
│    └── File data: demand-paged from host mmap regions               │
│                                                                     │
│  Guest Code                                                         │
│    ├── fs::init() → parse manifest, create PTEs for manifest        │
│    ├── fs::open("/config.json") → lookup in manifest                │
│    └── file.read() → page fault → PTE created → data available      │
└─────────────────────────────────────────────────────────────────────┘
```

1. **Build phase**: `HyperlightFSBuilder` opens and mmaps each host file
2. **Manifest creation**: File metadata serialized via FlatBuffers
3. **Sandbox wiring**: Manifest + file regions mapped into guest address space
4. **Guest initialization**: Guest creates page table entries for manifest
5. **On-demand access**: File pages are demand-paged via page fault handler

## Host API

### Adding Individual Files

```rust
use hyperlight_host::hyperlight_fs::HyperlightFSBuilder;

let fs = HyperlightFSBuilder::new()
    .add_file("/etc/config.json", "/config.json")?     // host path → guest path
    .add_file("/var/data/model.bin", "/models/model.bin")?
    .build()?;
```

### Adding Directories with Patterns

```rust
let fs = HyperlightFSBuilder::new()
    .add_dir("/opt/app/assets", "/assets")?
        .include("**/*.json")      // All JSON files recursively
        .include("**/*.txt")       // All text files recursively  
        .exclude("**/secret/*")    // Exclude secret directories
        .exclude("**/.git/**")     // Exclude .git
        .done()?
    .build()?;
```

### Preview Before Building

Use `list()` to see what would be mapped without creating memory mappings:

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

## Guest API

The guest filesystem API is available in both Rust and C.

### Rust API

The Rust guest filesystem API is in `hyperlight_guest::fs`:

```rust
use hyperlight_guest::fs;

// Check if filesystem is available
if fs::is_initialized() {
    // Open and read a file
    let mut file = fs::open("/config.json")?;
    let content = file.read_to_vec()?;
    
    // Or read into a buffer
    let mut buf = [0u8; 1024];
    let bytes_read = file.read(&mut buf)?;
    
    // Get file metadata
    let stat = fs::stat("/config.json")?;
    println!("Size: {} bytes", stat.size);
    
    // List directory contents
    for entry in fs::read_dir("/data")? {
        println!("{}: {} bytes", entry.name, entry.size);
    }
}
```

### C API

The C guest API provides libc-compatible functions via `hyperlight_guest.h`:

```c
#include "hyperlight_guest.h"

// Check if filesystem is available
if (hl_fs_initialized()) {
    // Open a file (read-only only)
    int fd = open("/config.json", O_RDONLY);
    if (fd >= 0) {
        // Get file size via lseek
        int64_t size = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        
        // Read file contents
        uint8_t *buf = malloc(size);
        int64_t bytes_read = read(fd, buf, size);
        
        close(fd);
        free(buf);
    }
    
    // Get file metadata
    hl_Stat st;
    if (stat("/config.json", &st) == 0) {
        // st.size contains the file size
    }
}
```

**Available C functions:**

| Function | Description |
|----------|-------------|
| `open(path, flags)` | Open file (flags must be `O_RDONLY`) |
| `close(fd)` | Close file descriptor |
| `read(fd, buf, n)` | Read up to n bytes |
| `lseek(fd, off, whence)` | Seek (`SEEK_SET`, `SEEK_CUR`, `SEEK_END`) |
| `fstat(fd, st)` | Get metadata by fd |
| `stat(path, st)` | Get metadata by path |
| `hl_fs_initialized()` | Check if FS is available |

The filesystem is automatically initialized during guest startup if the host configured HyperlightFS.

## TOML Configuration

Define filesystem mappings in a TOML file instead of code:

### Configuration Format

```toml
# hyperlight-fs.toml

# Single file mappings
[[file]]
host = "/etc/app/config.json"
guest = "/config.json"

[[file]]
host = "/var/data/model.bin"  
guest = "/models/model.bin"

# Directory mapping with glob patterns
[[directory]]
host = "/opt/app/assets"
guest = "/assets"
include = ["**/*.json", "**/*.txt"]
exclude = ["**/secret/*", "**/.git/**"]
```

### Loading Configuration

```rust
use hyperlight_host::hyperlight_fs::{HyperlightFSBuilder, HyperlightFsConfig};

// From a file
let config = HyperlightFsConfig::from_toml_file("hyperlight-fs.toml")?;
let fs = HyperlightFSBuilder::from_config(&config)?.build()?;

// Or from a string
let fs = HyperlightFSBuilder::from_toml(r#"
[[file]]
host = "/etc/config.json"
guest = "/config.json"
"#)?.build()?;
```

### Validation Tool

Validate configuration files before deployment:

```bash
cargo run --example hyperlight_fs_validate -- hyperlight-fs.toml
```

Output:
```
Loading config: hyperlight-fs.toml

✓ Config parsed: 1 file mapping(s), 1 directory mapping(s)

Files to be mapped:
  /config.json (1.2 KB) <- /etc/app/config.json
  /assets/data.json (892 B) <- /opt/app/assets/data.json

Summary:
  Files: 2
  Directories: 1
  Total size: 2.1 KB

✓ Configuration is valid!
```

Options:
- `-q, --quiet` — Show only errors, skip file listing
- `-v, --verbose` — Include directory entries in output
- `-h, --help` — Show usage information

### Stress Test

Run a stress test with large files and random reads:

```bash
# Default: 1GB file with Rust guest
cargo run --release --example hyperlight_fs_stress

# 512MB file with C guest
cargo run --release --example hyperlight_fs_stress -- --size 512 --guest c

# Verbose output showing each read verification
cargo run --release --example hyperlight_fs_stress -- --size 64 --verbose
```

Options:
- `-s, --size <MB>` — Test file size in megabytes (default: 1024)
- `-g, --guest <TYPE>` — Guest type: `rust` or `c` (default: rust)
- `-k, --keep` — Keep test file after completion
- `-v, --verbose` — Show each chunk verification

The stress test creates a file with random data, maps it into a sandbox, then has the guest read 10 random 256-byte chunks. Each chunk's offset is selected using an RDTSC-seeded LCG, and the host verifies that the data matches.

## Path Requirements

### Host Paths

| Requirement | Valid | Invalid |
|-------------|-------|---------|
| Must be absolute | `/etc/config.json` | `config.json` |
| No `..` components | `/opt/app/file.txt` | `/opt/../etc/passwd` |

### Guest Paths

| Requirement | Valid | Invalid |
|-------------|-------|---------|
| Must be absolute | `/config.json` | `config.json` |
| No `..` components | `/data/file.txt` | `/data/../secret` |
| No null bytes | `/file.txt` | `/file\0.txt` |

Guest paths are normalized automatically:
- `//foo//bar` → `/foo/bar`
- `/foo/` → `/foo`
- `/./foo` → `/foo`

## Error Handling

All errors are returned as `HyperlightError`:

```rust
// File doesn't exist
HyperlightFSBuilder::new().add_file("/nonexistent", "/file");
// Error: Cannot add file "/nonexistent": No such file or directory

// Symlink rejected (security)
HyperlightFSBuilder::new().add_file("/path/to/symlink", "/file");
// Error: Cannot add "/path/to/symlink": symlinks are not supported

// Path traversal blocked
HyperlightFSBuilder::new().add_file("/etc/passwd", "/guest/../escape");
// Error: Invalid guest path: '..' components are not allowed

// Duplicate guest path
HyperlightFSBuilder::new()
    .add_file("/file1", "/same")?
    .add_file("/file2", "/same");
// Error: Duplicate guest path "/same": already mapped
```

## Limitations

### Platform Support

| Platform | Status |
|----------|--------|
| Linux | ✅ Full support |
| Windows | ❌ Not yet implemented |

### Guest Language Support

| Language | Status |
|----------|--------|
| Rust | ✅ Full support (`hyperlight_guest::fs`) |
| C | ✅ Full support (libc-compatible API) |

### File Types

| Type | Supported |
|------|-----------|
| Regular files | ✅ Yes |
| Directories | ✅ Yes (as containers) |
| Symlinks | ❌ No (rejected for security) |
| Device files, sockets, FIFOs | ❌ No |

### Access Mode

- **Read-only only** — No write support, enforced at kernel level
- **No file creation** — Guests cannot create new files
- **Static mapping** — Files are mapped at sandbox creation, not dynamically

### SIGBUS Risk

If a host file is truncated or deleted while the sandbox is running, accessing the invalid region causes `SIGBUS`. 

**Mitigation**: Don't modify mapped files during sandbox execution.

## Security

1. **No implicit mappings** — Nothing exposed unless explicitly added
2. **Path validation** — Absolute paths required, no `..` traversal
3. **Symlink rejection** — Prevents TOCTOU attacks
4. **Kernel-enforced read-only** — `PROT_READ` at mmap level
5. **No directory auto-exposure** — Must specify include patterns

## Future Work

- **Windows support** — `CreateFileMapping`/`MapViewOfFile` implementation
- **Host file locking** — Lock mapped files to prevent modification/truncation during sandbox execution (avoids SIGBUS)
- **Read-write support** — Allow guests to modify mapped files with copy-on-write or explicit writeback
- **Metrics** — Track file access patterns and latency

