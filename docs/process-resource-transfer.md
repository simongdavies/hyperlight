# Process resource transfer

Process-bound host functions can receive already-open OS objects without
receiving a path, descriptor number, or handle value on function RPC. Each
object has a provider-session `ResourceId`, an `OsResourceKind`, and explicit
`OsResourceRights`.

The initial resource kind is an owned file. Linux transfers owned descriptors
with `SCM_RIGHTS`. Windows transfers restricted handles through Mesh ALPC.
Ordinary function calls remain byte-only.

## Application developer flow

The application opens the object, registers it before cloning the provider,
and declares the worker export policy.

```rust,no_run
use std::fs::OpenOptions;
use hyperlight_host::process::{
    MeshProcessProvider, OsResourceExportPolicy, OsResourceRights,
};
use hyperlight_host::Result;

fn configure() -> Result<MeshProcessProvider> {
    let rights = OsResourceRights::READ | OsResourceRights::WRITE;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("input.txt")?;
    let mut provider = MeshProcessProvider::discover()?;
    provider.register_file("file-resource", file, rights)?;
    provider.allow_file_exports(
        "file-resource",
        OsResourceExportPolicy::files(OsResourceRights::READ, 1)?,
    )?;
    Ok(provider)
}
```

The worker declares the exact inbound rights and export quota before native
objects cross the Mesh channel. It then claims the file and retains a cloneable
export authority for its bound function.

```rust,no_run
use std::io::{Seek, SeekFrom, Write};
use hyperlight_host::process::{
    OsResourceExportPolicy, OsResourceRights, ProcessResourceManifest,
    ProcessResources,
};
use hyperlight_host::Result;

fn manifest() -> Result<ProcessResourceManifest> {
    ProcessResourceManifest::new()
        .with_file(OsResourceRights::READ | OsResourceRights::WRITE)?
        .with_file_exports(OsResourceExportPolicy::files(
            OsResourceRights::READ,
            1,
        )?)
}

fn use_resources(resources: &mut ProcessResources, value: &str) -> Result<()> {
    let ids = resources.ids();
    let [id] = ids.as_slice() else {
        panic!("expected one file capability");
    };
    let mut input = resources.take_file(
        *id,
        OsResourceRights::READ | OsResourceRights::WRITE,
    )?;
    input.seek(SeekFrom::End(0))?;
    input.write_all(value.as_bytes())?;
    if let Some(exporter) = resources.exporter() {
        let mut result = tempfile::tempfile()?;
        result.write_all(value.as_bytes())?;
        result.seek(SeekFrom::Start(0))?;
        exporter.export_file(&result, OsResourceRights::READ)?;
    }
    Ok(())
}
```

The calling host takes the oldest pending object with
`MeshProcessProvider::take_exported_file`. `ExportedFile` enforces the granted
rights and does not expose its raw descriptor or handle.

`process_file_resource` is a runnable end-to-end example:

```text
cargo run -p hyperlight-host --features process-isolation \
  --example process_file_resource -- GUEST EXISTING_FILE INPUT
```

The controller opens and retains the input object, removes its path, launches
the worker, verifies worker reads and writes through the same object, and
verifies the exact pathname-free result object exported by the worker. The
Linux worker creates that result with `memfd_create`, so it needs no writable
filesystem path.
Provider setup errors link to `dev/process-isolation/QUICKSTART.md`.

## Platform operator flow

Applications use `MeshProcessProvider::discover`. They do not configure
cgroups, helper paths, AppContainer identities, or transport internals.

| Platform | Transfer | Application user support | Operator requirement |
| --- | --- | --- | --- |
| Windows | Mesh ALPC handle transfer | Supported | Install and authorize the Windows process provider described in the quickstart |
| Linux | Mesh Unix socket `SCM_RIGHTS` | Supported after operator setup | Install the pinned Minijail helper and provide a delegated cgroup v2 supervisor with `cpu`, `memory`, and `pids` controllers |
| macOS | Shared Unix resource encoding only | Not supported | A native confined process provider and native Apple Silicon qualification are required |

The repository branch containing this document does not install a production
Linux supervisor or service. A deployment must provide that integration before
normal users can run process isolation. This is an operator prerequisite, not
application configuration.

Linux cannot reduce access on a duplicated open file description. Inbound
registration therefore requires declared rights to exactly match native access.
For worker exports, the public parent wrapper enforces the reduced rights while
the transported descriptor can retain the source access mode. Windows creates
a native restricted duplicate in both directions.

## Authority and lifecycle

* Registration and export policies belong to one provider session.
* Configuration fails after the provider is cloned.
* The provider reserves a fresh nonzero generation before each launch attempt.
  Failed attempts consume their generation.
* Protocol, contract, generation, kind, rights, and quota declarations are
  accepted before any native object crosses the channel.
* Native payloads must exactly match accepted declarations. Adapter-defined
  typed validators inspect owned payloads before claims or worker readiness.
* Claims validate identity, kind, generation, and rights before consuming an
  object.
* Export policy validates worker identity, kind, rights, generation, and a
  bounded pending-object quota.
* Denied exports close the transferred duplicate and preserve the worker source.
* One export generation can be active per worker. Overlap and stale generations
  fail closed.
* Worker exit, replacement, provider drop, and queue drop close owned objects.
* A resource must be registered or exported again after reconstruction.

Guest snapshots contain guest state only. Host OS objects and their bytes are
not serialized into guest snapshots or OCI program artifacts. Restore requires
fresh provider authorization and fresh OS-object duplication. Resource
identities from an earlier worker generation are stale.

## Future secret delivery

A future secret-delivery use case could transfer a sealed memory file or
read-only mapping capability to a process-bound host function. The raw secret
would remain outside guest memory, function RPC, guest snapshots, and OCI
artifacts. The worker would return only a derived result.

This secret-delivery scenario is not implemented or tested by the file resource
API. It must not be presented as supported until native sealing, read-only
mapping, lifecycle, and leak tests pass on each claimed platform.
