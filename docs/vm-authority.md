# Function-worker VM authority

Function workers need an explicit runtime capability before creating a nested
Hyperlight VM. The capability belongs to one provider session and one worker
generation. It is absent from snapshots, OCI images, and process topology.

The provider registers authority before building the sandbox:

```rust
provider.register_vm_authority("nested-worker", VmBackend::Kvm)?;
```

The worker validates declarations before native transfer. It then claims and
installs the authority before constructing a sandbox:

```rust
let backend = startup.vm_authority_backend()?;
let manifest = ProcessResourceManifest::new()
    .with_vm_authority(backend)?
    .with_file(OsResourceRights::READ)?;

ProcessHostFunctions::run_with_resources(startup, contracts, manifest, |resources, functions| {
    resources
        .take_vm_authority(backend)?
        .install_for_current_generation()?;
    let guest = resources.take_file(guest_id, OsResourceRights::READ)?;
    // Register callbacks, then call SandboxBuilder::from_bytes.
    Ok(())
})?;
```

Linux opens and validates `/dev/kvm` or `/dev/mshv` in the provider. A fresh
owned descriptor is created after each generation is reserved. The worker
validates the received descriptor and the VM constructor consumes it directly.
The worker has no device bind, reopen, or fallback path.

One authority creates one VM in a worker generation. A second sandbox or
snapshot restore needs worker replacement so the provider can issue a fresh
generation and descriptor.

Windows function workers remain AppContainer by default. Registering WHP
authority selects the ordinary non-elevated same-user principal for that
worker. Process reports state that AppContainer filesystem and network
isolation are absent, including structured requested/effective Windows policy
and VM-host-authorization fields. The transferred authority is a no-handle
marker. Any unexpected native handle fails startup and is closed.

An elevated Windows controller is rejected during provider preparation. Run
the controller from an ordinary non-elevated session.

`VmHostAuthorization` is the Windows-facing name for a claimed `VmAuthority`.

Worker replacement reserves a fresh generation and reopens fresh authority
from the existing provider registration. Snapshot reconstruction requires a
new provider and a fresh authority registration.

Manifest declarations are positional. Register provider resources in the same
order as the worker's `ProcessResourceManifest`.

## Qualification

Build the fixture and use the debug Rust guest:

```text
cargo +1.95 build -p hyperlight-host --features process-isolation --example process_vm_authority
src/tests/rust_guests/bin/debug/simpleguest
```

The ignored driver accepts the fixture and guest through
`HYPERLIGHT_TEST_VM_AUTHORITY_FIXTURE` and
`HYPERLIGHT_TEST_VM_AUTHORITY_GUEST`. Run it only inside a configured Windows
process-isolation host or delegated Linux scope:

```text
cargo +1.95 test -p hyperlight-host --features process-isolation \
  process::vm_authority::tests::end_to_end_worker_authority_qualification \
  -- --ignored --exact
```
