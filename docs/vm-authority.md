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

## Same-process nested sandbox

The `nested_sandbox` example proves this topology:

```text
parent and outer Hyperlight guest
  -> process-bound host function
     -> inner Hyperlight guest in the same worker process
        -> co-located inner host function
```

The parent transfers the built guest as a read-only file capability. The
worker reads its owned bytes and calls `SandboxBuilder::from_bytes` only after
installing current-generation VM authority. No guest path, embedded guest, or
provider runtime-file fallback exists.

`NestedSandboxCompose("compose", 2)` returns exactly:

```text
inner-guest-function(process-host-function(compose),process-host-function(compose))
```

The inner guest passes that final string to its co-located host function. The
callback creates pathname-free storage, exports a read-only file capability,
and returns the input unchanged. The parent verifies that the returned and
exported bytes are identical.

The example also checks worker and inner-host PIDs, child-process denial,
repeated calls, in-place guest restore, worker replacement, reconstruction
with a new provider, fresh resource generations, and export cleanup.

`NestedSandboxCompose` is non-idempotent. Hyperlight cannot infer replay safety
from the topology or from successful VM construction. Idempotency covers the
outer worker, inner guest, inner host callbacks, exported resource identities,
and every external effect.

The recovery campaign uses a separate `NestedSandboxComposeRecoverable`
contract. Its caller supplies an invocation key. A provider-owned pathname-free
record tracks started and completed states, the exact result, and completion
provenance. The controlled crash occurs after recording started and before
inner or export effects. Replacement claims fresh authority and resources,
completes the keyed operation once, and records the result. A surviving worker
recreates one generation-bound read-only export from that record. Repeated
calls return the recorded result without another export. A separate
non-idempotent crash proves that an ambiguous composite call fails with a
host-function error that states replay is forbidden.

Applications and providers declare idempotency and own its correctness.
Hyperlight uses the declaration to decide whether replay is permitted. It does
not prove arbitrary guest or host-function semantics.

## Qualification

Build the fixture and use the debug Rust guest:

```text
cargo +1.95 build -p hyperlight-host --features process-isolation --example process_vm_authority
cargo +1.95 build -p hyperlight-host --features process-isolation --example nested_sandbox
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

HYPERLIGHT_TEST_NESTED_SANDBOX_FIXTURE=target/debug/examples/nested_sandbox \
HYPERLIGHT_TEST_NESTED_SANDBOX_GUEST=src/tests/rust_guests/bin/debug/simpleguest \
cargo +1.95 test -p hyperlight-host --features process-isolation \
  process::vm_authority::tests::end_to_end_nested_sandbox_qualification \
  -- --ignored --exact
```

The nested runtime is qualified on delegated Ubuntu 24.04 with KVM and
Minijail. Native WHP execution, MSHV execution, and macOS execution remain
unqualified. Windows builds and fail-closed policy tests cover the unavailable
WHP path.
