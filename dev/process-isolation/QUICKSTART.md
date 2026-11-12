# Process Isolation Quickstart

Process isolation moves native work out of your application process. Use it
when a host function should have fewer permissions, or when the Hyperlight VM
should run in a separate process.

There are two optional roles. A **worker** runs selected host functions. A
**VM host** runs the VM and guest. You can use either role or both. Unassigned
work stays in the application process.

This guide starts one worker and leaves the VM in the application process.

## Concepts

* **Worker contract:** the function name, argument types, result type, and
replay rule shared by the application and worker. Both sides must match.
* **Program artifact:** an immutable description of an executable, including
its digest, role, target platform, and contracts.
* **Local program store:** a directory containing artifacts and executable
bytes. It uses an OCI layout but does not contact a registry.
* **Provider:** the object that packages programs and starts processes using
the operating-system support available on this machine.
* **Topology:** which functions and VM belong to which processes. You describe
it with `SandboxBuilder`.
* **Profile:** the restrictions requested for one process. `Unrestricted`
means no process controls and caller-user permissions.
* **Restart policy:** how often Hyperlight may replace a worker that exits.
* **Resource transfer:** passing an already-open file to a worker with exact
rights, without letting it reopen an arbitrary path.
* **VM authority:** one-time permission for a worker to create a nested VM.

## Minimal worker example

### 1\. Enable the feature

Add the feature to the application and worker crates:

```toml
\[dependencies]
hyperlight-host = { workspace = true, features = \["process-isolation"] }
```

Replace `workspace = true` with your normal version or repository source when
using Hyperlight outside this workspace.

### 2\. Share a contract

Put this contract in a crate or module used by both executables:

```rust
use hyperlight\_host::process::{HostFunctionContract, Idempotency};

pub const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("HostAdd", Idempotency::Idempotent);
```

`Idempotent` allows replay after an uncertain worker failure. Use
`NonIdempotent` when repeating the function could repeat an external effect.

### 3\. Build the worker executable

The worker captures its launch connection, registers `HostAdd`, and waits:

```rust
use hyperlight\_host::process::{ProcessHostFunctions, ProcessStartup};
use hyperlight\_host::{Result, new\_error};
use my\_contracts::ADD;

fn main() -> Result<()> {
    // SAFETY: this is process entry, before threads or inherited-resource users.
    let startup = unsafe { ProcessStartup::capture() }?
        .ok\_or\_else(|| new\_error!("Worker was not launched by Hyperlight"))?;

    let mut functions = ProcessHostFunctions::default();
    functions.bind(ADD, |left, right| left + right)?;
    functions.run(startup)
}
```

Build it for the same platform as the application:

```sh
cargo build --features process-isolation --bin my-function-worker
```

Do not start the worker yourself. Hyperlight supplies a private launch
connection when the provider starts it.

### 4\. Register the worker and build the sandbox

`with\_program` packages the executable. The name `"calculator"` links it to
the matching `ProcessOptions`.

```rust
use std::path::Path;
use hyperlight\_host::process::{
    HostFunctionProcess, MeshProcessProvider, ProcessOptions, ProcessProfile,
};
use hyperlight\_host::{Result, SandboxBuilder};
use my\_contracts::ADD;

fn build\_sandbox(
    guest: \&Path,
    worker\_exe: \&Path,
) -> Result<hyperlight\_host::MultiUseSandbox> {
    let provider = MeshProcessProvider::discover()?
        .with\_program("calculator", worker\_exe)?;

    let worker = HostFunctionProcess::new(ProcessOptions::for\_provider(
        "calculator",
        ProcessProfile::unrestricted(),
    ))
    .function(ADD);

    SandboxBuilder::from\_file(guest)
        .mesh\_process\_provider(provider)
        .host\_function\_process(worker)
        .build()
}
```

The provider creates a temporary local program store. The builder assigns
`HostAdd` to the worker. The VM remains in the application process.

### 5\. Call and shut down

The guest makes its normal host call. Hyperlight routes it to the worker:

```rust
let mut sandbox = build\_sandbox(guest\_path, worker\_path)?;
let value = sandbox.call::<i32>("Add", (17, 25))?;
assert\_eq!(value, 42);
assert\_eq!(sandbox.process\_reports().len(), 1);
sandbox.shutdown()?;
```

A contract mismatch stops startup before guest initialization. Shutdown stops
the worker and cleans up the process state owned by this sandbox.

## Put the VM in another process

Build a second executable when the VM should not live in the application:

```rust
use hyperlight\_host::process::{
    ProcessHostFunctions, ProcessStartup, SandboxHost,
};
use hyperlight\_host::{Result, new\_error};

fn main() -> Result<()> {
    // SAFETY: capture runs at process entry before threads are created.
    let startup = unsafe { ProcessStartup::capture() }?
        .ok\_or\_else(|| new\_error!("VM host was not launched by Hyperlight"))?;
    SandboxHost::new(ProcessHostFunctions::default()).run(startup)
}
```

Register it before cloning the provider:

```rust
let provider = MeshProcessProvider::discover()?
    .with\_program("calculator", worker\_exe)?
    .with\_program("vm-host", vm\_host\_exe)?;
```

On Linux and macOS:

```rust
let builder = builder.sandbox\_process(ProcessOptions::for\_provider(
    "vm-host",
    ProcessProfile::unrestricted(),
));
```

On Windows, use the explicit WHP-compatible same-user boundary:

```rust
let builder = builder.windows\_vm\_host\_process(ProcessOptions::for\_provider(
    "vm-host",
    ProcessProfile::unrestricted(),
));
```

Use `sandbox\_host\_function(CONTRACT)` for a function implemented inside the VM
host executable.

## Restricted profiles

Use a restricted profile when the platform must enforce process controls.
At least one control must be required:

```rust
use hyperlight\_host::process::{
    ProcessControl, ProcessProfile, RequestedControl,
};

let profile = ProcessProfile::new(\[
    RequestedControl {
        control: ProcessControl::MemoryLimit(512 \* 1024 \* 1024),
        required: true,
    },
    RequestedControl {
        control: ProcessControl::DenyChildProcesses,
        required: true,
    },
]);
```

Other controls are `CpuBudget` and `DenyNetwork`. Windows also has
`windows\_cpu\_rate\_limit\_percent`. A required unsupported control stops startup.
macOS rejects all restricted profiles before staging or starting a process.

`ProcessProfile::unrestricted()` cannot include controls or platform limits.

## Worker restarts

The default allows three worker restarts in 60 seconds. Override it with
`SandboxBuilder::process\_restart\_policy`:

```rust
let policy = hyperlight\_host::process::RestartPolicy {
    max\_restarts: 3,
    window: std::time::Duration::from\_secs(60),
    initial\_backoff: std::time::Duration::from\_millis(100),
    max\_backoff: std::time::Duration::from\_secs(5),
};
let builder = builder.process\_restart\_policy(policy);
```

Replay also depends on the contract's `Idempotency`. An exhausted restart
budget returns an error. Hyperlight does not move the function in-process.

## Snapshots

A snapshot records the process arrangement and program digests. It does not
record reusable launch permission or open files.

Save provider-packaged programs with the snapshot:

```rust
let snapshot = sandbox.snapshot()?;
let digest = snapshot.save\_with\_process\_provider(
    "snapshot-layout",
    \&hyperlight\_host::sandbox::snapshot::OciTag::new("placed")?,
    \&provider,
)?;
```

Load it with a fresh provider:

```rust
use std::sync::Arc;
use hyperlight\_host::sandbox::snapshot::Snapshot;

let snapshot = Arc::new(Snapshot::checked\_load("snapshot-layout", digest)?);
let provider = MeshProcessProvider::discover\_for\_snapshot("snapshot-layout")?;
let builder = SandboxBuilder::from\_snapshot(snapshot)
    .mesh\_process\_provider(provider);
```

Call `allow\_windows\_vm\_host()` again for a Windows snapshot with a VM host.
Register files, Linux launch resources, export policies, and VM authority again.

## Files and VM authority

Use file transfer when a worker needs one open file with exact rights.
`ProcessHostFunctions::run\_with\_resources` receives those files. Use
`register\_vm\_authority` only when a worker must create a nested VM. The
authority belongs to one worker generation.

Working examples:

* `src/hyperlight\_host/tests/fixtures/process\_file\_resource.rs`
* `src/hyperlight\_host/tests/fixtures/process\_vm\_authority.rs`
* `src/hyperlight\_host/tests/fixtures/nested\_sandbox.rs`

## Explicit program stores

Most applications should use `MeshProcessProvider::with\_program`. Custom
packagers can use `LocalProgramStore::package` with a `ProgramConfig`, then put
the returned `ProgramArtifact` in `ProcessOptions::new`.

The config contains schema version `1`, the `ProgramRole`, the exact
`ProgramTarget`, and the worker's `FunctionContractDefinition` values. Pass the
store and target to `SandboxBuilder::process\_programs`. See
`src/hyperlight\_host/src/process/sandbox\_tests.rs` for compact examples.

## Platform summary

|Platform|Restricted worker|Dedicated VM host|Unrestricted|
|-|-|-|-|
|Windows|AppContainer and Job Object controls|Same-user process outside AppContainer|Yes|
|Linux|Namespaces, seccomp, Landlock, and cgroups when available|Yes|Yes|
|macOS|No|Yes|Yes|

macOS processes run with caller-user permissions. Each process root owns a
dedicated Mesh. See
[`docs/process-isolation-macos-qualification.md`](../../docs/process-isolation-macos-qualification.md)
for native Apple Silicon checks.

## More examples

* `src/hyperlight\_host/tests/fixtures/process\_placement.rs` covers worker-only,
VM-host-only, and combined placement.
* `src/hyperlight\_host/tests/fixtures/process\_worker.rs` is a small worker.
* `src/hyperlight\_host/tests/fixtures/sandbox\_worker.rs` is a small VM host.
* `src/hyperlight\_host/examples/process\_worker.rs` shows explicit artifact
declaration.

Repository commands:

```sh
just guests
cargo build -p hyperlight-host --features process-isolation \\
  --example process\_worker --example sandbox\_worker --example process\_placement
cargo test -p hyperlight-host --features process-isolation process::
```

