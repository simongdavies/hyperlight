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

## Run the guided sample

`process_isolation_cli` is the application-facing walkthrough. It is one
executable that acts as the application, function worker, and VM host. The
default menu runs one scenario at a time and pauses while native processes are
live. The tables show observed PIDs, parent relationships, executable paths,
placement, requested controls, effective controls, and lifecycle changes.

Build the guest and sample:

```sh
just guests
cargo build -p hyperlight-host --features process-isolation \
  --example process_isolation_cli
```

### Linux restricted-mode setup

Unrestricted Linux processes need no additional setup. Restricted profiles,
blocked child-process checks, and nested VM authority require resources
delegated by the host operator.

Provide an empty cgroup v2 directory that the application user can modify and
create children below. A systemd unit or container supervisor should create
this directory. For systemd, configure the owning unit with `Delegate=yes`.
Enable the `memory` controller because the sample restricted profile requests
a memory limit. Enable `cpu` when using `ProcessControl::CpuBudget`.

Verify the delegated directory before running:

```sh
CGROUP_ROOT=/sys/fs/cgroup/your-delegated-subtree

test "$(stat -fc %T "$CGROUP_ROOT")" = cgroup2fs
test -w "$CGROUP_ROOT"
test -w "$CGROUP_ROOT/cgroup.procs"
grep -qw memory "$CGROUP_ROOT/cgroup.controllers"
printf '+memory\n' > "$CGROUP_ROOT/cgroup.subtree_control"
grep -qw memory "$CGROUP_ROOT/cgroup.subtree_control"
```

Enable `cpu` in the same file when requesting CPU budgets.

Provide an explicitly trusted Minijail executable. Hyperlight requires an
absolute path and verifies its SHA-256 before every restricted launch.

```sh
export HYPERLIGHT_MESH_PROCESS_CGROUP_ROOT="$CGROUP_ROOT"
export HYPERLIGHT_MESH_PROCESS_MINIJAIL=/absolute/path/to/minijail0
export HYPERLIGHT_MESH_PROCESS_MINIJAIL_SHA256="$(
  sha256sum "$HYPERLIGHT_MESH_PROCESS_MINIJAIL" | cut -d ' ' -f1
)"
```

Nested VM authority also requires read/write access to `/dev/kvm` or
`/dev/mshv`:

```sh
test -r /dev/kvm && test -w /dev/kvm
```

Use `/dev/mshv` in that check when MSHV is the selected backend. The walkthrough
reports restricted scenarios as unavailable when delegated authority or a
required device is absent.

Run the interactive menu:

```sh
cargo run -p hyperlight-host --features process-isolation \
  --example process_isolation_cli -- \
  --guest src/tests/rust_guests/bin/debug/simpleguest
```

Run the complete walkthrough without prompts:

```sh
cargo run -p hyperlight-host --features process-isolation \
  --example process_isolation_cli -- \
  --guest src/tests/rust_guests/bin/debug/simpleguest \
  --non-interactive --details all
```

Every subcommand is independently runnable. Replace `all` in the previous
command with one of these names:

|Subcommand|What it demonstrates|
|-|-|
|`placement`|Local, function-worker, VM-host, and combined placement|
|`containment`|Unrestricted and restricted profiles with observed platform enforcement|
|`recovery`|Worker crash, replacement PID, and idempotent retry|
|`resources`|Typed file transfer with read/write and read-only rights|
|`vm-authority`|Generation-bound VM authority and a nested sandbox|
|`child-policy`|Allowed and blocked worker child-process creation|
|`timing`|Basic local and isolated callback timing|
|`all`|All applicable scenarios without prompts|

Use `--iterations COUNT` with `timing`. Use `--details` to include native
inspection and enforcement mechanisms. The timing output is illustrative, not
a benchmark.

Restricted macOS runs are expected to fail before spawn. The walkthrough
reports that limitation as an observed, successful capability check. It never
labels an unobserved control as enforced.

## Minimal worker example

### 1. Enable the feature

Add the feature to the application and worker crates:

```toml
[dependencies]
hyperlight-host = { workspace = true, features = ["process-isolation"] }
```

Replace `workspace = true` with your normal version or repository source when
using Hyperlight outside this workspace.

### 2. Share a contract

Put this contract in a crate or module used by both executables:

```rust
use hyperlight_host::process::{HostFunctionContract, Idempotency};

pub const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("HostAdd", Idempotency::Idempotent);
```

`Idempotent` allows replay after an uncertain worker failure. Use
`NonIdempotent` when repeating the function could repeat an external effect.

### 3. Build the worker executable

The worker captures its launch connection, registers `HostAdd`, and waits:

```rust
use hyperlight_host::process::{ProcessHostFunctions, ProcessStartup};
use hyperlight_host::{Result, new_error};
use my_contracts::ADD;

fn main() -> Result<()> {
    // SAFETY: this is process entry, before threads or inherited-resource users.
    let startup = unsafe { ProcessStartup::capture() }?
        .ok_or_else(|| new_error!("Worker was not launched by Hyperlight"))?;

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

### 4. Register the worker and build the sandbox

`with_program` packages the executable. The name `"calculator"` links it to
the matching `ProcessOptions`.

```rust
use std::path::Path;
use hyperlight_host::process::{
    HostFunctionProcess, MeshProcessProvider, ProcessOptions, ProcessProfile,
};
use hyperlight_host::{Result, SandboxBuilder};
use my_contracts::ADD;

fn build_sandbox(
    guest: &Path,
    worker_exe: &Path,
) -> Result<hyperlight_host::MultiUseSandbox> {
    let provider = MeshProcessProvider::discover()?
        .with_program("calculator", worker_exe)?;

    let worker = HostFunctionProcess::new(ProcessOptions::for_provider(
        "calculator",
        ProcessProfile::unrestricted(),
    ))
    .function(ADD);

    SandboxBuilder::from_file(guest)
        .mesh_process_provider(provider)
        .host_function_process(worker)
        .build()
}
```

The provider creates a temporary local program store. The builder assigns
`HostAdd` to the worker. The VM remains in the application process.

### 5. Call and shut down

The guest makes its normal host call. Hyperlight routes it to the worker:

```rust
let mut sandbox = build_sandbox(guest_path, worker_path)?;
let value = sandbox.call::<i32>("Add", (17, 25))?;
assert_eq!(value, 42);
assert_eq!(sandbox.process_reports().len(), 1);
sandbox.shutdown()?;
```

A contract mismatch stops startup before guest initialization. Shutdown stops
the worker and cleans up the process state owned by this sandbox.

## Put the VM in another process

Build a second executable when the VM should not live in the application:

```rust
use hyperlight_host::process::{
    ProcessHostFunctions, ProcessStartup, SandboxHost,
};
use hyperlight_host::{Result, new_error};

fn main() -> Result<()> {
    // SAFETY: capture runs at process entry before threads are created.
    let startup = unsafe { ProcessStartup::capture() }?
        .ok_or_else(|| new_error!("VM host was not launched by Hyperlight"))?;
    SandboxHost::new(ProcessHostFunctions::default()).run(startup)
}
```

Register it before cloning the provider:

```rust
let provider = MeshProcessProvider::discover()?
    .with_program("calculator", worker_exe)?
    .with_program("vm-host", vm_host_exe)?;
```

On Linux and macOS:

```rust
let builder = builder.sandbox_process(ProcessOptions::for_provider(
    "vm-host",
    ProcessProfile::unrestricted(),
));
```

On Windows, use the explicit WHP-compatible same-user boundary:

```rust
let builder = builder.windows_vm_host_process(ProcessOptions::for_provider(
    "vm-host",
    ProcessProfile::unrestricted(),
));
```

Use `sandbox_host_function(CONTRACT)` for a function implemented inside the VM
host executable.

## Restricted profiles

Use a restricted profile when the platform must enforce process controls.
At least one control must be required:

```rust
use hyperlight_host::process::{
    ProcessControl, ProcessProfile, RequestedControl,
};

let profile = ProcessProfile::new([
    RequestedControl {
        control: ProcessControl::MemoryLimit(512 * 1024 * 1024),
        required: true,
    },
    RequestedControl {
        control: ProcessControl::DenyChildProcesses,
        required: true,
    },
]);
```

Other controls are `CpuBudget` and `DenyNetwork`. Windows also has
`windows_cpu_rate_limit_percent`. A required unsupported control stops startup.
macOS rejects all restricted profiles before staging or starting a process.

`ProcessProfile::unrestricted()` cannot include controls or platform limits.

## Worker restarts

The default allows three worker restarts in 60 seconds. Override it with
`SandboxBuilder::process_restart_policy`:

```rust
let policy = hyperlight_host::process::RestartPolicy {
    max_restarts: 3,
    window: std::time::Duration::from_secs(60),
    initial_backoff: std::time::Duration::from_millis(100),
    max_backoff: std::time::Duration::from_secs(5),
};
let builder = builder.process_restart_policy(policy);
```

Replay also depends on the contract's `Idempotency`. An exhausted restart
budget returns an error. Hyperlight does not move the function in-process.

## Snapshots

A snapshot records the process arrangement and program digests. It does not
record reusable launch permission or open files.

Save provider-packaged programs with the snapshot:

```rust
let snapshot = sandbox.snapshot()?;
let digest = snapshot.save_with_process_provider(
    "snapshot-layout",
    &hyperlight_host::sandbox::snapshot::OciTag::new("placed")?,
    &provider,
)?;
```

Load it with a fresh provider:

```rust
use std::sync::Arc;
use hyperlight_host::sandbox::snapshot::Snapshot;

let snapshot = Arc::new(Snapshot::checked_load("snapshot-layout", digest)?);
let provider = MeshProcessProvider::discover_for_snapshot("snapshot-layout")?;
let builder = SandboxBuilder::from_snapshot(snapshot)
    .mesh_process_provider(provider);
```

Call `allow_windows_vm_host()` again for a Windows snapshot with a VM host.
Register files, Linux launch resources, export policies, and VM authority again.

## Files and VM authority

Use file transfer when a worker needs one open file with exact rights.
`ProcessHostFunctions::run_with_resources` receives those files. Use
`register_vm_authority` only when a worker must create a nested VM. The
authority belongs to one worker generation.

Working examples:

* `src/hyperlight_host/tests/fixtures/process_file_resource.rs`
* `src/hyperlight_host/tests/fixtures/process_vm_authority.rs`
* `src/hyperlight_host/tests/fixtures/nested_sandbox.rs`

## Explicit program stores

Most applications should use `MeshProcessProvider::with_program`. Custom
packagers can use `LocalProgramStore::package` with a `ProgramConfig`, then put
the returned `ProgramArtifact` in `ProcessOptions::new`.

The config contains schema version `1`, the `ProgramRole`, the exact
`ProgramTarget`, and the worker's `FunctionContractDefinition` values. Pass the
store and target to `SandboxBuilder::process_programs`. See
`src/hyperlight_host/src/process/sandbox_tests.rs` for compact examples.

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

* `src/hyperlight_host/examples/process-isolation-cli/` is the guided
application sample.
* `src/hyperlight_host/tests/fixtures/process_placement.rs` covers worker-only,
VM-host-only, and combined placement.
* `src/hyperlight_host/tests/fixtures/process_worker.rs` is a small worker.
* `src/hyperlight_host/tests/fixtures/sandbox_worker.rs` is a small VM host.
* `src/hyperlight_host/examples/process_worker.rs` shows explicit artifact
declaration.

Repository commands:

```sh
just guests
cargo build -p hyperlight-host --features process-isolation \
  --example process_isolation_cli
cargo test -p hyperlight-host --features process-isolation process::
```
