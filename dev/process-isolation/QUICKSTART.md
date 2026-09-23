# Process placement quickstart

This example demonstrates Hyperlight sandbox and host-function placement through
a Mesh/PAL process provider. Application code declares topology, typed contracts
and `ProcessProfile` constraints. It does not construct platform launch resources.

## Product feature versus this demo

Hyperlight remains an in-process Rust API. Process placement is an optional Mesh
capability consumed by `SandboxBuilder`.

Application-owned packaging uses the source-compatible
`ProcessOptions::new(name, artifact, profile)` API. Provider-backed applications
use `ProcessOptions::for_provider(name, profile)`.

```text
application
  | placement + contracts + ProcessProfile
  v
MeshProcessProvider
  | packages the native role and acquires current-host authority
  v
Mesh/PAL launcher
  | creates and confines sandbox hosts and function workers
  v
Hyperlight sandbox topology
```

The provider owns executable packaging, platform confinement, cleanup and current
host authorization. Linux helper paths, delegated resource domains, device access
and runtime-library closure are provider implementation details. Windows
AppContainer setup is also provider-owned. These values are not part of the
application API.

By default, the provider packages the application executable so it can enter a
worker or sandbox-host role. Applications may register a dedicated executable
for a logical process name with `MeshProcessProvider::with_program`. The
provider still owns its runtime closure and platform launch resources.

On Windows, the provider packages imported DLLs found beside the executable and
leaves Windows system DLLs to the host. Applications can add files that cannot
be inferred with `with_runtime_file` or `with_program_runtime_file`. This is a
bounded side-by-side closure, not a general installer or arbitrary DLL resolver.
Explicit files are registered before placement resolves and validates the full
transitive import closure.

Low-level platform-resource injection remains available to qualification tests
and specialized embedders. It is not the normal integration path.

Snapshots preserve guest state, process topology, typed contracts and immutable
program references. `save_with_process_provider` copies referenced native program
artifacts into an OCI layout. An OCI layout is a content-addressed directory of
manifests and blobs. Host launch authority is never stored. Reconstruction calls
`MeshProcessProvider::discover_for_snapshot`, which reacquires authority from the
current host.

| Item | Reader | Purpose | Portable? |
| --- | --- | --- | --- |
| Placement and `ProcessProfile` | Hyperlight and Mesh provider | Declares process ownership and required controls | Yes |
| OCI snapshot layout | Hyperlight and Mesh provider | Stores guest state and immutable program artifacts | Subject to snapshot platform compatibility |
| Provider authority | Mesh/PAL platform integration | Launches and confines current-host processes | No. Reacquire on every reconstruction |
| Measurement JSON | Optional analysis scripts | Records benchmark observations | Data only. Not a runtime input |

The guest never reads host placement configuration.

## What the example proves

The `process_placement` executable can run as the controller, a function worker
or a sandbox host. `ProcessStartup` selects the launched role. Executable-local
Rust functions are registered only after Mesh supplies that role's one-shot
startup capability.

Each mode verifies:

* identical `Add(17, 25) == 42` behavior
* string callback behavior where the mode includes `RoundTripHostString`
* guest static-state mutation and in-memory restore
* OCI export and checked load
* destruction of the original topology
* reconstruction with fresh native roles and fresh current-host authorization

The process reports show native roles created for the original and reconstructed
topologies. `local` prints empty reports because the VM and callbacks remain in
the caller process. This is expected. The example does not measure performance.
It does not demonstrate process confinement for `local`.

| Mode | VM placement | Host-function placement |
| --- | --- | --- |
| `local` | Caller process | Caller process |
| `function-worker` | Caller process | One confined function worker |
| `vm-host` | One dedicated sandbox host | Beside the VM in the sandbox host |
| `vm-host-and-function-worker` | One dedicated sandbox host | Separate confined worker with direct sandbox-to-worker routing |
| `worker-children-allowed` | Caller process | Confined worker profile permits child creation |
| `worker-children-blocked` | Caller process | Confined worker profile requires child-creation denial |

Function workers belong to one sandbox. They are not shared across independent
sandboxes. The guest cannot select a worker, channel or profile.

## Platform status

| Platform and role | Implementation and evidence | Status |
| --- | --- | --- |
| Windows `FunctionWorker` | Provider creates a distinct AppContainer with job, memory, CPU, network and child controls. See the [native execution record](WINDOWS-QUALIFICATION.md) | Native campaign passed on the recorded working tree and host |
| Windows sandbox host, AppContainer | This remains the general API default. WHP access was denied from AppContainer on the tested host | Fail-closed default, not a usable WHP path on that host |
| Windows VM host | `windows_vm_host_process` selects and authorizes an ordinary non-elevated WHP-compatible process. Memory, hard CPU rate, active-process, child, kill-on-close, handle-inheritance and private-staging controls remain. AppContainer filesystem and network isolation do not apply. See the [native execution record](WINDOWS-QUALIFICATION.md) | Native campaign passed on the recorded working tree and host |
| Linux | Provider discovery and the reviewed confinement backend are implemented | Build and static checks completed. Native runtime qualification remains pending |
| macOS | App Sandbox requires static signed entitlements. The dynamic `sandbox_init` interface is deprecated and has no supported replacement. The pinned Mesh dependency exposes owned-process launch only on Windows and Linux. No production backend uses deprecated Apple APIs | Unsupported |

Cross-compiling for `aarch64-apple-darwin` checks Rust cfgs and types only. macOS
support requires a native Apple Silicon build, signing and runtime campaign that
proves confinement denials, child and network policy, cleanup, Mesh transport,
snapshot reconstruction and HVF interaction.

## Windows PowerShell build

Run these commands in an ordinary non-elevated PowerShell session from the
repository root. No service installation or privileged setup is required.

```powershell
just build-rust-guests debug
just move-rust-guests debug
cargo +1.95 build --locked -p hyperlight-host --features process-isolation --example process_placement

$Guest = (Resolve-Path 'src\tests\rust_guests\bin\debug\simpleguest').Path
$Example = (Resolve-Path 'target\debug\examples\process_placement.exe').Path
$RunRoot = Join-Path (Resolve-Path 'target').Path ("pq-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $RunRoot -ErrorAction Stop | Out-Null

& $Example --help
```

Each mode owns its output directory and refuses an existing path. The unique
parent makes repeated campaigns independent. Create another `$RunRoot` for a
second campaign. Do not delete a failed run until its reports and snapshot have
been inspected. Keep the root short because OCI blob filenames add 64 characters
and the current atomic-write stack uses Windows paths limited by `MAX_PATH`.
The example resolves the output path before launch and requires the absolute
output directory to fit within 172 UTF-16 units. Longer paths fail before the
directory or topology is created and report the measured and maximum lengths.
The `pq-` plus GUID run-root name consumes 35 of those units beyond the resolved
`target` directory.
Extended-length paths require consistent support across temporary-file,
rename, OCI and consumer APIs. This example does not assume the machine-wide
registry and application-manifest opt-ins required by Windows long-path mode.

## Windows six-mode campaign

```powershell
& $Example local $Guest (Join-Path $RunRoot 'local')
& $Example function-worker $Guest (Join-Path $RunRoot 'function-worker')
& $Example worker-children-allowed $Guest (Join-Path $RunRoot 'worker-children-allowed')
& $Example worker-children-blocked $Guest (Join-Path $RunRoot 'worker-children-blocked')
& $Example vm-host $Guest (Join-Path $RunRoot 'vm-host') --allow-windows-vm-host
& $Example vm-host-and-function-worker $Guest (Join-Path $RunRoot 'vm-host-and-function-worker') --allow-windows-vm-host
```

The explicit flag acknowledges that the VM-owning process runs outside
AppContainer. Omitting it fails before guest initialization. The application API
uses `SandboxBuilder::windows_vm_host_process` for a new VM host and
`allow_windows_vm_host` when reconstructing a saved snapshot. The compatibility
names `WindowsSandboxHostPolicy::Trusted` and
`allow_trusted_windows_sandbox_host` remain accepted. An elevated controller is
rejected. Run the campaign from an ordinary non-elevated PowerShell session.
The serialized compatibility discriminant remains `trusted`.

Every successful command prints:

* `Add = 42`
* original and reconstructed process reports
* the effective OS boundary for each process
* each applicable requested memory, CPU, network and child control
* the OCI snapshot layout and manifest digest
* a final `PASS` line after checked snapshot load, reconstruction, explicit
  shutdown and PID residue verification

`local` has no additional process report. VM hosts do not request AppContainer
network denial. `worker-children-allowed` does not request child-process denial.

Expected reports:

| Mode | Original and reconstructed reports |
| --- | --- |
| `local` | No additional native processes |
| `function-worker` | One AppContainer `FunctionWorker` with child denial |
| `worker-children-allowed` | One AppContainer worker without child denial |
| `worker-children-blocked` | One AppContainer worker with child policy and Job active-process limit |
| `vm-host` | One ordinary non-elevated `SandboxHost`; co-located functions have no AppContainer filesystem or network isolation |
| `vm-host-and-function-worker` | One ordinary non-elevated `SandboxHost` plus one separate AppContainer `FunctionWorker` with child denial |

Windows function workers request a 512 MiB Job memory limit, a hard Job CPU rate
of 50 percent of aggregate host processor capacity and AppContainer network
denial. The blocked-child profile also
requires child-process denial, as do `function-worker` and the function worker
in `vm-host-and-function-worker`. Windows VM hosts request the memory limit, CPU
rate and child denial. They do not request `DenyNetwork` because that control is
unavailable outside AppContainer. The Windows CPU-rate setting supplements a
profile with another required process control. A required exact quota/period
`CpuBudget` or required VM-host `DenyNetwork` fails with an actionable error.

The VM boundary still protects guest execution. The ordinary VM-host process is
not a filesystem or network boundary against its caller or other same-user
processes. `vm-host` places host functions in that same process. Use
`vm-host-and-function-worker` when host functions need AppContainer confinement.

The executable checks every reported original and reconstructed PID after
fallible shutdown. `PASS` is printed only after those checks succeed. As an
external campaign assertion, also confirm that no `process_placement` process
remains:

```powershell
Get-Process process_placement -ErrorAction SilentlyContinue
```

No output is expected. Repeat the campaign with a new unique `$RunRoot` to
exercise fresh staging, AppContainer profile creation, cleanup and snapshot
directories.

## Linux checkout and build

Use Ubuntu 24.04 Bash for the Linux example. On WSL2, keep the checkout and
target directory on the distro filesystem.

```bash
: "${HYPERLIGHT_REPOSITORY_URL:?Set the repository URL}"
: "${HYPERLIGHT_REF:?Set the branch containing this quickstart}"
git clone --branch "$HYPERLIGHT_REF" --single-branch \
  "$HYPERLIGHT_REPOSITORY_URL" hyperlight-process-demo
cd hyperlight-process-demo

cargo +1.95 build --locked -p hyperlight-host --features process-isolation \
  --example process_placement
just build-rust-guests debug
just move-rust-guests debug
export GUEST="$PWD/src/tests/rust_guests/bin/debug/simpleguest"
test -s "$GUEST"
mkdir -p target/process-demo
export RUN_ROOT="$PWD/target/process-demo/$(date -u +%Y%m%dT%H%M%S)-$(cat /proc/sys/kernel/random/uuid)"
```

`Cargo.toml` and `Cargo.lock` pin the required Mesh/OpenVMM revision. Do not add a
path override or replace it with upstream main.

## Linux `local`

`local` needs no process provider or OS launcher:

```bash
target/debug/examples/process_placement \
  local "$GUEST" "$RUN_ROOT/local"
```

Each output directory must be new. Create only its parent. To preserve and retry:

```bash
mv "$RUN_ROOT/local" "$RUN_ROOT/local.saved"
target/debug/examples/process_placement \
  local "$GUEST" "$RUN_ROOT/local"
```

## Linux process-backed modes

Process-backed modes require an operator-configured supervisor that grants the
Mesh provider a bounded delegated run. This repository does not install a
privileged service or broaden the current user's device access.

The commands below are **request payloads for that supervisor**. Do not run them
directly in an ordinary shell. The supervisor must set up provider discovery,
enforce an outer deadline, kill the whole request domain on failure and verify
cleanup before accepting another request.

```bash
target/debug/examples/process_placement \
  function-worker "$GUEST" "$RUN_ROOT/function-worker"

target/debug/examples/process_placement \
  vm-host "$GUEST" "$RUN_ROOT/vm-host"

target/debug/examples/process_placement \
  vm-host-and-function-worker "$GUEST" "$RUN_ROOT/vm-host-and-function-worker"

target/debug/examples/process_placement \
  worker-children-allowed "$GUEST" "$RUN_ROOT/worker-children-allowed"

target/debug/examples/process_placement \
  worker-children-blocked "$GUEST" "$RUN_ROOT/worker-children-blocked"
```

Provider discovery fails closed before guest initialization when the supervisor
has not supplied launch authority. Required controls that the current platform
cannot enforce also fail startup. Optional omissions appear in `ProcessReport`.

The Linux provider currently expects the reviewed strict-helper and delegated
authority installation used by the process-isolation qualification environment.
That installation is an operator task, not application configuration. See
[the backend qualification notes](README.md) for the exact Linux control model.

## Focused validation without privileged runtime

These commands do not launch confined processes:

```bash
cargo +1.95 test --locked -p hyperlight-host \
  --features process-isolation --lib process::
cargo +1.95 test --locked -p hyperlight-host \
  --features process-isolation --example process_placement
cargo +1.95 clippy --locked -p hyperlight-host \
  --features process-isolation --all-targets -- -D warnings
just clippym
git diff --check
```

`just clippym` is cross-Clippy only. It does not qualify macOS.

## Existing fixtures and test-only scenarios

| Fixture | Purpose | Intended use |
| --- | --- | --- |
| `process_worker` | Direct function-worker bootstrap | Internal protocol and qualification tests |
| `sandbox_worker` | Dedicated sandbox-host bootstrap | Internal protocol and qualification tests |
| `process_child_policy` | Linux child/thread enforcement probe | Linux qualification tests |
| `isolation_bench` | Controlled placement, resident-memory and recovery measurements | Bounded measurement campaign |
| `isolation_bench_worker` | Measurement function worker | Launched by the measurement controller |
| `isolation_bench_sandbox` | Measurement sandbox host | Launched by the measurement controller |
| `isolation_local_consumer` | Feature-disabled local-path size/control binary | Build comparison only |

Worker and sandbox fixtures require inherited `ProcessStartup`. They are not
standalone commands.

Failure/replacement and idempotency behavior is exercised by the process runtime
tests and the bounded `isolation_bench` recovery mode. The six-mode demo checks
placement and reconstruction but does not deliberately crash a worker.

## Measurement tools

Measurement JSON is optional tooling output. It is not provider configuration.
The bounded runner and summarizer remain under `dev/process-isolation/`:

```bash
python3 dev/process-isolation/test_summarize_bench.py
python3 dev/process-isolation/summarize_bench.py \
  target/process-isolation-results \
  --output target/process-isolation-summary.json
```

Native measurements require the separate operator-approved observer, deadlines
and cleanup protocol documented in [README.md](README.md). Fixture presence is
not a qualification result.
