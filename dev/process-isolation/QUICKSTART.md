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
| `worker` | Caller process | One confined function worker |
| `sandbox` | One confined sandbox host | Beside the VM in that sandbox host |
| `sandbox-worker` | One confined sandbox host | Separate confined worker with direct sandbox-to-worker routing |
| `children-allow` | Caller process | Worker profile permits child creation |
| `children-deny` | Caller process | Worker profile requires child-creation denial |

Function workers belong to one sandbox. They are not shared across independent
sandboxes. The guest cannot select a worker, channel or profile.

## Platform status

| Platform and role | Implementation and evidence | Status |
| --- | --- | --- |
| Windows `FunctionWorker` | Provider creates a distinct AppContainer with job, memory, CPU, network and child controls. Native Windows qualification passed on the reviewed branch | Qualified by the recorded Windows tests |
| Windows sandbox host, AppContainer | This is the default requested policy. WHP access was denied from AppContainer on the tested host | Implemented, not a proven usable WHP path |
| Windows sandbox host, trusted | Explicit `allow_trusted_windows_sandbox_host` permission runs the VM host outside AppContainer. Job/resource/child controls remain. Filesystem and network AppContainer isolation do not | Proven path on the tested Windows host |
| Linux | Provider discovery and the reviewed confinement backend are implemented | Build and static checks completed. Native runtime qualification remains pending |
| macOS | App Sandbox requires static signed entitlements. The dynamic `sandbox_init` interface is deprecated and has no supported replacement. The pinned Mesh dependency exposes owned-process launch only on Windows and Linux. No production backend uses deprecated Apple APIs | Unsupported |

Cross-compiling for `aarch64-apple-darwin` checks Rust cfgs and types only. macOS
support requires a native Apple Silicon build, signing and runtime campaign that
proves confinement denials, child and network policy, cleanup, Mesh transport,
snapshot reconstruction and HVF interaction.

## Checkout and build

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
```

`Cargo.toml` and `Cargo.lock` pin the required Mesh/OpenVMM revision. Do not add a
path override or replace it with upstream main.

## Run `local`

`local` needs no process provider or OS launcher:

```bash
target/debug/examples/process_placement \
  local "$GUEST" target/process-demo/local
```

Each output directory must be new. Create only its parent. To preserve and retry:

```bash
mv target/process-demo/local target/process-demo/local.saved
target/debug/examples/process_placement \
  local "$GUEST" target/process-demo/local
```

## Run process-backed modes

Process-backed modes require an operator-configured supervisor that grants the
Mesh provider a bounded delegated run. This repository does not install a
privileged service or broaden the current user's device access.

The commands below are **request payloads for that supervisor**. Do not run them
directly in an ordinary shell. The supervisor must set up provider discovery,
enforce an outer deadline, kill the whole request domain on failure and verify
cleanup before accepting another request.

```bash
target/debug/examples/process_placement \
  worker "$GUEST" target/process-demo/worker

target/debug/examples/process_placement \
  sandbox "$GUEST" target/process-demo/sandbox

target/debug/examples/process_placement \
  sandbox-worker "$GUEST" target/process-demo/sandbox-worker

target/debug/examples/process_placement \
  children-allow "$GUEST" target/process-demo/children-allow

target/debug/examples/process_placement \
  children-deny "$GUEST" target/process-demo/children-deny
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
