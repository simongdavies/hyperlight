# Process placement quickstart

This example demonstrates Hyperlight sandbox and host-function placement through
a Mesh/PAL process provider. Application code declares topology, typed contracts
and `ProcessProfile` constraints. It does not construct platform launch resources.

## Application developer API

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

### Multiple ownership domains

One application can define several native ownership domains. Each
`HostFunctionProcess` and sandbox host gets its own immutable profile and
provider-owned cgroup:

```rust
use std::time::Duration;
use hyperlight_host::process::{
    HostFunctionProcess, MeshProcessProvider, ProcessControl, ProcessOptions,
    ProcessProfile, RequestedControl,
};

fn profile(memory: u64, cpu_ms: u64, deny_network: bool) -> ProcessProfile {
    let mut controls = vec![
        RequestedControl {
            control: ProcessControl::MemoryLimit(memory),
            required: true,
        },
        RequestedControl {
            control: ProcessControl::CpuBudget {
                quota: Duration::from_millis(cpu_ms),
                period: Duration::from_millis(100),
            },
            required: true,
        },
    ];
    if deny_network {
        controls.push(RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        });
    }
    ProcessProfile::new(controls)
}

let provider = MeshProcessProvider::discover()?;
let io_worker = HostFunctionProcess::new(ProcessOptions::for_provider(
    "io-worker",
    profile(256 << 20, 40, false),
));
let restricted_worker = HostFunctionProcess::new(ProcessOptions::for_provider(
    "restricted-worker",
    profile(128 << 20, 20, true),
));

let builder = SandboxBuilder::from_file(guest)
    .mesh_process_provider(provider)
    .host_function_process(io_worker)
    .host_function_process(restricted_worker);
```

Add typed function contracts to each process before `build()`. A function
belongs to one process. Guest input cannot select a process, profile or cgroup.
Child domains can tighten the aggregate unit ceiling but cannot raise it.

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
| Linux | Ubuntu 24.04 on WSL2 kernel 6.18 with KVM. An ordinary user ran the hardened installation through all six modes. Reports, restore, OCI reconstruction, isolated worker recovery, timeout cleanup and residue checks passed | Qualified on the tested KVM host |
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

## Linux architecture and threat boundary

The one-time privileged install writes immutable integration assets, activates
user-slice controller delegation, and grants group-based access to the present
hypervisor device. It does not install a daemon. It does not grant
capabilities. It does not make the Hyperlight host setuid or root.

Every run is a transient service created by the invoking user's systemd
manager. `DelegateSubgroup=application` places the application below an empty
delegated parent. The provider creates one sibling child cgroup per native
ownership domain. The unit's CPU, memory and task settings are aggregate
ceilings. Typed child CPU and memory controls can only tighten them.

The installed strict Minijail path is root-owned and digest checked before each
launch. A stable path allows Ubuntu AppArmor to grant user-namespace creation
only to that reviewed helper. Native roles enter private PID, mount, IPC and
network namespaces. Seccomp controls key and child-process syscalls. Landlock
controls filesystem access. Only sandbox hosts receive the selected KVM or MSHV
device. Function workers do not.

The ordinary host application is trusted to declare topology and profiles. The
guest and confined native roles are untrusted. They do not receive cgroup
control handles or visibility of the host cgroup filesystem. Another ordinary
user cannot write the invoking user's delegated subtree or root-owned
integration assets. Membership in `hyperlight` authorizes direct execution of
the AppArmor user-namespace helper, so grant it only to trusted application
accounts. The installed mode prevents other local users from using that
AppArmor exception.

## Operator installation

The Linux integration uses a one-time privileged installation. Hyperlight and
its native roles always run as the invoking unprivileged user. There is no
broker or privileged runtime.

Build and test the pinned helper as an ordinary user:

```bash
git clone https://chromium.googlesource.com/chromiumos/platform/minijail \
  target/minijail-validation/minijail
git -C target/minijail-validation/minijail checkout \
  8d20993c7189a948995bd20901abecc041e1a28e
python3 dev/process-isolation/build_minijail.py \
  target/minijail-validation/minijail --verify-recorded
python3 -u dev/process-isolation/test_minijail.py \
  target/minijail-validation/minijail/minijail0

cargo +1.95 build --locked -p hyperlight-host --features process-isolation \
  --example process_placement
just build-rust-guests debug
just move-rust-guests debug
```

Prerequisites are systemd 254 or newer, cgroup v2 with `cpu`, `memory` and
`pids`, `cgroup.kill`, unprivileged user namespaces through the installed
AppArmor profile, and Landlock ABI 5. Landlock ABI 5 normally requires Linux
6.10 or newer. The tested WSL kernel is 6.18 with Landlock ABI 7. Ubuntu 24.04
systems on the 6.8 GA kernel need a newer supported kernel before installation.

Install the verified helper, launcher and device policy. `init` validates and
prints the complete plan before requesting sudo for the mutation phase:

```bash
dev/process-isolation/hyperlight-run init \
  --plan \
  --source target/minijail-validation/minijail \
  --user "$USER"
dev/process-isolation/hyperlight-run init \
  --source target/minijail-validation/minijail \
  --user "$USER"
```

The plan is non-privileged. It validates the pinned source, patch and helper
digest and prints every mutation and required interruption. The second command
repeats that validation, then obtains sudo only for installation.

Log out and back in if the installer added group membership. WSL users can run
`wsl --shutdown` from PowerShell. Verify the installation:

```bash
hyperlight-run check
```

The installer grants `/dev/kvm` or `/dev/mshv` access through device-specific
groups and udev mode `0660`. It grants execution of the AppArmor-authorized
helper through the dedicated `hyperlight` group. It does not grant capabilities
or root execution.

The privileged command installs these exact assets:

* `/usr/libexec/hyperlight/minijail0` and its SHA-256 file
* `/usr/libexec/hyperlight/hyperlight-unit-entry`
* `/usr/bin/hyperlight-run`
* `/usr/libexec/hyperlight/hyperlight-check`
* private lifecycle and example drivers under `/usr/libexec/hyperlight`
* the built `process_placement` example and `simpleguest` under
  `/usr/libexec/hyperlight`
* `/var/lib/hyperlight/install-state.json`, mode `0600`
* `/etc/udev/rules.d/70-hyperlight-hypervisor.rules`
* `/etc/apparmor.d/usr.libexec.hyperlight.minijail0` when AppArmor is active
* systemd drop-ins under `user.slice.d`, `user-.slice.d` and
  `user@.service.d`
* membership of the selected user in `hyperlight` and the group for each
  present hypervisor device

The installer uses hard-coded source, patch and helper digests. It verifies the
exact Minijail commit, exact repository patch, absence of staged source changes
and the recorded helper digest before copying anything. The helper digest is
the byte-level trust root. Installed files and directories are root-owned. The
helper is `root:hyperlight` mode `0750`; policy and digest files are mode
`0644`. Other local users cannot execute the AppArmor-authorized helper.
The state manifest records the exact pre-install files, device ownership,
group creation and membership changes. Any failed mutation triggers bounded
rollback. Reinstallation preserves the original baseline.

`hyperlight-run` creates one transient user service per request with no sudo,
polkit prompt, setuid program, file capabilities or root process. The one-time
install activates CPU accounting through `user.slice` and `user-.slice`, and
delegates `cpu memory pids` through `user@.service`. The ordinary user's systemd
manager can then delegate those controllers to its own transient services.

The service
sets aggregate `MemoryMax`, `TasksMax`, `CPUQuota`, `RuntimeMaxSec`,
`TimeoutStopSec`, `KillMode=control-group` and `Delegate=cpu memory pids`.
`DelegateSubgroup=application` keeps the delegated parent free of processes.
Its entrypoint discovers that parent, creates an empty provider root,
and validates and supplies the three internal `HYPERLIGHT_MESH_PROCESS_*`
values. Applications must not set those variables.

The parent unit limits are aggregate ceilings. `TasksMax` is not a per-domain
`pids.max` claim. Each provider-owned child domain can tighten typed CPU and
memory limits but cannot raise the unit ceilings. Minijail
applies per-launch PID, mount, IPC and network namespaces, seccomp, Landlock and
selective hypervisor-device exposure. Cgroup membership and cleanup are
per-domain. The native roles cannot see the host cgroup filesystem.

Preview uninstall, then restore the exact pre-install state:

```bash
hyperlight-run uninstall --plan --user "$USER"
hyperlight-run uninstall --user "$USER"
```

Uninstall stops and collects active Hyperlight units, unloads installed
AppArmor policy, restores or removes every managed file and systemd drop-in,
reloads and retriggers udev policy, restores prior device ownership, removes
only the memberships and groups created by the installer, reloads systemd and
verifies the baseline. A failure rolls the uninstall back to the installed
state. Log out and back in afterward. WSL users run `wsl --shutdown`.

### Multi-user isolation verification

Each run is below the invoking user's `user-$UID.slice`. The delegated cgroup
files are writable by that user, not another ordinary user. Shared integration
assets are root-owned. Provider images use private per-user temporary
directories.

The root-assisted cross-account verifier is repository-only and remains
deferred in the recorded qualification. The installed runtime does not expose
it as a user command.

To verify the boundary with a second existing ordinary account, keep a run
alive in one terminal:

```bash
hyperlight-run run -- bash -c 'echo "PID=$$"; sleep 60'
```

In another terminal, pass the printed PID and second account:

```bash
sudo dev/process-isolation/hyperlight-verify-multi-user \
  --pid PID --other-user OTHER_USER
```

The check must report that the second account cannot enroll into or mutate the
first user's delegation and cannot modify installed assets.
It creates no users, groups, files or services. The root process only uses
`runuser` to attempt three denied `cgroup.procs` writes as the existing second
user, then checks installed paths for writability. Stop the first terminal with
Ctrl+C after the result. `hyperlight-run` kills the transient control group and
verifies unit and cgroup collection.

## Linux checkout and build

Use Ubuntu 24.04 Bash for the Linux example. On WSL2, keep the checkout and
target directory on the distro filesystem.

```bash
rustup toolchain install 1.95 1.94 nightly-2026-02-27
rustup target add --toolchain 1.94 \
  x86_64-unknown-none x86_64-unknown-linux-musl

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

## Run all modes

The installation captures root-owned copies of the built example and guest.
One command runs those installed bits in `local` and all five process-backed
modes, verifies reports and snapshot reconstruction, and checks that each
transient unit is cleaned up. It does not depend on a source checkout:

```bash
hyperlight-run examples --all
```

Results are written below a new timestamped
`hyperlight-process-isolation-output` directory in the current directory.
Rerunning is safe.

The final Ubuntu 24.04 WSL2 qualification exercised failed-install rollback,
checkout-independent check and six-mode execution, recovery, reconstruction,
outer timeout, uninstall while a transient unit was active, zero file/unit/
cgroup residue, clean reinstall, WSL restart, and a second installed six-mode
campaign. The retained combined-tree campaigns are
`/tmp/hyperlight-process-isolation-output/20260923T084522-538f5a17Z` and
`/tmp/hyperlight-process-isolation-output/20260923T085544-dc4985c6Z`.

The `sandbox-worker` case has two simultaneous provider-owned domains. The
sandbox domain has stricter network and child-process policy and a different
CPU and memory budget from the worker domain. The example verifies distinct,
stable cgroup membership, independent reports, snapshot reconstruction and
recursive cleanup. The qualification driver verifies the outer unit is gone.

Use the launcher directly for an application:

```bash
hyperlight-run run -- \
  target/debug/examples/process_placement \
  worker "$PWD/src/tests/rust_guests/bin/debug/simpleguest" \
  "$PWD/target/process-demo/worker"
```

Run `hyperlight-run --help` for aggregate ceiling and deadline options.

## Run `local` directly

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

## Process-backed command payloads

Run each payload with `hyperlight-run run --`. The qualification command above is
the supported full campaign.

```bash
hyperlight-run run -- target/debug/examples/process_placement \
  worker "$GUEST" target/process-demo/worker

hyperlight-run run -- target/debug/examples/process_placement \
  sandbox "$GUEST" target/process-demo/sandbox

hyperlight-run run -- target/debug/examples/process_placement \
  sandbox-worker "$GUEST" target/process-demo/sandbox-worker

hyperlight-run run -- target/debug/examples/process_placement \
  children-allow "$GUEST" target/process-demo/children-allow

hyperlight-run run -- target/debug/examples/process_placement \
  children-deny "$GUEST" target/process-demo/children-deny
```

Provider discovery fails closed before guest initialization when the supervisor
has not supplied launch authority. Required controls that the current platform
cannot enforce also fail startup. Optional omissions appear in `ProcessReport`.

If discovery fails, run `hyperlight-run check`. Diagnostics identify missing user
systemd, cgroup-v2 controllers, helper integrity, group membership and device
permissions.

Expected success includes `Original processes`, `Reconstructed processes`, a
mode-specific `passed (Add = 42)` line, an OCI layout path and manifest digest.
For `sandbox-worker`, the two reports have different root PIDs, cgroup paths,
memory and CPU budgets, and network and child-process policy.
The campaign also kills the pinned worker root, verifies only that domain is
replaced, verifies the retired cgroup is removed, checks membership remains
fixed across in-place restore, and runs an expected timeout failure followed by
residue checks.

Verify cleanup after a run:

```bash
systemctl --user list-units 'hyperlight-*'
find /sys/fs/cgroup/user.slice/user-"$(id -u)".slice \
  -type d -name 'hyperlight-*' -print
```

Both commands must show no completed run.

### Diagnostics

* `the user systemd manager is unavailable`: enable systemd in WSL, restart
  WSL, and log in again.
* `Landlock ABI 5 is required`: install a supported Linux 6.10 or newer kernel.
  Ubuntu 24.04 GA kernel 6.8 is insufficient.
* `unprivileged user namespaces are blocked`: verify the installed AppArmor
  profile is loaded and rerun `hyperlight-run check`.
* `cpu controller is not delegated`: rerun the installer, then log out. WSL
  needs `wsl --shutdown`.
* `helper integrity check failed`: uninstall, rebuild the pinned helper, and
  reinstall. Do not replace the installed binary.
* `/dev/kvm` or `/dev/mshv` is absent: enable the host hypervisor device.
* device exists but is not writable: verify `id`, the device group and udev
  rule, then log out and back in.
* a required control is unavailable: inspect the named controller and run
  `hyperlight-run check`. Startup fails before guest initialization.
* cleanup failure: inspect `systemctl --user status hyperlight-*` and the unit
  journal. Do not treat a failed run as successful qualification.

## Portability beyond systemd

The installed Ubuntu path is systemd-specific. These pieces depend on systemd:

* the installer drop-ins that propagate `cpu`, `memory` and `pids` through the
  user slice
* `hyperlight-run`, which creates a transient user service with aggregate
  limits, `RuntimeMaxSec`, `KillMode=control-group` and
  `DelegateSubgroup=application`
* `hyperlight-check`, which validates the user manager and its delegated cgroup
* the unit entrypoint's discovery of the empty parent above `application`

The provider is otherwise init-independent. `LinuxProcessResources`, child
domain creation, typed CPU and memory limits, Minijail confinement, reports,
recovery, snapshots and cleanup need an empty delegated cgroup-v2 subtree, a
verified helper and optional device access. They do not call systemd.

The current release has no supported non-systemd launcher. Passing arbitrary
cgroup paths through the three internal environment variables is not a public
contract. A future pre-delegated backend should receive capabilities, not path
authority:

1. The init system or container runtime creates an aggregate cgroup with
   `cpu`, `memory` and `pids` delegated, applies the outer deadline and
   aggregate ceilings, and places the application in a sibling child cgroup.
2. It opens the empty provider cgroup directory plus required control files
   such as `cgroup.procs`, `cgroup.subtree_control`, `cgroup.events` and
   `cgroup.kill`.
3. It passes those descriptors and an opened verified helper descriptor to the
   unprivileged application. Descriptor identity, cgroup-v2 filesystem type,
   enabled controllers, empty-parent state and helper digest are validated
   before provider discovery succeeds.
4. Hyperlight creates only descendants of that directory. The outer runtime
   owns deadline enforcement, whole-tree kill and final cgroup removal.

This contract needs a typed inherited-resource API in Mesh. It must not grant
`CAP_SYS_ADMIN`, expose a writable host cgroup mount, accept an arbitrary host
path, or require a persistent privileged broker.

### Current compatibility evidence

| Environment | Current status | Evidence required |
| --- | --- | --- |
| Ubuntu 24.04 WSL2, systemd 255, KVM | Installed lifecycle qualified | Failed-install rollback, check, two installed six-mode campaigns, recovery, timeout, active-unit uninstall, zero residue and clean reinstall passed on kernel 6.18 with Landlock ABI 7. Cross-account verification remains deferred |
| Ubuntu 24.04 bare metal with systemd and KVM | Expected to use the same installed path, not yet qualified here | Run installer, `hyperlight-run check`, six-mode campaign and multi-user check |
| Azure Linux with systemd | Not tested | Verify systemd version, cgroup-v2 delegation, kernel/Landlock, user namespaces, Minijail build, KVM/MSHV device policy and all six modes |
| Non-systemd distribution | Not implemented or qualified | Implement the descriptor-based pre-delegated backend and run the same campaign |
| Generic OCI container | Not supported by the installed launcher | Runtime must provide the future pre-delegated descriptor contract |
| Kubernetes or AKS | Design only | RuntimeClass/node integration and real KVM-capable node qualification described below |

There are no Azure Linux, AKS or non-systemd tests in this repository today.

## Kubernetes and AKS design

This is a deployment design. It is not implemented or qualified.

Use a dedicated Linux `RuntimeClass` backed by a containerd shim, or a narrow
node plugin integrated with the runtime. The runtime creates and delegates only
the pod's provider subtree, then passes opened cgroup capabilities to the
application. A Kubernetes device plugin advertises `/dev/kvm` or `/dev/mshv`
as an extended resource. The helper comes from a signed, read-only image and is
opened and digest-checked before launch.

The pod runs as a fixed non-root UID with all capabilities dropped,
`allowPrivilegeEscalation: false`, a read-only root filesystem and a runtime
seccomp profile that permits the host application's required VM and namespace
operations. Never run a privileged sidecar as the normal path. Never mount the
host `/sys/fs/cgroup` read-write into the pod.

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: hyperlight-kvm
handler: hyperlight-kvm
---
apiVersion: v1
kind: Pod
metadata:
  name: hyperlight-process-placement
spec:
  runtimeClassName: hyperlight-kvm
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 10000
    runAsGroup: 10000
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/hyperlight-host.json
  containers:
    - name: app
      image: ghcr.io/example/hyperlight-app@sha256:REPLACE_WITH_SIGNED_DIGEST
      args: ["process-placement", "sandbox-worker"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        requests:
          cpu: "1"
          memory: 1Gi
          hyperlight.dev/kvm: "1"
        limits:
          cpu: "2"
          memory: 2Gi
          hyperlight.dev/kvm: "1"
```

Pod CPU, memory and runtime-configured pids limits are aggregate ceilings.
Per-role `ProcessProfile` limits can only tighten child domains. Kubelet and
the container runtime own pod deadline, kill and final cleanup.

Required nodes have unified cgroup v2 with delegated `cpu`, `memory` and
`pids`, `cgroup.kill`, unprivileged user namespaces allowed for the reviewed
helper, seccomp, Landlock ABI 5 or newer, and a working KVM or MSHV device.
Production policy also needs signed-image verification and immutable helper
digest policy.

An AKS/Azure Linux end-to-end campaign must run on real KVM-capable nodes and
cover:

* `local`, `worker`, `sandbox`, `sandbox-worker`, `children-allow` and
  `children-deny`
* original and reconstructed reports and snapshots
* distinct sandbox and worker cgroups with effective child limits
* worker crash recovery without replacing the sandbox host
* pod deadline and forced deletion with no processes, cgroups or device handles
  left behind
* denial of host cgroup mutation, helper replacement, undeclared devices,
  privilege escalation, network access where denied and child creation where
  denied
* repeated runs, node drain, container restart and concurrent pods owned by
  different service accounts

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
| `nested_sandbox` | Same-process nested VM, reverse file export and lifecycle proof | Delegated Linux KVM qualification |
| `isolation_bench` | Controlled placement, resident-memory and recovery measurements | Bounded measurement campaign |
| `isolation_bench_worker` | Measurement function worker | Launched by the measurement controller |
| `isolation_bench_sandbox` | Measurement sandbox host | Launched by the measurement controller |
| `isolation_local_consumer` | Feature-disabled local-path size/control binary | Build comparison only |

Worker and sandbox fixtures require inherited `ProcessStartup`. They are not
standalone commands.

Failure/replacement and idempotency behavior is exercised by the process runtime
tests and the bounded `isolation_bench` recovery mode. The six-mode demo kills
and replaces the function worker in `sandbox-worker`.

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
