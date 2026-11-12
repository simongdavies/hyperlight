# macOS Process Isolation Qualification

## Purpose

This guide qualifies the process-isolation forward-port on native Apple
Silicon macOS. The branch is `simongdavies-mesh-macos-forward-port`.

Qualification covers the complete historical process-placement stack from
`25b37989` on current main, plus `Unrestricted` macOS support for separate
VM-host and host-function worker processes. It does not qualify macOS
`Restricted` execution. macOS must reject `Restricted` profiles before any
process is staged or spawned.

Do not report a passing subset, successful compilation, or one process role as
complete qualification.

## Implemented capability matrix

| Capability | Implemented behavior |
| --- | --- |
| Process profiles | `Unrestricted` means no process controls. It cannot be combined with controls or platform limits. Restricted profiles require controls. |
| VM-host process | A dedicated process owns the sandbox and serves sandbox RPC. |
| Host-function worker | A separate process serves registered host functions with restart and poisoning behavior. |
| Program identity | Immutable OCI identities and exact function contracts are attested at startup. |
| Resources | Typed OS resources, file transfer, rights, generations, and export policy are enforced. |
| VM authority | KVM, MSHV, and WHP authorization is one-use and generation-bound. macOS uses the caller's Hypervisor.framework entitlement. HVF authority transfer is not implemented. |
| Snapshots | Process topology is persisted, validated, reconstructed, and bound during restore. |
| Windows restricted backend | AppContainer worker and trusted VM-host paths are preserved. |
| Linux restricted backend | Namespace, seccomp, Landlock, and cgroup enforcement is preserved. |
| macOS unrestricted VM-host | Runs as the caller user in a dedicated Mesh process root. |
| macOS unrestricted worker | Runs as the caller user in a separate dedicated Mesh process root. |
| macOS restricted backend | Rejected before staging or spawning. |
| Cleanup | Each macOS process root owns one dedicated Mesh. Cleanup is bounded to that owned root. Generic descendant-domain containment is not claimed. |

## Prerequisites

* Apple Silicon Mac.
* Xcode Command Line Tools with a usable Apple SDK.
* The repository Rust toolchain.
* `just`.
* Hypervisor.framework access.
* Permission to build and sign the test executable when local policy requires
  signing.
* The `com.apple.security.hypervisor` entitlement when required by the host
  signing policy.

Use the branch as fetched. Do not substitute generated bindings, fake Apple
SDKs, disable signing requirements, or weaken process-profile validation.

## Qualification sequence

1. Confirm the branch and clean worktree:

   ```sh
   git branch --show-current
   git status --short
   ```

   The branch must be `simongdavies-mesh-macos-forward-port`.

2. Build the guest libraries and test guests:

   ```sh
   just guests
   ```

3. Check the host with process isolation enabled:

   ```sh
   cargo check -p hyperlight-host --features process-isolation
   ```

4. Run the focused process-isolation tests:

   ```sh
   cargo build -p hyperlight-host --features process-isolation --examples
   codesign --force --sign - --entitlements dev/macos-entitlements.plist \
     target/debug/examples/sandbox_worker \
     target/debug/examples/process_worker \
     target/debug/examples/process_file_resource
   cargo test -p hyperlight-host --features process-isolation process::
   ```

   Cargo signs test executables through the macOS runner. Example executables
   need the explicit signing step after each build.

5. Run native macOS clippy:

   ```sh
   just clippy
   cargo clippy -p hyperlight-host --features process-isolation --all-targets -- -D warnings
   ```

6. Run native end-to-end qualification and the full test suites:

   ```sh
   cargo test -p hyperlight-host --features process-isolation process::macos::tests::
   just test
   just test debug hvf,build-metadata,process-isolation
   ```

   The native provider tests cover VM-host only, worker only, and combined
   placement. They check caller UID, private executable staging, large RPC
   payloads, snapshot restore and OCI reconstruction, worker recovery, resource
   rights, restricted-profile preflight, and independent cleanup.

## Required native behaviors

### VM-host process

* An `Unrestricted` profile starts a dedicated VM-host process.
* The process runs with the caller user's permissions.
* Sandbox calls cross the dedicated sandbox RPC path.
* Snapshot capture and restore preserve and validate the VM-host topology.
* Shutdown removes the owned process root and does not claim containment of
  unrelated descendants.

### Host-function worker

* An `Unrestricted` profile starts a separate host-function worker process.
* The process runs with the caller user's permissions.
* Registered calls cross the worker RPC path and preserve exact function
  contracts.
* Restart, poisoning, resource transfer, and cleanup follow the configured
  process topology.
* VM-host and worker roots are independently owned and cleaned up.

### Rejection and cleanup

* Every macOS `Restricted` profile fails before staging or spawning.
* `Unrestricted` rejects controls, platform limits, and nonempty runtime-file
  closures.
* Each process root uses its own dedicated Mesh.
  Sibling Mesh owners share one parent IPC node for cross-role endpoints.
  Each owner waits for and cleans up only its own root.
* Qualification must confirm bounded cleanup of each owned root after normal
  shutdown and failure.

## Completion criteria

Qualification is complete only when all commands pass and native execution
confirms both the VM-host and worker behaviors above. Record the Mac model,
macOS version, Rust toolchain, signing identity or ad-hoc signing method,
entitlements, commands, and results.

Prior Windows validation passed except for the known
environmental WHP resource-exhaustion failure in
`interrupt_infinite_moving_loop_stress_test`. WHP returned `0x800705AA`
(`Insufficient system resources`) while creating VMs. The failure was not an
assertion or process-isolation failure. Native macOS validation does not
requalify the Windows or Linux backends.

Do not claim complete macOS qualification from compilation alone, from
process-isolation unit tests alone, or until both native process roles and all
rejection and cleanup requirements pass.

## Native evidence

The 2026-11-12 run uses:

* Mac model `Mac16,10`, arm64, 16 GiB memory.
* macOS 26.5.2, build 25F84.
* Rust 1.99.1, commit `58cf8f9c3`, target `aarch64-apple-darwin`.
* Apple Command Line Tools SDK at
  `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk`.
* Ad-hoc signing with `codesign --force --sign -`.
* `dev/macos-entitlements.plist`, with
  `com.apple.security.hypervisor = true`. The executable entitlements are
  checked with `codesign --display --entitlements -`.
* Effective UID 501 in the caller, VM host, and worker.
* OpenVMM fork revision
  [`f7838c69`](https://github.com/simongdavies/openvmm/commit/f7838c69be1f2180bf8365872e6570c6541c8941).
  All three direct dependencies and the lockfile use this remote revision.

### Command results

| Command | Result |
| --- | --- |
| `just guests` | Pass. Debug and release guest artifacts built. |
| `cargo check --locked -p hyperlight-host --features process-isolation` | Pass. Remote fork revision resolves without local overrides. |
| `cargo build -p hyperlight-host --features process-isolation --examples` | Pass. Native child signatures and entitlements verified after signing. |
| `cargo test -p hyperlight-host --features process-isolation process::` | Pass. 157 tests in the normal parallel runner. |
| `just fmt-apply` | Pass. |
| `just clippy` | Pass. |
| `cargo clippy -p hyperlight-host --features process-isolation --all-targets -- -D warnings` | Pass. |
| `just test` | Pass. Full default recipe, including isolated, integration, documentation, and tool tests. |
| `just test debug hvf,build-metadata,process-isolation` | Pass. Full feature-enabled recipe. Host unit run has 626 passes and 11 standard ignored tests. The recipe runs isolated tests separately. |

Both macOS unrestricted process roles satisfy the native requirements above.
Restricted execution, generic descendant containment, and HVF authority
transfer remain outside the qualified capability set.

### Execution evidence

The native provider tests use the production launcher and signed executables,
not prepared-launch containment fixtures.

| Requirement | Evidence |
| --- | --- |
| Both roles | VM-host-only, worker-only, and combined placement pass. Combined placement has distinct caller-user PIDs. |
| Guest loading and RPC | The 17 MiB debug guest starts. A 1 MiB string round-trips through guest RPC. Nondefault transport geometry reaches the VM host. |
| Snapshots | Capture, mutation, restore, provider-aware OCI save, load, and process reconstruction pass for all three placements. |
| Worker recovery | Killing the worker produces a new root. Calls succeed and the VM-host PID stays unchanged. The retired image is removed. |
| Resource rights | Native file transfer preserves read-write and read-only access. Writes through the read-only resource fail. |
| Restricted preflight | Both role positions reject required network, child-process, memory, and CPU controls. Mixed topologies stage zero process images. |
| Normal cleanup | Original and reconstructed topologies clean up independently. The surviving topology remains callable. Shutdown completes within 35 seconds and removes owned images. |
| Failure cleanup | Invalid guest startup removes both staged images and leaves no retained cleanup owner. |

The broader process suite exercises startup attestation, exact contracts,
typed-resource generations, export policy, one-use authority contracts,
idempotent replay, ambiguous non-idempotent calls, restart exhaustion,
poisoning, cancellation, and cleanup error ownership. Its prepared-launch
tests do not claim macOS descendant containment.

The OpenVMM regression suites pass with 25 Mesh process tests, 11 remote
transport tests, and one PAL unit test. Two ignored process tests are child
entrypoints, not skipped qualification cases. The transport suite includes a
17 MiB message followed by small, threshold-crossing, and empty payloads.
Sibling-owner tests cover shared ports, cancellation-safe reaping, and
independent shutdown.

Fork clippy passes with `-D warnings -A unfulfilled-lint-expectations`.
The allowance isolates an existing expectation in `mesh_channel_core` that
Rust 1.99.1 does not fulfill. Hyperlight clippy uses `-D warnings` without that
allowance.
