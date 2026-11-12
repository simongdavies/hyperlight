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
| VM authority | Backend authorization is one-use and generation-bound. |
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
   cargo test -p hyperlight-host --features process-isolation process::
   ```

5. Run native macOS clippy:

   ```sh
   just clippym
   ```

6. Run native end-to-end qualification for both macOS process roles.
   Codesign the executable with the Hypervisor.framework entitlement first
   when required by the host policy.

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
* Qualification must confirm bounded cleanup of each owned root after normal
  shutdown and failure.

## Completion criteria

Qualification is complete only when all commands pass and native execution
confirms both the VM-host and worker behaviors above. Record the Mac model,
macOS version, Rust toolchain, signing identity or ad-hoc signing method,
entitlements, commands, and results.

Windows validation passed on the final source except for the known
environmental WHP resource-exhaustion failure in
`interrupt_infinite_moving_loop_stress_test`. WHP returned `0x800705AA`
(`Insufficient system resources`) while creating VMs. The failure was not an
assertion or process-isolation failure.

Do not claim complete macOS qualification from compilation alone, from
process-isolation unit tests alone, or until both native process roles and all
rejection and cleanup requirements pass.
