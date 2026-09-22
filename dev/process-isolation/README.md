# Required Minijail Landlock prerequisite

This directory contains an opt-in patch for Minijail commit
`8d20993c7189a948995bd20901abecc041e1a28e`. The process adapter requires
`--require-landlock --landlock-abi 5`. A pristine helper rejects the new option.
The upstream ChromiumOS BSD-style source license and headers remain intact.

## Contract

`--require-landlock` requires all of the following before workload exec:

* The target filesystem ABI is known to this source (1 through 5) and supported
  by the running kernel. The enforcing child queries the ABI itself.
* Ruleset creation accepts the complete filesystem access mask for that ABI.
* Every configured path opens successfully and every Landlock rule is inserted.
* `landlock_restrict_self` succeeds.

Disabled restrictions, missing rules, an unavailable ruleset, and preload-based
launches fail closed. Use `-T static` to select the no-preload path. This option
controls Minijail's launch mechanism, not the target binary's actual ELF linkage.
The C API requires selecting the target ABI before adding rules in strict mode.

Strict failures use `_exit(253)`. The upstream `abort()` error path can spin in
a namespace's PID 1. The outer supervisor can independently abort when an early
child failure races its UID/GID-map setup. Both outcomes are non-success and
the workload is not executed.

Default, non-required Minijail behavior is unchanged. This is a filesystem
confinement prerequisite, not a network policy or a process cleanup mechanism.
Minijail is a supervisor. Killing the outer helper is **not** a kill-tree
guarantee. No cgroup, driver, or Hyperlight runtime validation is claimed here.

## Linux IPC, keyring and child-process isolation

Both process roles require a private IPC namespace (`-l`) and a fresh anonymous
session keyring (`-w`). The pinned helper creates the keyring before installing
seccomp. Namespace or keyring creation failure prevents workload exec.
A native-ABI seccomp filter always denies `keyctl`, `add_key`, and `request_key`
with `EPERM`, independently of `DenyChildProcesses`.

The launcher stages the filter beside the trusted helper, outside the workload
root. Minijail loads it before workload exec. The existing `-I` launch makes
the workload namespace PID 1, without a helper fork after filter installation.
The calling application owns worker launch and recovery. A dedicated sandbox
host receives worker endpoints, not a native launch capability.

The filter rejects alternate syscall ABIs, including x32 on x86-64.
`DenyChildProcesses` additionally denies `fork`, `vfork`, and `clone` without
`CLONE_THREAD` with `EPERM`. With this control, `clone3` returns `ENOSYS` because
seccomp cannot inspect its pointed-to flags.
The pinned glibc 2.39 runtime falls back to `clone` for thread creation.
Direct `clone3` callers must handle that result. Threads inherit the filter.
Adding another filter cannot relax it.

The trusted helper must use `USE_seccomp=yes` and `USE_ASAN=no`.
Installation failure prevents workload exec and readiness, including when
child denial is absent. This filter controls key access and optional process
creation, not every syscall or all kernel attack surface.

`child_process_probe.c` exercises native process-creation calls, inherited
key and thread restrictions, and filter immutability. Compile the same source
with `-DHYPERLIGHT_BASELINE_PROBE` for the key-only probe and supply its path as
`HYPERLIGHT_TEST_BASELINE_PROBE`. The ordinary build uses
`HYPERLIGHT_TEST_CHILD_PROCESS_PROBE`. Both need the explicit runtime-file
manifest, strict helper, hypervisor device and delegated driver used by the
Linux integration tests. The IPC/keyring regression compares the workload's
IPC namespace identity with the caller's in both roles and policy modes.
Key denials are checked before thread creation, in a new thread, and after
stacking a permissive filter. `process_child_policy` exercises
Rust thread creation and process denial during a Mesh host-function call.
The delegated-driver tests are opt-in qualification, separate from the BPF
and private-staging unit tests. Their presence is not a qualification result.

`invalid_seccomp_filter_fails_before_workload_and_cleans_domain` supplies a
complete binary BPF instruction without a terminating return, with and without
child denial. The strict helper must reach kernel filter installation, report
failure, and never emit
the probe's entry marker. The test also requires root/domain cleanup and image
removal. It changes only its private test image, not the helper or production
filter. An unrelated early launch failure does not satisfy the test.

## Hyperlight cleanup limitation

Hyperlight requires original-root completion and domain emptiness before
replacement or resource release. Cleanup ownership remains with a live sandbox,
runtime or ownership-carrying startup error. Final-owner Drop is bounded best
effort. If cleanup cannot be confirmed, the last owner can disappear without
leaving a retry capability. Failures are logged, not reported as successful
release.

Windows kill-on-close requests termination, not observed domain emptiness.
Linux has no equivalent lifetime guarantee, so descendants or resources can
remain. Failed file or profile deletion after proven emptiness is resource
residue, not evidence of a running process. The final-owner regression injects
cleanup failure. It does not demonstrate a production orphan.

## Explicit offline build

Use the existing unprivileged Ubuntu-24.04 WSL toolchain. The source must already
be present under the current worktree. No fetching, package installation,
privilege changes, service operations, or Cargo build hooks are involved.

From the worktree root inside WSL:

```sh
python3 dev/process-isolation/build_minijail.py \
  target/minijail-validation/minijail --verify-recorded
python3 -u dev/process-isolation/test_minijail.py \
  target/minijail-validation/minijail/minijail0
```

From PowerShell, enter that worktree directory in `wsl -d Ubuntu-24.04 -- bash`
and run those commands. The script refuses a different commit or tracked source
diff. A pristine checkout receives the digest-verified patch. An already patched
checkout must match that exact patch. It runs a clean `make -j8 all`, with
`SHELL=/bin/bash`, explicit build settings, a controlled environment, a
source-derived `SOURCE_DATE_EPOCH`, and compiler source-path normalization.
It prints tool versions and source, patch, and helper digests. Tool versions are
recorded in `minijail-source.json`. `--verify-recorded` requires the tested helper
digest, so a differing toolchain fails that check.
Two clean builds with the recorded toolchain produced the same helper digest.

For an additional pristine control, add `--base-control` to the build command.
It extracts the local pinned Git archive into
`target/minijail-validation/minijail/.validation/base-control`, builds it without
the patch, and verifies rejection of `--require-landlock`. The control directory
must not already exist. The control's digest differs from the originally supplied
unpatched binary because the explicit build uses source-path normalization.

The patch is deterministic output from:

```sh
git -c core.autocrlf=false diff --no-ext-diff --no-textconv --binary \
  --full-index --src-prefix=a/ --dst-prefix=b/ HEAD --
```

Run this in the Minijail checkout when reproducing the patch bytes.
`minijail-source.json` records the original unpatched helper digest separately
from the built strict helper and the rebuilt pristine control.

## Regression coverage

`test_minijail.py` builds `minijail_probe.c` as a static workload. It runs directly
as a non-root user, using user, mount, and PID namespaces. It does not contact
the driver service. Its private root contains both an allowed file and a denied
file. A real, untraced strict launch verifies an allowed read and `EACCES` for
write, truncate, read of the denied file, and creation of a new file.

The x86-64 ptrace harness traces the **actual built helper** and its children.
The parent retains real syscall results. Only child Landlock calls are injected.
An independent traced-success control verifies that tracing permits the normal
launch. The workload writes `WORKLOAD_EXECUTED` to inherited stdout on entry,
so the failure assertion does not depend on permission to create a marker file.

Validated on WSL kernel `6.18.33.2-microsoft-standard-WSL2`, real Landlock ABI 7:

| Case | Result |
| --- | --- |
| Real strict private-root confinement | Pass |
| Traced success, three rules and final `restrict_self` | Pass |
| Child VERSION reports ABI 4 for required ABI 5 | Non-success, marker absent |
| Child VERSION returns `ENOSYS` | Non-success, marker absent |
| Child VERSION succeeds with ABI 7, CREATE returns `EOPNOTSUPP` | Non-success, marker absent |
| Child VERSION succeeds with ABI 7, CREATE rejects access mask with `EINVAL` | Non-success, marker absent |
| Each of rule insertions 1, 2, and 3 returns `EIO` | Non-success, marker absent in every case |
| Child final `restrict_self` returns `EPERM` | Non-success, marker absent |
| Missing rule path, no rules, disabled restrictions | Non-success, marker absent |
| Target ABI 0 or 6, preload launch | Non-success, marker absent |
| Default mode with injected child CREATE failure | Success, marker present |
| Pristine pinned source helper with required option | Option rejected |

The injected CREATE failures occur after successful real child VERSION queries.
These tests exercise child enforcement, not just a parent availability check.
They do not claim full upstream test-suite or Hyperlight runtime coverage.
