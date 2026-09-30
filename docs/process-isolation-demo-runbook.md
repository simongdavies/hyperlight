# Process isolation demo runbook

This runbook builds and runs the process-placement, typed resource capability,
and nested-sandbox demos on x86-64 Ubuntu 24.04. It supports a native Ubuntu
host, an Ubuntu VM from any provider, or Ubuntu 24.04 under WSL2.

The reviewed source is:

* Repository: `https://github.com/simongdavies/hyperlight.git`
* Branch: `simongdavies-land-vm-authority`
* Commit: `bb153b2db78e2c8a8bf035a40c65afe8f93afdca`

## Host requirements

The host requires:

* systemd 254 or newer
* cgroup v2 with the `cpu`, `memory`, and `pids` controllers
* KVM available through `/dev/kvm`
* Landlock ABI 5 or newer
* Rustup and `just`

WSL2 also requires systemd and `/dev/kvm` access. A VM must expose nested
virtualization to the Ubuntu guest. No cloud-specific service or agent is
required.

Check the basic host state:

```bash
uname -m
systemctl --version | head -1
stat -fc %T /sys/fs/cgroup
ls -l /dev/kvm
test "$(ps -p 1 -o comm=)" = systemd
```

The architecture must be `x86_64`, and the cgroup filesystem must be
`cgroup2fs`.

Install the build dependencies:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  pkg-config \
  libcap-dev \
  git \
  curl \
  python3
```

Install Rustup if needed:

```bash
command -v rustup >/dev/null || \
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Install the required toolchains and guest targets:

```bash
rustup toolchain install 1.95 1.94 nightly-2026-02-27
rustup target add --toolchain 1.94 \
  x86_64-unknown-none \
  x86_64-unknown-linux-musl
command -v just >/dev/null || cargo +1.95 install just
```

## Clone the reviewed source

Keep the checkout on the Ubuntu filesystem:

```bash
mkdir -p "$HOME/src"
cd "$HOME/src"
git clone \
  --branch simongdavies-land-vm-authority \
  --single-branch \
  https://github.com/simongdavies/hyperlight.git \
  hyperlight-process-demo
cd hyperlight-process-demo
git checkout bb153b2db78e2c8a8bf035a40c65afe8f93afdca
test "$(git rev-parse HEAD)" = \
  bb153b2db78e2c8a8bf035a40c65afe8f93afdca
```

`git log -1 --oneline` must report:

```text
bb153b2d Add concise nested sandbox demo
```

## Build the pinned Minijail helper

Run these commands as the ordinary application user:

```bash
git clone \
  https://chromium.googlesource.com/chromiumos/platform/minijail \
  target/minijail-validation/minijail
git -C target/minijail-validation/minijail checkout \
  8d20993c7189a948995bd20901abecc041e1a28e

python3 dev/process-isolation/build_minijail.py \
  target/minijail-validation/minijail \
  --verify-recorded
```

Do not substitute another Minijail revision or binary.

## Build the release demos and guest

```bash
cargo +1.95 build --release --locked \
  -p hyperlight-host \
  --features process-isolation \
  --example process_placement \
  --example process_file_resource \
  --example nested_sandbox

just build-rust-guests release
just move-rust-guests release
```

Verify the outputs:

```bash
test -x target/release/examples/process_placement
test -x target/release/examples/process_file_resource
test -x target/release/examples/nested_sandbox
test -s src/tests/rust_guests/bin/release/simpleguest
```

## Install the Linux integration

Review the installation plan:

```bash
dev/process-isolation/hyperlight-run init \
  --plan \
  --source target/minijail-validation/minijail \
  --user "$USER"
```

Perform the installation:

```bash
dev/process-isolation/hyperlight-run init \
  --source target/minijail-validation/minijail \
  --user "$USER"
```

The installer uses sudo only for system installation. Hyperlight and its
native roles run as the ordinary user. If group membership changed, end the
current Ubuntu login and open a new one. Under WSL2, close the current Ubuntu
shell and open a new Ubuntu shell.

Verify the installation:

```bash
hyperlight-run check
```

The final line must be:

```text
Hyperlight Linux integration is ready.
```

A user systemd state of `degraded` is acceptable when every Hyperlight check
passes.

## Run the six-mode process-placement demo

Interactive mode pauses while each topology is alive:

```bash
cd "$HOME"
hyperlight-run demo
```

The six modes are:

1. local VM and host functions
2. separate function worker
3. separate VM host
4. separate VM host and function worker
5. worker with child creation allowed
6. worker with child creation denied

Use the noninteractive form for automation or redirected input:

```bash
hyperlight-run demo --noninteractive
```

Success ends with:

```text
PASS all six process placement modes
```

## Run the nested-sandbox demo

Interactive mode keeps the nested topology alive for inspection:

```bash
hyperlight-run nested-demo
```

The topology is:

```text
application
  -> outer Hyperlight guest
     -> isolated host-function worker
        -> inner Hyperlight sandbox in the worker
```

Use the noninteractive form for automation:

```bash
hyperlight-run nested-demo --noninteractive
```

Success ends with:

```text
PASS nested sandbox composition
```

Recovery, crash, snapshot, and replay diagnostics remain in the separate
qualification path.

## Run the typed resource capability demo

Run this example from the repository checkout:

```bash
cd "$HOME/src/hyperlight-process-demo"
RESOURCE_DIR=$(mktemp -d /tmp/hyperlight-resource-demo.XXXXXX)
printf 'writable-data' > "$RESOURCE_DIR/read-write.txt"
printf 'protected-data' > "$RESOURCE_DIR/read-only.txt"

hyperlight-run -- \
  "$PWD/target/release/examples/process_file_resource" \
  "$PWD/src/tests/rust_guests/bin/release/simpleguest" \
  "$RESOURCE_DIR/read-write.txt" \
  "$RESOURCE_DIR/read-only.txt" \
  '-appended'
```

Expected output includes:

```text
Typed resource capability transfer:
  read/write capability: read and write succeeded
  read-only capability: read succeeded
  read-only capability write: denied
```

Verify that only the writable resource changed:

```bash
cat "$RESOURCE_DIR/read-write.txt"
cat "$RESOURCE_DIR/read-only.txt"
```

Expected values:

```text
writable-data-appended
protected-data
```

Remove the temporary directory:

```bash
rm -rf "$RESOURCE_DIR"
```

## Run exhaustive qualification

This command is separate from the presentation demos:

```bash
mkdir -p "$HOME/hyperlight-qualification"
cd "$HOME/hyperlight-qualification"
hyperlight-run qualify --all
```

It checks recovery, snapshot reconstruction, and cleanup across the six
process-placement modes.

## Troubleshooting

### The launcher reports `unknown option: demo`

The installed launcher is stale. Build the release assets from the reviewed
commit and rerun the complete `init` workflow.

### The process-placement binary prints its legacy positional usage

The launcher is newer than the installed example binary. Rerun the complete
installation. Do not replace individual installed files.

### The nested demo reports `GuestFunctionNotFound`

The installed guest is stale. Rebuild the release guest and rerun the complete
installation.

### The user systemd manager is unavailable

Check:

```bash
systemctl --user is-system-running --no-pager
echo "$XDG_RUNTIME_DIR"
hyperlight-run check
```

`degraded` is usable when `hyperlight-run check` passes.

### Hyperlight cannot find a hypervisor

Check device presence and access:

```bash
ls -l /dev/kvm /dev/mshv 2>/dev/null || true
for device in /dev/kvm /dev/mshv; do
  if test -e "$device"; then
    test -r "$device" && echo "readable: $device" || echo "not readable: $device"
    test -w "$device" && echo "writable: $device" || echo "not writable: $device"
  fi
done
```
