# Windows process placement qualification

Recorded on native Windows from an ordinary non-elevated PowerShell session on
2026-09-23. The tested uncommitted working tree was based on commit `c0ba671a`.

## Commands

```powershell
just fmt-apply
just build
just clippy
just test
cargo +1.95 test --locked -p hyperlight-host --features process-isolation --lib -- --test-threads=1
cargo +1.95 test --locked -p hyperlight-host --features process-isolation --example process_placement
```

Windows cross-Clippy ran from Ubuntu 24.04 WSL:

```bash
CARGO_TARGET_DIR=target/wsl-clippyw CARGO_BUILD_JOBS=1 just clippyw
```

The two campaigns used the build and six commands in
[QUICKSTART.md](QUICKSTART.md), with fresh roots `target\qf5-001133` and
`target\qf6-001409`. Each executable run required:

* original and reconstructed reports with distinct process IDs
* `Add = 42`, guest restore, checked OCI load and reconstruction
* aggregate-host CPU-rate wording and topology-specific boundaries
* explicit successful shutdown before `PASS`
* an OCI index and manifest digest for every mode

The operator also checked for reported PID and `process_placement` residue and
searched the logs for skip, mock and missing-hypervisor text. These external
checks are not part of the example executable.

## Results

| Campaign | Mode | Original and reconstructed PIDs | Manifest |
| --- | --- | --- | --- |
| 1 | `local` | none | `sha256:bfdb326860eb79ceac9450c26ebbb332526acc72e095237fe74dd05f5917c091` |
| 1 | `function-worker` | 78832, 64036 | `sha256:af43a50ef12cca97de30c8a9231ef505355e8b7286ff063548a19e1c9eed105c` |
| 1 | `worker-children-allowed` | 19544, 63024 | `sha256:80e1c8386a9ddb02ef798a2fb895edf769321ec6e46298e8a0af8e4003577ef4` |
| 1 | `worker-children-blocked` | 32628, 105192 | `sha256:45de0e72b2b2cce414c4f02ebac6b8caf805b33f6d0474b511cfe84a8ae49314` |
| 1 | `vm-host` | 48616, 100980 | `sha256:a13bd23c7e4d3e56d4c3ae30c9d22cdd4c4079fcd2e8641c2cab1aa7d2cf3d17` |
| 1 | `vm-host-and-function-worker` | 64624, 22792, 79940, 90468 | `sha256:2b51f3ab91cc8499757c810c8f0ba950510f197598cc4557e1be559fd5d2e6cf` |
| 2 | `local` | none | `sha256:35e811caff21d3f541ddf450f132529f98b0d7425765380dd34dc804157a9f27` |
| 2 | `function-worker` | 1836, 29884 | `sha256:6c01ad177d0b1cf01178427cc5ff335c13ba3c539bd2ba75f9708b64b1454482` |
| 2 | `worker-children-allowed` | 91172, 108900 | `sha256:d5b0dacf7842cfd7fdbf1c32c9f6e6166395a37286a8cac26dd394876902d07e` |
| 2 | `worker-children-blocked` | 45636, 79892 | `sha256:31f73454208d77892cbd08d242a736512120bfe67a50fe59aeb77543d2d8d2f6` |
| 2 | `vm-host` | 111800, 114032 | `sha256:57c734cd9421ae38f2cf29743cf09cc95553c74e70beb30c22ade1a779291212` |
| 2 | `vm-host-and-function-worker` | 58936, 52528, 28696, 93456 | `sha256:1bfaac6da0e79cffbf0cf102b6729b6c033785840a984539a5ad5d85d08f09a7` |

Manifest digests identify each generated OCI layout. Snapshots contain
run-specific state, so matching digests across campaigns are not expected.

`just test` also passed
`hypervisor::virtual_machine::whp::no_surrogate_tests::single_vm_lifecycle`.
The campaign logs remain under the two local, gitignored roots on the qualifying
machine. They are an operator record, not versioned repository artifacts.
