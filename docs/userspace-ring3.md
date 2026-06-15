# Running guest code in ring 3 (the `userspace` feature)

> Status: **in development**, behind the default-off `userspace` cargo feature,
> x86-64 only. This document describes the design, the current implementation
> status, how to validate it, the benchmark plan, and the future work. It is
> the living "report" for the ring 3 effort and is updated as the work lands.

## 1. Overview and goal

Historically, **all** code in a Hyperlight guest — both the Hyperlight runtime
(the guest library: entry point, exception handlers, guest-function dispatch,
host-call plumbing) and the **user-provided** code (`hyperlight_main` and
registered guest functions) — runs at **ring 0** (CPL 0, supervisor) inside the
micro-VM.

The goal of the `userspace` feature is to run **user-provided code in ring 3**
(CPL 3, user mode) while keeping the Hyperlight runtime in ring 0. Whenever
control passes from the runtime into non-Hyperlight code we switch to ring 3,
and whenever user code needs a privileged service (host calls, logging, abort)
or finishes, it traps back to ring 0.

This adds a hardware-enforced privilege boundary **inside** the guest, on top of
the existing VM boundary, so that a bug or exploit in user guest code cannot
directly tamper with the runtime's privileged state (page tables, descriptor
tables, the I/O instructions used to talk to the host, and the runtime's own
mutable data).

This is x86-64 only. i686 and aarch64 are out of scope (see
[Future work](#9-future-work)).

## 2. Isolation goals (threat model)

With the feature enabled, ring 3 user code:

- **cannot execute privileged instructions** — `out`/`in` (host hypercalls),
  `cli`/`hlt`, `mov crN`, `wrmsr`, `lgdt`/`lidt`/`ltr`, etc. all `#GP` in ring 3;
- **cannot read or write the page tables**, the GDT/IDT/TSS, or the kernel
  (runtime) stack — these are mapped supervisor-only (U/S = 0);
- **cannot read or write the runtime's mutable data** — writable guest memory is
  mapped supervisor-only;
- **can** execute guest code, read constants (`.rodata`), use its own user
  stack, and (once the user heap lands) allocate user-accessible memory;
- reaches the runtime only through a **narrow syscall ABI** (see §3.6), so the
  runtime mediates every privileged action on the user's behalf.

The privilege drop is one-way per call: the runtime enters ring 3 to run user
code and regains control via a controlled `syscall` trap.

## 3. Architecture

### 3.1 Privilege levels and the GDT

x86-64 long mode still consults the **Global Descriptor Table** for the code and
stack segment descriptors' privilege level (DPL) and the long-mode (`L`) bit.
Hyperlight's GDT lives in the per-guest `ProcCtrl` structure and historically had
five entries:

```
0x00  null
0x08  kernel code   (DPL 0, L=1)
0x10  kernel data   (DPL 0)
0x18  TSS           (two entries, 0x18 and 0x20)
```

With the `userspace` feature the GDT is extended to eight entries by **appending**
the user-mode descriptors *after* the TSS, so the existing prefix — and every
existing selector, including the TSS selector `0x18` — is unchanged and the
default (non-`userspace`) GDT is byte-identical:

```
0x28  user code 32  (DPL 3)   - sysret selector base; never loaded at runtime
0x30  user data     (DPL 3)   - ring 3 SS/DS, selector 0x33 (0x30 | RPL 3)
0x38  user code 64  (DPL 3)   - ring 3 CS,    selector 0x3b (0x38 | RPL 3)
```

Compile-time `offset_of!` assertions pin these offsets, because the
`syscall`/`sysret` selector arithmetic (below) depends on them exactly.

Source: [`src/hyperlight_guest_bin/src/arch/amd64/init.rs`](../src/hyperlight_guest_bin/src/arch/amd64/init.rs)
(`HyperlightGDT`, `init_gdt`) and
[`machine.rs`](../src/hyperlight_guest_bin/src/arch/amd64/machine.rs)
(`GDT`, `TSS`).

### 3.2 Page tables: the User/Supervisor bit

Each x86-64 page-table entry has a **U/S** bit (bit 2): when set, the page is
reachable from CPL 3; when clear, only from CPL 0-2. A user access succeeds only
if U/S is set at **every** level of the 4-level walk, so the leaf bit is
authoritative and intermediate tables are kept permissive.

The shared page-table builder in
[`src/hyperlight_common/src/arch/amd64/vmem.rs`](../src/hyperlight_common/src/arch/amd64/vmem.rs)
already carried a `Mapping::user_accessible` flag (honoured by the i686 backend
but ignored by amd64). The feature wires it up on amd64 via a `page_user_flag`
helper:

- without `userspace`, the helper returns `0`, so the emitted page tables are
  **byte-identical** to before;
- with `userspace`, leaf PTEs get U/S according to `user_accessible`, and
  intermediate tables are permissive.

The guest's dynamic mapper grows a `map_region_with_access(.., user_accessible)`
entry point (the public `map_region` keeps its supervisor-only signature for
backwards compatibility). The host's initial page-table build marks **executable**
guest regions (the guest code) and **read-only** regions (rodata/init-data blobs)
user-accessible, and keeps purely **writable** regions (the heap), the page
tables, and the scratch region supervisor-only.

The guest image (code + rodata + data + bss) is currently loaded as a single
`READ|WRITE|EXECUTE` region, so exposing it for execution also exposes the
runtime's writable data that shares it. Carving that data into its own
supervisor-only section is the job of the hardened data partition (Phases 4b/4c,
see [Future work](#9-future-work)).

### 3.3 syscall / sysret MSRs

Ring 3 returns to ring 0 with the `syscall` instruction (and the runtime returns
to ring 3 with `sysret`/`iretq`). These are configured through MSRs, programmed
in `ring3::init`:

| MSR | Value | Purpose |
|-----|-------|---------|
| `IA32_EFER` (`0xC000_0080`) | `+SCE` | enable `syscall`/`sysret` (host already sets it; set defensively) |
| `IA32_STAR` (`0xC000_0081`) | `0x0028_0008_0000_0000` | selector bases |
| `IA32_LSTAR` (`0xC000_0082`) | `&hl_syscall_entry` | 64-bit `syscall` entry RIP |
| `IA32_FMASK` (`0xC000_0084`) | `TF\|IF\|DF\|NT\|AC` | RFLAGS bits cleared on `syscall` |

`STAR[47:32] = 0x08` makes `syscall` load `CS = 0x08` (kernel code) and
`SS = 0x10` (kernel data). `STAR[63:48] = 0x28` makes `sysretq` load
`CS = 0x28 + 16 = 0x38 | 3 = 0x3b` and `SS = 0x28 + 8 = 0x30 | 3 = 0x33` — which
is exactly why the user descriptors sit at GDT `0x30`/`0x38`. Clearing `IF` in
`FMASK` keeps the entry path from being interrupted before it has switched
stacks.

### 3.4 Transitions: `enter_user` and the syscall stub

Source: [`src/hyperlight_guest_bin/src/arch/amd64/ring3.rs`](../src/hyperlight_guest_bin/src/arch/amd64/ring3.rs).

`enter_user(entry, arg)` drops to ring 3:

1. push the System V callee-saved registers (`rbx`, `rbp`, `r12`-`r15`);
2. record the current kernel `RSP` in `HL_KERNEL_RETURN_RSP`;
3. build an `iretq` frame — `SS = 0x33`, `RSP = user_stack_top - 8`,
   `RFLAGS = 0x202` (IF + reserved bit 1), `CS = 0x3b`, `RIP = entry`;
4. move `arg` into `rdi` (the user function's first parameter), scrub all other
   GP registers so no ring 0 state leaks into ring 3, and `iretq`.

`hl_syscall_entry` is the `syscall` entry point. For the `SYS_RETURN` syscall it
unwinds straight back into `enter_user`'s caller: restore `RSP` from
`HL_KERNEL_RETURN_RSP`, put the return value in `rax`, pop the callee-saved
registers, and `ret`. Other syscall numbers are not yet implemented (they trap);
the privileged-service dispatcher is added when host calls are wired through
ring 3.

### 3.5 The stack-switching contract

`syscall` does **not** change `RSP`, and on a single-vCPU, single-threaded guest
there is no need for `swapgs`/per-CPU state. Instead:

- `enter_user` saves the kernel `RSP` (just below its saved callee frame) in
  `HL_KERNEL_RETURN_RSP`;
- the saved frame is preserved on the kernel stack while ring 3 runs;
- `SYS_RETURN` restores that `RSP` and unwinds — a tidy stack switch that makes
  `enter_user` "return" with the user's result;
- returning syscalls (host calls etc.) will run on that same kernel stack,
  growing *downward* below the saved frame, so they never clobber it.

The TSS's `RSP0` (newly exposed) is set so that a ring 3 → ring 0 exception entry
lands on a kernel stack; today every exception vector also selects an IST stack,
so `RSP0` is belt-and-braces.

### 3.6 Syscall ABI

Syscall number in `rax`, arguments in `rdi`, `rsi`, `rdx`. There are two kinds:
*non-returning* syscalls unwind the kernel stack back into the `enter_user`
caller, and *returning* syscalls run a ring 0 handler and `sysretq` back into the
ring 3 code with a result in `rax`. Implemented so far:

| # | Name | Kind | Meaning |
|---|------|------|---------|
| 0 | `SYS_RETURN` | non-returning | return a 64-bit value (in `rdi`) from the user function to the `enter_user` caller |
| 1 | `SYS_SELFTEST` | returning | XOR two scalars in ring 0 (validates the `sysretq` path) |

Planned (when host calls / logging / abort move through ring 3):
`SYS_HOST_CALL`, `SYS_LOG`, `SYS_TRACE`, `SYS_ABORT`.

## 4. Feature gating and the host/guest contract

`userspace` is a cargo feature on `hyperlight-common`, `hyperlight-guest`,
`hyperlight-guest-bin`, and `hyperlight-host`. It is **off by default** and
x86-64 only. With it off, the build is byte-identical to mainline (the page
tables, GDT, and code paths are all unchanged).

The host and the guest **must agree** on the feature: the host marks guest code
pages user-accessible only when it is built with `userspace`, and the guest only
drops to ring 3 when *it* is built with `userspace`. A mismatch fails fast — a
ring 3 guest on a non-`userspace` host would fault on the first user instruction
because its code pages would be supervisor-only.

## 5. Implementation status

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | `userspace` cargo feature scaffolding (4 crates) | **done**, validated |
| 4a | Linker-script injection spike (de-risk) | **done** (proven, reverted) |
| 1 | Page-table U/S plumbing (shared vmem, guest, host) | **done**, unit-tested |
| 2 | GDT user segments + TSS.rsp0 | **done**, asserts + build |
| 3 | Transition core (`enter_user`, syscall stub, MSRs, self-test) | **done**, runtime-validated on KVM |
| 4c | Split kernel/user heaps + CPL-routed allocator | **done**, runtime-validated on KVM |
| 5a | Returning syscall (`sysretq`) dispatch path | **done**, runtime-validated on KVM |
| 5b | Run registered guest functions in ring 3 (arg/result marshalling) | **done**, runtime-validated on KVM |
| 5c | Host calls / logging / abort from ring 3 (`SYS_HOST_CALL` etc.) | **next** (design below) |
| 4b | Archive-keyed data partition (full data isolation) | designed, not implemented |
| 6 | Exception robustness from ring 3 + negative security tests | designed, not implemented |
| 7 | Benchmarks (ring 0 vs ring 3) | harness designed, not implemented |

### What is validated, and how

Everything through Phase 4c is validated by unit tests
(`cargo test -p hyperlight-common --features userspace`), compile-time
assertions, clean builds/clippy in **both** feature states, and — for the parts
that only run inside a VM — the `userspace_test` integration test on KVM. The
default (non-`userspace`) build is byte-identical.

Today, ring 3 is exercised by three boot-time self-tests (a pure transition
round-trip, a user-heap allocation, and a returning-syscall round-trip) and,
more importantly, by **real registered guest functions**: with the `userspace`
feature the guest-function dispatch path runs the function body in ring 3, with
its argument and result marshalled across the privilege boundary. The function
*lookup* and parameter *verification* stay in ring 0 (they read the supervisor
function registry). `hyperlight_main` and host calls from within a guest function
are not yet routed through ring 3 (Phase 5c); a guest function that calls a host
function faults in ring 3 today.

Phase 3's hand-written assembly (`enter_user`, `hl_syscall_entry`, the MSR
programming) has been verified both by **disassembling** the built ring 3 guest
and checking it instruction-by-instruction against the AMD64 manual, and by
**running it on KVM**: the `userspace_test` integration test performs a ring 0 →
ring 3 → ring 0 round-trip (an `iretq` into ring 3, a transform in ring 3, and a
`syscall` back) and an end-to-end guest function call, and both pass.

- `enter_user` builds the `iretq` frame in the correct order (`SS=0x33`,
  `RSP=user_top-8`, `RFLAGS=0x202`, `CS=0x3b`, `RIP=entry`), preserves
  callee-saved registers, records the kernel `RSP`, and scrubs registers;
- `hl_syscall_entry` restores the kernel `RSP`, returns the value in `rax`, and
  pops callee-saved registers symmetrically;
- the MSRs are programmed with `STAR=0x0028_0008_0000_0000`, `LSTAR` pointing at
  `hl_syscall_entry`, and the expected `FMASK`.

The boot-time self-test (`ring3::selftest`) performs the same ring 0 → ring 3 →
ring 0 round-trip during guest initialisation and aborts the guest if it fails,
so every ring 3 guest is self-checking on its first run.

### 5.1 Phase 5 design: running user code in ring 3

The remaining keystone is to actually run `hyperlight_main` and registered guest
functions in ring 3. The boundary functions are already known: guest-function
lookup and parameter verification (which read the supervisor-only
`REGISTERED_GUEST_FUNCTIONS`) stay in ring 0, and only the user function *body*
runs in ring 3. Three problems must be solved, all stemming from the fact that
ring 3 cannot touch supervisor memory or execute privileged instructions:

1. **Input marshaling.** The `FunctionCall` arrives in the supervisor input
   buffer and is deserialised into the kernel heap. Before entering ring 3 the
   raw bytes are copied into a user-accessible buffer and re-deserialised into
   the user heap, so the function body (running in ring 3) can read its
   arguments.
2. **Output marshaling.** The function returns a `Vec<u8>` in the user heap; the
   ring 0 side copies it into the supervisor output buffer after `SYS_RETURN`.
3. **Privileged services.** Everything a guest function might do that touches the
   host funnels through the guest's `out32` chokepoint: host calls, logging, and
   abort all call `out`, which faults in ring 3. The plan mediates this with a
   small set of returning syscalls:
   - `SYS_OUTB(port, val)` — performs a single `out32` on the caller's behalf in
     ring 0. Because abort and log messages are streamed *inline* through the
     `out32` value (not via a shared buffer), this one syscall covers both. The
     guest's `out32` gains a ring-3 branch (chosen by reading `CS & 3`) that
     issues `SYS_OUTB` instead of `out`.
   - `SYS_HOST_CALL(user_ptr, len)` — host calls *do* use the shared (supervisor)
     output buffer, so this syscall copies the serialised call from a user buffer
     into the supervisor buffer, performs the real `out`, and copies the result
     back to the user buffer.

This needs a returning-syscall path in `hl_syscall_entry` (save the user
context, switch to the kernel stack, dispatch in ring 0, then `sysretq` back to
ring 3) in addition to the existing non-returning `SYS_RETURN`. It is best built
and reviewed as one cohesive unit, since the pieces are interdependent and are
naturally validated together by a real guest function that allocates, logs, and
calls a host function from ring 3.

## 6. How to validate (requires a hypervisor)

The ring 3 path runs only inside a VM, so it needs KVM (Linux), mshv (Linux), or
WHP (Windows). On a development box where `/dev/kvm` exists but is owned by the
wrong group (a common WSL2 quirk), grant the `kvm` group access:

```bash
# /dev/kvm should be root:kvm, not root:uuidd
sudo chown root:kvm /dev/kvm     # you must already be a member of the kvm group
ls -l /dev/kvm                   # crw-rw---- root kvm
```

Then build the ring 3 guest and run the userspace integration tests:

```bash
just guests                        # (plus the userspace guest variant, see §8)
cargo test -p hyperlight-host --features userspace --test userspace_test
```

`userspace_guest_boots_and_selftests` passing proves the round-trip works end to
end (evolving the sandbox runs the guest's boot-time self-test).

## 7. Benchmarks: methodology and plan

Performance is a primary concern: dropping to ring 3 adds a privilege transition
to guest entry and turns each host call into a syscall plus a marshaling copy.
The plan measures that cost directly.

**Methodology.** Reuse the existing Criterion harness in
[`src/hyperlight_host/benches/benchmarks.rs`](../src/hyperlight_host/benches/benchmarks.rs)
and add a `GuestMode { Ring0, Ring3 }` axis so the **same** workload is measured
in both modes on the **same** hardware in one `just bench` run. The ring 3 mode
loads the `userspace` build of `simpleguest`.

**Workloads.**

- `guest_calls/call/{ring0,ring3}` — a minimal guest function call.
- `guest_calls/call_with_restore/{ring0,ring3}` — call plus snapshot restore.
- `guest_calls/call_with_host_function/{ring0,ring3}` — a guest call that calls
  back into a host function (exercises the syscall + marshaling path).
- Micro-benchmarks isolating each cost: a no-op guest function (pure
  `iretq` + `sysret` round-trip), an N-host-call function (per-call marshaling),
  and a guest-heap allocation (the CPL-routed allocator).

**Reporting.** `just bench` prints the ring 0 vs ring 3 delta per workload. A
lightweight A/B harness also exists in
[`src/hyperlight_host/tests/userspace_bench.rs`](../src/hyperlight_host/tests/userspace_bench.rs),
which loads the ring 0 and ring 3 builds of `simpleguest` and times identical
`Echo` calls against each on the same host:

```text
cargo test -p hyperlight-host --features userspace --test userspace_bench \
    -- --ignored --nocapture
```

### First results (KVM, release host + release guests)

| Workload | ring 0 | ring 3 | overhead |
|----------|-------:|-------:|---------:|
| `Echo` guest call (per call) | ~24-25 µs | ~27-29 µs | **~3-4 µs (12-16%)** |

Interpretation:

- The ring 3 cost is a **fixed ~3-4 µs per call**, dominated by the
  cross-privilege **marshalling** (re-encoding the `FunctionCall` into a user
  buffer and copying the result back, plus the user-heap allocations), not the
  raw privilege transition (the `iretq`/`syscall`/`sysretq` instructions are
  sub-microsecond).
- `Echo` is close to the **cheapest possible** guest function, so its ~16% is
  near the worst-case *relative* overhead. Because the cost is fixed per call,
  any guest function that does real work amortises it toward zero.
- A known optimisation is to avoid the **double-marshalling**: the runtime
  currently decodes the `FunctionCall` in ring 0 (for parameter verification),
  re-encodes it into a user buffer, and re-decodes it in ring 3. Passing the raw
  request bytes through (decoding only once, in ring 3) would remove the
  re-encode. This is tracked as a follow-up.

Still to measure: `call_with_restore`, host calls from ring 3 (once Phase 5c
lands), and the allocation micro-benchmark.


## 8. Building the ring 3 guest

The `userspace` build of `simpleguest` is a separate artifact
(`simpleguest-userspace`) so the ring 0 and ring 3 variants can be compared
directly. It is produced from the same source with the `userspace` feature and
resolved by the `simple_guest_userspace_as_string()` testing helper. Wiring this
into `just guests` and CI is part of Phase 7.

## 9. Future work

### 9.1 Multithreading and multiple vCPUs

The single-vCPU, single-threaded assumption is load-bearing in several places,
and lifting it is the largest follow-up:

- **Per-CPU kernel stacks via `swapgs`.** `syscall` does not switch `RSP`, so we
  currently find the kernel stack through a single fixed `HL_KERNEL_RETURN_RSP`
  slot. With multiple vCPUs each CPU needs its own kernel stack, found through a
  per-CPU structure pointed to by `IA32_KERNEL_GS_BASE` and reached with a
  `swapgs` at syscall entry/exit.
- **Per-CPU GDT/TSS/IST.** Each CPU needs its own TSS (`RSP0` and IST stacks) and
  may need its own GDT; the `ProcCtrl` structure becomes per-CPU.
- **Per-thread user and kernel stacks**, and a real save/restore of the
  transition state rather than the single global slots used today.
- **Allocator locking and page-table maintenance.** The CPL-routed allocator
  needs proper locking, and dynamic mapping needs break-before-make / TLB
  shoot-down across CPUs.

### 9.2 Hardened data partition (Phase 4b)

The split kernel/user heap (Phase 4c) is **done**: ring 3 code allocates from a
user-accessible heap whose control structure lives in user memory, while the
runtime keeps its supervisor-only kernel heap. Combined with the host marking all
**writable** guest memory supervisor-only, the runtime's mutable data is already
out of ring 3's reach. What remains to make the split fully explicit and robust:

- an **archive-keyed linker script** (the Phase 4a spike proved a guest
  `build.rs` can inject `-T <script>` through `cargo-hyperlight`, and that an
  `INSERT AFTER` script augments lld's default layout) that places the runtime
  crates' writable data into page-aligned supervisor `.kdata`/`.kbss` sections.
  Today the guest image (code + rodata + data + bss) is a single RWX region that
  is exposed to ring 3 for execution, so the runtime's `.data`/`.bss` that share
  it are technically reachable; the linker partition carves them out;
- **on-demand growth** of the user stack and user heap via the page-fault
  handler, removing the eager mappings (and the enlarged default scratch size)
  that currently back them.

### 9.3 Other

- **i686 / aarch64.** The i686 page-table backend already honours
  `user_accessible`; a full ring 3 story for either architecture is unscoped.
- **Benchmark perf gate.** Once baselines are stable, consider a CI threshold on
  ring 3 overhead. Initially the ring 3 benchmarks run informationally.
- **`cargo-hyperlight`.** The Phase 4a spike confirmed no changes are required to
  inject the linker script; if that ever changes, the script injection would need
  upstreaming.

## 10. References

- AMD64 Architecture Programmer's Manual, Volume 2: System Programming —
  §4 (segmentation), §5 (paging), §6 (exceptions/interrupts), §A (syscall/sysret).
- Intel 64 and IA-32 Architectures SDM, Volume 3A — Chapter 5 (paging).
- Source of truth in-tree:
  [`ring3.rs`](../src/hyperlight_guest_bin/src/arch/amd64/ring3.rs),
  [`init.rs`](../src/hyperlight_guest_bin/src/arch/amd64/init.rs),
  [`machine.rs`](../src/hyperlight_guest_bin/src/arch/amd64/machine.rs),
  [`vmem.rs`](../src/hyperlight_common/src/arch/amd64/vmem.rs).
