# Running guest code in ring 3 (the `userspace` feature)

> This document records the design and implementation of the `userspace`
> feature, which runs user-provided guest code in ring 3 while the Hyperlight
> runtime stays in ring 0. The feature is x86-64 only and lives behind a
> default-off cargo feature. The document covers the architecture, the isolation
> guarantees, the measured performance, the current limitations, and the potential
> future work.

## 1. Overview and goal

Historically, **all** code in a Hyperlight guest — both the Hyperlight runtime
(the guest library: entry point, exception handlers, guest-function dispatch,
host-call plumbing) and the **user-provided** code (`hyperlight_main` and
registered guest functions) — runs at **ring 0** (CPL 0, privileged) inside the
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

This is **defense in depth**, not a replacement for any existing boundary.
Hyperlight's primary security boundary is and remains the VM boundary: the
hypervisor (KVM/mshv/WHP) and second-level address translation confine the
guest. Ring 3 isolation adds a *second, independent* hardware-enforced layer
*inside* the guest, and the gap it closes is two-fold — because a compromised
guest is the launch point for attacking the host's trust base, and that base is
not bug-free:

- **Hypervisor bugs and escapes.** The host trusts the hypervisor to confine the
  guest, but hypervisors do have bugs — rare, but real and demonstrated (e.g.
  [V4bel/ITScape](https://github.com/V4bel/ITScape)). Untrusted code running at
  ring 0 in the guest has the *entire* hypervisor-facing surface at its disposal
  — every VM exit, MSR access, and instruction- or device-emulation path — to
  probe for and trigger such a bug. Confining user code to ring 3 means it no
  longer drives that surface directly; the small, trusted runtime does, through a
  narrow and predictable set of interactions.
- **Layered attacks on the host through the guest interface.** Even with the
  hypervisor intact, a malicious guest can attack *the host's handling* of the
  legitimate guest/host interface — corrupting the shared-memory structures the
  host parses, deliberately forcing exits, or malforming the request framing to
  hit a bug in the host's transport/deserialization code. At ring 0, user code
  crafts those raw interactions directly. In ring 3 the shared buffers are
  supervisor-only and every interaction is mediated by the runtime through the
  narrow syscall ABI (§3.6), so the host only ever sees well-formed,
  runtime-produced requests. (This protects the *transport*; the *values* inside
  a well-formed request remain the application's responsibility.)

In both cases the principle is the same: shrink the surface that *untrusted user
code* can reach, and keep the hypervisor- and host-facing interfaces under the
sole control of the small, trusted runtime rather than of arbitrary user code.

This second layer is itself composed of several independent mechanisms, each of
which must hold on its own (enumerated in §2): privileged-instruction trapping,
supervisor-only page protection, a single narrow syscall entry point, and the
critical-data partition — overlapping barriers rather than one all-or-nothing
check.

**Performance is a primary consideration, not an afterthought.** Hyperlight's
value lies in creating sandboxes and running guest functions with very low
latency, so a boundary that taxes **startup** or **per-call execution** has to
earn its place. Dropping to ring 3 adds work in both: at guest startup
(programming the GDT and `syscall`/`sysret` MSRs, the boot-time transition
self-tests, and the one-time critical-data re-protection), and on every call (the
privilege transition plus a marshalling copy for each guest call, host call, log,
and abort). That cost is the reason the
feature is default-off and byte-identical to mainline when disabled, and the
reason its overhead is **measured directly** — both startup and per-call — rather
than assumed (see §7).

This is x86-64 only. i686 and aarch64 are out of scope (see
[Future work](#9-future-work)).

## 2. Isolation goals (threat model)

### Trust boundary

The guest binary is a **single trust unit**: the Hyperlight runtime
(`hyperlight-guest-bin`) and the user-provided code (`hyperlight_main` and the
registered guest functions) are compiled and linked together by a **trusted**
party, against the *unmodified* runtime. This is the same arrangement an
operating system relies on: compiling a program does not grant it ring 0,
because the trusted kernel and the libraries it is linked against expose no
ring 0 primitives. Here the trusted runtime owns the entrypoint and drops **all**
user code — `hyperlight_main` included — into ring 3, and the only way back into
ring 0 is the narrow syscall ABI it defines (§3.6).

The threat this contains is therefore **untrusted *input*, not an untrusted
binary author**: a trusted author writes a guest function that processes
attacker-controlled data and has a memory-safety bug. Ring 3 isolation ensures
that hijacking such a function cannot corrupt the runtime or drive the host and
hypervisor interfaces directly (§1). Containing an untrusted *binary* — one whose
author is the adversary — remains the job of the VM boundary, which confines the
guest regardless of the ring its code runs in.

For this to hold, **no author-provided code may run at ring 0**. Every entry into
author code drops to ring 3 first:

- `hyperlight_main` (the init entry point) runs in ring 3 (§3.8);
- registered guest functions run their bodies in ring 3 (§3.8);
- the `guest_dispatch_function` fallback for unregistered calls runs in ring 3
  (§3.8);
- exception and interrupt handlers run at ring 0, but a handler can only be
  *installed* by writing supervisor-only state (the `HANDLERS` table lives in the
  `.kdata` partition (§3.7); the IDT lives in supervisor memory), so ring 3
  cannot install one — and no ring-0 runtime path installs author handlers.

The only code that runs at ring 0 is the trusted runtime itself
(`hyperlight-guest-bin` and the crates it builds on). This is the same division
as an operating system: the kernel runs privileged, everything the application
author supplies runs unprivileged.

### Guarantees

With the feature enabled, ring 3 user code:

- **cannot execute privileged instructions** — `out`/`in` (host hypercalls),
  `cli`/`hlt`, `mov crN`, `wrmsr`, `lgdt`/`lidt`/`ltr`, etc. all `#GP` in ring 3;
- **cannot read or write the page tables**, the GDT/IDT/TSS, or the kernel
  (runtime) stack — these are mapped supervisor-only (U/S = 0);
- **cannot reach the runtime's most security-critical statics** — the guest
  function pointer table (which ring 0 dereferences to dispatch a call), the PEB
  handle, and the exception-handler table are gathered into a supervisor-only
  `.kdata` section, closing the primary privilege-escalation path (a ring 3
  write that ring 0 would later honour — see §3.7);
- **can** execute guest code, read constants (`.rodata`), use its own user
  stack, and allocate from its own user heap;
- reaches the runtime only through a **narrow syscall ABI** (see §3.6), so the
  runtime mediates every privileged action on the user's behalf.

The privilege drop is one-way per call: the runtime enters ring 3 to run user
code and regains control via a controlled `syscall` trap.

These guarantees are **enforced by hardware and proven by negative tests**
(`userspace_test`): a ring 3 guest function that attempts a privileged
instruction (`cli`, a raw `out`) faults with a general-protection fault, and one
that reads or writes the runtime's supervisor-only memory (the kernel stack, or
the `.kdata` critical-statics section) faults with a page fault. In every case
the guest aborts cleanly; further tests confirm the abort poisons the sandbox
without corrupting the host and that a snapshot restore recovers it — and that
the `.kdata` protection still holds *after* a restore.

> **Known limitation.** The guest image is loaded as a single read/write/execute
> region, so general runtime *writable* data that shares it (`.data`/`.bss` of
> the runtime crates, including the CPL-routed allocator's own control state,
> which ring 3 must be able to read) remains ring-3-accessible. The `.kdata`
> partition removes the statics whose corruption gives a *direct* ring 0
> code-execution escalation; sweeping *all* runtime writable data into
> supervisor memory is potential future work (see
> [Future work](#9-future-work)).


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
runtime's writable data that shares it. The most security-critical statics are
carved out of that exposure into a supervisor-only `.kdata` section (§3.7);
sweeping the *remaining* runtime writable data into supervisor memory is
potential future work (see [Future work](#9-future-work)).

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

`hl_syscall_entry` is the `syscall` entry point and handles both kinds of
syscall (§3.6). For the non-returning `SYS_RETURN` it unwinds straight back into
`enter_user`'s caller: restore `RSP` from `HL_KERNEL_RETURN_RSP`, put the return
value in `rax`, pop the callee-saved registers, and `ret`. For a returning
syscall it stashes the user `RSP`, switches onto the kernel stack (growing down
below the parked `enter_user` frame), dispatches the requested service in
ring 0, and `sysretq`s back into ring 3 with the result in `rax`.

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

The ring 3 **user stack is grown on demand**: nothing is mapped at init, and the
page-fault handler faults pages in as the stack descends from
`USER_STACK_TOP_GVA` (a fault below `USER_STACK_LIMIT_GVA` is a genuine overflow
and aborts). A guest that never enters ring 3 — or uses only a shallow stack —
costs no physical pages, and snapshot/restore only ever touches the pages
actually used.

### 3.6 Syscall ABI

Syscall number in `rax`, arguments in `rdi`, `rsi`, `rdx`. There are two kinds:
*non-returning* syscalls unwind the kernel stack back into the `enter_user`
caller, and *returning* syscalls run a ring 0 handler and `sysretq` back into the
ring 3 code with a result in `rax`. The complete set is:

| # | Name | Kind | Meaning |
|---|------|------|---------|
| 0 | `SYS_RETURN` | non-returning | return a 64-bit value (in `rdi`) from the user function to the `enter_user` caller |
| 1 | `SYS_SELFTEST` | returning | XOR two scalars in ring 0 (validates the `sysretq` path) |
| 2 | `SYS_HOST_CALL` | returning | perform a host function call (request/result marshalled via a user-memory descriptor) |
| 3 | `SYS_OUTB` | returning | perform a privileged `out dx, eax` (abort / debug-print, whose data rides in the value) |
| 4 | `SYS_LOG` | returning | push a serialized guest log record to the host |
| 5 | `SYS_REGISTER` | returning | register a guest function whose definition was built in ring 3 (e.g. in `hyperlight_main`); the handler deep-clones it into the kernel heap and inserts it into the supervisor-only registry |

The ABI numbers live in one place, `hyperlight_guest::syscall`, shared by the
ring 3 issuers and the ring 0 dispatcher. Each privileged service keeps all PEB,
shared-buffer and `out` access in ring 0: ring 3 only ever serialises into, and
reads results from, its own user-accessible buffers.

### 3.7 The critical-data partition (`.kdata`)

Because the guest image is mapped user-accessible so ring 3 can execute it, the
runtime's writable statics that share the image would also be reachable from
ring 3. Most are merely *readable* (an information leak at worst), but a few are
**function pointers and handles that ring 0 itself dereferences**, which makes
them a direct privilege-escalation target:

| Static | Why it is dangerous |
|--------|---------------------|
| `REGISTERED_GUEST_FUNCTIONS` | ring 0 looks up and **calls** these pointers when dispatching a guest call |
| `HANDLERS` | exception-handler pointers ring 0 **calls** on a fault |
| `GUEST_HANDLE` | the PEB pointer ring 0 **dereferences** to reach the host |

The danger is not hypothetical. There is a single address space (one `CR3`;
neither `iretq` nor `syscall`/`sysret` switches it), and the shared image is
mapped copy-on-write *and* user-accessible. So a ring 3 **write** to the function
table would take the page-fault handler's CoW path, which — seeing a
user-accessible page — remaps that virtual address to a fresh **writable user**
page. Because the page-table entry is global, ring 0 would then dereference the
attacker-controlled copy on its next dispatch: ring 0 code execution.

The fix moves these statics out of ring 3's reach:

1. each is tagged `#[link_section = ".kdata"]` (only under the feature; in the
   default build they stay in `.bss`, byte-identical to mainline);
2. an augmenting linker script gathers `.kdata` into a single **page-aligned**
   output section bounded by `__kdata_start` / `__kdata_end` (so it never shares
   a page with anything ring 3 still needs, such as the CPL-routed allocator's
   control state). The script is **generated by `hyperlight-guest-bin`'s build
   script** (so its content lives once, with the runtime) and its path is
   exported to dependents via the `links` metadata channel; each guest applies
   it with a tiny, uniform build script that reads
   `DEP_HYPERLIGHT_GUEST_BIN_KDATA_LINKER_SCRIPT` (cargo does not propagate a
   library's link arguments to the final binary link, so the guest binary must
   add the `-T` argument itself). With the feature off nothing is emitted and the
   build is byte-identical;
3. at boot, **after** the function table is populated but **before** any ring 3
   code runs, `ring3::protect_kernel_data` walks `[__kdata_start, __kdata_end)`
   and re-protects every page supervisor-only, read/write, non-executable, with
   its own private physical backing (`paging::reprotect_page_supervisor`).

Giving each page private backing matters: it severs the CoW relationship with the
shared image, so a later ring 3 fault on a neighbouring image page cannot
resurrect access to a `.kdata` page.

Crucially, this protection is established **during initialisation**, so it is
captured by — and therefore survives — every snapshot and restore (the same
mechanism the user heap already relies on). A negative test reads `__kdata_start`
from ring 3 and asserts a page fault both before and after a restore.

**Scope and limitation.** This is the *critical-statics* slice of the data
partition, deliberately chosen over a blanket sweep of all runtime writable data
because the CPL-routed allocator (§3.9) keeps dispatch state that ring 3 must be
able to read; a blanket sweep would fault ring 3's own allocator. It closes the
*escalation* (ring 0 honouring ring-3-controlled pointers) but not every
*information leak* from shared runtime data — the full sweep is tracked as
[future work](#9-future-work).

### 3.8 Running guest functions in ring 3

With the feature enabled, the guest-function dispatch path runs the user function
*body* in ring 3. The function *lookup* and parameter *verification* stay in
ring 0, because they read the supervisor-only function registry; only the body
runs in ring 3. Crucially, ring 0 verification decodes only the call **header**
(the function name and the parameter *types*) from the encoded buffer — not the
parameter *values*. The whole buffer is still structurally validated, but the
values are materialised only once, in ring 3, on the user heap. This keeps a
large parameter (say a multi-kilobyte `Vec<u8>`) from being copied onto the
runtime's small kernel heap just to be type-checked and discarded. Three things
cross the privilege boundary, all because ring 3 cannot touch supervisor memory
or execute privileged instructions:

1. **Input marshalling.** The `FunctionCall` arrives in the supervisor input
   buffer. Its already-encoded bytes are copied **straight from the input buffer
   into a user-accessible buffer** — in place, without an intermediate copy onto
   the runtime's kernel heap — before entering ring 3, where the body
   deserialises its arguments from the user copy. (Forwarding the raw bytes
   avoids re-encoding the call; the header-only verification above avoids
   decoding the values in ring 0 at all; and staging in place means even a very
   large parameter is never copied onto the small kernel heap — only onto the
   user heap it is destined for.)
2. **Output marshalling.** The body returns a `Vec<u8>` in the user heap; after
   `SYS_RETURN` the ring 0 side pushes it **straight from the user heap** into
   the supervisor output buffer, with no intermediate kernel-heap copy (ring 0
   may read user memory, so the result never has to be staged through a kernel
   `Vec` first). The output buffer itself stays supervisor-only, so the host
   still only ever sees runtime-produced bytes.
3. **Privileged services.** Everything a guest function does that reaches the
   host funnels through the guest's `out32` chokepoint — host calls, logging, and
   abort all ultimately execute `out`, which faults in ring 3. `out32` gains a
   ring-3 branch (chosen by reading `CS & 3`) that issues a syscall instead:
   `SYS_OUTB` for the inline abort/log/debug values, and `SYS_HOST_CALL` for host
   calls, whose request and result are marshalled through user buffers while the
   privileged `out` and the shared-buffer access stay in ring 0.

The initialisation entry point, `hyperlight_main`, **also runs in ring 3** (via a
trampoline that runs its body and returns through `SYS_RETURN`), so *all* user
code runs unprivileged. `hyperlight_main` commonly registers guest functions, and
registration writes the supervisor-only registry (§3.7); that write is therefore
mediated by the `SYS_REGISTER` syscall. The ring 0 handler **deep-clones** the
definition into the kernel heap — so the registry never holds pointers into the
user heap — and inserts it. This grants ring 3 no new privilege: the registered
function is guest code that itself runs in ring 3 when later dispatched.
Guest-function *lookup* and parameter *verification* (which read the registry)
stay in ring 0.

Note that a function registered this way must, like any guest function, be
safe to run in ring 3 — it must reach the host only through the runtime's
CPL-aware entry points (which issue the mediating syscalls), not by directly
dereferencing the supervisor `GUEST_HANDLE` or issuing a raw `out`.

### 3.9 Heaps and the CPL-routed allocator

The guest has two heaps: a supervisor-only **kernel heap** for the runtime, and a
user-accessible **user heap** for ring 3 code. A single global allocator routes
between them: allocations are directed by the current privilege level (it reads
`CS & 3`, so ring 3 allocations come from the user heap and ring 0 allocations
from the kernel heap), and frees are routed by address range. The user heap's
control structure lives in user memory so ring 3 can manage it without a syscall.

The configured guest heap is the total budget. A small, configurable slice
(`SandboxConfiguration::set_kernel_heap_size`, default 64 KiB) backs the kernel
heap and the remainder backs the user heap, so the user heap scales with
`heap_size`. Both slices are copy-on-write from the configured heap, so the user
heap is reset correctly on snapshot restore. The dispatch state this allocator
reads on every allocation is why the user heap is deliberately *not* part of the
supervisor `.kdata` partition (§3.7).

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

## 5. What is implemented

The feature is complete enough to run real user code in ring 3 end to end:

- **Privilege transitions.** Ring 0 → ring 3 via `iretq`, ring 3 → ring 0 via
  `syscall`, with `sysret` for returning syscalls. The GDT user descriptors, the
  TSS, and the `syscall`/`sysret` MSRs are programmed at guest init.
- **User code in ring 3.** Both `hyperlight_main` and the registered guest
  functions run their bodies in ring 3, with arguments and results marshalled
  across the boundary (§3.8). Function lookup and parameter verification stay in
  ring 0. Registration performed by `hyperlight_main` is mediated to the
  supervisor registry by the `SYS_REGISTER` syscall.
- **Privileged services from ring 3.** Host calls, logging, and abort are
  mediated by syscalls (`SYS_HOST_CALL`, `SYS_LOG`, `SYS_OUTB`); ring 3 never
  executes a privileged instruction or touches a shared buffer directly.
- **Two heaps with a CPL-routed allocator** (§3.9): a supervisor kernel heap and
  a user-accessible user heap, both copy-on-write from the configured guest heap
  and reset correctly on snapshot restore.
- **The critical-data partition** (§3.7): the runtime statics that ring 0
  dereferences (the guest function table, the PEB handle, the exception-handler
  table) are supervisor-only and re-protected at boot, surviving snapshot/restore.
- **Snapshot and restore** work with ring 3 guests, including the copy-on-write
  re-fault of the user stack and user heap after a restore.

### How it is validated

- **Unit tests** for the page-table U/S plumbing
  (`cargo test -p hyperlight-common --features userspace`), plus compile-time
  `offset_of!` assertions that pin the GDT and selector layout the
  `syscall`/`sysret` arithmetic depends on.
- **Both feature states build and lint clean**, and the default
  (non-`userspace`) build is byte-identical to mainline.
- **Integration tests on a hypervisor** (`userspace_test`, KVM/mshv/WHP) cover
  the end-to-end path: a guest boots and passes its boot-time transition
  self-tests; guest functions echo typed values (string, `f64`, `f32`); a guest
  function calls a host function; logging and abort work; `hyperlight_main` runs
  in ring 3 and registers a guest function through `SYS_REGISTER` that is then
  dispatched and run; and repeated calls, call/restore cycles, and a configurable
  heap size all behave.
- **Negative security tests** (same suite) prove the isolation holds — see §2.

The boot-time self-test (`ring3::selftest`) performs a ring 0 → ring 3 → ring 0
round-trip during guest initialisation and aborts the guest if it fails, so every
ring 3 guest is self-checking on its first run.

## 6. How to build and run it

The ring 3 path runs only inside a VM, so validating it needs a hypervisor: KVM
or mshv on Linux, or WHP on Windows.

Build the guests (including the ring 3 variant, see §8) and run the userspace
integration tests:

```bash
just guests        # builds the guests, including the userspace variant (§8)
cargo test -p hyperlight-host --features userspace --test userspace_test
```

`userspace_guest_boots_and_selftests` passing proves the round-trip works end to
end: evolving the sandbox runs the guest's boot-time transition self-test, which
aborts the guest if the machinery is broken.

## 7. Performance

Because low-latency startup and guest-function execution are central to what
Hyperlight is for, the overhead of this boundary is a primary design
consideration, and is measured directly rather than assumed. Dropping to ring 3
adds a one-time cost at guest startup (the GDT/MSR programming, boot self-tests,
and critical-data re-protection) and a per-call cost (the privilege transition,
plus a marshalling copy for each guest call, host call, log, and abort). Both are
measured with a lightweight A/B harness in
[`src/hyperlight_host/tests/userspace_bench.rs`](../src/hyperlight_host/tests/userspace_bench.rs),
which loads the ring 0 and ring 3 builds of `simpleguest` and times identical
workloads against each in the same process, so the reported delta is a controlled
A/B:

```text
cargo test -p hyperlight-host --features userspace --test userspace_bench \
    -- --ignored --nocapture
```

### Results: dedicated A/B harness (`userspace_bench`)

KVM, release host + release guests. Representative medians over repeated runs on
a developer machine. The absolute figures are dominated by VM entry/exit and move
with the host, so the **delta** is the figure of interest.

| Workload | ring 0 | ring 3 delta | what it isolates |
|----------|-------:|-------------:|------------------|
| sandbox creation (one-time) | ~4.8-6.3 ms | **~1.5-2.2 ms (~25-40%)** | startup: image load, page tables, GDT/MSR setup, boot self-tests, `.kdata` re-protect |
| `GetStatic` — minimal call, no payload | ~22-23 µs | **~0-0.7 µs** | the bare transition; usually within noise |
| `CallMalloc` — 1 KiB allocate/free | ~24-26 µs | **~1 µs** | the CPL-routed allocator |
| `Echo` — 6-byte string round-trip | ~25-26 µs | **~1-1.5 µs** | payload marshalling both ways |
| `Echo` — 4 KiB string round-trip | ~30-31 µs | **~2-4 µs** | how marshalling scales with payload size |
| `Add` → `HostAdd` — host call from guest | ~45-49 µs | **~2.5-4.5 µs** | the nested ring 3 → ring 0 host-call path |
| `Echo` + snapshot restore | ~52-57 µs | **~10-14 µs (~20-29%)** | copy-on-write re-fault of user pages |

(The per-call micro-benchmarks are tens of microseconds, so on a loaded
developer box a single scheduling hiccup can briefly inflate a delta; the figures
above are the stable medians across runs.)

Interpretation:

- **The raw privilege transition is essentially free.** The minimal `GetStatic`
  call adds well under a microsecond, usually within measurement noise: the
  `iretq`/`syscall`/`sysretq` instructions are sub-microsecond, and the per-call
  baseline is dominated by VM entry/exit, which both modes pay equally.
- **The per-call ring 3 cost is cross-boundary marshalling, and it is roughly
  fixed.** Copying the call into a user buffer and the result back (and, for host
  calls, the request and result), plus the user-heap allocations, is what the
  `Echo`, `CallMalloc`, and host-call deltas measure. It grows only mildly with
  payload size (the 4 KiB `Echo` adds a little over the 6-byte one), so any guest
  function that does real work amortises it toward zero.
- **The one-time startup cost is the largest *relative* delta.** Creating a ring 3
  sandbox costs ~25-40% more than a ring 0 one — the GDT/MSR programming, the
  three boot self-tests, and the critical-data re-protection all run once at
  `evolve()`. This is paid once and amortised across every call the sandbox
  serves; for a sandbox that handles more than a handful of calls it is
  negligible, but it matters for create-once-call-once usage and is the first
  place to optimise if startup latency dominates.
- **Snapshot restore is the largest steady-state delta.** Restore is
  copy-on-write, so each cycle re-faults the user stack and user-heap pages that
  ring 3 dirtied during the call — the one place the extra ring 3 writable
  regions show up.
- **The critical-data partition (§3.7) adds no measurable per-call cost.** A
  controlled A/B against a build *without* the partition, measured under
  identical conditions, showed a statistically identical restore delta with and
  without it: the supervisor `.kdata` page is re-protected once at boot (captured
  in the snapshot baseline) and is never written on the hot path.

### Results: Criterion suite (`just bench`)

The same comparison is also produced by the main Criterion suite, so it is
tracked by the same tooling (and the same day-over-day baselines) as every other
Hyperlight benchmark. Building it with `--features userspace` adds a `/ring3`
variant for each guest-executing benchmark — every `guest_calls/{op}/{size}` row,
the `sandboxes` creation rows, the `snapshots` rows, the `sample_workloads`
`24K_in_8K_out` I/O workload, and the `guest_functions_with_large_parameters`
workload (~100 MiB of parameters). The ring 0 IDs and their saved baselines are
unchanged, so the ring 3 rows are purely additive.

Two benchmark groups are intentionally **not** given a ring 3 variant because no
guest code runs in them, so the ring would make no difference:
`function_call_serialization` (host-side flatbuffer encode/decode) and
`shared_memory` (host-side buffer fill/copy). `guest_calls/different_thread` and
`guest_calls/interrupt_latency` likewise stay ring-0-only — they measure thread
and interrupt mechanics, not the privilege boundary.

```text
# the microsecond-scale rows (guest_calls / sandboxes / snapshots / 24K_in_8K_out)
cargo bench -p hyperlight-host --features userspace -- 'guest_calls/|sandboxes/|snapshots/|sample_workloads/24K'
# the ~100 MiB-payload workload (hundreds of ms to ~1 s per iteration), run separately
cargo bench -p hyperlight-host --features userspace -- guest_functions_with_large_parameters
```

The tables below pair each ring 0 row with its `/ring3` sibling from the same
run. **Δ% is the ring 3 overhead** — a positive number means ring 3 is that much
slower than ring 0. (This is the opposite sign convention to a "speed-up" report,
where an improvement is negative; here ring 3 is the more-secured, slower
variant, so the interesting deltas are positive.) A row where ring 3 measured
*faster* than ring 0 is an impossible "negative overhead" — pure run-to-run
variance — and is labelled `noise`; the larger millisecond-scale rows, dominated
by guest-memory zeroing that both rings pay equally, are the noisiest.

These are measured on **real hardware**, one section per hypervisor (produced by
[`dev/run-userspace-benchmarks.sh`](../dev/run-userspace-benchmarks.sh)). The
absolute figures move with the machine and hypervisor — mshv/KVM/WHP VM-exit
costs, the CPU, and the vCPU count all differ — so the portable figure is the
**Δ%**. (All three machines below — mshv, Ubuntu/KVM, and Windows/WHP.)

#### Machine 1 — mshv · Azure `Standard_D2s_v5` · Intel Xeon Platinum 8370C · 2 vCPU

Release host + guests on `feature/userspace-ring3`, rustc 1.89, idle box.

**Guest calls** — the core per-call cost, at four sandbox sizes:

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `guest_calls/call/default` | 69.21 µs | 74.58 µs | +7.8% |
| `guest_calls/call/small` | 70.77 µs | 75.67 µs | +6.9% |
| `guest_calls/call/medium` | 73.61 µs | 74.57 µs | +1.3% |
| `guest_calls/call/large` | 69.03 µs | 74.37 µs | +7.7% |
| `guest_calls/call_with_restore/default` | 234.3 µs | 235.6 µs | +0.5% |
| `guest_calls/call_with_restore/small` | 234.5 µs | 238.3 µs | +1.6% |
| `guest_calls/call_with_restore/medium` | 248.0 µs | 252.0 µs | +1.6% |
| `guest_calls/call_with_restore/large` | 356.2 µs | 357.1 µs | +0.3% |
| `guest_calls/call_with_host_function/default` | 104.7 µs | 113.6 µs | +8.5% |
| `guest_calls/call_with_host_function/small` | 105.6 µs | 115.8 µs | +9.7% |
| `guest_calls/call_with_host_function/medium` | 107.2 µs | 114.3 µs | +6.6% |
| `guest_calls/call_with_host_function/large` | 107.8 µs | 115.9 µs | +7.5% |

**Sandbox creation** — the one-time startup cost, at four sandbox sizes, for the
create-only benchmarks and the `_and_drop` variants that also measure teardown
(the larger sizes are dominated by the time to zero/copy the bigger guest memory,
which both rings pay equally, so the ring 3 fraction shrinks into copy-time
noise):

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `sandboxes/create_uninitialized/default` | 379.2 µs | 421.9 µs | +11.3% |
| `sandboxes/create_uninitialized/small` | 2.250 ms | 2.352 ms | +4.5% |
| `sandboxes/create_uninitialized/medium` | 27.03 ms | 26.94 ms | noise |
| `sandboxes/create_uninitialized/large` | 97.38 ms | 82.02 ms | noise |
| `sandboxes/create_uninitialized_and_drop/default` | 404.0 µs | 440.0 µs | +8.9% |
| `sandboxes/create_uninitialized_and_drop/small` | 2.435 ms | 2.483 ms | +2.0% |
| `sandboxes/create_uninitialized_and_drop/medium` | 26.73 ms | 26.88 ms | +0.6% |
| `sandboxes/create_uninitialized_and_drop/large` | 97.51 ms | 82.89 ms | noise |
| `sandboxes/create_initialized/default` | 1.758 ms | 1.834 ms | +4.4% |
| `sandboxes/create_initialized/small` | 5.856 ms | 5.914 ms | +1.0% |
| `sandboxes/create_initialized/medium` | 29.71 ms | 30.43 ms | +2.4% |
| `sandboxes/create_initialized/large` | 89.40 ms | 87.76 ms | noise |
| `sandboxes/create_initialized_and_drop/default` | 32.38 ms | 32.06 ms | noise |
| `sandboxes/create_initialized_and_drop/small` | 40.04 ms | 39.98 ms | noise |
| `sandboxes/create_initialized_and_drop/medium` | 63.00 ms | 63.44 ms | +0.7% |
| `sandboxes/create_initialized_and_drop/large` | 122.2 ms | 119.8 ms | noise |

**Snapshots** — create and restore, at four sizes:

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `snapshots/create/default` | 364.1 µs | 383.9 µs | +5.4% |
| `snapshots/create/small` | 3.660 ms | 4.135 ms | +13.0% |
| `snapshots/create/medium` | 50.35 ms | 50.94 ms | +1.2% |
| `snapshots/create/large` | 189.3 ms | 175.8 ms | noise |
| `snapshots/restore/default` | 153.7 µs | 155.2 µs | +1.0% |
| `snapshots/restore/small` | 156.4 µs | 155.8 µs | noise |
| `snapshots/restore/medium` | 173.7 µs | 167.7 µs | noise |
| `snapshots/restore/large` | 1.818 ms | 1.106 ms | noise |

**I/O workloads** (the large-parameter row is from a separate run since its
~100-millisecond iterations would otherwise dominate the wall-clock):

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `sample_workloads/24K_in_8K_out` (24 KiB in, 8 KiB out; rust guest) | 89.56 µs | 92.61 µs | +3.4% |
| `guest_functions_with_large_parameters` (~100 MiB in) | 137.3 ms | 193.0 ms | +40.6% |

These confirm the per-call cost scales with how much data crosses the boundary,
and the bare transition does not:

- **The bare transition is a few percent.** `guest_calls/call` is +7-8% at three
  of the four sizes (the +1.3% at `medium` is a high ring 0 outlier inflating the
  baseline, not a real reduction), and `snapshots/restore/default` is +1.0% — the
  privilege drop plus the small fixed marshalling is a single-digit percentage of
  a call otherwise dominated by VM entry/exit, which both rings pay equally.
- **The per-call delta tracks payload size.** `24K_in_8K_out` (+3.4%) and
  `guest_functions_with_large_parameters` (+40.6% for ~100 MiB) are dominated by
  the cross-boundary marshalling copy: the encoded call is staged into the user
  heap and the result copied back, so the ring 3 cost grows with the bytes moved.
  The large-parameter row only runs at all because the ring 0 dispatch stages the
  call **in place** from the input buffer (§3.8) — the ~100 MiB payload is never
  copied onto the runtime's small kernel heap, only onto the user heap it is
  destined for.
- **`call_with_restore` (+0.3-1.6%)** is dominated by the restore work itself, so
  the ring 3 fraction is small. The per-size `snapshots/restore` rows sit at or
  below the noise floor on this 2-vCPU box (the `large` rows swing especially
  widely), so they are not a reliable ring 3 signal at this sample size — the
  copy-on-write re-fault of the user pages is real but small relative to the
  restore.
- **Creation deltas** (`create_uninitialized/default` +11.3%,
  `create_initialized/default` +4.4%, `snapshots/create/default` +5.4%) come from
  the larger user-accessible image, the extra GDT/MSR/boot self-test setup, and
  the user-heap regions captured in the initial snapshot. At larger sandbox sizes
  the absolute startup cost is swamped by the time to zero/copy the bigger guest
  memory (which both rings pay equally), so the *ring 3* fraction shrinks and the
  large-size rows fall into copy-time noise.

#### Machine 2 — kvm · Azure · Ubuntu 20.04 · Intel Xeon Platinum 8370C · 8 vCPU

Release host + guests on `feature/userspace-ring3`, rustc 1.89, idle box. Same
CPU as the mshv box but 8 vCPU and a cheaper KVM VM-exit path, so the absolute
figures are roughly 3× lower — the per-call `call` rows (~17-19 µs) sit at the
noise floor, where a jittery ring 0 baseline (the four sizes land in a
non-monotonic 18.8 / 19.5 / 16.7 / 17.3 µs order) swings the per-call delta from
ring 3 marginally *faster* to a spurious +13% — all run-to-run variance.

**Guest calls** — the core per-call cost, at four sandbox sizes:

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `guest_calls/call/default` | 18.76 µs | 18.93 µs | +0.9% |
| `guest_calls/call/small` | 19.48 µs | 19.24 µs | noise |
| `guest_calls/call/medium` | 16.74 µs | 18.92 µs | +13.0% |
| `guest_calls/call/large` | 17.34 µs | 18.59 µs | +7.2% |
| `guest_calls/call_with_restore/default` | 38.26 µs | 41.99 µs | +9.7% |
| `guest_calls/call_with_restore/small` | 38.47 µs | 41.24 µs | +7.2% |
| `guest_calls/call_with_restore/medium` | 43.73 µs | 46.84 µs | +7.1% |
| `guest_calls/call_with_restore/large` | 97.35 µs | 102.6 µs | +5.4% |
| `guest_calls/call_with_host_function/default` | 31.98 µs | 34.11 µs | +6.7% |
| `guest_calls/call_with_host_function/small` | 31.78 µs | 35.39 µs | +11.4% |
| `guest_calls/call_with_host_function/medium` | 31.33 µs | 35.26 µs | +12.5% |
| `guest_calls/call_with_host_function/large` | 31.80 µs | 35.04 µs | +10.2% |

**Sandbox creation** — create-only and `_and_drop` (create + teardown), four sizes:

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `sandboxes/create_uninitialized/default` | 371.2 µs | 420.9 µs | +13.4% |
| `sandboxes/create_uninitialized/small` | 3.605 ms | 3.625 ms | +0.5% |
| `sandboxes/create_uninitialized/medium` | 21.93 ms | 21.31 ms | noise |
| `sandboxes/create_uninitialized/large` | 83.29 ms | 79.57 ms | noise |
| `sandboxes/create_uninitialized_and_drop/default` | 408.8 µs | 441.1 µs | +7.9% |
| `sandboxes/create_uninitialized_and_drop/small` | 3.564 ms | 3.562 ms | noise |
| `sandboxes/create_uninitialized_and_drop/medium` | 21.98 ms | 21.23 ms | noise |
| `sandboxes/create_uninitialized_and_drop/large` | 83.75 ms | 79.01 ms | noise |
| `sandboxes/create_initialized/default` | 1.613 ms | 1.783 ms | +10.6% |
| `sandboxes/create_initialized/small` | 5.464 ms | 5.112 ms | noise |
| `sandboxes/create_initialized/medium` | 22.51 ms | 22.89 ms | +1.7% |
| `sandboxes/create_initialized/large` | 80.63 ms | 80.20 ms | noise |
| `sandboxes/create_initialized_and_drop/default` | 2.154 ms | 2.388 ms | +10.9% |
| `sandboxes/create_initialized_and_drop/small` | 5.958 ms | 5.939 ms | noise |
| `sandboxes/create_initialized_and_drop/medium` | 23.77 ms | 23.50 ms | noise |
| `sandboxes/create_initialized_and_drop/large` | 83.33 ms | 83.67 ms | +0.4% |

**Snapshots** — create and restore, at four sizes:

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `snapshots/create/default` | 286.2 µs | 310.2 µs | +8.4% |
| `snapshots/create/small` | 4.111 ms | 3.959 ms | noise |
| `snapshots/create/medium` | 48.75 ms | 48.20 ms | noise |
| `snapshots/create/large` | 183.8 ms | 182.8 ms | noise |
| `snapshots/restore/default` | 14.29 µs | 14.62 µs | +2.3% |
| `snapshots/restore/small` | 14.70 µs | 15.03 µs | +2.2% |
| `snapshots/restore/medium` | 18.38 µs | 18.69 µs | +1.7% |
| `snapshots/restore/large` | 84.93 µs | 82.78 µs | noise |

**I/O workloads** (the large-parameter row is from a separate run):

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `sample_workloads/24K_in_8K_out` (24 KiB in, 8 KiB out; rust guest) | 29.23 µs | 32.30 µs | +10.5% |
| `guest_functions_with_large_parameters` (~100 MiB in) | 464.3 ms | 746.5 ms | +60.8% |

The KVM numbers match mshv on the fundamentals: the bare transition is lost in
the noise (the per-call `call` rows swing with a jittery ring 0 baseline rather
than showing real ring 3 overhead), the marshalling-bound rows scale with payload
(`24K` +10.5%, large-parameters +60.8%), and the host-call, restore, and creation
overheads are a steady single-to-low-double-digit percentage
(`call_with_host_function` +7-13%, `call_with_restore` +5-10%, `snapshots/restore`
+1.7-2.3%, `create_*/default` +8-13%). The larger millisecond-scale create/snapshot
rows are dominated by guest-memory zeroing that both rings pay equally, so they
fall into the noise.

#### Machine 3 — whp · Azure · Windows Server 2022 · Intel Xeon Platinum 8573C · 8 vCPU

Release host + guests on `feature/userspace-ring3`, rustc 1.89, idle box. WHP has
the most expensive VM exits of the three hypervisors, so the absolute latencies
are the highest here (per-call `call` ~88-98 µs; the ~100 MiB large-parameter
workload takes whole seconds), which makes the small per-call deltas the noisiest
of the three machines.

**Guest calls** — the core per-call cost, at four sandbox sizes:

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `guest_calls/call/default` | 89.48 µs | 92.95 µs | +3.9% |
| `guest_calls/call/small` | 89.39 µs | 92.23 µs | +3.2% |
| `guest_calls/call/medium` | 92.89 µs | 96.03 µs | +3.4% |
| `guest_calls/call/large` | 88.43 µs | 97.55 µs | +10.3% |
| `guest_calls/call_with_restore/default` | 204.3 µs | 209.4 µs | +2.5% |
| `guest_calls/call_with_restore/small` | 222.4 µs | 231.8 µs | +4.2% |
| `guest_calls/call_with_restore/medium` | 262.2 µs | 276.3 µs | +5.4% |
| `guest_calls/call_with_restore/large` | 388.0 µs | 397.4 µs | +2.4% |
| `guest_calls/call_with_host_function/default` | 166.1 µs | 176.9 µs | +6.5% |
| `guest_calls/call_with_host_function/small` | 186.2 µs | 174.9 µs | noise |
| `guest_calls/call_with_host_function/medium` | 186.1 µs | 179.6 µs | noise |
| `guest_calls/call_with_host_function/large` | 194.4 µs | 185.4 µs | noise |

**Sandbox creation** — create-only and `_and_drop` (create + teardown), four sizes:

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `sandboxes/create_uninitialized/default` | 896.5 µs | 858.7 µs | noise |
| `sandboxes/create_uninitialized/small` | 8.743 ms | 8.749 ms | noise |
| `sandboxes/create_uninitialized/medium` | 63.21 ms | 63.61 ms | +0.6% |
| `sandboxes/create_uninitialized/large` | 244.3 ms | 256.7 ms | +5.1% |
| `sandboxes/create_uninitialized_and_drop/default` | 921.3 µs | 920.9 µs | noise |
| `sandboxes/create_uninitialized_and_drop/small` | 9.628 ms | 9.501 ms | noise |
| `sandboxes/create_uninitialized_and_drop/medium` | 69.23 ms | 69.94 ms | +1.0% |
| `sandboxes/create_uninitialized_and_drop/large` | 272.5 ms | 280.0 ms | +2.7% |
| `sandboxes/create_initialized/default` | 7.498 ms | 8.224 ms | +9.7% |
| `sandboxes/create_initialized/small` | 17.36 ms | 17.75 ms | +2.3% |
| `sandboxes/create_initialized/medium` | 74.08 ms | 73.99 ms | noise |
| `sandboxes/create_initialized/large` | 270.2 ms | 266.0 ms | noise |
| `sandboxes/create_initialized_and_drop/default` | 9.050 ms | 9.160 ms | +1.2% |
| `sandboxes/create_initialized_and_drop/small` | 17.20 ms | 19.74 ms | +14.8% |
| `sandboxes/create_initialized_and_drop/medium` | 80.90 ms | 82.37 ms | +1.8% |
| `sandboxes/create_initialized_and_drop/large` | 292.0 ms | 293.0 ms | +0.3% |

**Snapshots** — create and restore, at four sizes:

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `snapshots/create/default` | 622.8 µs | 672.8 µs | +8.0% |
| `snapshots/create/small` | 11.78 ms | 11.98 ms | +1.7% |
| `snapshots/create/medium` | 93.86 ms | 94.23 ms | +0.4% |
| `snapshots/create/large` | 387.3 ms | 388.5 ms | +0.3% |
| `snapshots/restore/default` | 100.96 µs | 110.45 µs | +9.4% |
| `snapshots/restore/small` | 114.3 µs | 116.8 µs | +2.2% |
| `snapshots/restore/medium` | 186.2 µs | 179.1 µs | noise |
| `snapshots/restore/large` | 28.11 ms | 27.89 ms | noise |

**I/O workloads** (the large-parameter row is from a separate run):

| Benchmark | ring 0 | ring 3 | Δ% |
|-----------|-------:|-------:|----:|
| `sample_workloads/24K_in_8K_out` (24 KiB in, 8 KiB out; rust guest) | 103.8 µs | 116.7 µs | +12.5% |
| `guest_functions_with_large_parameters` (~100 MiB in) | 7.915 s | 10.96 s | +38.4% |

Same story on the third hypervisor: the bare transition is small and noisy
relative to WHP's expensive VM exits (`call` +3-10%), the marshalling-bound rows
scale with payload (`24K` +12.5%, large-parameters +38.4%), and the host-call,
restore, and creation overheads are single-to-low-double-digit percentages
(`call_with_restore` +2.4-5.4%, `snapshots/restore/default` +9.4%,
`create_*/default` +8-10%). WHP's `call_with_host_function` and several large
millisecond-scale rows sit at or below the noise floor (a few measure ring 3
marginally faster). Across all three machines the absolute latencies differ
widely (KVM < mshv < WHP) but the **Δ% story is consistent**: ring 3 adds a
small, payload-scaling percentage, and the bare privilege transition is lost in
the per-call VM-exit cost that both rings pay.

Wiring the userspace guest build into `just guests`/CI and gating on the ring 3
overhead remain open (see [Future work](#9-future-work)).



## 8. Building the ring 3 guest

The `userspace` build of `simpleguest` is a separate artifact
(`simpleguest-userspace`) so the ring 0 and ring 3 variants can be compared
directly. It is produced from the same source with the `userspace` feature and
resolved by the `simple_guest_userspace_as_string()` testing helper. Wiring this
build into `just guests` and CI is a remaining task (see
[Future work](#9-future-work)).

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

### 9.2 Completing the data partition

The critical-data partition (§3.7) and the split kernel/user heap (§3.9) are in
place, and the `.kdata` hardening is applied automatically to any guest that
enables the feature (the runtime crate generates the linker script and each
guest applies it through a uniform build script — see §3.7). One thing remains to
make the data partition *complete* rather than *escalation-safe*:

- **A full sweep of runtime writable data.** Today only the escalation-critical
  statics are carved into supervisor `.kdata`; the rest of the runtime crates'
  `.data`/`.bss` still shares the user-accessible guest image, leaving a residual
  *information-leak* surface. Extending the generated linker script to place all
  of it into supervisor sections would close this, but must special-case the
  CPL-routed allocator's control state, which ring 3 legitimately reads.

### 9.3 Other

- **Single-buffer marshalling copy.** The ring 3 input marshalling stages the
  encoded call into a single contiguous user-heap buffer (§3.8). This is no
  longer a *correctness* limit — the buffer comes from the user heap, which
  scales with the configured heap, and staging in place avoids any kernel-heap
  copy — but for a very large parameter it still means one large (power-of-two
  rounded) allocation and one full copy per call. Chunked or streamed marshalling
  would reduce the peak footprint and the copy cost for multi-hundred-megabyte
  payloads; it is not required for correctness.
- **Benchmark CI integration.** The `GuestMode { Ring0, Ring3 }` axis is wired
  into the Criterion suite (§7) — including sandbox creation, so the one-time
  startup cost is captured — but the userspace guest build is not yet wired into
  `just guests` and CI, so the ring 3 rows only appear when the suite is built
  with `--features userspace`. A perf gate on ring 3 overhead can follow once
  baselines are stable on a stable CI machine; initially the ring 3 benchmarks
  run informationally.
- **i686 / aarch64.** The i686 page-table backend already honours
  `user_accessible`; a full ring 3 story for either architecture is unscoped.

## 10. References

- AMD64 Architecture Programmer's Manual, Volume 2: System Programming —
  §4 (segmentation), §5 (paging), §6 (exceptions/interrupts), §A (syscall/sysret).
- Intel 64 and IA-32 Architectures SDM, Volume 3A — Chapter 5 (paging).
- Source of truth in-tree:
  [`ring3.rs`](../src/hyperlight_guest_bin/src/arch/amd64/ring3.rs),
  [`init.rs`](../src/hyperlight_guest_bin/src/arch/amd64/init.rs),
  [`machine.rs`](../src/hyperlight_guest_bin/src/arch/amd64/machine.rs),
  [`vmem.rs`](../src/hyperlight_common/src/arch/amd64/vmem.rs).
