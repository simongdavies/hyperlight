#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Unprivileged x86-64 Linux regression of the actual helper, using ptrace."""

import argparse
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi "
        "orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs"
    ).split()]


libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [
    ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p
]


def ptrace(request, pid, addr=0, data=0):
    result = libc.ptrace(request, pid, addr, data)
    if result == -1:
        raise OSError(ctypes.get_errno(), f"ptrace {request:#x}, pid {pid}")
    return result


def traced_run(command, mode):
    """Inject only in a forked child. Parent probes and setup run unchanged."""
    def traceme():
        ptrace(0, 0)

    def timed_out(signum, frame):
        raise TimeoutError("traced helper exceeded 15 seconds")

    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            command, stdout=output, stderr=errors, preexec_fn=traceme
        )
        _, status = os.waitpid(process.pid, 0)
        assert os.WIFSTOPPED(status), status
        # TRACESYSGOOD, TRACEFORK/VFORK/CLONE, EXITKILL.
        ptrace(0x4200, process.pid, 0, 1 | 2 | 4 | 8 | 0x100000)
        live = {process.pid}
        pending = {}
        counts = {}
        events = []
        injected = False
        root_status = None
        ptrace(24, process.pid)
        previous_alarm = signal.signal(signal.SIGALRM, timed_out)
        signal.alarm(15)
        try:
            while live:
                pid, status = os.waitpid(-1, 0x40000000)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    live.discard(pid)
                    if pid == process.pid:
                        root_status = os.waitstatus_to_exitcode(status)
                    continue
                live.add(pid)
                stop = os.WSTOPSIG(status)
                event = status >> 16
                if os.environ.get("MINIJAIL_TRACE_DEBUG") and stop != 133:
                    print("trace-stop", mode, pid, stop, event, flush=True)
                if event in (1, 2, 3):
                    child = ctypes.c_ulong()
                    ptrace(0x4201, pid, 0, ctypes.byref(child))
                    live.add(child.value)
                if stop == (signal.SIGTRAP | 0x80):
                    info = ctypes.create_string_buffer(128)
                    ptrace(0x420e, pid, 128, ctypes.byref(info))
                    operation = info.raw[0]
                    regs = Registers()
                    ptrace(12, pid, 0, ctypes.byref(regs))
                    if operation == 1 and regs.orig_rax in (444, 445, 446):
                        kind = {444: "create", 445: "rule", 446: "apply"}[
                            regs.orig_rax
                        ]
                        if regs.orig_rax == 444 and regs.rdx == 1:
                            kind = "version"
                        counts[pid, kind] = counts.get((pid, kind), 0) + 1
                        replacement = None
                        if pid != process.pid:
                            if mode == "abi" and kind == "version":
                                replacement = 4
                            if mode == "query-error" and kind == "version":
                                replacement = -errno.ENOSYS
                            if mode == "create" and kind == "create":
                                replacement = -errno.EOPNOTSUPP
                            if mode == "access-mask" and kind == "create":
                                replacement = -errno.EINVAL
                            if mode == "apply" and kind == "apply":
                                replacement = -errno.EPERM
                            if mode.startswith("rule-") and kind == "rule":
                                if counts[pid, kind] == int(mode.split("-")[1]):
                                    replacement = -errno.EIO
                        pending[pid] = (kind, replacement)
                        if replacement is not None:
                            regs.orig_rax = 0xffffffffffffffff
                            ptrace(13, pid, 0, ctypes.byref(regs))
                            injected = True
                    elif operation == 2 and pid in pending:
                        kind, replacement = pending.pop(pid)
                        if replacement is not None:
                            regs.rax = replacement & 0xffffffffffffffff
                            ptrace(13, pid, 0, ctypes.byref(regs))
                        result = ctypes.c_longlong(regs.rax).value
                        events.append((pid != process.pid, kind, result))
                        if os.environ.get("MINIJAIL_TRACE_DEBUG"):
                            print("landlock", mode, events[-1], flush=True)
                deliver = 0 if stop in (
                    signal.SIGTRAP, signal.SIGTRAP | 0x80, signal.SIGSTOP
                ) else stop
                ptrace(24, pid, 0, deliver)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_alarm)
            for pid in live:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for pid in live:
                try:
                    os.waitpid(pid, 0x40000000)
                except ChildProcessError:
                    pass
            process.returncode = root_status
        output.seek(0)
        errors.seek(0)
        return root_status, output.read().decode(), errors.read().decode(), events, injected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("helper", type=Path)
    args = parser.parse_args()
    helper = args.helper.resolve()
    assert platform.machine() == "x86_64", "ptrace register layout is x86-64"
    assert os.geteuid() != 0, "run directly as an unprivileged user"
    print("helper_sha256", hashlib.sha256(helper.read_bytes()).hexdigest())
    with tempfile.TemporaryDirectory(prefix="minijail-required-") as directory:
        root = Path(directory) / "root"
        root.mkdir()
        (root / "proc").mkdir()
        (root / "allowed").write_text("allowed\n")
        (root / "denied").write_text("private\n")
        subprocess.run([
            "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
            str(Path(__file__).with_name("minijail_probe.c")),
            "-o", str(root / "program"),
        ], check=True)
        base = [
            str(helper), "-U", "-m", "-M", "-I", "-n", "-c0", "--ambient",
            "-P", str(root), "-b", f"{root},/,1",
            "-k", "proc,/proc,proc,15", "--landlock-abi", "5",
        ]
        rules = [
            "--fs-path-rx", "/program", "--fs-path-ro", "/allowed",
            "--fs-path-ro", "/proc",
        ]
        tail = ["-T", "static", "--logging", "stderr", "--", "/program"]
        required = base + ["--require-landlock"] + rules + tail

        # This is a real untraced launch, not a parent availability probe.
        result = subprocess.run(required, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, (result.returncode, result.stderr, result.stdout)
        assert "CONFINEMENT_OK" in result.stdout, result.stdout
        assert (root / "allowed").read_text() == "allowed\n"
        assert not (root / "created").exists()
        print("PASS real strict root confinement:", result.stdout.strip())

        # A traced success controls for ptrace itself affecting namespace setup.
        status, out, err, events, injected = traced_run(required, "none")
        assert status == 0 and "CONFINEMENT_OK" in out, (status, out, err, events)
        assert any(child and kind == "apply" and value == 0
                   for child, kind, value in events), events
        print("PASS traced strict success", events)

        for mode in (
            "abi", "query-error", "create", "access-mask",
            "rule-1", "rule-2", "rule-3", "apply",
        ):
            status, out, err, events, injected = traced_run(required, mode)
            assert injected, (mode, err, events)
            assert status != 0 and "WORKLOAD_EXECUTED" not in out, (
                mode, status, out, err, events
            )
            assert "required Landlock:" in err, (mode, err, events)
            if mode in ("create", "access-mask"):
                assert any(child and kind == "version" and value >= 5
                           for child, kind, value in events), events
            print(f"PASS child {mode}: exit={status} marker=absent events={events}")

        # Default best-effort behavior still runs after child CREATE failure.
        default = base + rules + tail + ["marker"]
        status, out, err, events, injected = traced_run(default, "create")
        assert injected and status == 0 and "WORKLOAD_EXECUTED" in out, (
            status, out, err, events
        )
        print("PASS default CREATE failure remains best-effort")

        cases = {
            "missing-rule": base + ["--require-landlock"] + rules +
                ["--fs-path-ro", "/missing"] + tail,
            "no-rules": base + ["--require-landlock"] + tail,
            "disabled": base + ["--require-landlock", "--no-fs-restrictions"] + tail,
            "unsupported-target": base + ["--landlock-abi", "6", "--require-landlock"] +
                rules + tail,
            "zero-target": base + ["--landlock-abi", "0", "--require-landlock"] +
                rules + tail,
            "preload": base + ["--require-landlock"] + rules +
                ["-T", "dynamic", "--preload-library",
                 str(helper.with_name("libminijailpreload.so")),
                 "--logging", "stderr", "--", "/program"],
        }
        for name, command in cases.items():
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            assert result.returncode != 0 and "WORKLOAD_EXECUTED" not in result.stdout, (
                name, result.returncode, result.stdout, result.stderr
            )
            assert "required Landlock" in result.stderr, (name, result.stderr)
            print(f"PASS {name}: exit={result.returncode} marker=absent")


if __name__ == "__main__":
    main()
