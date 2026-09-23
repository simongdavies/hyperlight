#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Hyperlight Authors.

"""Run the installed unprivileged Linux process-placement campaign."""

import argparse
import datetime
import os
from pathlib import Path
import subprocess
import time
import uuid


LIBEXEC = Path("/usr/libexec/hyperlight")
EXECUTABLE = LIBEXEC / "process_placement"
GUEST = LIBEXEC / "simpleguest"
MODE_TIMEOUT = 690


def run(command, **kwargs):
    print("+", " ".join(map(str, command)), flush=True)
    kwargs.setdefault("timeout", MODE_TIMEOUT)
    return subprocess.run(command, check=True, **kwargs)


def assert_no_residue():
    units = subprocess.run(
        [
            "systemctl", "--user", "list-units", "--all", "--plain",
            "--no-legend", "hyperlight-*",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    ).stdout.strip()
    if units:
        raise RuntimeError(f"Hyperlight transient unit residue:\n{units}")
    user_root = Path(
        f"/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice/"
        f"user@{os.getuid()}.service"
    )
    residue = [
        path
        for path in user_root.rglob("hyperlight-*")
        if path.is_dir()
    ]
    if residue:
        raise RuntimeError(f"Hyperlight cgroup residue: {residue}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit("qualification must run as an ordinary user")
    launcher = Path("/usr/bin/hyperlight-run")
    for asset in (launcher, EXECUTABLE, GUEST):
        if not asset.is_file():
            raise SystemExit(f"installed qualification asset is missing: {asset}")
    run([str(launcher), "check"])
    assert_no_residue()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    stamp += f"-{uuid.uuid4().hex[:8]}Z"
    output = Path.cwd() / "hyperlight-process-isolation-output" / stamp
    output.mkdir(parents=True)
    modes = [
        "local", "worker", "sandbox", "sandbox-worker",
        "children-allow", "children-deny",
    ]
    for mode in modes:
        destination = output / mode
        if mode == "local":
            command = [str(EXECUTABLE), mode, str(GUEST), str(destination)]
        else:
            command = [
                launcher, "--runtime-max", "10min", "--",
                str(EXECUTABLE), mode, str(GUEST), str(destination),
            ]
        try:
            run(command, timeout=MODE_TIMEOUT)
        except subprocess.TimeoutExpired:
            assert_no_residue()
            raise
        if not (destination / "snapshot").is_dir():
            raise RuntimeError(f"{mode}: snapshot layout is missing")
        assert_no_residue()
    start = time.monotonic()
    try:
        timeout = subprocess.run(
            [
                launcher, "--runtime-max", "1s", "--stop-timeout", "10", "--",
                "/bin/bash", "-c", "sleep 30",
            ],
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        assert_no_residue()
        raise
    elapsed = time.monotonic() - start
    if timeout.returncode == 0 or not 0.8 <= elapsed < 25:
        raise RuntimeError(
            "outer runtime deadline did not terminate the request "
            f"(rc={timeout.returncode}, elapsed={elapsed:.1f}s)"
        )
    assert_no_residue()
    print(f"PASS complete Linux process-placement campaign: {output}")


if __name__ == "__main__":
    main()
