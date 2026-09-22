#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Offline, explicit Minijail build. Never called from Cargo or build.rs."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile


HERE = Path(__file__).resolve().parent


def run(command, **kwargs):
    print("+", " ".join(map(str, command)), flush=True)
    return subprocess.run(command, check=True, **kwargs)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(source, epoch):
    # No caller-supplied compiler flags, make flags, preload or search paths.
    env = {
        "PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"],
        "PWD": str(source),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
        "SHELL": "/bin/bash", "SOURCE_DATE_EPOCH": epoch,
        "CC": "gcc", "CXX": "g++", "AR": "ar",
        "CFLAGS": f"-ffile-prefix-map={source}=/minijail",
        "CXXFLAGS": f"-ffile-prefix-map={source}=/minijail",
    }
    settings = [
        "SHELL=/bin/bash", "MODE=opt", "NOSTRIP=1", "SPLITDEBUG=0",
        "BUILD_STATIC_LIBS=no", "USE_SYSTEM_GTEST=no",
        "USE_seccomp=yes", "USE_ASAN=no",
    ]
    run(["make", *settings, "clean"], cwd=source, env=env)
    run(["make", *settings, "-j8", "all"], cwd=source, env=env)
    return source / "minijail0"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="existing pinned source checkout")
    parser.add_argument("--base-control", action="store_true",
                        help="also build a pristine offline control under source/.validation")
    parser.add_argument("--verify-recorded", action="store_true",
                        help="require the recorded helper digest (same toolchain)")
    args = parser.parse_args()
    assert os.geteuid() != 0, "run unprivileged"
    source = args.source.resolve()
    manifest = json.loads((HERE / "minijail-source.json").read_text())
    patch = HERE / "minijail-require-landlock.patch"
    assert digest(patch) == manifest["patch_sha256"], "patch digest mismatch"
    git = ["git", "-C", str(source)]
    head = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    assert head == manifest["source_commit"], f"unexpected source pin: {head}"
    assert not subprocess.check_output([*git, "diff", "--cached"]), "staged source edits"
    diff_command = [
        *git, "-c", "core.autocrlf=false", "diff", "--no-ext-diff",
        "--no-textconv", "--binary", "--full-index", "--src-prefix=a/",
        "--dst-prefix=b/", "HEAD", "--",
    ]
    diff = subprocess.check_output(diff_command)
    if not diff:
        run([*git, "apply", "--check", str(patch)])
        run([*git, "apply", str(patch)])
        diff = subprocess.check_output(diff_command)
    assert diff == patch.read_bytes(), "source changes differ from the pinned patch"
    epoch = subprocess.check_output(
        [*git, "show", "-s", "--format=%ct", "HEAD"], text=True
    ).strip()
    for command in (["gcc", "--version"], ["ld", "--version"], ["make", "--version"],
                    ["pkg-config", "--modversion", "libcap"], ["python3", "--version"]):
        run(command)
    helper = build(source, epoch)
    actual = digest(helper)
    print("source_commit", head)
    print("patch_sha256", digest(patch))
    print("helper_sha256", actual)
    if args.verify_recorded:
        assert actual == manifest["tested_helper_sha256"], "helper digest mismatch"
    if args.base_control:
        control = source / ".validation" / "base-control"
        # Never overwrite a pre-existing directory or another task's outputs.
        control.mkdir(parents=True, exist_ok=False)
        archive = subprocess.check_output([*git, "archive", "--format=tar", head])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
            tree.extractall(control, filter="data")
        base = build(control, epoch)
        result = subprocess.run(
            [str(base), "--require-landlock", "--", "/bin/true"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode != 0 and "unrecognized option" in result.stderr, (
            result.returncode, result.stdout, result.stderr
        )
        print("PASS pristine pinned helper rejects --require-landlock")
        print("rebuilt_base_control_sha256", digest(base))


if __name__ == "__main__":
    main()
