#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Hyperlight Authors.

"""Install or uninstall the unprivileged Hyperlight Linux integration."""

import argparse
import base64
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE_COMMIT = "8d20993c7189a948995bd20901abecc041e1a28e"
PATCH_SHA256 = "f95409720cc074229231ef8b01decad19773cbc83b4faa200edee8bca1483e1a"
HELPER_SHA256 = "d16432b3f6fcf1b0859f36dae50440863e6bff441b67eab688b02275d5e951b6"
LIBEXEC = Path("/usr/libexec/hyperlight")
STATE_DIR = Path("/var/lib/hyperlight")
STATE_FILE = STATE_DIR / "install-state.json"
UDEV_RULE = Path("/etc/udev/rules.d/70-hyperlight-hypervisor.rules")
APPARMOR_PROFILE = Path("/etc/apparmor.d/usr.libexec.hyperlight.minijail0")
APPARMOR_NAME = "hyperlight-minijail"
APPARMOR_CONTENT = """\
#include <tunables/global>

profile hyperlight-minijail /usr/libexec/hyperlight/minijail0 flags=(unconfined) {
  userns,
}
"""
SYSTEMD_FILES = {
    Path("/etc/systemd/system/user.slice.d/50-hyperlight-cpu.conf"):
        "[Slice]\nCPUAccounting=yes\n",
    Path("/etc/systemd/system/user-.slice.d/50-hyperlight-cpu.conf"):
        "[Slice]\nCPUAccounting=yes\n",
    Path("/etc/systemd/system/user@.service.d/50-hyperlight-delegation.conf"):
        "[Service]\nDelegate=cpu memory pids\n",
}
SYSTEMD_DIRS = sorted({path.parent for path in SYSTEMD_FILES}, key=str)
INSTALLED_ASSETS = {
    "hyperlight-run": (Path("/usr/bin/hyperlight-run"), 0o755, 0),
    "hyperlight-check": (LIBEXEC / "hyperlight-check", 0o755, 0),
    "hyperlight-unit-entry": (LIBEXEC / "hyperlight-unit-entry", 0o755, 0),
    "install_linux.py": (LIBEXEC / "install_linux.py", 0o755, 0),
    "qualify_linux.py": (LIBEXEC / "qualify_linux.py", 0o755, 0),
    "minijail-require-landlock.patch": (
        LIBEXEC / "minijail-require-landlock.patch", 0o644, 0
    ),
}
REPOSITORY_EXAMPLE_ASSETS = {
    ROOT / "target/debug/examples/process_placement":
        (LIBEXEC / "process_placement", 0o755),
    ROOT / "src/tests/rust_guests/bin/debug/simpleguest":
        (LIBEXEC / "simpleguest", 0o755),
}
LEGACY_TOOLS = [
    Path("/usr/bin/hyperlight-doctor"),
    Path("/usr/sbin/hyperlight-verify-multi-user"),
]
MANAGED_PATHS = [
    *(destination for destination, _, _ in INSTALLED_ASSETS.values()),
    *(destination for destination, _ in REPOSITORY_EXAMPLE_ASSETS.values()),
    LIBEXEC / "minijail0",
    LIBEXEC / "minijail0.sha256",
    UDEV_RULE,
    APPARMOR_PROFILE,
    *SYSTEMD_FILES,
    *LEGACY_TOOLS,
]


def asset_sources():
    if HERE == LIBEXEC:
        lifecycle = {
            destination: (destination, mode, group)
            for destination, mode, group in INSTALLED_ASSETS.values()
        }
        lifecycle[Path("/usr/bin/hyperlight-run")] = (
            Path("/usr/bin/hyperlight-run"), 0o755, 0
        )
        examples = {
            destination: (destination, mode)
            for destination, mode in REPOSITORY_EXAMPLE_ASSETS.values()
        }
        return lifecycle, examples
    lifecycle = {
        HERE / name: (destination, mode, group)
        for name, (destination, mode, group) in INSTALLED_ASSETS.items()
    }
    examples = dict(REPOSITORY_EXAMPLE_ASSETS)
    return lifecycle, examples


def run(*command, check=True, timeout=30, capture_output=False):
    print("+", " ".join(map(str, command)), flush=True)
    return subprocess.run(
        command,
        check=check,
        timeout=timeout,
        text=capture_output,
        capture_output=capture_output,
    )


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot_path(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"kind": "absent"}
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"refusing to replace non-regular path: {path}")
    return {
        "kind": "file",
        "content": base64.b64encode(path.read_bytes()).decode(),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def snapshot_paths(paths):
    return {str(path): snapshot_path(path) for path in paths}


def snapshot_directories(paths):
    return {str(path): path.is_dir() for path in paths}


def restore_directories(records):
    for name, existed in records.items():
        path = Path(name)
        if existed:
            path.mkdir(parents=True, exist_ok=True)
            os.chown(path, 0, 0)
            os.chmod(path, 0o755)
        else:
            try:
                path.rmdir()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise RuntimeError(
                    f"installer-created directory is not empty: {path}"
                ) from error


def restore_path(path, record):
    if record["kind"] == "absent":
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".restore")
    temporary.write_bytes(base64.b64decode(record["content"]))
    os.chown(temporary, record["uid"], record["gid"])
    os.chmod(temporary, record["mode"])
    os.replace(temporary, path)


def restore_paths(records):
    for name, record in records.items():
        restore_path(Path(name), record)


def install_file(source, destination, mode, group=0):
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.chown(destination.parent, 0, 0)
    os.chmod(destination.parent, 0o755)
    temporary = destination.with_name(destination.name + ".new")
    shutil.copyfile(source, temporary)
    gid = grp.getgrnam(group).gr_gid if isinstance(group, str) else group
    os.chown(temporary, 0, gid)
    os.chmod(temporary, mode)
    os.replace(temporary, destination)


def ensure_group(name):
    try:
        grp.getgrnam(name)
        return False
    except KeyError:
        run("groupadd", "--system", name)
        return True


def user_in_group(user, group):
    account = pwd.getpwnam(user)
    entry = grp.getgrnam(group)
    return account.pw_gid == entry.gr_gid or user in entry.gr_mem


def apparmor_loaded():
    profiles = Path("/sys/kernel/security/apparmor/profiles")
    try:
        return any(
            line.startswith(f"{APPARMOR_NAME} ")
            for line in profiles.read_text().splitlines()
        )
    except OSError:
        return False


def unload_apparmor():
    if apparmor_loaded():
        if not shutil.which("apparmor_parser"):
            raise RuntimeError("AppArmor profile is loaded but apparmor_parser is unavailable")
        run("apparmor_parser", "-R", str(APPARMOR_PROFILE))
        if apparmor_loaded():
            raise RuntimeError("AppArmor profile remained loaded after removal")


def restore_apparmor(was_loaded):
    if apparmor_loaded():
        unload_apparmor()
    if was_loaded:
        if not APPARMOR_PROFILE.exists() or not shutil.which("apparmor_parser"):
            raise RuntimeError("cannot restore the previous AppArmor profile")
        run("apparmor_parser", "-r", str(APPARMOR_PROFILE))
        if not apparmor_loaded():
            raise RuntimeError("previous AppArmor profile was not restored")


def device_state():
    result = {}
    for path in (Path("/dev/kvm"), Path("/dev/mshv")):
        if path.exists():
            metadata = path.stat()
            result[str(path)] = {
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
            }
    return result


def restore_devices(records):
    for name, record in records.items():
        path = Path(name)
        if path.exists():
            os.chown(path, record["uid"], record["gid"])
            os.chmod(path, record["mode"])


def reload_policy():
    run("systemctl", "daemon-reload")
    run("udevadm", "control", "--reload-rules")
    run("udevadm", "trigger", "--subsystem-match=misc", "--action=change")


def validate_source(source):
    source = source.resolve()
    helper = source / "minijail0"
    git_env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    git = [
        "git", "--no-optional-locks", "-c", "core.fsmonitor=false",
        "-c", f"safe.directory={source}", "-C", str(source),
    ]
    head = subprocess.check_output(
        [*git, "rev-parse", "HEAD"], text=True, env=git_env
    ).strip()
    if head != SOURCE_COMMIT:
        raise ValueError(f"unexpected Minijail source commit: {head}")
    if subprocess.check_output([*git, "diff", "--cached"], env=git_env):
        raise ValueError("Minijail source has staged changes")
    diff = subprocess.check_output([
        *git, "-c", "core.autocrlf=false", "diff",
        "--no-ext-diff", "--no-textconv", "--binary", "--full-index",
        "--src-prefix=a/", "--dst-prefix=b/", "HEAD", "--",
    ], env=git_env)
    patch = (HERE / "minijail-require-landlock.patch").read_bytes()
    if hashlib.sha256(patch).hexdigest() != PATCH_SHA256:
        raise ValueError("repository Minijail patch digest is invalid")
    if diff != patch:
        raise ValueError("Minijail source does not contain only the pinned patch")
    actual = digest(helper)
    if actual != HELPER_SHA256:
        raise ValueError(
            f"helper digest {actual} does not match the tested build {HELPER_SHA256}"
        )
    return helper


def validate_assets():
    lifecycle, examples = asset_sources()
    missing = [
        str(path)
        for path in [*lifecycle, *examples]
        if not path.is_file()
    ]
    if missing:
        raise ValueError(
            "build or restore the required installation assets before init: "
            + ", ".join(missing)
        )


def present_device_groups():
    return [
        group
        for device, group in ((Path("/dev/kvm"), "kvm"), (Path("/dev/mshv"), "mshv"))
        if device.exists()
    ]


def load_state():
    try:
        return json.loads(STATE_FILE.read_text())
    except FileNotFoundError:
        return None


def write_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(STATE_DIR, 0, 0)
    os.chmod(STATE_DIR, 0o711)
    temporary = STATE_FILE.with_suffix(".new")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    os.chown(temporary, 0, 0)
    os.chmod(temporary, 0o600)
    os.replace(temporary, STATE_FILE)


def user_systemctl(user, *arguments, check=True, capture_output=False):
    uid = pwd.getpwnam(user).pw_uid
    environment = [
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
    ]
    return run(
        "runuser", "-u", user, "--", "env", *environment,
        "systemctl", "--user", *arguments,
        check=check,
        timeout=30,
        capture_output=capture_output,
    )


def stop_active_units(users):
    for user in sorted(set(users)):
        result = user_systemctl(
            user, "list-units", "--all", "--plain", "--no-legend",
            "hyperlight-*.service", check=False, capture_output=True,
        )
        if result.returncode != 0:
            continue
        units = [
            line.split()[0]
            for line in result.stdout.splitlines()
            if line.split()
        ]
        for unit in units:
            user_systemctl(user, "stop", unit)
        remaining = user_systemctl(
            user, "list-units", "--all", "--plain", "--no-legend",
            "hyperlight-*.service", check=False, capture_output=True,
        ).stdout.strip()
        if remaining:
            raise RuntimeError(f"active Hyperlight units remain for {user}: {remaining}")


def remove_memberships(records):
    for user, groups in records.items():
        for group in groups:
            try:
                if user_in_group(user, group):
                    run("gpasswd", "-d", user, group)
            except KeyError:
                pass


def remove_created_groups(groups):
    for group in reversed(groups):
        try:
            entry = grp.getgrnam(group)
        except KeyError:
            continue
        if entry.gr_mem:
            raise RuntimeError(
                f"cannot remove installer-created group {group}; members remain: "
                + ", ".join(entry.gr_mem)
            )
        run("groupdel", group)


def restore_groups(records):
    for group, gid in records.items():
        try:
            grp.getgrnam(group)
        except KeyError:
            run("groupadd", "--system", "--gid", str(gid), group)


def restore_memberships(records):
    for user, groups in records.items():
        for group in groups:
            if not user_in_group(user, group):
                run("usermod", "-a", "-G", group, user)


def rollback(
    snapshot, directory_snapshot, apparmor_was_loaded, devices,
    memberships, created_groups,
):
    errors = []
    for action in (
        lambda: unload_apparmor() if apparmor_loaded() else None,
        lambda: restore_paths(snapshot),
        lambda: restore_directories(directory_snapshot),
        lambda: restore_apparmor(apparmor_was_loaded),
        lambda: remove_memberships(memberships),
        lambda: remove_created_groups(created_groups),
        reload_policy,
        lambda: restore_devices(devices),
    ):
        try:
            action()
        except Exception as error:
            errors.append(str(error))
    try:
        LIBEXEC.rmdir()
    except OSError:
        pass
    try:
        STATE_DIR.rmdir()
    except OSError:
        pass
    if errors:
        raise RuntimeError("rollback failed: " + "; ".join(errors))


def print_plan(user, uninstall, groups, apparmor_enabled):
    action = "Restore or remove" if uninstall else "Install or replace"
    print(f"{action}:")
    for path in [path for path in MANAGED_PATHS if path not in LEGACY_TOOLS]:
        print(f"  {path}")
    for path in LEGACY_TOOLS:
        if uninstall:
            operation = "Restore recorded pre-install path or remove installed path"
        else:
            operation = "Remove legacy path"
        print(f"  {operation}: {path}")
    print(f"  {STATE_FILE}")
    if not uninstall:
        print("Ensure system groups: hyperlight and present hypervisor device groups")
        print(f"Add {user} to: {', '.join(['hyperlight', *groups])}")
        print("Record the exact pre-install state for rollback and uninstall")
        print(
            "AppArmor profile: "
            + ("install and load" if apparmor_enabled else "record only; AppArmor is inactive")
        )
        print("Reload systemd, AppArmor, and udev policy; retrigger misc devices")
        print("Required interruption: log out and back in")
        print("WSL interruption: run `wsl --shutdown` from PowerShell")
    else:
        print("Stop and collect active Hyperlight user units")
        print("Restore pre-install files, memberships, groups, and device state")
        print("Reload systemd, AppArmor, and udev policy; verify clean state")


def verify_install(groups):
    expected = {
        destination: (0, group, mode)
        for destination, mode, group in INSTALLED_ASSETS.values()
    }
    expected.update({
        destination: (0, 0, mode)
        for destination, mode in REPOSITORY_EXAMPLE_ASSETS.values()
    })
    expected[LIBEXEC / "minijail0"] = (
        0, grp.getgrnam("hyperlight").gr_gid, 0o750
    )
    for path, (uid, group, mode) in expected.items():
        metadata = path.stat()
        gid = grp.getgrnam(group).gr_gid if isinstance(group, str) else group
        actual = (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
        if actual != (uid, gid, mode):
            raise RuntimeError(f"invalid installed ownership or mode for {path}: {actual}")
    if digest(LIBEXEC / "minijail0") != HELPER_SHA256:
        raise RuntimeError("installed helper digest verification failed")
    if not STATE_FILE.is_file():
        raise RuntimeError("installation state manifest is missing")
    for group in groups:
        grp.getgrnam(group)


def verify_uninstall(baseline, directory_baseline, state):
    for name, record in baseline.items():
        current = snapshot_path(Path(name))
        if current != record:
            raise RuntimeError(f"uninstall did not restore {name}")
    if STATE_FILE.exists():
        raise RuntimeError("installation state manifest remains")
    for user, groups in state["memberships_added"].items():
        for group in groups:
            try:
                if user_in_group(user, group):
                    raise RuntimeError(f"{user} remains in installer-added group {group}")
            except KeyError:
                pass
    for group in state["created_groups"]:
        try:
            grp.getgrnam(group)
        except KeyError:
            continue
        raise RuntimeError(f"installer-created group remains: {group}")
    for name, existed in directory_baseline.items():
        if Path(name).is_dir() != existed:
            raise RuntimeError(f"uninstall did not restore directory state: {name}")
    if apparmor_loaded() != state["apparmor_was_loaded"]:
        raise RuntimeError("uninstall did not restore AppArmor loaded state")


def install(args, helper, groups, apparmor_enabled):
    snapshot = snapshot_paths([*MANAGED_PATHS, STATE_FILE])
    directory_snapshot = snapshot_directories(SYSTEMD_DIRS)
    apparmor_was_loaded = apparmor_loaded()
    devices = device_state()
    existing = load_state()
    legacy_install = (
        existing is None
        and (LIBEXEC / "minijail0").is_file()
        and digest(LIBEXEC / "minijail0") == HELPER_SHA256
    )
    baseline = (
        {str(path): {"kind": "absent"} for path in MANAGED_PATHS}
        if legacy_install
        else snapshot_paths(MANAGED_PATHS)
    )
    state = existing or {
        "version": 1,
        "baseline": baseline,
        "directory_baseline": (
            {str(path): False for path in SYSTEMD_DIRS}
            if legacy_install
            else snapshot_directories(SYSTEMD_DIRS)
        ),
        "apparmor_was_loaded": apparmor_was_loaded,
        "devices": devices,
        "memberships_added": (
            {args.user: ["hyperlight"]}
            if legacy_install and user_in_group(args.user, "hyperlight")
            else {}
        ),
        "created_groups": (
            ["hyperlight"] if legacy_install else []
        ),
    }
    if "directory_baseline" not in state:
        state["directory_baseline"] = {
            str(directory): any(
                record["kind"] != "absent"
                for name, record in state["baseline"].items()
                if Path(name).parent == directory
            )
            for directory in SYSTEMD_DIRS
        }
    transaction_memberships = {}
    transaction_groups = []
    try:
        for group in ["hyperlight", *groups]:
            if ensure_group(group):
                transaction_groups.append(group)
                if group not in state["created_groups"]:
                    state["created_groups"].append(group)
        install_file(helper, LIBEXEC / "minijail0", 0o750, "hyperlight")
        digest_file = LIBEXEC / "minijail0.sha256"
        digest_file.write_text(f"{HELPER_SHA256}  {LIBEXEC / 'minijail0'}\n")
        os.chown(digest_file, 0, 0)
        os.chmod(digest_file, 0o644)
        lifecycle, examples = asset_sources()
        for source, (destination, mode, group) in lifecycle.items():
            install_file(source, destination, mode, group)
        for source, (destination, mode) in examples.items():
            install_file(source, destination, mode)
        for path in LEGACY_TOOLS:
            path.unlink(missing_ok=True)
        for path, content in SYSTEMD_FILES.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            os.chown(path, 0, 0)
            os.chmod(path, 0o644)
        UDEV_RULE.write_text(
            'KERNEL=="kvm", GROUP="kvm", MODE="0660"\n'
            'KERNEL=="mshv", GROUP="mshv", MODE="0660"\n'
        )
        os.chown(UDEV_RULE, 0, 0)
        os.chmod(UDEV_RULE, 0o644)
        if apparmor_enabled:
            APPARMOR_PROFILE.write_text(APPARMOR_CONTENT)
            os.chown(APPARMOR_PROFILE, 0, 0)
            os.chmod(APPARMOR_PROFILE, 0o644)
            run("apparmor_parser", "-r", str(APPARMOR_PROFILE))
        added = []
        for group in ["hyperlight", *groups]:
            if not user_in_group(args.user, group):
                run("usermod", "-a", "-G", group, args.user)
                added.append(group)
                transaction_memberships.setdefault(args.user, []).append(group)
        if added:
            recorded = state["memberships_added"].setdefault(args.user, [])
            for group in added:
                if group not in recorded:
                    recorded.append(group)
        write_state(state)
        reload_policy()
        verify_install(["hyperlight", *groups])
    except Exception as error:
        try:
            rollback(
                snapshot, directory_snapshot, apparmor_was_loaded, devices,
                transaction_memberships, transaction_groups,
            )
        except Exception as rollback_error:
            raise RuntimeError(f"{error}; {rollback_error}") from error
        raise


def uninstall(args):
    state = load_state()
    if state is None:
        raise RuntimeError("installation state manifest is missing; refusing unsafe uninstall")
    baseline = state["baseline"]
    directory_baseline = state["directory_baseline"]
    stop_active_units([args.user, *state["memberships_added"]])
    snapshot = snapshot_paths([*MANAGED_PATHS, STATE_FILE])
    apparmor_was_loaded = apparmor_loaded()
    devices = device_state()
    memberships = {
        user: [
            group for group in groups
            if user_in_group(user, group)
        ]
        for user, groups in state["memberships_added"].items()
    }
    group_records = {
        group: grp.getgrnam(group).gr_gid
        for group in state["created_groups"]
        if group in {entry.gr_name for entry in grp.getgrall()}
    }
    try:
        unload_apparmor()
        restore_paths(baseline)
        restore_directories(directory_baseline)
        restore_apparmor(state["apparmor_was_loaded"])
        reload_policy()
        restore_devices(state["devices"])
        remove_memberships(state["memberships_added"])
        remove_created_groups(state["created_groups"])
        STATE_FILE.unlink()
        verify_uninstall(baseline, directory_baseline, state)
    except Exception as error:
        rollback_errors = []
        for action in (
            lambda: restore_groups(group_records),
            lambda: restore_memberships(memberships),
            lambda: restore_paths(snapshot),
            reload_policy,
            lambda: restore_devices(devices),
            lambda: restore_apparmor(apparmor_was_loaded),
        ):
            try:
                action()
            except Exception as rollback_error:
                rollback_errors.append(str(rollback_error))
        if rollback_errors:
            raise RuntimeError(
                f"{error}; uninstall rollback failed: " + "; ".join(rollback_errors)
            ) from error
        raise
    try:
        LIBEXEC.rmdir()
    except OSError:
        pass
    try:
        STATE_DIR.rmdir()
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    try:
        pwd.getpwnam(args.user)
    except KeyError:
        parser.error(f"unknown user: {args.user}")

    helper = None
    groups = present_device_groups()
    apparmor_enabled = (
        Path("/sys/module/apparmor/parameters/enabled").exists()
        and Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y"
    )
    if not args.uninstall:
        if args.source is None:
            parser.error("--source is required for installation")
        try:
            helper = validate_source(args.source)
            validate_assets()
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            parser.error(str(error))
        if not groups:
            parser.error("neither /dev/kvm nor /dev/mshv is present")
        if apparmor_enabled and not shutil.which("apparmor_parser"):
            parser.error("AppArmor is enabled but apparmor_parser is unavailable")
    print_plan(args.user, args.uninstall, groups, apparmor_enabled)
    if args.plan:
        return
    if os.geteuid() != 0:
        parser.error("run the mutation with sudo, or use --plan without sudo")

    try:
        if args.uninstall:
            uninstall(args)
            print("Uninstalled Hyperlight integration and restored pre-install state.")
        else:
            install(args, helper, groups, apparmor_enabled)
            print("Installed Hyperlight integration.")
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        parser.exit(1, f"hyperlight installer: {error}\n")
    print("Log out and back in to refresh group and controller delegation.")
    print("WSL users must run `wsl --shutdown` from PowerShell.")


if __name__ == "__main__":
    main()
