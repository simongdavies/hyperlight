#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Hyperlight Authors.

"""Install or uninstall the unprivileged Hyperlight Linux integration."""

import argparse
import base64
import grp
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tarfile


HERE = Path(
    os.environ.get("HYPERLIGHT_INSTALL_HERE", Path(__file__).resolve().parent)
).resolve()
ROOT = Path(
    os.environ.get("HYPERLIGHT_INSTALL_ROOT", HERE.parents[1])
).resolve()
SOURCE_COMMIT = "8d20993c7189a948995bd20901abecc041e1a28e"
PATCH_SHA256 = "f95409720cc074229231ef8b01decad19773cbc83b4faa200edee8bca1483e1a"
HELPER_SHA256 = "d16432b3f6fcf1b0859f36dae50440863e6bff441b67eab688b02275d5e951b6"
HELPER_GROUP = "hyperlight"
HELPER_MODE = 0o750
LIBEXEC = Path("/usr/libexec/hyperlight")
STATE_DIR = Path("/var/lib/hyperlight")
STATE_FILE = STATE_DIR / "install-state.json"
STATE_STATUS_FILE = STATE_DIR / "install-state.status.json"
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
    ROOT / "target/release/examples/process_placement":
        (LIBEXEC / "process_placement", 0o755),
    ROOT / "target/release/examples/nested_sandbox":
        (LIBEXEC / "nested_sandbox", 0o755),
    ROOT / "target/release/examples/process_file_resource":
        (LIBEXEC / "process_file_resource", 0o755),
    ROOT / "src/tests/rust_guests/bin/release/simpleguest":
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
    STATE_STATUS_FILE,
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


def installation_bundle(helper_bytes):
    encoded_installer = os.environ.get("HYPERLIGHT_INSTALLER_B64")
    if not encoded_installer:
        raise RuntimeError("captured installer content is unavailable")
    try:
        installer_bytes = base64.b64decode(encoded_installer, validate=True)
    except ValueError as error:
        raise RuntimeError("captured installer content is invalid") from error

    lifecycle, examples = asset_sources()
    files = {Path("minijail/minijail0"): (helper_bytes, 0o755)}
    for name, (destination, mode, _) in INSTALLED_ASSETS.items():
        source = next(
            source
            for source, installed in lifecycle.items()
            if installed[0] == destination
        )
        content = (
            installer_bytes if name == "install_linux.py" else source.read_bytes()
        )
        files[Path("dev/process-isolation") / name] = (content, mode)
    for repository_source, (destination, mode) in REPOSITORY_EXAMPLE_ASSETS.items():
        source = next(
            source
            for source, installed in examples.items()
            if installed[0] == destination
        )
        files[repository_source.relative_to(ROOT)] = (source.read_bytes(), mode)

    bundle = io.BytesIO()
    with tarfile.open(fileobj=bundle, mode="w") as archive:
        for name, (content, mode) in files.items():
            record = tarfile.TarInfo(name.as_posix())
            record.size = len(content)
            record.mode = mode
            record.uid = 0
            record.gid = 0
            archive.addfile(record, io.BytesIO(content))
    return bundle.getvalue()


ROOT_BOOTSTRAP = r"""
import pathlib
import subprocess
import sys
import tarfile
import tempfile

with tempfile.TemporaryDirectory(prefix="hyperlight-install-") as directory:
    root = pathlib.Path(directory).resolve()
    root.chmod(0o711)
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as archive:
        for member in archive:
            if not member.isfile():
                raise RuntimeError(f"unexpected bundle entry: {member.name}")
            destination = (root / member.name).resolve()
            if root not in destination.parents:
                raise RuntimeError(f"bundle path escapes staging directory: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"bundle entry is unreadable: {member.name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read())
            destination.chmod(member.mode & 0o777)
    (root / "minijail").chmod(0o755)
    installer = root / "dev/process-isolation/install_linux.py"
    subprocess.run(
        [
            sys.executable,
            str(installer),
            "--source",
            str(root / "minijail"),
            "--staged-source",
            "--effective-groups",
            sys.argv[2],
            "--user",
            sys.argv[1],
        ],
        check=True,
    )
"""


def sudo_install(args, helper_bytes):
    if os.geteuid() == 0:
        raise RuntimeError("bundle creation must run as the invoking user")
    bundle = installation_bundle(helper_bytes)
    effective_groups = ",".join(
        str(group) for group in sorted(user_effective_groups(args.user))
    )
    subprocess.run(
        [
            "sudo", "--", sys.executable, "-c", ROOT_BOOTSTRAP,
            args.user, effective_groups,
        ],
        input=bundle,
        check=True,
    )


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


def migrate_state(state):
    baseline = state.setdefault("baseline", {})
    for path in MANAGED_PATHS:
        name = str(path)
        if name not in baseline:
            baseline[name] = snapshot_path(path)
    state.setdefault(
        "policy",
        {"apparmor": False, "device": False, "systemd": False},
    )
    state["version"] = 3


def validate_record(name, record):
    if not isinstance(record, dict) or record.get("kind") not in {"absent", "file"}:
        raise RuntimeError(f"invalid rollback record for {name}")
    if record["kind"] == "absent":
        if set(record) != {"kind"}:
            raise RuntimeError(f"invalid absent rollback record for {name}")
        return
    if set(record) != {"kind", "content", "mode", "uid", "gid"}:
        raise RuntimeError(f"invalid file rollback record for {name}")
    try:
        base64.b64decode(record["content"], validate=True)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"invalid rollback content for {name}") from error
    if not isinstance(record["mode"], int) or not 0 <= record["mode"] <= 0o7777:
        raise RuntimeError(f"invalid rollback mode for {name}")
    for field in ("uid", "gid"):
        if not isinstance(record[field], int) or record[field] < 0:
            raise RuntimeError(f"invalid rollback {field} for {name}")


def validate_state(state):
    required = {
        "version", "baseline", "directory_baseline", "apparmor_was_loaded",
        "devices", "memberships_added", "created_groups", "policy",
    }
    if not isinstance(state, dict) or set(state) != required:
        raise RuntimeError("installation state manifest has an invalid schema")
    if state["version"] != 3:
        raise RuntimeError(f"unsupported installation state version: {state['version']}")
    expected_paths = {str(path) for path in MANAGED_PATHS}
    if not isinstance(state["baseline"], dict) or set(state["baseline"]) != expected_paths:
        raise RuntimeError("installation state baseline path set is invalid")
    for name, record in state["baseline"].items():
        validate_record(name, record)
    expected_directories = {str(path) for path in SYSTEMD_DIRS}
    if (
        not isinstance(state["directory_baseline"], dict)
        or set(state["directory_baseline"]) != expected_directories
        or not all(
            isinstance(value, bool)
            for value in state["directory_baseline"].values()
        )
    ):
        raise RuntimeError("installation state directory baseline is invalid")
    if not isinstance(state["apparmor_was_loaded"], bool):
        raise RuntimeError("installation state AppArmor flag is invalid")
    if not isinstance(state["devices"], dict) or not set(state["devices"]).issubset(
        {"/dev/kvm", "/dev/mshv"}
    ):
        raise RuntimeError("installation state device set is invalid")
    for name, record in state["devices"].items():
        if set(record) != {"uid", "gid", "mode"} or not all(
            isinstance(record[field], int) and record[field] >= 0
            for field in ("uid", "gid", "mode")
        ):
            raise RuntimeError(f"installation state device record is invalid: {name}")
    allowed_groups = {"hyperlight", "kvm", "mshv"}
    if not isinstance(state["memberships_added"], dict):
        raise RuntimeError("installation state memberships are invalid")
    for user, groups in state["memberships_added"].items():
        if (
            not isinstance(user, str)
            or not isinstance(groups, list)
            or len(groups) != len(set(groups))
            or not set(groups).issubset(allowed_groups)
        ):
            raise RuntimeError("installation state membership record is invalid")
    if (
        not isinstance(state["created_groups"], list)
        or len(state["created_groups"]) != len(set(state["created_groups"]))
        or not set(state["created_groups"]).issubset(allowed_groups)
    ):
        raise RuntimeError("installation state created groups are invalid")
    if (
        not isinstance(state["policy"], dict)
        or set(state["policy"]) != {"apparmor", "device", "systemd"}
        or not all(isinstance(value, bool) for value in state["policy"].values())
    ):
        raise RuntimeError("installation state policy record is invalid")


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


def install_bytes(content, destination, mode, group=0):
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.chown(destination.parent, 0, 0)
    os.chmod(destination.parent, 0o755)
    temporary = destination.with_name(destination.name + ".new")
    temporary.write_bytes(content)
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


def user_effective_groups(user):
    if user == pwd.getpwuid(os.getuid()).pw_name:
        return {os.getegid(), *os.getgroups()}
    account = pwd.getpwnam(user)
    groups = {account.pw_gid}
    groups.update(
        entry.gr_gid
        for entry in grp.getgrall()
        if user in entry.gr_mem
    )
    return groups


def user_can_access_device(user, path, effective_groups=None):
    metadata = path.stat()
    account = pwd.getpwnam(user)
    groups = (
        effective_groups
        if effective_groups is not None
        else user_effective_groups(user)
    )
    if account.pw_uid == metadata.st_uid:
        bits = (metadata.st_mode >> 6) & 0o7
    elif metadata.st_gid in groups:
        bits = (metadata.st_mode >> 3) & 0o7
    else:
        bits = metadata.st_mode & 0o7
    return bits & 0o6 == 0o6


def selected_device():
    for path, group in (
        (Path("/dev/kvm"), "kvm"),
        (Path("/dev/mshv"), "mshv"),
    ):
        if path.is_char_device():
            return path, group
    return None, None


def apparmor_enabled():
    path = Path("/sys/module/apparmor/parameters/enabled")
    try:
        return path.read_text().strip() == "Y"
    except OSError:
        return False


def apparmor_restricts_userns():
    path = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    try:
        return path.read_text().strip() == "1"
    except OSError:
        return False


def namespace_probe(helper, user):
    if helper is None or not helper.is_file() or not os.access(helper, os.X_OK):
        return False
    command = [
        str(helper), "-U", "-m", "-M", "-I", "-n", "-c0",
        "--ambient", "-T", "static", "--", "/bin/true",
    ]
    if user == pwd.getpwuid(os.getuid()).pw_name:
        result = subprocess.run(
            command, check=False, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15,
        )
    elif os.geteuid() == 0:
        result = subprocess.run(
            ["runuser", "-u", user, "--", *command],
            check=False, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15,
        )
    else:
        return False
    return result.returncode == 0


def user_manager_probe(user):
    script = (
        'root="/sys/fs/cgroup$(systemctl --user show -P ControlGroup)"; '
        'test -w "$root/cgroup.procs"; '
        'for controller in cpu memory pids; do '
        'grep -qw "$controller" "$root/cgroup.controllers" || exit 1; done'
    )
    command = [
        "systemd-run", "--user", "--wait", "--collect", "--pipe",
        "--service-type=exec",
        "--property=Delegate=cpu memory pids",
        "--property=DelegateSubgroup=application",
        "/bin/sh", "-c", script,
    ]
    if user == pwd.getpwuid(os.getuid()).pw_name:
        result = subprocess.run(
            command, check=False, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=30,
        )
    elif os.geteuid() == 0:
        result = user_systemctl_run(user, command)
    else:
        return False
    return result.returncode == 0


def user_systemctl_run(user, command):
    uid = pwd.getpwnam(user).pw_uid
    environment = [
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
    ]
    return subprocess.run(
        ["runuser", "-u", user, "--", "env", *environment, *command],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=30,
    )


def file_matches(source, destination, mode, group):
    try:
        metadata = destination.stat()
        gid = grp.getgrnam(group).gr_gid if isinstance(group, str) else group
        return (
            metadata.st_uid == 0
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == mode
            and digest(source) == digest(destination)
        )
    except (FileNotFoundError, KeyError, PermissionError):
        return False


def installed_helper_matches(destination, mode, group):
    try:
        metadata = destination.stat()
        gid = grp.getgrnam(group).gr_gid if isinstance(group, str) else group
        return (
            metadata.st_uid == 0
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == mode
            and digest(destination) == HELPER_SHA256
        )
    except (FileNotFoundError, KeyError, PermissionError):
        return False


def text_file_matches(path, content, mode=0o644):
    try:
        metadata = path.stat()
        return (
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == mode
            and path.read_text() == content
        )
    except (FileNotFoundError, PermissionError):
        return False


def installation_plan(
    user, helper, allow_unprobed_namespace=False, effective_groups=None
):
    device, device_group = selected_device()
    if device is None:
        raise RuntimeError("neither /dev/kvm nor /dev/mshv is present")

    installed_helper = LIBEXEC / "minijail0"
    installed_helper_valid = (
        installed_helper.is_file()
        and digest(installed_helper) == HELPER_SHA256
    )
    source_namespace = namespace_probe(helper, user)
    installed_namespace = installed_helper_valid and namespace_probe(installed_helper, user)
    namespace_unprobed = helper is None and not installed_helper_valid
    needs_apparmor = False
    if not source_namespace and not installed_namespace:
        if namespace_unprobed and allow_unprobed_namespace:
            pass
        elif apparmor_enabled() and apparmor_restricts_userns():
            needs_apparmor = True
        else:
            raise RuntimeError(
                "unprivileged Minijail namespace creation failed and no "
                "supported AppArmor restriction was detected"
            )
    use_apparmor = needs_apparmor or apparmor_loaded()
    helper_group = HELPER_GROUP
    helper_mode = HELPER_MODE

    device_policy = not user_can_access_device(user, device, effective_groups)
    delegation_policy = not user_manager_probe(user)
    required_groups = [HELPER_GROUP]
    if device_policy:
        required_groups.append(device_group)

    lifecycle, examples = asset_sources()
    asset_changes = []
    if helper is not None and not installed_helper_matches(
        installed_helper, helper_mode, helper_group
    ):
        asset_changes.append(installed_helper)
    digest_content = f"{HELPER_SHA256}  {installed_helper}\n"
    if not text_file_matches(installed_helper.with_suffix(".sha256"), digest_content):
        asset_changes.append(installed_helper.with_suffix(".sha256"))
    for source, (destination, mode, group) in lifecycle.items():
        if not file_matches(source, destination, mode, group):
            asset_changes.append(destination)
    for source, (destination, mode) in examples.items():
        if not file_matches(source, destination, mode, 0):
            asset_changes.append(destination)

    policy_changes = []
    if device_policy and not text_file_matches(
        UDEV_RULE,
        'KERNEL=="kvm", GROUP="kvm", MODE="0660"\n'
        'KERNEL=="mshv", GROUP="mshv", MODE="0660"\n',
    ):
        policy_changes.append(UDEV_RULE)
    if delegation_policy:
        policy_changes.extend(
            path for path, content in SYSTEMD_FILES.items()
            if not text_file_matches(path, content)
        )
    if needs_apparmor and (
        not text_file_matches(APPARMOR_PROFILE, APPARMOR_CONTENT)
        or not apparmor_loaded()
    ):
        policy_changes.append(APPARMOR_PROFILE)

    groups_to_create = []
    memberships_to_add = []
    for group in required_groups:
        try:
            grp.getgrnam(group)
        except KeyError:
            groups_to_create.append(group)
            memberships_to_add.append(group)
            continue
        if not user_in_group(user, group):
            memberships_to_add.append(group)

    state_change = state_status() != "current"
    effective_groups = (
        effective_groups
        if effective_groups is not None
        else user_effective_groups(user)
    )
    pending_memberships = []
    for group in required_groups:
        try:
            entry = grp.getgrnam(group)
        except KeyError:
            continue
        if user_in_group(user, group) and entry.gr_gid not in effective_groups:
            pending_memberships.append(group)
    delegation_pending = (
        delegation_policy
        and all(
            text_file_matches(path, content)
            for path, content in SYSTEMD_FILES.items()
        )
    )
    return {
        "user": user,
        "device": device,
        "device_group": device_group,
        "device_policy": device_policy,
        "delegation_policy": delegation_policy,
        "needs_apparmor": needs_apparmor,
        "namespace_unprobed": namespace_unprobed,
        "use_apparmor": use_apparmor,
        "helper_group": helper_group,
        "helper_mode": helper_mode,
        "required_groups": required_groups,
        "groups_to_create": groups_to_create,
        "memberships_to_add": memberships_to_add,
        "pending_memberships": pending_memberships,
        "delegation_pending": delegation_pending,
        "asset_changes": asset_changes,
        "policy_changes": policy_changes,
        "state_change": state_change,
        "restart_reasons": [
            *(
                [f"new group membership: {', '.join(memberships_to_add)}"]
                if memberships_to_add else []
            ),
            *(
                [
                    "previously added group membership awaits a fresh login: "
                    + ", ".join(pending_memberships)
                ]
                if pending_memberships else []
            ),
            *(
                ["systemd delegation policy changed"]
                if delegation_policy and any(
                    path in policy_changes for path in SYSTEMD_FILES
                ) else []
            ),
            *(
                ["installed systemd delegation awaits a fresh user manager"]
                if delegation_pending else []
            ),
        ],
    }


def plan_requires_mutation(plan):
    return bool(
        plan["asset_changes"]
        or plan["policy_changes"]
        or plan["groups_to_create"]
        or plan["memberships_to_add"]
        or plan["state_change"]
    )


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


def validate_source(source, allow_missing_helper=False, staged_source=False):
    source = source.resolve()
    helper = source / "minijail0"
    if staged_source:
        helper_bytes = helper.read_bytes()
        if hashlib.sha256(helper_bytes).hexdigest() != HELPER_SHA256:
            raise ValueError("staged Minijail helper digest does not match the pinned build")
        return helper, helper_bytes
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
    try:
        descriptor = os.open(helper, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if allow_missing_helper:
            return None, None
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Minijail helper is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            helper_bytes = stream.read()
    finally:
        os.close(descriptor)
    actual = hashlib.sha256(helper_bytes).hexdigest()
    if actual != HELPER_SHA256:
        raise ValueError(
            f"helper digest {actual} does not match the tested build {HELPER_SHA256}"
        )
    return helper, helper_bytes


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


def state_status():
    try:
        metadata = STATE_FILE.stat()
    except FileNotFoundError:
        return "missing"
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        return "migration"
    try:
        status_metadata = STATE_STATUS_FILE.stat()
        status = json.loads(STATE_STATUS_FILE.read_text())
    except (FileNotFoundError, PermissionError, json.JSONDecodeError):
        return "migration"
    if (
        status_metadata.st_uid != 0
        or status_metadata.st_gid != 0
        or stat.S_IMODE(status_metadata.st_mode) != 0o644
    ):
        return "migration"
    if (
        not isinstance(status, dict)
        or set(status) != {
            "version",
            "state_device",
            "state_inode",
            "state_mtime_ns",
            "state_size",
            "state_sha256",
        }
        or status.get("version") != 3
        or status.get("state_device") != metadata.st_dev
        or status.get("state_inode") != metadata.st_ino
        or status.get("state_mtime_ns") != metadata.st_mtime_ns
        or status.get("state_size") != metadata.st_size
        or not isinstance(status.get("state_sha256"), str)
        or len(status["state_sha256"]) != 64
    ):
        return "migration"
    return "current"


def validate_state_status():
    if state_status() != "current":
        raise RuntimeError("installation state status marker is invalid")
    status = json.loads(STATE_STATUS_FILE.read_text())
    if status["state_sha256"] != digest(STATE_FILE):
        raise RuntimeError("installation state digest does not match its status marker")


def write_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(STATE_DIR, 0, 0)
    os.chmod(STATE_DIR, 0o711)
    temporary = STATE_FILE.with_suffix(".new")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    os.chown(temporary, 0, 0)
    os.chmod(temporary, 0o600)
    os.replace(temporary, STATE_FILE)
    metadata = STATE_FILE.stat()
    status = {
        "version": 3,
        "state_device": metadata.st_dev,
        "state_inode": metadata.st_ino,
        "state_mtime_ns": metadata.st_mtime_ns,
        "state_size": metadata.st_size,
        "state_sha256": digest(STATE_FILE),
    }
    status_temporary = STATE_STATUS_FILE.with_suffix(".new")
    status_temporary.write_text(json.dumps(status, sort_keys=True) + "\n")
    os.chown(status_temporary, 0, 0)
    os.chmod(status_temporary, 0o644)
    os.replace(status_temporary, STATE_STATUS_FILE)


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


def print_install_plan(plan):
    print("Hyperlight constrained-process installation plan:")
    print(f"  Hypervisor device: {plan['device']}")
    if plan["device_policy"]:
        print("  Device access: install stable udev/group policy")
    else:
        print("  Device access: reuse existing effective read/write access")
    if plan["delegation_policy"]:
        print("  Cgroup delegation: install systemd delegation drop-ins")
    else:
        print("  Cgroup delegation: reuse the working user-manager boundary")
    if plan["namespace_unprobed"]:
        print("  User namespaces: probe deferred until the pinned helper is built")
    elif plan["needs_apparmor"]:
        print("  User namespaces: install the path-scoped Minijail AppArmor policy")
    else:
        print("  User namespaces: current host policy already permits Minijail")
    if plan["asset_changes"]:
        print("  Refresh immutable runtime/demo assets:")
        for path in plan["asset_changes"]:
            print(f"    {path}")
    else:
        print("  Immutable runtime/demo assets: current")
    if plan["policy_changes"]:
        print("  Host-policy changes:")
        for path in plan["policy_changes"]:
            print(f"    {path}")
    else:
        print("  Host-policy changes: none")
    if plan["state_change"]:
        print("  Installer state: create or migrate the rollback manifest")
    else:
        print("  Installer state: current")
    if plan["memberships_to_add"]:
        print(
            f"  Add {plan['user']} to: "
            + ", ".join(plan["memberships_to_add"])
        )
    if plan["restart_reasons"]:
        print("  A fresh login/user manager is required:")
        for reason in plan["restart_reasons"]:
            print(f"    {reason}")
        print("  WSL users may run `wsl --shutdown` from PowerShell after work is saved.")
    else:
        print("  Login or WSL restart required: no")
    if not plan_requires_mutation(plan):
        print("  Result: already configured. No sudo or mutation is required.")


def print_uninstall_plan(user):
    print(f"Restore or remove for {user}:")
    for path in [path for path in MANAGED_PATHS if path not in LEGACY_TOOLS]:
        print(f"  {path}")
    for path in LEGACY_TOOLS:
        print(f"  Restore recorded pre-install path or remove installed path: {path}")
    print(f"  {STATE_FILE}")
    print("Stop and collect active Hyperlight user units")
    print("Restore pre-install files, memberships, groups, and device state")
    print("Reload changed systemd, AppArmor, and udev policy; verify clean state")


def verify_install(plan):
    expected = {
        destination: (0, group, mode)
        for destination, mode, group in INSTALLED_ASSETS.values()
    }
    expected.update({
        destination: (0, 0, mode)
        for destination, mode in REPOSITORY_EXAMPLE_ASSETS.values()
    })
    expected[LIBEXEC / "minijail0"] = (
        0, plan["helper_group"], plan["helper_mode"]
    )
    for path, (uid, group, mode) in expected.items():
        metadata = path.stat()
        gid = grp.getgrnam(group).gr_gid if isinstance(group, str) else group
        actual = (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
        if actual != (uid, gid, mode):
            raise RuntimeError(f"invalid installed ownership or mode for {path}: {actual}")
    if digest(LIBEXEC / "minijail0") != HELPER_SHA256:
        raise RuntimeError("installed helper digest verification failed")
    if not namespace_probe(LIBEXEC / "minijail0", plan["user"]):
        raise RuntimeError(
            "installed helper cannot create required namespaces as the target user"
        )
    if not STATE_FILE.is_file():
        raise RuntimeError("installation state manifest is missing")
    metadata = STATE_FILE.stat()
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeError("installation state manifest ownership or mode is invalid")
    validate_state(load_state())
    validate_state_status()
    for group in plan["required_groups"]:
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


def install(args, helper_bytes, plan):
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
        "version": 3,
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
    migrate_state(state)
    validate_state(state)
    transaction_memberships = {}
    transaction_groups = []
    try:
        for group in plan["required_groups"]:
            if ensure_group(group):
                transaction_groups.append(group)
                if group not in state["created_groups"]:
                    state["created_groups"].append(group)
        if LIBEXEC / "minijail0" in plan["asset_changes"]:
            install_bytes(
                helper_bytes, LIBEXEC / "minijail0",
                plan["helper_mode"], plan["helper_group"],
            )
        digest_file = LIBEXEC / "minijail0.sha256"
        if digest_file in plan["asset_changes"]:
            digest_file.parent.mkdir(parents=True, exist_ok=True)
            digest_file.write_text(f"{HELPER_SHA256}  {LIBEXEC / 'minijail0'}\n")
            os.chown(digest_file, 0, 0)
            os.chmod(digest_file, 0o644)
        lifecycle, examples = asset_sources()
        for source, (destination, mode, group) in lifecycle.items():
            if destination in plan["asset_changes"]:
                install_file(source, destination, mode, group)
        for source, (destination, mode) in examples.items():
            if destination in plan["asset_changes"]:
                install_file(source, destination, mode)
        for path in LEGACY_TOOLS:
            path.unlink(missing_ok=True)
        if plan["delegation_policy"]:
            for path, content in SYSTEMD_FILES.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                os.chown(path, 0, 0)
                os.chmod(path, 0o644)
        if plan["device_policy"]:
            UDEV_RULE.write_text(
                'KERNEL=="kvm", GROUP="kvm", MODE="0660"\n'
                'KERNEL=="mshv", GROUP="mshv", MODE="0660"\n'
            )
            os.chown(UDEV_RULE, 0, 0)
            os.chmod(UDEV_RULE, 0o644)
        if plan["needs_apparmor"]:
            APPARMOR_PROFILE.write_text(APPARMOR_CONTENT)
            os.chown(APPARMOR_PROFILE, 0, 0)
            os.chmod(APPARMOR_PROFILE, 0o644)
            run("apparmor_parser", "-r", str(APPARMOR_PROFILE))
        added = []
        for group in plan["required_groups"]:
            if not user_in_group(args.user, group):
                run("usermod", "-a", "-G", group, args.user)
                added.append(group)
                transaction_memberships.setdefault(args.user, []).append(group)
        if added:
            recorded = state["memberships_added"].setdefault(args.user, [])
            for group in added:
                if group not in recorded:
                    recorded.append(group)
        state["policy"] = {
            "apparmor": plan["use_apparmor"],
            "device": plan["device_policy"],
            "systemd": plan["delegation_policy"],
        }
        write_state(state)
        if plan["delegation_policy"]:
            run("systemctl", "daemon-reload")
        if plan["device_policy"]:
            run("udevadm", "control", "--reload-rules")
            run("udevadm", "trigger", "--subsystem-match=misc", "--action=change")
        verify_install(plan)
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
    original_version = state.get("version")
    migrate_state(state)
    validate_state(state)
    if original_version == 3:
        validate_state_status()
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
    parser.add_argument("--needs-mutation", action="store_true")
    parser.add_argument("--check-prerequisites", action="store_true")
    parser.add_argument("--sudo-install", action="store_true")
    parser.add_argument("--staged-source", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--effective-groups", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        pwd.getpwnam(args.user)
    except KeyError:
        parser.error(f"unknown user: {args.user}")

    helper = None
    helper_bytes = None
    plan = None
    if not args.uninstall:
        if args.source is None and not args.check_prerequisites:
            parser.error("--source is required for installation")
        if args.source is not None and args.source.exists():
            try:
                helper, helper_bytes = validate_source(
                    args.source,
                    allow_missing_helper=args.check_prerequisites,
                    staged_source=args.staged_source,
                )
            except (OSError, subprocess.SubprocessError, ValueError) as error:
                parser.error(str(error))
        elif not args.check_prerequisites:
            parser.error(f"Minijail source is missing: {args.source}")
        if not args.check_prerequisites:
            try:
                validate_assets()
            except (OSError, ValueError) as error:
                parser.error(str(error))
        try:
            effective_groups = (
                {int(group) for group in args.effective_groups.split(",") if group}
                if args.effective_groups is not None
                else None
            )
            plan = installation_plan(
                args.user, helper,
                allow_unprobed_namespace=args.check_prerequisites,
                effective_groups=effective_groups,
            )
        except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
            parser.error(str(error))
        if plan["needs_apparmor"] and not shutil.which("apparmor_parser"):
            parser.error("AppArmor policy is required but apparmor_parser is unavailable")
    if args.uninstall:
        print_uninstall_plan(args.user)
    else:
        print_install_plan(plan)
        if args.check_prerequisites:
            if helper is None:
                print("  Source prerequisite: pinned Minijail checkout/build is required")
            else:
                print("  Source prerequisite: pinned Minijail helper is verified")
            missing_assets = [
                str(path)
                for path in [*asset_sources()[0], *asset_sources()[1]]
                if not path.is_file()
            ]
            if missing_assets:
                print("  Build prerequisite: release assets are required")
                for path in missing_assets:
                    print(f"    {path}")
            else:
                print("  Build prerequisite: release assets are present")
            return
    if args.needs_mutation:
        if args.uninstall or plan_requires_mutation(plan):
            sys.exit(10)
        return
    if args.plan:
        return
    if not args.uninstall and not plan_requires_mutation(plan):
        print("Hyperlight integration is already configured.")
        return
    if args.sudo_install:
        sudo_install(args, helper_bytes)
        return
    if os.geteuid() != 0:
        parser.error("run the mutation with sudo, or use --plan without sudo")

    try:
        if args.uninstall:
            uninstall(args)
            print("Uninstalled Hyperlight integration and restored pre-install state.")
        else:
            install(args, helper_bytes, plan)
            print("Installed Hyperlight integration.")
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        parser.exit(1, f"hyperlight installer: {error}\n")
    if not args.uninstall and plan["restart_reasons"]:
        print("Log out and back in to activate the changed login/user-manager state.")
        print("WSL users may run `wsl --shutdown` from PowerShell after work is saved.")


if __name__ == "__main__":
    main()
