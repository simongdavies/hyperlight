#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Hyperlight Authors.

"""Focused tests for Linux process-placement installation assets."""

from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
import grp
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("install_linux.py")
SPEC = importlib.util.spec_from_file_location("install_linux", MODULE_PATH)
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


class InstallationAssetTests(unittest.TestCase):
    def test_privileged_bundle_captures_installer_helper_and_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lifecycle_source = root / "hyperlight-run"
            lifecycle_source.write_bytes(b"launcher")
            example_source = root / "target/release/examples/demo"
            example_source.parent.mkdir(parents=True)
            example_source.write_bytes(b"example")
            installer = b"captured installer"
            lifecycle = {
                lifecycle_source: (Path("/usr/bin/hyperlight-run"), 0o755, 0),
                root / "install_linux.py": (
                    Path("/usr/libexec/hyperlight/install_linux.py"), 0o755, 0
                ),
            }
            examples = {
                example_source: (Path("/usr/libexec/hyperlight/demo"), 0o755)
            }
            installed = {
                "hyperlight-run": (Path("/usr/bin/hyperlight-run"), 0o755, 0),
                "install_linux.py": (
                    Path("/usr/libexec/hyperlight/install_linux.py"), 0o755, 0
                ),
            }
            repository_examples = {
                example_source: (Path("/usr/libexec/hyperlight/demo"), 0o755)
            }
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "HYPERLIGHT_INSTALLER_B64":
                            INSTALL.base64.b64encode(installer).decode()
                    },
                ),
                mock.patch.object(INSTALL, "ROOT", root),
                mock.patch.object(INSTALL, "INSTALLED_ASSETS", installed),
                mock.patch.object(
                    INSTALL, "REPOSITORY_EXAMPLE_ASSETS", repository_examples
                ),
                mock.patch.object(
                    INSTALL, "asset_sources", return_value=(lifecycle, examples)
                ),
            ):
                bundle = INSTALL.installation_bundle(b"helper")

        with tarfile.open(fileobj=io.BytesIO(bundle)) as archive:
            contents = {
                member.name: archive.extractfile(member).read()
                for member in archive.getmembers()
            }
        self.assertEqual(contents["minijail/minijail0"], b"helper")
        self.assertEqual(
            contents["dev/process-isolation/install_linux.py"], installer
        )
        self.assertEqual(
            contents["dev/process-isolation/hyperlight-run"], b"launcher"
        )
        self.assertEqual(
            contents["target/release/examples/demo"], b"example"
        )

    def test_demo_assets_are_release_builds(self):
        sources = {str(path) for path in INSTALL.REPOSITORY_EXAMPLE_ASSETS}
        self.assertTrue(
            any(path.endswith("target/release/examples/process_placement")
                for path in sources)
        )
        self.assertTrue(
            any(path.endswith("target/release/examples/nested_sandbox")
                for path in sources)
        )
        self.assertTrue(
            any(path.endswith("target/release/examples/process_file_resource")
                for path in sources)
        )
        self.assertTrue(
            any(path.endswith("src/tests/rust_guests/bin/release/simpleguest")
                for path in sources)
        )
        self.assertFalse(any("/debug/" in path for path in sources))

    def test_release_assets_keep_root_owned_install_modes(self):
        destinations = set(INSTALL.REPOSITORY_EXAMPLE_ASSETS.values())
        self.assertEqual(
            destinations,
            {
                (Path("/usr/libexec/hyperlight/process_placement"), 0o755),
                (Path("/usr/libexec/hyperlight/nested_sandbox"), 0o755),
                (Path("/usr/libexec/hyperlight/process_file_resource"), 0o755),
                (Path("/usr/libexec/hyperlight/simpleguest"), 0o755),
            },
        )

    def test_check_metadata_matches_installer_and_runtime_contract(self):
        check = MODULE_PATH.with_name("hyperlight-check").read_text()
        entry = MODULE_PATH.with_name("hyperlight-unit-entry").read_text()
        self.assertEqual(INSTALL.HELPER_GROUP, "hyperlight")
        self.assertEqual(INSTALL.HELPER_MODE, 0o750)
        self.assertIn("helper_owner=0:${helper_gid:-missing}:750", check)
        self.assertNotIn("helper_owner=0:0:755", check)
        self.assertIn('"0:$helper_gid:750"', entry)
        for _, (destination, mode, group) in INSTALL.INSTALLED_ASSETS.items():
            self.assertIn(f'"{destination} 0:{group}:{mode:o}"', check)
        for destination, mode in INSTALL.REPOSITORY_EXAMPLE_ASSETS.values():
            self.assertIn(f'"{destination} 0:0:{mode:o}"', check)

    def test_installed_helper_match_requires_root_hyperlight_0750(self):
        helper = Path("/usr/libexec/hyperlight/minijail0")
        group = grp.struct_group(("hyperlight", "x", 41, []))
        mismatch = os.stat_result((
            stat.S_IFREG | 0o755, 0, 0, 1, 0, 0, 6, 0, 0, 0
        ))
        corrected = os.stat_result((
            stat.S_IFREG | 0o750, 0, 0, 1, 0, 41, 6, 0, 0, 0
        ))
        with (
            mock.patch.object(INSTALL.grp, "getgrnam", return_value=group),
            mock.patch.object(INSTALL, "digest", return_value=INSTALL.HELPER_SHA256),
            mock.patch.object(INSTALL.Path, "stat", return_value=mismatch),
        ):
            self.assertFalse(INSTALL.installed_helper_matches(
                helper, INSTALL.HELPER_MODE, INSTALL.HELPER_GROUP
            ))
        with (
            mock.patch.object(INSTALL.grp, "getgrnam", return_value=group),
            mock.patch.object(INSTALL, "digest", return_value=INSTALL.HELPER_SHA256),
            mock.patch.object(INSTALL.Path, "stat", return_value=corrected),
        ):
            self.assertTrue(INSTALL.installed_helper_matches(
                helper, INSTALL.HELPER_MODE, INSTALL.HELPER_GROUP
            ))

    def test_helper_install_applies_runtime_metadata(self):
        group = grp.struct_group(("hyperlight", "x", 41, []))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "minijail0"
            with (
                mock.patch.object(INSTALL.grp, "getgrnam", return_value=group),
                mock.patch.object(INSTALL.os, "chown") as chown,
                mock.patch.object(INSTALL.os, "chmod") as chmod,
            ):
                INSTALL.install_bytes(
                    b"helper",
                    destination,
                    INSTALL.HELPER_MODE,
                    INSTALL.HELPER_GROUP,
                )
            self.assertEqual(destination.read_bytes(), b"helper")
        chown.assert_any_call(
            destination.with_name("minijail0.new"), 0, group.gr_gid
        )
        chmod.assert_any_call(
            destination.with_name("minijail0.new"), 0o750
        )

    def test_state_status_detects_same_size_state_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            state_file = Path(directory) / "install-state.json"
            status_file = Path(directory) / "install-state.status.json"
            real_stat = Path.stat

            def root_owned_stat(path):
                metadata = real_stat(path)
                return mock.Mock(
                    st_uid=0,
                    st_gid=0,
                    st_mode=metadata.st_mode,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino,
                    st_mtime_ns=metadata.st_mtime_ns,
                    st_size=metadata.st_size,
                )

            with (
                mock.patch.object(INSTALL, "STATE_DIR", Path(directory)),
                mock.patch.object(INSTALL, "STATE_FILE", state_file),
                mock.patch.object(INSTALL, "STATE_STATUS_FILE", status_file),
                mock.patch.object(INSTALL.os, "chown"),
                mock.patch.object(
                    INSTALL.Path, "stat", autospec=True, side_effect=root_owned_stat
                ),
            ):
                INSTALL.write_state({"version": 3})
                self.assertEqual(INSTALL.state_status(), "current")
                replacement = state_file.with_suffix(".replacement")
                replacement.write_bytes(state_file.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, state_file)
                self.assertEqual(INSTALL.state_status(), "migration")

    def test_upgrade_records_new_managed_path_in_uninstall_baseline(self):
        old_path = Path("/installed/old")
        new_path = Path("/installed/new")
        old_record = {"kind": "file", "content": "old"}
        state = {
            "version": 1,
            "baseline": {str(old_path): old_record},
        }
        new_record = {"kind": "absent"}

        with (
            mock.patch.object(INSTALL, "MANAGED_PATHS", [old_path, new_path]),
            mock.patch.object(
                INSTALL, "snapshot_path", return_value=new_record
            ) as snapshot,
        ):
            INSTALL.migrate_state(state)

        self.assertEqual(state["version"], 3)
        self.assertEqual(
            state["policy"],
            {"apparmor": False, "device": False, "systemd": False},
        )
        self.assertIs(state["baseline"][str(old_path)], old_record)
        self.assertEqual(state["baseline"][str(new_path)], new_record)
        snapshot.assert_called_once_with(new_path)


class AdaptivePlanTests(unittest.TestCase):
    def test_empty_effective_group_snapshot_is_preserved(self):
        account = pwd.struct_passwd(("simon", "x", 1000, 1000, "", "/home/simon", "/bin/bash"))
        device = os.stat_result((
            stat.S_IFCHR | 0o660, 0, 0, 1, 0, 42, 0, 0, 0, 0
        ))
        with (
            mock.patch.object(INSTALL.pwd, "getpwnam", return_value=account),
            mock.patch.object(INSTALL.Path, "stat", return_value=device),
            mock.patch.object(
                INSTALL, "user_effective_groups", return_value={42}
            ) as fallback,
        ):
            self.assertFalse(
                INSTALL.user_can_access_device(
                    "simon", Path("/dev/kvm"), effective_groups=set()
                )
            )
        fallback.assert_not_called()

    def plan(self, *, device_access=True, delegation=True,
             source_namespace=True, installed_namespace=True,
             apparmor=False, profile_loaded=False, state_version=3,
             files_match=True, helper_matches=None,
             memberships=("hyperlight",),
             effective_memberships=("hyperlight",)):
        groups = {
            "hyperlight": grp.struct_group(("hyperlight", "x", 41, [])),
            "kvm": grp.struct_group(("kvm", "x", 42, [])),
        }
        patches = (
            mock.patch.object(
                INSTALL, "selected_device",
                return_value=(Path("/dev/kvm"), "kvm"),
            ),
            mock.patch.object(
                INSTALL, "user_can_access_device",
                return_value=device_access,
            ),
            mock.patch.object(
                INSTALL, "user_manager_probe",
                return_value=delegation,
            ),
            mock.patch.object(
                INSTALL, "namespace_probe",
                side_effect=[source_namespace, installed_namespace],
            ),
            mock.patch.object(INSTALL, "apparmor_enabled", return_value=apparmor),
            mock.patch.object(
                INSTALL, "apparmor_restricts_userns",
                return_value=apparmor,
            ),
            mock.patch.object(
                INSTALL, "apparmor_loaded",
                return_value=profile_loaded,
            ),
            mock.patch.object(INSTALL, "asset_sources", return_value=({}, {})),
            mock.patch.object(INSTALL, "file_matches", return_value=files_match),
            mock.patch.object(
                INSTALL, "installed_helper_matches",
                return_value=files_match if helper_matches is None else helper_matches,
            ),
            mock.patch.object(
                INSTALL, "text_file_matches", return_value=files_match
            ),
            mock.patch.object(
                INSTALL, "state_status",
                return_value="current" if state_version == 3 else "migration",
            ),
            mock.patch.object(INSTALL.Path, "is_file", return_value=True),
            mock.patch.object(INSTALL, "digest", return_value=INSTALL.HELPER_SHA256),
            mock.patch.object(
                INSTALL.grp, "getgrnam", side_effect=lambda name: groups[name]
            ),
            mock.patch.object(
                INSTALL, "user_in_group",
                side_effect=lambda _user, name: name in memberships,
            ),
            mock.patch.object(
                INSTALL, "user_effective_groups",
                return_value={
                    groups[name].gr_gid for name in effective_memberships
                },
            ),
        )
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            return INSTALL.installation_plan("developer", Path("/source/minijail0"))

    def test_working_host_reuses_device_delegation_and_namespace_policy(self):
        plan = self.plan()
        self.assertFalse(plan["device_policy"])
        self.assertFalse(plan["delegation_policy"])
        self.assertFalse(plan["needs_apparmor"])
        self.assertEqual(plan["required_groups"], ["hyperlight"])
        self.assertEqual(plan["policy_changes"], [])
        self.assertEqual(plan["restart_reasons"], [])
        self.assertEqual(plan["helper_group"], "hyperlight")
        self.assertEqual(plan["helper_mode"], 0o750)

    def test_systemd_policy_change_is_the_only_restart_reason(self):
        plan = self.plan(delegation=False, files_match=False)
        self.assertTrue(plan["delegation_policy"])
        self.assertEqual(
            plan["restart_reasons"],
            ["systemd delegation policy changed"],
        )

    def test_apparmor_policy_adds_only_the_helper_group(self):
        plan = self.plan(
            source_namespace=False,
            installed_namespace=False,
            apparmor=True,
            memberships=(),
            effective_memberships=(),
        )
        self.assertTrue(plan["needs_apparmor"])
        self.assertEqual(plan["required_groups"], ["hyperlight"])
        self.assertEqual(plan["memberships_to_add"], ["hyperlight"])
        self.assertEqual(
            plan["restart_reasons"],
            ["new group membership: hyperlight"],
        )

    def test_existing_device_access_never_requests_device_group(self):
        plan = self.plan(
            apparmor=True,
            source_namespace=False,
            installed_namespace=False,
        )
        self.assertNotIn("kvm", plan["required_groups"])

    def test_asset_only_refresh_never_requests_restart(self):
        plan = self.plan(
            files_match=False,
        )
        plan["policy_changes"] = []
        self.assertTrue(plan["asset_changes"])
        self.assertEqual(plan["restart_reasons"], [])

    def test_persisted_but_ineffective_membership_reports_pending_activation(self):
        plan = self.plan(
            device_access=False,
            memberships=("hyperlight", "kvm"),
            effective_memberships=(),
        )
        self.assertEqual(plan["memberships_to_add"], [])
        self.assertEqual(plan["pending_memberships"], ["hyperlight", "kvm"])
        self.assertIn("awaits a fresh login", plan["restart_reasons"][0])

    def test_root_root_0755_helper_is_refreshed_then_idempotent(self):
        mismatch = self.plan(helper_matches=False)
        self.assertIn(INSTALL.LIBEXEC / "minijail0", mismatch["asset_changes"])
        self.assertEqual(mismatch["helper_group"], "hyperlight")
        self.assertEqual(mismatch["helper_mode"], 0o750)

        corrected = self.plan(helper_matches=True)
        self.assertNotIn(INSTALL.LIBEXEC / "minijail0", corrected["asset_changes"])
        self.assertEqual(corrected["restart_reasons"], [])

    def test_missing_hypervisor_device_fails_closed(self):
        with mock.patch.object(
            INSTALL, "selected_device", return_value=(None, None)
        ):
            with self.assertRaisesRegex(RuntimeError, "neither /dev/kvm nor /dev/mshv"):
                INSTALL.installation_plan("developer", Path("/source/minijail0"))

    def test_prerequisite_check_defers_namespace_probe_without_helper(self):
        with (
            mock.patch.object(
                INSTALL, "selected_device",
                return_value=(Path("/dev/kvm"), "kvm"),
            ),
            mock.patch.object(INSTALL.Path, "is_file", return_value=False),
            mock.patch.object(INSTALL, "user_can_access_device", return_value=True),
            mock.patch.object(INSTALL, "user_manager_probe", return_value=True),
            mock.patch.object(INSTALL, "namespace_probe", return_value=False),
            mock.patch.object(INSTALL, "apparmor_enabled", return_value=False),
            mock.patch.object(INSTALL, "apparmor_loaded", return_value=False),
            mock.patch.object(INSTALL, "asset_sources", return_value=({}, {})),
            mock.patch.object(INSTALL, "text_file_matches", return_value=True),
            mock.patch.object(INSTALL, "state_status", return_value="missing"),
            mock.patch.object(INSTALL, "user_effective_groups", return_value=set()),
            mock.patch.object(
                INSTALL.grp,
                "getgrnam",
                return_value=grp.struct_group(("hyperlight", "x", 41, [])),
            ),
            mock.patch.object(INSTALL, "user_in_group", return_value=False),
        ):
            plan = INSTALL.installation_plan(
                "developer", None, allow_unprobed_namespace=True
            )
        self.assertTrue(plan["namespace_unprobed"])
        self.assertFalse(plan["needs_apparmor"])

    def test_prerequisite_check_accepts_verified_unbuilt_checkout(self):
        with tempfile.TemporaryDirectory() as source:
            plan = {"needs_apparmor": False}
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "install_linux.py",
                        "--check-prerequisites",
                        "--source",
                        source,
                        "--user",
                        "developer",
                    ],
                ),
                mock.patch.object(INSTALL.pwd, "getpwnam"),
                mock.patch.object(
                    INSTALL,
                    "validate_source",
                    return_value=(None, None),
                ) as validate_source,
                mock.patch.object(
                    INSTALL,
                    "installation_plan",
                    return_value=plan,
                ),
                mock.patch.object(INSTALL, "print_install_plan"),
                mock.patch.object(INSTALL, "asset_sources", return_value=({}, {})),
            ):
                INSTALL.main()
        validate_source.assert_called_once_with(
            Path(source),
            allow_missing_helper=True,
            staged_source=False,
        )

    def test_state_rejects_paths_outside_managed_allowlist(self):
        state = {
            "version": 3,
            "baseline": {"/etc/shadow": {"kind": "absent"}},
            "directory_baseline": {
                str(path): False for path in INSTALL.SYSTEMD_DIRS
            },
            "apparmor_was_loaded": False,
            "devices": {},
            "memberships_added": {},
            "created_groups": [],
            "policy": {"apparmor": False, "device": False, "systemd": False},
        }
        with self.assertRaisesRegex(RuntimeError, "baseline path set"):
            INSTALL.validate_state(state)

    def test_noop_plan_has_no_restart_or_shutdown_advice(self):
        plan = self.plan()
        output = io.StringIO()
        with redirect_stdout(output):
            INSTALL.print_install_plan(plan)
        text = output.getvalue()
        self.assertIn("Login or WSL restart required: no", text)
        self.assertNotIn("wsl --shutdown", text)
        self.assertFalse(INSTALL.plan_requires_mutation(plan))

    def test_missing_release_asset_is_reported_before_install(self):
        missing = Path("/missing/process_placement")
        with mock.patch.object(
            INSTALL, "asset_sources",
            return_value=({missing: (Path("/installed/process_placement"), 0o755, 0)}, {}),
        ):
            with self.assertRaisesRegex(ValueError, str(missing)):
                INSTALL.validate_assets()


class TransactionTests(unittest.TestCase):
    def test_uninstall_migrates_pre_v3_state_without_status_marker(self):
        state = {
            "version": 2,
            "baseline": {},
            "directory_baseline": {},
            "memberships_added": {},
            "created_groups": [],
        }

        def migrate(value):
            value["version"] = 3

        with (
            mock.patch.object(INSTALL, "load_state", return_value=state),
            mock.patch.object(INSTALL, "migrate_state", side_effect=migrate) as migrate_mock,
            mock.patch.object(INSTALL, "validate_state") as validate,
            mock.patch.object(INSTALL, "validate_state_status") as validate_status,
            mock.patch.object(
                INSTALL, "stop_active_units", side_effect=RuntimeError("stop")
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                INSTALL.uninstall(mock.Mock(user="simon"))

        migrate_mock.assert_called_once_with(state)
        validate.assert_called_once_with(state)
        validate_status.assert_not_called()

    def test_helper_mismatch_is_preserved_in_rollback_metadata(self):
        metadata = os.stat_result((
            stat.S_IFREG | 0o755, 0, 0, 1, 0, 0, 6, 0, 0, 0
        ))
        helper = Path("/usr/libexec/hyperlight/minijail0")
        with (
            mock.patch.object(INSTALL.Path, "lstat", return_value=metadata),
            mock.patch.object(INSTALL.Path, "read_bytes", return_value=b"helper"),
        ):
            record = INSTALL.snapshot_path(helper)
        self.assertEqual(
            record,
            {
                "kind": "file",
                "content": "aGVscGVy",
                "mode": 0o755,
                "uid": 0,
                "gid": 0,
            },
        )

    def test_rollback_restores_every_recorded_surface(self):
        with (
            mock.patch.object(INSTALL, "apparmor_loaded", return_value=False),
            mock.patch.object(INSTALL, "restore_paths") as restore_paths,
            mock.patch.object(INSTALL, "restore_directories") as restore_directories,
            mock.patch.object(INSTALL, "restore_apparmor") as restore_apparmor,
            mock.patch.object(INSTALL, "remove_memberships") as remove_memberships,
            mock.patch.object(INSTALL, "remove_created_groups") as remove_groups,
            mock.patch.object(INSTALL, "reload_policy") as reload_policy,
            mock.patch.object(INSTALL, "restore_devices") as restore_devices,
            mock.patch.object(INSTALL.Path, "rmdir"),
        ):
            INSTALL.rollback(
                {"file": "record"},
                {"directory": False},
                True,
                {"/dev/kvm": {"mode": 0o660}},
                {"developer": ["kvm"]},
                ["kvm"],
            )
        restore_paths.assert_called_once()
        restore_directories.assert_called_once()
        restore_apparmor.assert_called_once_with(True)
        remove_memberships.assert_called_once()
        remove_groups.assert_called_once()
        reload_policy.assert_called_once()
        restore_devices.assert_called_once()


class JustRecipeTests(unittest.TestCase):
    def test_constrained_process_recipes_are_discoverable_and_explicit(self):
        root = MODULE_PATH.parents[2]
        result = subprocess.run(
            ["just", "--dry-run", "install-constrained-process"],
            cwd=root,
            text=True,
            capture_output=True,
            check=True,
        )
        output = result.stdout + result.stderr
        self.assertIn("build_minijail.py", output)
        self.assertIn("--example process_file_resource", output)
        self.assertIn("hyperlight-run init", output)
        run = subprocess.run(
            ["just", "--dry-run", "run-constrained-process", "/bin/true"],
            cwd=root,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn(
            "hyperlight-run run -- /bin/true",
            run.stdout + run.stderr,
        )

    def test_launcher_help_lists_suite_and_resource_inputs(self):
        launcher = MODULE_PATH.with_name("hyperlight-run")
        suite = subprocess.run(
            [launcher, "demo", "--help"],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("placement-demo, resource-demo and nested-demo", suite.stdout)
        self.assertIn("--no-color", suite.stdout)
        self.assertIn("--no-clipboard", suite.stdout)
        resource = subprocess.run(
            [launcher, "resource-demo", "--help"],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("--read-write PATH", resource.stdout)
        self.assertIn("CLI options override", resource.stdout)

    def test_launcher_quietly_preserves_curated_output(self):
        launcher = MODULE_PATH.with_name("hyperlight-run")
        with tempfile.TemporaryDirectory() as directory:
            tools = Path(directory)
            systemctl = tools / "systemctl"
            systemd_run = tools / "systemd-run"
            systemctl.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *is-system-running*) echo running ;;\n"
                "  *'show -P LoadState'*) echo not-found ;;\n"
                "esac\n"
            )
            systemd_run.write_text(
                "#!/bin/sh\n"
                "quiet=0\n"
                "for argument in \"$@\"; do [ \"$argument\" = --quiet ] && quiet=1; done\n"
                "if [ \"$quiet\" -ne 1 ]; then\n"
                "  echo 'Running as unit: hyperlight-test.service; invocation ID: leaked'\n"
                "  echo 'Press ^] three times within 1s to disconnect TTY.'\n"
                "  echo 'Finished with result: success'\n"
                "fi\n"
                "echo 'CURATED DEMO OUTPUT'\n"
            )
            systemctl.chmod(0o755)
            systemd_run.chmod(0o755)
            result = subprocess.run(
                [launcher, "run", "--", "/bin/true"],
                text=True,
                capture_output=True,
                check=True,
                env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"},
            )
        output = result.stdout + result.stderr
        self.assertIn("CURATED DEMO OUTPUT", output)
        for noise in (
            "Running as unit:",
            "invocation ID:",
            "Press ^]",
            "Finished with result",
            "Main processes terminated",
        ):
            self.assertNotIn(noise, output)

    def test_launcher_runs_local_directly_before_constrained_modes(self):
        launcher = MODULE_PATH.with_name("hyperlight-run").read_text()
        local = (
            "/usr/libexec/hyperlight/process_placement demo \\\n"
            "        /usr/libexec/hyperlight/simpleguest \\\n"
            '        "${demo_options[@]}" --local-only'
        )
        constrained = (
            "/usr/libexec/hyperlight/process_placement demo \\\n"
            '        /usr/libexec/hyperlight/simpleguest "${demo_options[@]}" --constrained-only'
        )
        self.assertIn(local, launcher)
        self.assertIn(constrained, launcher)
        self.assertLess(
            launcher.index(local),
            launcher.index('set -- --runtime-max "$demo_runtime" --'),
        )
        self.assertGreater(
            launcher.index("systemd-run --user --wait --collect"),
            launcher.index(constrained),
        )

    def test_launcher_never_reopens_installer_after_sudo(self):
        launcher = MODULE_PATH.with_name("hyperlight-run").read_text()
        init = launcher.split("if [[ ${1-} == check ]]", maxsplit=1)[0]
        self.assertIn('installer_b64=$(base64 -w0 -- "$installer")', init)
        self.assertIn("printf '%s' \"$installer_b64\" | base64 -d", init)
        self.assertIn("run_installer --sudo-install", init)
        self.assertNotIn('exec sudo -- "${command[@]}"', init)
        uninstall = launcher.split("if [[ ${1-} == uninstall ]]", maxsplit=1)[1]
        self.assertIn("trusted installed uninstaller is unavailable", uninstall)
        self.assertNotIn("bootstrap_tool install_linux.py", uninstall)

    def test_no_color_suppresses_suite_screen_clears(self):
        launcher = MODULE_PATH.with_name("hyperlight-run").read_text()
        clear_blocks = launcher.split("printf '\\033[2J\\033[H'")[:-1]
        self.assertEqual(len(clear_blocks), 2)
        for block in clear_blocks:
            self.assertIn('--no-color "', block[-180:])


if __name__ == "__main__":
    unittest.main()
