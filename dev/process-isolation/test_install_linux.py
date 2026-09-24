#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Hyperlight Authors.

"""Focused tests for Linux process-placement installation assets."""

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("install_linux.py")
SPEC = importlib.util.spec_from_file_location("install_linux", MODULE_PATH)
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


class InstallationAssetTests(unittest.TestCase):
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
                (Path("/usr/libexec/hyperlight/simpleguest"), 0o755),
            },
        )

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

        self.assertEqual(state["version"], 2)
        self.assertIs(state["baseline"][str(old_path)], old_record)
        self.assertEqual(state["baseline"][str(new_path)], new_record)
        snapshot.assert_called_once_with(new_path)


if __name__ == "__main__":
    unittest.main()
