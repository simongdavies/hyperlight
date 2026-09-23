#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Hyperlight Authors.

"""Focused tests for Linux process-placement installation assets."""

import importlib.util
from pathlib import Path
import unittest


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
                (Path("/usr/libexec/hyperlight/simpleguest"), 0o755),
            },
        )


if __name__ == "__main__":
    unittest.main()
