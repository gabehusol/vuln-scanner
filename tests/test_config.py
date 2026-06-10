from __future__ import annotations

import json
import shutil
import unittest
import uuid
from pathlib import Path

from vulnscanner.cli import build_parser
from vulnscanner.config import load_config, resolve_command_defaults


TEST_TMP_ROOT = Path("tests_tmp")
TEST_TMP_ROOT.mkdir(exist_ok=True)


def make_test_dir(name: str) -> Path:
    path = TEST_TMP_ROOT / f"{name}_{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=True)
    return path


class ConfigTests(unittest.TestCase):
    def test_load_config_reads_json_object(self) -> None:
        tmp = make_test_dir("config")
        try:
            config_path = tmp / "vulnscanner.json"
            config_path.write_text(json.dumps({"shared": {"timeout": 9}}), encoding="utf-8")

            data, loaded_path = load_config(str(config_path))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        self.assertEqual(data["shared"]["timeout"], 9)
        self.assertEqual(loaded_path, config_path)

    def test_resolve_command_defaults_merges_shared_and_command_values(self) -> None:
        config = {
            "shared": {"timeout": 7, "statuses": [200]},
            "scan": {"threads": 3},
        }

        defaults = resolve_command_defaults(config, "scan")

        self.assertEqual(defaults["timeout"], 7)
        self.assertEqual(defaults["threads"], 3)
        self.assertEqual(defaults["statuses"], [200])

    def test_parser_uses_config_defaults(self) -> None:
        defaults = {
            "target": "example.com",
            "timeout": 11,
            "statuses": [200, 403],
            "include_patterns": ["admin*"],
            "verbose": True,
        }

        parser = build_parser(defaults)
        args = parser.parse_args(["scan"])

        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.timeout, 11)
        self.assertEqual(args.statuses, [200, 403])
        self.assertEqual(args.include_patterns, ["admin*"])
        self.assertTrue(args.verbose)
