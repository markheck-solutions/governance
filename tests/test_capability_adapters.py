from __future__ import annotations

import copy
import unittest
from pathlib import Path

from governance_eval.capability_catalog import capability_adapters
from governance_eval.paths import repo_root
from governance_eval.supportability import (
    SupportabilityError,
    load_supportability_config,
    parse_supportability_config_bytes,
    validate_supportability_config,
)
from governance_eval.supportability_config_v2 import V2_CAPABILITIES


ADAPTER_IDS = {
    "lint": "python.ruff-check.v1",
    "format_check": "python.ruff-format-check.v1",
    "typecheck": "python.mypy.v1",
    "complexity": "python.ruff-c901.v1",
    "architecture": "governance.architecture.v1",
    "tests": "python.unittest.v1",
    "build": "python.pip-wheel-no-deps.v1",
    "package_audit": "python.package-audit-isolated.v1",
    "benchmark": "governance.phase1-benchmark.v1",
    "diff_integrity": "git.diff-check.v1",
}


class CapabilityAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def _config(self) -> dict:
        legacy = load_supportability_config(
            self.root / ".github/governance/supportability.yml"
        )
        config = {
            key: copy.deepcopy(value)
            for key, value in legacy.items()
            if key != "required_gates"
        }
        config["schema_version"] = "2.0"
        config["capabilities"] = {
            capability: [
                {
                    "adapter": adapter,
                    "root": ".",
                    **({"threshold": 10} if capability == "complexity" else {}),
                }
            ]
            for capability, adapter in ADAPTER_IDS.items()
        }
        return config

    def test_governance_v2_capabilities_block_until_all_runtimes_exist(self) -> None:
        config = self._config()

        errors = validate_supportability_config(config)
        self.assertEqual(tuple(config["capabilities"]), V2_CAPABILITIES)
        self.assertEqual(
            {(item.capability, item.adapter_id) for item in capability_adapters()},
            {
                ("lint", ADAPTER_IDS["lint"]),
                ("format_check", ADAPTER_IDS["format_check"]),
                ("complexity", ADAPTER_IDS["complexity"]),
            },
        )
        self.assertEqual(
            sum("unsupported capability adapter" in error for error in errors), 7
        )
        self.assertFalse(any("python.ruff-check.v1" in error for error in errors))
        self.assertFalse(
            any("python.ruff-format-check.v1" in error for error in errors)
        )
        self.assertFalse(any("python.ruff-c901.v1" in error for error in errors))

    def test_v1_config_validation_remains_supported(self) -> None:
        config = load_supportability_config(
            self.root / ".github/governance/supportability.yml"
        )

        self.assertEqual(validate_supportability_config(config), [])

    def test_unknown_config_version_fails_closed(self) -> None:
        config = self._config()
        config["schema_version"] = "2.1"

        self.assertEqual(
            validate_supportability_config(config),
            ["supportability config schema_version is unsupported: '2.1'"],
        )

    def test_v2_rejects_shell_text_paths_options_thresholds_and_missing_gates(
        self,
    ) -> None:
        mutations = {
            "shell": lambda value: value["capabilities"]["lint"][0].update(
                adapter="python -m ruff check ."
            ),
            "path": lambda value: value["capabilities"]["lint"][0].update(
                root="../target"
            ),
            "arguments": lambda value: value["capabilities"]["lint"][0].update(
                arguments=["--ignore", "E501"]
            ),
            "threshold": lambda value: value["capabilities"]["complexity"][0].update(
                threshold=11
            ),
            "missing": lambda value: value["capabilities"].pop("tests"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                config = self._config()
                mutate(config)
                self.assertTrue(validate_supportability_config(config))

    def test_v2_rejects_adapter_reuse_across_semantic_gates(self) -> None:
        config = self._config()
        config["capabilities"]["format_check"][0]["adapter"] = ADAPTER_IDS["lint"]

        errors = validate_supportability_config(config)

        self.assertIn(
            "adapter python.ruff-check.v1 cannot satisfy both lint and format_check",
            errors,
        )

    def test_config_parser_rejects_duplicate_json_and_yaml_keys(self) -> None:
        inputs = (
            (b'{"schema_version":"2.0","schema_version":"2.0"}', ".json"),
            (b"schema_version: '2.0'\nschema_version: '2.0'\n", ".yml"),
            (
                b"capabilities:\n  lint:\n    - adapter: first\n      adapter: second\n      root: '.'\n",
                ".yml",
            ),
        )
        for raw, suffix in inputs:
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(
                    SupportabilityError, "duplicate supportability config key"
                ):
                    parse_supportability_config_bytes(raw, suffix=suffix)


if __name__ == "__main__":
    unittest.main()
