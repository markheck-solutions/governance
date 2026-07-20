from __future__ import annotations

import unittest

from governance_eval.capability_catalog import capability_adapters


EXPECTED = {
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


class CapabilityCatalogTests(unittest.TestCase):
    def test_catalog_contains_only_the_ten_certified_adapters(self) -> None:
        adapters = capability_adapters()

        self.assertEqual(
            {adapter.capability: adapter.adapter_id for adapter in adapters},
            EXPECTED,
        )
        self.assertEqual(len(adapters), len(EXPECTED))

    def test_adapter_contracts_own_scope_runtime_and_limits(self) -> None:
        for adapter in capability_adapters():
            with self.subTest(adapter=adapter.adapter_id):
                self.assertIn(adapter.execution, {"docker", "trusted_judge"})
                self.assertTrue(adapter.scope_rule_id)
                self.assertLessEqual(adapter.timeout_seconds, 120)
                self.assertEqual(adapter.output_limit_bytes, 65_536)
                self.assertNotIn("shell", adapter.__dict__)

        by_capability = {
            adapter.capability: adapter for adapter in capability_adapters()
        }
        self.assertEqual(
            by_capability["tests"].mount_profile,
            "target-toolchain-base-tests.v1",
        )
        self.assertEqual(
            by_capability["package_audit"].mount_profile,
            "wheel-only.v1",
        )
        self.assertEqual(by_capability["architecture"].execution, "trusted_judge")
        self.assertEqual(by_capability["diff_integrity"].execution, "trusted_judge")


if __name__ == "__main__":
    unittest.main()
