from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityAdapter:
    capability: str
    adapter_id: str
    execution: str
    scope_rule_id: str
    mount_profile: str
    argv_prefix: tuple[str, ...] = ()
    append_authenticated_paths: bool = False
    operation_id: str | None = None
    working_directory: str = "/workspace"
    timeout_seconds: int = 90
    total_timeout_seconds: int = 120
    output_limit_bytes: int = 65_536
    expected_artifacts: tuple[str, ...] = ()


_ADAPTERS = (
    CapabilityAdapter(
        "lint",
        "python.ruff-check.v1",
        "docker",
        "tracked-python.v1",
        "target-toolchain.v1",
        (
            "/opt/governance-toolchain/python/bin/ruff",
            "check",
            "--isolated",
            "--no-cache",
            "--no-respect-gitignore",
            "--ignore-noqa",
            "--target-version=py312",
            "--select=E4,E7,E9,F",
            "--output-format=concise",
            "--",
        ),
        True,
    ),
    CapabilityAdapter(
        "format_check",
        "python.ruff-format-check.v1",
        "docker",
        "tracked-python.v1",
        "target-toolchain.v1",
        (
            "/opt/governance-toolchain/python/bin/ruff",
            "format",
            "--check",
            "--isolated",
            "--no-cache",
            "--no-respect-gitignore",
            "--target-version=py312",
            "--",
        ),
        True,
    ),
    CapabilityAdapter(
        "typecheck",
        "python.mypy.v1",
        "docker",
        "tracked-production-python.v1",
        "target-toolchain.v1",
        (
            "/usr/local/bin/python",
            "-P",
            "-s",
            "-m",
            "mypy",
            "--config-file=/opt/governance-judge/governance_eval/judges/mypy_v1.ini",
            "--python-version=3.12",
            "--show-error-codes",
            "--no-incremental",
            "--no-site-packages",
            "--",
        ),
        True,
    ),
    CapabilityAdapter(
        "complexity",
        "python.ruff-c901.v1",
        "docker",
        "tracked-python.v1",
        "target-toolchain.v1",
        (
            "/opt/governance-toolchain/python/bin/ruff",
            "check",
            "--isolated",
            "--no-cache",
            "--no-respect-gitignore",
            "--ignore-noqa",
            "--target-version=py312",
            "--select=C901",
            "--config=lint.mccabe.max-complexity=10",
            "--output-format=concise",
            "--",
        ),
        True,
    ),
    CapabilityAdapter(
        "architecture",
        "governance.architecture.v1",
        "trusted_judge",
        "authenticated-tree.v1",
        "judge-only.v1",
        operation_id="governance.architecture.authenticated.v1",
        expected_artifacts=("architecture-result",),
    ),
    CapabilityAdapter(
        "tests",
        "python.unittest.v1",
        "docker",
        "pr-base-protected-tests.v1",
        "target-toolchain-base-tests.v1",
        (
            "/usr/local/bin/python",
            "-I",
            "/opt/governance-judge/governance_eval/judges/unittest_gate_v1.py",
            "/scope/scope-manifest.json",
        ),
        expected_artifacts=("unittest-summary",),
    ),
    CapabilityAdapter(
        "build",
        "python.pip-wheel-no-deps.v1",
        "docker",
        "authenticated-tree.v1",
        "target-toolchain.v1",
        (
            "/usr/local/bin/python",
            "-P",
            "-s",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "--no-input",
            "--no-cache-dir",
            "wheel",
            "--no-deps",
            "--no-index",
            "--no-build-isolation",
            "--wheel-dir=/governance-output",
            ".",
        ),
        expected_artifacts=("python-wheel",),
    ),
    CapabilityAdapter(
        "package_audit",
        "python.package-audit-isolated.v1",
        "docker",
        "verified-wheel.v1",
        "wheel-only.v1",
        (
            "/usr/local/bin/python",
            "-I",
            "/opt/governance-judge/governance_eval/judges/package_audit_v1.py",
            "/input",
            "/scratch",
        ),
        working_directory="/scratch",
        expected_artifacts=("package-audit-summary",),
    ),
    CapabilityAdapter(
        "benchmark",
        "governance.phase1-benchmark.v1",
        "docker",
        "certified-evaluator-tree.v1",
        "evaluator-toolchain.v1",
        (
            "/usr/local/bin/python",
            "-P",
            "-s",
            "-m",
            "governance_eval",
            "benchmark",
            "--repeat=3",
            "--artifacts-dir=/governance-output/phase1",
        ),
        expected_artifacts=("phase1-benchmark",),
    ),
    CapabilityAdapter(
        "diff_integrity",
        "git.diff-check.v1",
        "trusted_judge",
        "authenticated-diff.v1",
        "judge-only.v1",
        operation_id="git.diff-check.authenticated.v1",
        expected_artifacts=("diff-integrity-result",),
    ),
)
_ADAPTER_INDEX = {
    (adapter.capability, adapter.adapter_id): adapter for adapter in _ADAPTERS
}


def capability_adapters() -> tuple[CapabilityAdapter, ...]:
    return _ADAPTERS


def get_capability_adapter(capability: str, adapter_id: str) -> CapabilityAdapter:
    return _ADAPTER_INDEX[(capability, adapter_id)]
