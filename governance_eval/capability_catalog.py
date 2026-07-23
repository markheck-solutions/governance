from __future__ import annotations

from dataclasses import dataclass


STANDARD_PROFILE_ADAPTERS = (
    ("lint", "python.ruff-check.v1", "EVALUATOR_AUTHORITATIVE"),
    ("format", "python.ruff-format-check.v1", "EVALUATOR_AUTHORITATIVE"),
    ("typecheck", "python.mypy.v1", "EVALUATOR_AUTHORITATIVE"),
    ("complexity", "python.ruff-c901.v1", "EVALUATOR_AUTHORITATIVE"),
    ("architecture", "python.architecture.v1", "EVALUATOR_AUTHORITATIVE"),
    ("tests", "python.unittest.v1", "COOPERATIVE_DYNAMIC"),
    ("build", "python.wheel-build.v1", "CONTAINED_BUILD"),
    ("package_audit", "python.package-audit.v1", "EVALUATOR_AUTHORITATIVE"),
    ("benchmark", "governance.phase1.v1", "EVALUATOR_AUTHORITATIVE"),
    ("integrity", "git.diff-integrity.v1", "EVALUATOR_AUTHORITATIVE"),
)


@dataclass(frozen=True)
class CapabilityAdapter:
    capability: str
    adapter_id: str
    assurance_class: str
    runtime_id: str
    module: str
    arguments: tuple[str, ...]
    working_directory: str
    timeout_seconds: int
    output_limit_bytes: int


_ADAPTERS = {
    ("lint", "python.ruff-check.v1"): CapabilityAdapter(
        capability="lint",
        adapter_id="python.ruff-check.v1",
        assurance_class="EVALUATOR_AUTHORITATIVE",
        runtime_id="evaluator.python-isolated.v1",
        module="ruff",
        arguments=("check", "--isolated", "--no-cache", "--no-respect-gitignore", "."),
        working_directory=".",
        timeout_seconds=120,
        output_limit_bytes=65536,
    ),
    ("standard_profile", "python.standard-profile.v1"): CapabilityAdapter(
        capability="standard_profile",
        adapter_id="python.standard-profile.v1",
        assurance_class="COOPERATIVE_DYNAMIC",
        runtime_id="evaluator.python-isolated.v1",
        module="governance_eval.standard_profile",
        arguments=(
            "-P",
            "-s",
            "-m",
            "governance_eval.standard_profile",
            "--workspace",
            "/workspace",
            "--benchmark-root",
            "/opt/governance-toolchain/benchmark",
        ),
        working_directory="/workspace",
        timeout_seconds=300,
        output_limit_bytes=65536,
    ),
}


def get_capability_adapter(capability: str, adapter_id: str) -> CapabilityAdapter:
    return _ADAPTERS[(capability, adapter_id)]
