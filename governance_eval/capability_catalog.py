from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityAdapter:
    capability: str
    adapter_id: str
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
        runtime_id="evaluator.python-isolated.v1",
        module="ruff",
        arguments=("check", "--isolated", "--no-cache", "--no-respect-gitignore", "."),
        working_directory=".",
        timeout_seconds=120,
        output_limit_bytes=65536,
    ),
    ("format_check", "python.ruff-format-check.v1"): CapabilityAdapter(
        capability="format_check",
        adapter_id="python.ruff-format-check.v1",
        runtime_id="evaluator.python-isolated.v1",
        module="ruff",
        arguments=(
            "format",
            "--check",
            "--isolated",
            "--no-cache",
            "--no-respect-gitignore",
            ".",
        ),
        working_directory=".",
        timeout_seconds=120,
        output_limit_bytes=65536,
    ),
}


def get_capability_adapter(capability: str, adapter_id: str) -> CapabilityAdapter:
    return _ADAPTERS[(capability, adapter_id)]
