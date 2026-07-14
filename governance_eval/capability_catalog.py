from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityAdapter:
    capability: str
    adapter_id: str
    argv: tuple[str, ...]
    working_directory: str
    timeout_seconds: int
    output_limit_bytes: int


_ADAPTERS = {
    ("lint", "python.ruff-check.v1"): CapabilityAdapter(
        capability="lint",
        adapter_id="python.ruff-check.v1",
        argv=("python", "-m", "ruff", "check", "."),
        working_directory=".",
        timeout_seconds=120,
        output_limit_bytes=65536,
    )
}


def get_capability_adapter(capability: str, adapter_id: str) -> CapabilityAdapter:
    return _ADAPTERS[(capability, adapter_id)]
