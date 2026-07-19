from __future__ import annotations

from typing import Any

from governance_eval.capability_catalog import get_capability_adapter


V2_CAPABILITIES = (
    "lint",
    "format_check",
    "typecheck",
    "complexity",
    "architecture",
    "tests",
    "build",
    "package_audit",
    "benchmark",
    "diff_integrity",
)


class DuplicateSupportabilityKey(ValueError):
    pass


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateSupportabilityKey(
                f"duplicate supportability config key: {key}"
            )
        result[key] = value
    return result


def capability_errors(capabilities: Any) -> list[str]:
    if not isinstance(capabilities, dict):
        return ["capabilities must be an object"]
    errors: list[str] = []
    observed_adapters: dict[str, str] = {}
    for capability in V2_CAPABILITIES:
        entries = capabilities.get(capability)
        if not isinstance(entries, list) or len(entries) != 1:
            errors.append(f"capabilities.{capability} must contain exactly one adapter")
            continue
        errors.extend(_entry_errors(capability, entries[0], observed_adapters))
    unknown = sorted(set(capabilities) - set(V2_CAPABILITIES))
    errors.extend(f"capabilities.{name} is not supported" for name in unknown)
    return errors


def _entry_errors(
    capability: str, entry: Any, observed_adapters: dict[str, str]
) -> list[str]:
    if not isinstance(entry, dict):
        return [f"capabilities.{capability}[0] must be an object"]
    errors: list[str] = []
    allowed = (
        {"adapter", "root", "threshold"}
        if capability == "complexity"
        else {"adapter", "root"}
    )
    errors.extend(
        f"capabilities.{capability}[0].{name} is not supported"
        for name in sorted(set(entry) - allowed)
    )
    adapter_id = entry.get("adapter")
    if not isinstance(adapter_id, str):
        errors.append(f"capabilities.{capability}[0].adapter must be a string")
    else:
        errors.extend(_adapter_errors(capability, adapter_id, observed_adapters))
    if entry.get("root") != ".":
        errors.append(f"capabilities.{capability}[0].root must be '.'")
    if capability == "complexity" and entry.get("threshold") != 10:
        errors.append("capabilities.complexity[0].threshold must be 10")
    return errors


def _adapter_errors(
    capability: str, adapter_id: str, observed: dict[str, str]
) -> list[str]:
    errors: list[str] = []
    try:
        get_capability_adapter(capability, adapter_id)
    except KeyError:
        errors.append(f"unsupported capability adapter: {capability}/{adapter_id}")
    previous = observed.setdefault(adapter_id, capability)
    if previous != capability:
        errors.append(
            f"adapter {adapter_id} cannot satisfy both {previous} and {capability}"
        )
    return errors
