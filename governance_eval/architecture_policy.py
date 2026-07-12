from __future__ import annotations

from typing import Any


def architecture_command_lines(workflow_text: str) -> list[str]:
    return [
        line.strip()
        for line in workflow_text.splitlines()
        if "python -m governance_eval architecture-gate" in line
    ]


def architecture_policy_weakening_errors(
    base_config: dict[str, Any], head_config: dict[str, Any]
) -> list[str]:
    base_policy = base_config.get("architecture_policy")
    head_policy = head_config.get("architecture_policy")
    if not isinstance(base_policy, dict):
        return []
    if not isinstance(head_policy, dict):
        return ["architecture_policy deleted; protected baseline judge must report RED"]
    errors: list[str] = []
    if head_policy.get("enforcement_mode") != "block_all":
        errors.append(
            "architecture_policy.enforcement_mode changed away from block_all"
        )
    errors.extend(_removed_or_narrowed_roots(base_policy, head_policy))
    errors.extend(_runtime_relevance_weakening_errors(base_policy, head_policy))
    errors.extend(_vague_name_weakening_errors(base_policy, head_policy))
    errors.extend(_module_policy_weakening_errors(base_policy, head_policy))
    errors.extend(_known_debt_policy_change_errors(base_policy, head_policy))
    return errors


def _removed_or_narrowed_roots(
    base_policy: dict[str, Any], head_policy: dict[str, Any]
) -> list[str]:
    base_roots = {
        _norm_policy_path(root.get("path")): root
        for root in base_policy.get("governed_roots", [])
        if isinstance(root, dict)
    }
    head_roots = {
        _norm_policy_path(root.get("path")): root
        for root in head_policy.get("governed_roots", [])
        if isinstance(root, dict)
    }
    errors = []
    for path, base_root in sorted(base_roots.items()):
        head_root = head_roots.get(path)
        if head_root is None:
            errors.append(f"architecture_policy.governed_roots removed: {path}")
            continue
        for key in ("kind", "owner", "purpose"):
            if head_root.get(key) != base_root.get(key):
                errors.append(
                    f"architecture_policy.governed_roots narrowed or changed for {path}: {key}"
                )
    return errors


def _runtime_relevance_weakening_errors(
    base_policy: dict[str, Any], head_policy: dict[str, Any]
) -> list[str]:
    base = _dict_value(base_policy.get("runtime_relevance"))
    head = _dict_value(head_policy.get("runtime_relevance"))
    errors = []
    if not set(base.get("production_globs") or []).issubset(
        set(head.get("production_globs") or [])
    ):
        errors.append("architecture_policy.runtime_relevance.production_globs narrowed")
    if not set(head.get("non_runtime_globs") or []).issubset(
        set(base.get("non_runtime_globs") or [])
    ):
        errors.append(
            "architecture_policy.runtime_relevance.non_runtime_globs broadened"
        )
    return errors


def _vague_name_weakening_errors(
    base_policy: dict[str, Any], head_policy: dict[str, Any]
) -> list[str]:
    base = _dict_value(base_policy.get("vague_names"))
    head = _dict_value(head_policy.get("vague_names"))
    if not set(base.get("forbidden") or []).issubset(set(head.get("forbidden") or [])):
        return ["architecture_policy.vague_names.forbidden narrowed"]
    return []


def _module_policy_weakening_errors(
    base_policy: dict[str, Any], head_policy: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    base_modules = _dict_value(base_policy.get("modules"))
    head_modules = _dict_value(head_policy.get("modules"))
    for module_id, base_module in sorted(base_modules.items()):
        head_module = head_modules.get(module_id)
        if not isinstance(base_module, dict) or not isinstance(head_module, dict):
            errors.append(f"architecture_policy.modules.{module_id} removed")
            continue
        if not set(head_module.get("allowed_dependencies") or []).issubset(
            set(base_module.get("allowed_dependencies") or [])
        ):
            errors.append(
                f"architecture_policy.modules.{module_id}.allowed_dependencies broadened"
            )
        if not set(base_module.get("forbidden_dependencies") or []).issubset(
            set(head_module.get("forbidden_dependencies") or [])
        ):
            errors.append(
                f"architecture_policy.modules.{module_id}.forbidden_dependencies narrowed"
            )
        errors.extend(_limit_weakening_errors(module_id, base_module, head_module))
    return errors


def _limit_weakening_errors(
    module_id: str, base_module: dict[str, Any], head_module: dict[str, Any]
) -> list[str]:
    errors = []
    base_limits = _dict_value(base_module.get("limits"))
    head_limits = _dict_value(head_module.get("limits"))
    for key in (
        "max_file_lines",
        "max_function_lines",
        "max_class_lines",
        "max_functions_per_file",
        "max_classes_per_file",
    ):
        base_value = base_limits.get(key)
        head_value = head_limits.get(key)
        if (
            isinstance(base_value, int)
            and isinstance(head_value, int)
            and head_value > base_value
        ):
            errors.append(
                f"architecture_policy.modules.{module_id}.limits.{key} increased"
            )
    return errors


def _known_debt_policy_change_errors(
    base_policy: dict[str, Any], head_policy: dict[str, Any]
) -> list[str]:
    base_debt = {
        _known_debt_identity(item): item
        for item in base_policy.get("known_debt", [])
        if isinstance(item, dict)
    }
    errors = []
    for item in head_policy.get("known_debt", []):
        if not isinstance(item, dict):
            continue
        base_item = base_debt.get(_known_debt_identity(item))
        if base_item is None:
            errors.append("architecture_policy.known_debt added or changed")
        elif str(item.get("expires_on") or "") > str(base_item.get("expires_on") or ""):
            errors.append("architecture_policy.known_debt extended")
    return errors


def _known_debt_identity(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        item.get("rule"),
        _norm_policy_path(item.get("path")),
        item.get("source_module", ""),
        item.get("target_module", ""),
        item.get("symbol_name", ""),
        item.get("detail", ""),
        item.get("fingerprint", ""),
    )


def _norm_policy_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip("/")


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
