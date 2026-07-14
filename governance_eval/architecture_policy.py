from __future__ import annotations

import posixpath
from typing import Any


def architecture_command_lines(workflow_text: str) -> list[str]:
    return [
        line.strip()
        for line in workflow_text.splitlines()
        if "python -m governance_eval architecture-gate" in line
    ]


def duplicate_governed_root_errors(roots: Any) -> list[str]:
    if not isinstance(roots, list):
        return []
    paths = [
        _normalized_policy_path(root.get("path"))
        for root in roots
        if isinstance(root, dict)
        and isinstance(root.get("path"), str)
        and root["path"].strip()
    ]
    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    return [
        f"architecture_policy.governed_roots contains duplicate normalized path: {path}"
        for path in duplicates
    ]


def duplicate_module_path_errors(modules: Any) -> list[str]:
    if not isinstance(modules, dict):
        return []
    paths = [
        _normalized_policy_path(module.get("path"))
        for module in modules.values()
        if isinstance(module, dict)
        and isinstance(module.get("path"), str)
        and module["path"].strip()
    ]
    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    return [
        f"architecture_policy.modules contains duplicate normalized path: {path}"
        for path in duplicates
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
    errors.extend(_added_nested_module_weakening_errors(base_modules, head_modules))
    return errors


def _added_nested_module_weakening_errors(
    base_modules: dict[str, Any], head_modules: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    for module_id, head_module in sorted(head_modules.items()):
        if module_id in base_modules or not isinstance(head_module, dict):
            continue
        base_match = _most_specific_base_module(base_modules, head_module.get("path"))
        if base_match is None:
            continue
        base_id, base_module = base_match
        errors.extend(
            _nested_module_policy_errors(module_id, head_module, base_id, base_module)
        )
    return errors


def _most_specific_base_module(
    base_modules: dict[str, Any], head_path_value: Any
) -> tuple[str, dict[str, Any]] | None:
    head_path = _norm_policy_path(head_path_value)
    matches = [
        (module_id, module)
        for module_id, module in base_modules.items()
        if isinstance(module, dict)
        and _path_is_under(head_path, _norm_policy_path(module.get("path")))
    ]
    return max(
        matches,
        key=lambda item: len(_norm_policy_path(item[1].get("path"))),
        default=None,
    )


def _nested_module_policy_errors(
    module_id: str,
    head_module: dict[str, Any],
    base_id: str,
    base_module: dict[str, Any],
) -> list[str]:
    prefix = f"new nested module {module_id} weakens protected module {base_id}:"
    errors: list[str] = []
    if not set(head_module.get("allowed_dependencies") or []).issubset(
        set(base_module.get("allowed_dependencies") or [])
    ):
        errors.append(f"{prefix} allowed_dependencies")
    if not set(base_module.get("forbidden_dependencies") or []).issubset(
        set(head_module.get("forbidden_dependencies") or [])
    ):
        errors.append(f"{prefix} forbidden_dependencies")
    if head_module.get("classification") != base_module.get("classification"):
        errors.append(f"{prefix} classification")
    errors.extend(
        _nested_module_limit_errors(module_id, head_module, base_id, base_module)
    )
    return errors


def _nested_module_limit_errors(
    module_id: str,
    head_module: dict[str, Any],
    base_id: str,
    base_module: dict[str, Any],
) -> list[str]:
    head_limits = _dict_value(head_module.get("limits"))
    base_limits = _dict_value(base_module.get("limits"))
    return [
        f"new nested module {module_id} weakens protected module {base_id}: {key}"
        for key, base_value in base_limits.items()
        if isinstance(base_value, int)
        and isinstance(head_limits.get(key), int)
        and head_limits[key] > base_value
    ]


def _path_is_under(path: str, root: str) -> bool:
    return bool(root) and (path == root or path.startswith(root.rstrip("/") + "/"))


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


def _normalized_policy_path(value: Any) -> str:
    normalized = str(value or "").replace("\\", "/")
    return posixpath.normpath(normalized).strip("/").casefold()


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
