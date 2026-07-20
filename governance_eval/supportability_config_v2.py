from __future__ import annotations

import re
from copy import deepcopy
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any, Mapping

from governance_eval.architecture_gate import architecture_policy_errors
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_packaged_named
from governance_eval.supportability import (
    SupportabilityError,
    parse_supportability_config_bytes,
)


AUTHORIZED_GOVERNANCE_V1_SHA256 = (
    "d4cb27133e26b6893667c7a4ff57fa718bc9e6848558b46607cfabcd47740e16"
)
TYPED_CAPABILITIES = {
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
    "sql_supportability": "auto",
}
_ENVELOPE_FIELDS = {
    "mode",
    "source_schema_version",
    "effective_schema_version",
    "content_sha256",
    "source",
    "effective",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ExecutableConfigError(ValueError):
    pass


def validate_executable_supportability_config_bytes(
    raw: bytes,
    *,
    repository_full_name: str,
    path: str,
) -> dict[str, Any]:
    if len(raw) > 1024 * 1024:
        raise ExecutableConfigError("supportability config exceeds size limit")
    digest = sha256(raw).hexdigest()
    try:
        parsed = parse_supportability_config_bytes(raw, suffix=".yml")
        _validate_depth(parsed)
    except (RecursionError, SupportabilityError) as exc:
        raise ExecutableConfigError("supportability config is malformed") from exc
    if "schema_version" in parsed:
        return _typed_v2(parsed, digest)
    return _authorized_v1(parsed, digest, repository_full_name, path)


def validate_config_transition(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> None:
    baseline_mode = _validate_envelope(baseline)
    candidate_mode = _validate_envelope(candidate)
    if baseline_mode == "typed_v2" and candidate_mode != "typed_v2":
        raise ExecutableConfigError("typed supportability config cannot downgrade")
    if baseline_mode == "legacy_v1_exact" and candidate_mode == "typed_v2":
        _validate_preserved_sections(baseline, candidate)
    if baseline_mode == candidate_mode and (
        baseline["content_sha256"] != candidate["content_sha256"]
    ):
        raise ExecutableConfigError("same-version supportability config changed")


def _typed_v2(parsed: dict[str, Any], digest: str) -> dict[str, Any]:
    _validate_typed_config(parsed)
    return _envelope("typed_v2", digest, parsed, parsed)


def _authorized_v1(
    parsed: dict[str, Any], digest: str, repository_full_name: str, path: str
) -> dict[str, Any]:
    if (
        digest != AUTHORIZED_GOVERNANCE_V1_SHA256
        or repository_full_name != "markheck-solutions/governance"
        or path != ".github/governance/supportability.yml"
    ):
        raise ExecutableConfigError("legacy supportability config is validation-only")
    effective = {
        **deepcopy(parsed),
        "schema_version": "2.0",
        "capabilities": deepcopy(TYPED_CAPABILITIES),
    }
    effective.pop("required_gates", None)
    _validate_typed_config(effective)
    return _envelope("legacy_v1_exact", digest, parsed, effective)


def _validate_typed_config(parsed: dict[str, Any]) -> None:
    try:
        validate_packaged_named("supportability_config_v2", parsed)
    except (KeyError, OSError, SchemaValidationError, ValueError) as exc:
        raise ExecutableConfigError("typed supportability config is invalid") from exc
    if parsed["capabilities"] != TYPED_CAPABILITIES:
        raise ExecutableConfigError("typed capability profile is not certified")
    _validate_repository_path(parsed["standard"]["source"], "standard.source")
    errors = architecture_policy_errors(parsed["architecture_policy"])
    errors.extend(_architecture_contract_errors(parsed["architecture_policy"]))
    if errors:
        raise ExecutableConfigError(
            "typed architecture policy is invalid: " + "; ".join(errors)
        )


def _envelope(
    mode: str,
    digest: str,
    source: Mapping[str, Any],
    effective: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "mode": mode,
        "source_schema_version": "1.0" if mode == "legacy_v1_exact" else "2.0",
        "effective_schema_version": "2.0",
        "content_sha256": digest,
        "source": deepcopy(dict(source)),
        "effective": deepcopy(dict(effective)),
    }


def _validate_envelope(envelope: Mapping[str, Any]) -> str:
    if set(envelope) != _ENVELOPE_FIELDS:
        raise ExecutableConfigError("supportability config envelope shape is invalid")
    mode = envelope.get("mode")
    if mode not in {"legacy_v1_exact", "typed_v2"}:
        raise ExecutableConfigError("supportability config envelope mode is invalid")
    source = envelope.get("source")
    effective = envelope.get("effective")
    if not isinstance(source, dict) or not isinstance(effective, dict):
        raise ExecutableConfigError("supportability config envelope content is invalid")
    expected_source = "1.0" if mode == "legacy_v1_exact" else "2.0"
    if (
        envelope.get("source_schema_version") != expected_source
        or envelope.get("effective_schema_version") != "2.0"
        or not isinstance(envelope.get("content_sha256"), str)
        or not _SHA256_RE.fullmatch(envelope["content_sha256"])
    ):
        raise ExecutableConfigError(
            "supportability config envelope identity is invalid"
        )
    _validate_typed_config(effective)
    if mode == "typed_v2" and source != effective:
        raise ExecutableConfigError("typed supportability envelope differs from source")
    if mode == "legacy_v1_exact":
        _validate_legacy_envelope(envelope)
    return str(mode)


def _validate_legacy_envelope(envelope: Mapping[str, Any]) -> None:
    if envelope["content_sha256"] != AUTHORIZED_GOVERNANCE_V1_SHA256:
        raise ExecutableConfigError(
            "legacy supportability envelope identity is invalid"
        )
    expected = {
        **deepcopy(envelope["source"]),
        "schema_version": "2.0",
        "capabilities": deepcopy(TYPED_CAPABILITIES),
    }
    expected.pop("required_gates", None)
    if envelope["effective"] != expected:
        raise ExecutableConfigError("legacy supportability translation is invalid")


def _validate_preserved_sections(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> None:
    fields = ("standard", "coverage", "ai_review", "receipt", "architecture_policy")
    before = baseline["source"]
    after = candidate["source"]
    if any(before.get(field) != after.get(field) for field in fields):
        raise ExecutableConfigError(
            "typed migration changes a preserved policy section"
        )


def _validate_depth(value: Any, depth: int = 0) -> None:
    if depth > 128:
        raise SupportabilityError("supportability config nesting exceeds limit")
    if isinstance(value, dict):
        for item in value.values():
            _validate_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_depth(item, depth + 1)


def _architecture_contract_errors(policy: Any) -> list[str]:
    if not isinstance(policy, Mapping):
        return []
    errors = _unknown_keys(
        policy,
        {
            "version",
            "enforcement_mode",
            "governed_roots",
            "runtime_relevance",
            "vague_names",
            "modules",
            "known_debt",
        },
        "architecture_policy",
    )
    errors.extend(_architecture_child_errors(policy))
    return errors


def _architecture_child_errors(policy: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    roots = policy.get("governed_roots")
    if isinstance(roots, list):
        errors.extend(_root_contract_errors(roots))
    errors.extend(
        _unknown_keys(
            policy.get("runtime_relevance"),
            {"production_globs", "non_runtime_globs"},
            "architecture_policy.runtime_relevance",
        )
    )
    errors.extend(
        _unknown_keys(
            policy.get("vague_names"),
            {"forbidden"},
            "architecture_policy.vague_names",
        )
    )
    errors.extend(_module_contract_errors(policy.get("modules")))
    errors.extend(_debt_contract_errors(policy.get("known_debt")))
    return errors


def _root_contract_errors(roots: list[Any]) -> list[str]:
    errors: list[str] = []
    paths: list[str] = []
    for index, root in enumerate(roots):
        errors.extend(
            _unknown_keys(
                root,
                {"path", "kind", "owner", "purpose"},
                f"architecture_policy.governed_roots[{index}]",
            )
        )
        if isinstance(root, Mapping) and isinstance(root.get("path"), str):
            paths.append(root["path"])
            errors.extend(_repository_path_errors(root["path"], f"root[{index}].path"))
    if len(paths) != len(set(paths)):
        errors.append("architecture_policy.governed_roots paths must be unique")
    return errors


def _module_contract_errors(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    errors: list[str] = []
    paths: list[str] = []
    for name, module in value.items():
        errors.extend(_module_entry_contract_errors(str(name), module))
        if isinstance(module, Mapping) and isinstance(module.get("path"), str):
            paths.append(module["path"])
    if len(paths) != len(set(paths)):
        errors.append("architecture_policy module paths must be unique")
    return errors


def _module_entry_contract_errors(name: str, module: Any) -> list[str]:
    errors = _unknown_keys(
        module,
        {
            "path",
            "owner",
            "purpose",
            "classification",
            "domain",
            "allowed_dependencies",
            "forbidden_dependencies",
            "test_strategy",
            "limits",
        },
        f"architecture_policy.modules.{name}",
    )
    if not isinstance(module, Mapping):
        return errors
    path = module.get("path")
    if isinstance(path, str):
        errors.extend(_repository_path_errors(path, f"modules.{name}.path"))
    errors.extend(
        _unknown_keys(
            module.get("limits"),
            {
                "max_file_lines",
                "max_function_lines",
                "max_class_lines",
                "max_functions_per_file",
                "max_classes_per_file",
            },
            f"architecture_policy.modules.{name}.limits",
        )
    )
    return errors


def _debt_contract_errors(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    allowed = {
        "rule",
        "path",
        "source_module",
        "target_module",
        "symbol_name",
        "detail",
        "fingerprint",
        "owner",
        "reason",
        "expires_on",
    }
    errors: list[str] = []
    for index, item in enumerate(value):
        errors.extend(_unknown_keys(item, allowed, f"known_debt[{index}]"))
    return errors


def _validate_repository_path(value: Any, label: str) -> None:
    errors = _repository_path_errors(value, label)
    if errors:
        raise ExecutableConfigError(errors[0])


def _repository_path_errors(value: Any, label: str) -> list[str]:
    if not isinstance(value, str) or not value or len(value) > 240:
        return [f"{label} is not a canonical repository path"]
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in value
        or any(ord(character) < 32 for character in value)
    ):
        return [f"{label} is not a canonical repository path"]
    return []


def _unknown_keys(value: Any, allowed: set[str], label: str) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    return [f"{label}.{key} is not supported" for key in sorted(set(value) - allowed)]
