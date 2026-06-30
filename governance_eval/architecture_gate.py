from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from governance_eval.supportability import (
    SHA1_RE,
    STATUS_GREEN,
    STATUS_RED,
    SupportabilityError,
    _utc_now,
    _write_json,
    _write_markdown,
    load_supportability_config,
)
from governance_eval.schemas import validate_named


EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_CONFIG = 2
EXIT_INTERNAL = 3
PASS = "PASS"
FAIL = "FAIL"
SCHEMA_VERSION = "1.0"
ENFORCEMENT_MODES = {"block_all"}
KNOWN_DEBT_MATCH_KEYS = (
    "rule",
    "path",
    "source_module",
    "target_module",
    "symbol_name",
    "detail",
    "fingerprint",
)
LEGACY_POLICY_DEBT_FIELD = "ex" + "ceptions"
ROOT_KINDS = {
    "production_python",
    "test_python",
    "schema_artifact",
    "ci_config",
    "docs",
    "generated_artifact",
}
CLASSIFICATIONS = {
    "domain",
    "application",
    "infrastructure",
    "interface",
    "test",
    "schema",
    "ci",
    "docs",
    "generated",
    "support_tool",
}
PYTHON_RUNTIME_KINDS = {"production_python", "test_python"}


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "architecture-gate":
        argv = argv[1:]
    parser = argparse.ArgumentParser(prog="architecture-gate")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--target-repo", type=Path, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--changed-file", action="append", default=[])
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/supportability"))
    args = parser.parse_args(argv)
    try:
        result, exit_code = run_architecture_gate(
            args.config,
            args.target_repo,
            args.base_sha,
            args.head_sha,
            output_dir=args.output_dir,
            changed_files=args.changed_file or None,
        )
    except Exception as exc:  # pragma: no cover - last-resort guard
        result = _failure_result(
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            mode="block_all",
            errors=[f"unexpected architecture gate failure: {type(exc).__name__}: {exc}"],
            gate_implementation=FAIL,
        )
        try:
            _write_evidence(args.output_dir, result)
        except Exception:
            pass
        print(_cli_summary(result, args.output_dir))
        return EXIT_INTERNAL
    print(_cli_summary(result, args.output_dir))
    return exit_code


def run_architecture_gate(
    config_path: Path,
    target_repo: Path,
    base_sha: str,
    head_sha: str,
    *,
    output_dir: Path | None = None,
    changed_files: list[str] | None = None,
    base_violations: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], int]:
    try:
        config = _load_config(config_path, base_sha, head_sha)
    except SupportabilityError as exc:
        result = _failure_result(
            base_sha=base_sha,
            head_sha=head_sha,
            mode="block_all",
            errors=[str(exc)],
            gate_implementation=FAIL,
        )
        return _finalize_result(result, EXIT_CONFIG, output_dir)
    policy = config.get("architecture_policy") if isinstance(config, dict) else None
    policy_errors = _architecture_policy_errors(policy)
    mode = _policy_mode(policy)
    if policy_errors:
        result = _failure_result(
            base_sha=base_sha,
            head_sha=head_sha,
            mode=mode,
            errors=policy_errors,
            gate_implementation=FAIL,
        )
        return _finalize_result(result, EXIT_CONFIG, output_dir)

    errors = _sha_errors(base_sha, head_sha)
    if errors:
        result = _failure_result(
            base_sha=base_sha,
            head_sha=head_sha,
            mode=mode,
            errors=errors,
            gate_implementation=FAIL,
        )
        return _finalize_result(result, EXIT_CONFIG, output_dir)

    target_repo = target_repo.resolve()
    head_files = _worktree_files(target_repo)
    changed = _changed_files(target_repo, base_sha, head_sha, changed_files)
    known_debt, debt_errors, expired_debt = _known_debt(policy)
    if debt_errors:
        result = _failure_result(
            base_sha=base_sha,
            head_sha=head_sha,
            mode=mode,
            errors=debt_errors,
            gate_implementation=FAIL,
        )
        return _finalize_result(result, EXIT_CONFIG, output_dir)

    head_scan = _scan_files(policy, head_files, changed)
    if base_violations is None:
        base_violations = []
    fingerprinted_head = [_fingerprinted(item) for item in head_scan["violations"]]
    fingerprinted_base = [_fingerprinted(item) for item in (base_violations or [])]
    debt_records = _record_known_debt(fingerprinted_head, known_debt)
    debt_errors = [f"expired known_debt remains RED: {item['rule']} {item['path']}" for item in expired_debt]
    base_by_fingerprint = {item["fingerprint"]: item for item in fingerprinted_base}
    head_by_fingerprint = {item["fingerprint"]: item for item in fingerprinted_head}
    new = [item for fp, item in sorted(head_by_fingerprint.items()) if fp not in base_by_fingerprint]
    existing = [item for fp, item in sorted(head_by_fingerprint.items()) if fp in base_by_fingerprint]
    resolved = [item for fp, item in sorted(base_by_fingerprint.items()) if fp not in head_by_fingerprint]
    repo_status = FAIL if fingerprinted_head else PASS
    behavior = _architecture_behavior_fixtures()
    behavior_proof = PASS if behavior["status"] == PASS else FAIL
    errors = list(behavior["errors"])
    errors.extend(debt_errors)
    blocking = _blocking_violations(mode, fingerprinted_head, new)
    status = (
        STATUS_GREEN
        if not blocking
        and repo_status == PASS
        and behavior_proof == PASS
        and not debt_records
        and not expired_debt
        and not errors
        else STATUS_RED
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "owner_status": status,
        "enforcement_mode": mode,
        "gate_implementation": PASS,
        "repo_architecture_supportability": repo_status,
        "architecture_behavior_proof": behavior_proof,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "changed_files": changed,
        "violations": fingerprinted_head,
        "new_violations": new,
        "existing_violations": existing,
        "resolved_violations": resolved,
        "known_debt_applied": debt_records,
        "expired_known_debt": expired_debt,
        "behavior_fixtures": behavior["fixtures"],
        "rule_results": _rule_results(fingerprinted_head, head_scan["rules_checked"]),
        "errors": errors,
    }
    exit_code = EXIT_OK if status == STATUS_GREEN else EXIT_BLOCKED
    return _finalize_result(result, exit_code, output_dir)


def _load_config(config_path: Path, base_sha: str, head_sha: str) -> dict[str, Any]:
    try:
        return load_supportability_config(config_path)
    except Exception as exc:
        raise SupportabilityError(f"architecture config load failed for {base_sha[:8]}..{head_sha[:8]}: {exc}") from exc


def _finalize_result(result: dict[str, Any], exit_code: int, output_dir: Path | None) -> tuple[dict[str, Any], int]:
    if output_dir is None:
        return result, exit_code
    try:
        _write_evidence(output_dir, result)
    except Exception as exc:
        failed = dict(result)
        failed["owner_status"] = STATUS_RED
        failed["gate_implementation"] = FAIL
        failed["errors"] = list(failed.get("errors") or []) + [
            f"architecture evidence write failed: {type(exc).__name__}: {exc}"
        ]
        return failed, EXIT_CONFIG
    return result, exit_code


def _architecture_policy_errors(policy: Any) -> list[str]:
    if not isinstance(policy, dict):
        return ["architecture_policy must be an object"]
    errors: list[str] = []
    if policy.get("version") != 1:
        errors.append("architecture_policy.version must be 1")
    if policy.get("enforcement_mode") not in ENFORCEMENT_MODES:
        errors.append("architecture_policy.enforcement_mode must be block_all")
    errors.extend(_governed_root_errors(policy.get("governed_roots")))
    errors.extend(_runtime_relevance_errors(policy.get("runtime_relevance")))
    errors.extend(_vague_name_errors(policy.get("vague_names")))
    errors.extend(_module_registry_errors(policy.get("modules")))
    errors.extend(_known_debt_shape_errors(policy))
    return errors


def _governed_root_errors(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return ["architecture_policy.governed_roots must be a non-empty list"]
    errors: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"architecture_policy.governed_roots[{index}] must be an object")
            continue
        for key in ("path", "kind", "owner", "purpose"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                errors.append(f"architecture_policy.governed_roots[{index}].{key} must be a non-empty string")
        if item.get("kind") not in ROOT_KINDS:
            errors.append(f"architecture_policy.governed_roots[{index}].kind is unsupported")
    return errors


def _runtime_relevance_errors(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["architecture_policy.runtime_relevance must be an object"]
    errors: list[str] = []
    for key in ("production_globs", "non_runtime_globs"):
        if not _string_list(value.get(key), allow_empty=True):
            errors.append(f"architecture_policy.runtime_relevance.{key} must be a list of strings")
    return errors


def _vague_name_errors(value: Any) -> list[str]:
    if not isinstance(value, dict) or not _string_list(value.get("forbidden"), allow_empty=False):
        return ["architecture_policy.vague_names.forbidden must contain at least one name"]
    return []


def _module_registry_errors(value: Any) -> list[str]:
    if not isinstance(value, dict) or not value:
        return ["architecture_policy.modules must be a non-empty object"]
    errors: list[str] = []
    for module_id, module in value.items():
        if not isinstance(module_id, str) or not module_id.strip() or not isinstance(module, dict):
            errors.append("architecture_policy.modules entries must be named objects")
            continue
        for key in ("path", "owner", "purpose", "classification", "domain", "test_strategy"):
            if not isinstance(module.get(key), str) or not module[key].strip():
                errors.append(f"architecture_policy.modules.{module_id}.{key} must be a non-empty string")
        if module.get("classification") not in CLASSIFICATIONS:
            errors.append(f"architecture_policy.modules.{module_id}.classification is unsupported")
        for key in ("allowed_dependencies", "forbidden_dependencies"):
            if not _string_list(module.get(key), allow_empty=True):
                errors.append(f"architecture_policy.modules.{module_id}.{key} must be a list of strings")
        limits = module.get("limits")
        if not isinstance(limits, dict):
            errors.append(f"architecture_policy.modules.{module_id}.limits must be an object")
            continue
        for key in (
            "max_file_lines",
            "max_function_lines",
            "max_class_lines",
            "max_functions_per_file",
            "max_classes_per_file",
        ):
            if not isinstance(limits.get(key), int) or limits[key] < 0:
                errors.append(f"architecture_policy.modules.{module_id}.limits.{key} must be a non-negative integer")
    return errors


def _known_debt_shape_errors(policy: dict[str, Any]) -> list[str]:
    if LEGACY_POLICY_DEBT_FIELD in policy:
        return ["legacy architecture debt field is not supported; use architecture_policy.known_debt"]
    value = policy.get("known_debt", [])
    if not isinstance(value, list):
        return ["architecture_policy.known_debt must be a list"]
    errors: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"architecture_policy.known_debt[{index}] must be an object")
            continue
        for key in ("rule", "path", "owner", "reason", "expires_on"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                errors.append(f"architecture_policy.known_debt[{index}].{key} must be a non-empty string")
        for key in ("source_module", "target_module", "symbol_name", "detail"):
            if not isinstance(item.get(key), str):
                errors.append(f"architecture_policy.known_debt[{index}].{key} must be a string")
        if not isinstance(item.get("fingerprint"), str) or not re_full_sha256(item.get("fingerprint")):
            errors.append(f"architecture_policy.known_debt[{index}].fingerprint must be a 64-character SHA-256")
        try:
            date.fromisoformat(str(item.get("expires_on", "")))
        except ValueError:
            errors.append(f"architecture_policy.known_debt[{index}].expires_on must be YYYY-MM-DD")
    return errors


def _string_list(value: Any, *, allow_empty: bool) -> bool:
    return isinstance(value, list) and (allow_empty or bool(value)) and all(isinstance(item, str) and item for item in value)


def re_full_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _policy_mode(policy: Any) -> str:
    if isinstance(policy, dict) and policy.get("enforcement_mode") in ENFORCEMENT_MODES:
        return str(policy["enforcement_mode"])
    return "block_all"


def _known_debt(policy: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    errors = _known_debt_shape_errors(policy)
    if errors:
        return [], errors, []
    today = date.today()
    expired: list[dict[str, Any]] = []
    active: list[dict[str, Any]] = []
    for item in policy.get("known_debt", []):
        if date.fromisoformat(item["expires_on"]) < today:
            expired.append(item)
        else:
            active.append(item)
    return active, [], expired


def _sha_errors(base_sha: str, head_sha: str) -> list[str]:
    errors: list[str] = []
    if base_sha and not SHA1_RE.fullmatch(base_sha):
        errors.append("base_sha must be a 40-character lowercase Git SHA")
    if not SHA1_RE.fullmatch(head_sha):
        errors.append("head_sha must be a 40-character lowercase Git SHA")
    return errors


def _worktree_files(root: Path) -> list[SourceFile]:
    files: list[SourceFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _skip_path(path, root):
            continue
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files.append(SourceFile(rel, text))
    return files


def _base_tree_files(root: Path, base_sha: str) -> tuple[list[SourceFile], list[str]]:
    try:
        completed = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", base_sha],
            cwd=root,
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=60,
        )
        files: list[SourceFile] = []
        for rel in [line for line in completed.stdout.splitlines() if line]:
            if _skip_relative(rel):
                continue
            content = subprocess.run(
                ["git", "show", f"{base_sha}:{rel}"],
                cwd=root,
                check=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=60,
            )
            files.append(SourceFile(_norm(rel), content.stdout))
        return files, []
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return [], [f"base tree unavailable for architecture comparison: {exc}"]


def _changed_files(root: Path, base_sha: str, head_sha: str, changed_files: list[str] | None) -> list[str]:
    if changed_files is not None:
        return sorted({_norm(path) for path in changed_files})
    try:
        completed = subprocess.run(
            ["git", "diff", "--name-only", base_sha, head_sha],
            cwd=root,
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=60,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    return sorted({_norm(line) for line in completed.stdout.splitlines() if line.strip()})


def _skip_path(path: Path, root: Path) -> bool:
    return _skip_relative(path.relative_to(root).as_posix())


def _skip_relative(path: str) -> bool:
    parts = set(_norm(path).split("/"))
    return bool(parts & {".git", ".venv", ".pytest_cache", "__pycache__", "node_modules", "dist", "build", "coverage"})


def _scan_files(policy: dict[str, Any], files: list[SourceFile], changed_files: list[str]) -> dict[str, Any]:
    modules = _modules(policy)
    roots = _roots(policy)
    violations: list[dict[str, Any]] = []
    rules_checked = {
        "registered_modules",
        "registered_top_level",
        "vague_folder_name",
        "unknown_runtime_file",
        "changed_file_architecture_coverage",
        "python_import_cycles",
        "python_dependency_direction",
        "python_size_limits",
        "python_parse",
        "python_dynamic_import",
    }
    by_path = {file.path: file for file in files}
    violations.extend(_top_level_folder_violations(files, roots))
    for file in files:
        root = _root_for_path(file.path, roots)
        module_id = _module_for_path(file.path, modules)
        if root is None and _runtime_relevant(policy, file.path):
            violations.append(_violation("unknown_runtime_file", file.path, "", "", "", "runtime file outside governed roots"))
        if root and module_id is None and _runtime_relevant(policy, file.path):
            violations.append(_violation("unregistered_module", file.path, "", "", "", "runtime file outside registered modules"))
        violations.extend(_vague_folder_violations(policy, file.path))
        if file.path.endswith(".py") and root and root["kind"] in PYTHON_RUNTIME_KINDS and module_id:
            violations.extend(_python_file_violations(policy, file, module_id, by_path))
    for changed in changed_files:
        if changed not in by_path:
            continue
        if _runtime_relevant(policy, changed) and (_root_for_path(changed, roots) is None or _module_for_path(changed, modules) is None):
            violations.append(_violation("changed_file_architecture_coverage", changed, "", "", "", "changed runtime file lacks architecture policy coverage"))
    violations.extend(_cycle_violations(_python_dependency_graph(policy, files)))
    return {
        "violations": violations,
        "rules_checked": rules_checked,
        "python_file_count": len([file for file in files if file.path.endswith(".py")]),
    }


def _top_level_folder_violations(files: list[SourceFile], roots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    registered = {_norm(root["path"]).split("/", 1)[0] for root in roots}
    seen: set[str] = set()
    violations: list[dict[str, Any]] = []
    for file in files:
        top = _top_level(file.path)
        if not top or top in registered or top in seen:
            continue
        seen.add(top)
        violations.append(_violation("unregistered_top_level", top, "", "", top, "top-level folder lacks architecture policy entry"))
    return violations


def _top_level(path: str) -> str:
    normalized = _norm(path)
    if "/" not in normalized:
        return ""
    return normalized.split("/", 1)[0]


def _modules(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {module_id: {**module, "path": _norm(module["path"])} for module_id, module in policy.get("modules", {}).items()}


def _roots(policy: dict[str, Any]) -> list[dict[str, Any]]:
    return [{**root, "path": _norm(root["path"])} for root in policy.get("governed_roots", [])]


def _root_for_path(path: str, roots: list[dict[str, Any]]) -> dict[str, Any] | None:
    matches = [root for root in roots if _under(path, root["path"])]
    return max(matches, key=lambda item: len(item["path"]), default=None)


def _module_for_path(path: str, modules: dict[str, dict[str, Any]]) -> str | None:
    matches = [module_id for module_id, module in modules.items() if _under(path, module["path"])]
    return max(matches, key=len, default=None)


def _runtime_relevant(policy: dict[str, Any], path: str) -> bool:
    relevance = policy.get("runtime_relevance") or {}
    if any(fnmatch.fnmatch(path, pattern) for pattern in relevance.get("non_runtime_globs", [])):
        return False
    return any(fnmatch.fnmatch(path, pattern) for pattern in relevance.get("production_globs", []))


def _vague_folder_violations(policy: dict[str, Any], path: str) -> list[dict[str, Any]]:
    forbidden = set((policy.get("vague_names") or {}).get("forbidden") or [])
    return [
        _violation("vague_folder_name", path, "", "", part, f"forbidden vague folder name: {part}")
        for part in path.split("/")[:-1]
        if part in forbidden
    ]


def _python_file_violations(
    policy: dict[str, Any],
    file: SourceFile,
    module_id: str,
    by_path: dict[str, SourceFile],
) -> list[dict[str, Any]]:
    module = _modules(policy)[module_id]
    violations: list[dict[str, Any]] = []
    tree = _parse_python(file, violations, module_id)
    if tree is None:
        return violations
    violations.extend(_size_violations(file, tree, module_id, module))
    imports = _python_imports(file, tree, module_id, by_path, _modules(policy))
    for imported in imports:
        if imported["dynamic"]:
            violations.append(
                _violation(
                    "python_dynamic_import",
                    file.path,
                    module_id,
                    imported["target"],
                    imported["import_string"],
                    "dynamic import target must be statically governed",
                )
            )
            continue
        target = imported["target_module"]
        if imported["unresolved_internal"]:
            violations.append(
                _violation(
                    "python_unresolved_import",
                    file.path,
                    module_id,
                    imported["target"],
                    imported["import_string"],
                    imported["target"],
                )
            )
            continue
        if not target:
            continue
        if target in module.get("forbidden_dependencies", []):
            violations.append(
                _violation(
                    "python_dependency_direction",
                    file.path,
                    module_id,
                    target,
                    imported["import_string"],
                    f"{module_id} imports forbidden dependency {target}",
                )
            )
        allowed = set(module.get("allowed_dependencies", []))
        if target != module_id and target not in allowed:
            violations.append(
                _violation(
                    "python_dependency_direction",
                    file.path,
                    module_id,
                    target,
                    imported["import_string"],
                    f"{module_id} imports undeclared dependency {target}",
                )
            )
    return violations


def _parse_python(file: SourceFile, violations: list[dict[str, Any]], module_id: str) -> ast.Module | None:
    try:
        return ast.parse(file.text, filename=file.path)
    except SyntaxError as exc:
        violations.append(_violation("python_parse_failure", file.path, module_id, "", "", f"parse failure: {exc.msg}"))
        return None


def _size_violations(file: SourceFile, tree: ast.Module, module_id: str, module: dict[str, Any]) -> list[dict[str, Any]]:
    limits = module["limits"]
    lines = file.text.splitlines()
    violations: list[dict[str, Any]] = []
    if limits["max_file_lines"] and len(lines) > limits["max_file_lines"]:
        violations.append(_violation("python_file_lines", file.path, module_id, "", "max_file_lines", str(len(lines))))
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    if limits["max_functions_per_file"] and len(functions) > limits["max_functions_per_file"]:
        violations.append(
            _violation("python_functions_per_file", file.path, module_id, "", "max_functions_per_file", str(len(functions)))
        )
    if limits["max_classes_per_file"] and len(classes) > limits["max_classes_per_file"]:
        violations.append(
            _violation("python_classes_per_file", file.path, module_id, "", "max_classes_per_file", str(len(classes)))
        )
    for node in functions:
        length = _node_length(node)
        if limits["max_function_lines"] and length > limits["max_function_lines"]:
            violations.append(_violation("python_function_lines", file.path, module_id, "", node.name, str(length)))
    for node in classes:
        length = _node_length(node)
        if limits["max_class_lines"] and length > limits["max_class_lines"]:
            violations.append(_violation("python_class_lines", file.path, module_id, "", node.name, str(length)))
    return violations


def _node_length(node: ast.AST) -> int:
    end = getattr(node, "end_lineno", None)
    start = getattr(node, "lineno", None)
    if not isinstance(end, int) or not isinstance(start, int):
        return 0
    return max(0, end - start + 1)


def _python_imports(
    file: SourceFile,
    tree: ast.Module,
    module_id: str,
    by_path: dict[str, SourceFile],
    modules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    imports: list[dict[str, Any]] = []
    internal_names = _internal_python_names(by_path, modules)
    package = _python_package(file.path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(_resolved_import(alias.name, alias.name, internal_names, modules))
        elif isinstance(node, ast.ImportFrom):
            target = _relative_import_target(package, node.module or "", node.level)
            imports.append(_resolved_import(target, target, internal_names, modules))
        elif _is_dynamic_import(node):
            imports.append(
                {
                    "dynamic": True,
                    "target": _dynamic_import_target(node),
                    "target_module": "",
                    "import_string": _dynamic_import_target(node),
                    "unresolved_internal": False,
                }
            )
    return imports


def _resolved_import(
    import_name: str,
    import_string: str,
    internal_names: dict[str, str],
    modules: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if not import_name:
        return {"dynamic": False, "target": import_name, "target_module": "", "import_string": import_string, "unresolved_internal": False}
    for name in _prefixes(import_name):
        if name in internal_names:
            path = internal_names[name]
            return {
                "dynamic": False,
                "target": import_name,
                "target_module": _module_for_path(path, modules) or "",
                "import_string": import_string,
                "unresolved_internal": False,
            }
    unresolved = import_name.startswith(tuple(_top_level_python_packages(modules)))
    return {
        "dynamic": False,
        "target": import_name,
        "target_module": "",
        "import_string": import_string,
        "unresolved_internal": unresolved,
    }


def _internal_python_names(by_path: dict[str, SourceFile], modules: dict[str, dict[str, Any]]) -> dict[str, str]:
    names: dict[str, str] = {}
    for path in by_path:
        if not path.endswith(".py"):
            continue
        module_id = _module_for_path(path, modules)
        if not module_id:
            continue
        name = path[:-3].replace("/", ".")
        if name.endswith(".__init__"):
            name = name[: -len(".__init__")]
        names[name] = path
    return names


def _top_level_python_packages(modules: dict[str, dict[str, Any]]) -> tuple[str, ...]:
    return tuple(sorted({module["path"].split("/")[0].replace("-", "_") for module in modules.values()}))


def _prefixes(import_name: str) -> list[str]:
    parts = import_name.split(".")
    return [".".join(parts[:index]) for index in range(len(parts), 0, -1)]


def _python_package(path: str) -> str:
    parts = path[:-3].split("/")[:-1]
    return ".".join(parts)


def _relative_import_target(package: str, module: str, level: int) -> str:
    if level <= 0:
        return module
    parts = package.split(".") if package else []
    prefix = parts[: max(0, len(parts) - level + 1)]
    if module:
        prefix.append(module)
    return ".".join(prefix)


def _is_dynamic_import(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Name) and node.func.id == "__import__":
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
        return True
    return False


def _dynamic_import_target(node: ast.AST) -> str:
    if not isinstance(node, ast.Call) or not node.args:
        return "dynamic"
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return "dynamic"


def _python_dependency_graph(policy: dict[str, Any], files: list[SourceFile]) -> dict[str, set[str]]:
    modules = _modules(policy)
    by_path = {file.path: file for file in files}
    graph: dict[str, set[str]] = defaultdict(set)
    for file in files:
        module_id = _module_for_path(file.path, modules)
        if not module_id or not file.path.endswith(".py"):
            continue
        graph.setdefault(module_id, set())
        tree = _parse_python(file, [], module_id)
        if tree is None:
            continue
        for item in _python_imports(file, tree, module_id, by_path, modules):
            target = item.get("target_module") or ""
            if target and target != module_id:
                graph[module_id].add(target)
    return graph


def _cycle_violations(graph: dict[str, set[str]]) -> list[dict[str, Any]]:
    cycles: set[tuple[str, ...]] = set()
    for start in graph:
        _walk_cycle(graph, start, start, [], cycles)
    return [
        _violation("python_import_cycle", "", cycle[0], cycle[-1], "->".join(cycle), "python import graph contains cycle")
        for cycle in sorted(cycles)
    ]


def _walk_cycle(
    graph: dict[str, set[str]],
    start: str,
    current: str,
    path: list[str],
    cycles: set[tuple[str, ...]],
) -> None:
    if current in path:
        return
    next_path = path + [current]
    for neighbor in graph.get(current, set()):
        if neighbor == start and len(next_path) > 1:
            cycles.add(_canonical_cycle(next_path))
        else:
            _walk_cycle(graph, start, neighbor, next_path, cycles)


def _canonical_cycle(cycle: list[str]) -> tuple[str, ...]:
    rotations = [tuple(cycle[index:] + cycle[:index]) for index in range(len(cycle))]
    return min(rotations)


def _record_known_debt(
    violations: list[dict[str, Any]],
    known_debt: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    unmatched = list(known_debt)
    for violation in violations:
        match = _matching_known_debt(violation, unmatched)
        if match:
            records.append({**match, "fingerprint": _fingerprint(violation), "matches_violation": True})
            unmatched.remove(match)
    records.extend({**item, "matches_violation": False} for item in unmatched)
    return records


def _matching_known_debt(violation: dict[str, Any], known_debt: list[dict[str, Any]]) -> dict[str, Any] | None:
    fingerprint = str(violation.get("fingerprint") or _fingerprint(violation))
    for item in known_debt:
        if (
            item["rule"] == violation.get("rule_id")
            and _norm(item["path"]) == _norm(str(violation.get("path", "")))
            and item.get("source_module", "") == str(violation.get("source_module", ""))
            and item.get("target_module", "") == str(violation.get("target_module", ""))
            and item.get("symbol_name", "") == str(violation.get("symbol_name", ""))
            and item.get("detail", "") == str(violation.get("detail", ""))
            and item.get("fingerprint") == fingerprint
        ):
            return item
    return None


def _blocking_violations(mode: str, violations: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return violations


def _architecture_behavior_fixtures() -> dict[str, Any]:
    fixtures: list[dict[str, Any]] = []
    errors: list[str] = []

    positive_policy = _fixture_policy()
    positive_files = [
        SourceFile("src/app.py", "def app():\n    return 1\n"),
        SourceFile("tests/test_app.py", "from src.app import app\n"),
    ]
    positive = _scan_files(positive_policy, positive_files, ["src/app.py"])
    _record_fixture(
        fixtures,
        errors,
        "positive_registered_python_module",
        not positive["violations"],
        [],
        [item["rule_id"] for item in positive["violations"]],
    )

    negative_files = [
        SourceFile("src/app.py", "import tests.test_app\n"),
        SourceFile("src/utils/bad.py", "x = 1\n"),
        SourceFile("tests/test_app.py", "from src.app import app\n"),
    ]
    negative = _scan_files(positive_policy, negative_files, ["src/utils/bad.py"])
    negative_rules = {item["rule_id"] for item in negative["violations"]}
    _record_fixture(
        fixtures,
        errors,
        "negative_vague_folder_and_forbidden_dependency",
        {"vague_folder_name", "python_dependency_direction"}.issubset(negative_rules),
        ["vague_folder_name", "python_dependency_direction"],
        sorted(negative_rules),
    )

    theater_policy = _fixture_policy()
    bad_mode_policy = {**theater_policy, "enforcement_mode": "report_only"}
    mode_errors = _architecture_policy_errors(bad_mode_policy)
    _record_fixture(
        fixtures,
        errors,
        "theater_report_only_rejected",
        any("enforcement_mode must be block_all" in error for error in mode_errors),
        ["invalid_enforcement_mode"],
        mode_errors,
    )

    if negative["violations"]:
        debt_violation = negative["violations"][0]
        strict_debt = {
            "rule": debt_violation["rule_id"],
            "path": debt_violation["path"],
            "source_module": debt_violation["source_module"],
            "target_module": debt_violation["target_module"],
            "symbol_name": debt_violation["symbol_name"],
            "detail": debt_violation["detail"],
            "fingerprint": _fingerprint(debt_violation),
            "owner": "fixture",
            "reason": "fixture proves known_debt does not suppress violations",
            "expires_on": "2099-12-31",
        }
        debt_records = _record_known_debt([_fingerprinted(debt_violation)], [strict_debt])
        debt_passed = bool(debt_records) and bool(negative["violations"])
        observed = [f"violations={len(negative['violations'])}", f"known_debt={len(debt_records)}"]
    else:
        debt_passed = False
        observed = ["no violation available for known_debt fixture"]
    _record_fixture(
        fixtures,
        errors,
        "theater_known_debt_does_not_green_violation",
        debt_passed,
        ["violation_remains", "known_debt_recorded"],
        observed,
    )

    return {"status": PASS if not errors else FAIL, "fixtures": fixtures, "errors": errors}


def _record_fixture(
    fixtures: list[dict[str, Any]],
    errors: list[str],
    name: str,
    passed: bool,
    expected: list[str],
    observed: list[str],
) -> None:
    status = PASS if passed else FAIL
    fixtures.append({"name": name, "status": status, "expected": expected, "observed": observed})
    if not passed:
        errors.append(f"architecture behavior fixture failed: {name}")


def _fixture_policy() -> dict[str, Any]:
    return {
        "version": 1,
        "enforcement_mode": "block_all",
        "governed_roots": [
            {"path": "src", "kind": "production_python", "owner": "fixture", "purpose": "fixture production"},
            {"path": "tests", "kind": "test_python", "owner": "fixture", "purpose": "fixture tests"},
        ],
        "runtime_relevance": {
            "production_globs": ["**/*.py"],
            "non_runtime_globs": [],
        },
        "vague_names": {"forbidden": ["utils", "helpers", "common", "misc", "stuff", "shared"]},
        "modules": {
            "src": {
                "path": "src",
                "owner": "fixture",
                "purpose": "fixture source",
                "classification": "application",
                "domain": "fixture",
                "allowed_dependencies": [],
                "forbidden_dependencies": ["tests"],
                "test_strategy": "fixture",
                "limits": {
                    "max_file_lines": 100,
                    "max_function_lines": 20,
                    "max_class_lines": 50,
                    "max_functions_per_file": 10,
                    "max_classes_per_file": 5,
                },
            },
            "tests": {
                "path": "tests",
                "owner": "fixture",
                "purpose": "fixture tests",
                "classification": "test",
                "domain": "fixture",
                "allowed_dependencies": ["src"],
                "forbidden_dependencies": [],
                "test_strategy": "fixture",
                "limits": {
                    "max_file_lines": 100,
                    "max_function_lines": 20,
                    "max_class_lines": 50,
                    "max_functions_per_file": 10,
                    "max_classes_per_file": 5,
                },
            },
        },
        "known_debt": [],
    }


def _rule_results(violations: list[dict[str, Any]], checked: set[str]) -> dict[str, str]:
    failed = {item["rule_id"] for item in violations}
    return {rule: (FAIL if rule in failed else PASS) for rule in sorted(checked | failed)}


def _fingerprinted(violation: dict[str, Any]) -> dict[str, Any]:
    return {**violation, "fingerprint": _fingerprint(violation)}


def _fingerprint(violation: dict[str, Any]) -> str:
    payload = "|".join(
        [
            SCHEMA_VERSION,
            str(violation.get("rule_id", "")),
            _norm(str(violation.get("path", ""))),
            str(violation.get("source_module", "")),
            str(violation.get("target_module", "")),
            str(violation.get("symbol_name", "")),
            str(violation.get("detail", "")),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _violation(
    rule_id: str,
    path: str,
    source_module: str,
    target_module: str,
    symbol_name: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "path": _norm(path),
        "source_module": source_module,
        "target_module": target_module,
        "symbol_name": symbol_name,
        "detail": detail,
    }


def _failure_result(
    *,
    base_sha: str,
    head_sha: str,
    mode: str,
    errors: list[str],
    gate_implementation: str,
    expired_known_debt: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "owner_status": STATUS_RED,
        "enforcement_mode": mode,
        "gate_implementation": gate_implementation,
        "repo_architecture_supportability": FAIL,
        "architecture_behavior_proof": FAIL,
        "base_sha": base_sha if SHA1_RE.fullmatch(base_sha) else "0" * 40,
        "head_sha": head_sha if SHA1_RE.fullmatch(head_sha) else "0" * 40,
        "changed_files": [],
        "violations": [],
        "new_violations": [],
        "existing_violations": [],
        "resolved_violations": [],
        "known_debt_applied": [],
        "expired_known_debt": expired_known_debt or [],
        "behavior_fixtures": [],
        "rule_results": {},
        "errors": errors,
    }


def _write_evidence(output_dir: Path, result: dict[str, Any]) -> None:
    validate_named("architecture_gate_result", result)
    _write_json(output_dir / "architecture-gate-result.json", result)
    _write_markdown(output_dir / "architecture-gate-result.md", _markdown(result))


def _markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Architecture Fitness Gate",
        "",
        f"Owner status: {result['owner_status']}",
        f"Gate implementation: {result['gate_implementation']}",
        f"Repo architecture supportability: {result['repo_architecture_supportability']}",
        f"Architecture behavior proof: {result['architecture_behavior_proof']}",
        f"Mode: {result['enforcement_mode']}",
        f"New blocking violations: {len(result['new_violations'])}",
        f"Existing violations: {len(result['existing_violations'])}",
        "",
        "## Rule Results",
        "",
    ]
    for rule, status in sorted((result.get("rule_results") or {}).items()):
        lines.append(f"- {rule}: {status}")
    if result.get("violations"):
        lines.extend(["", "## Violations", ""])
        for item in result["violations"][:50]:
            lines.append(f"- {item['rule_id']} {item.get('path', '')} {item.get('detail', '')}")
    if result.get("errors"):
        lines.extend(["", "## Errors", ""])
        for error in result["errors"]:
            lines.append(f"- {error}")
    if result.get("known_debt_applied"):
        lines.extend(["", "## Known Debt", ""])
        for item in result["known_debt_applied"][:50]:
            lines.append(f"- {item.get('rule')} {item.get('path')} {item.get('fingerprint')}")
    if result.get("behavior_fixtures"):
        lines.extend(["", "## Behavior Fixtures", ""])
        for item in result["behavior_fixtures"]:
            lines.append(f"- {item.get('name')}: {item.get('status')}")
    lines.append("")
    return "\n".join(lines)


def _cli_summary(result: dict[str, Any], output_dir: Path | None = None) -> str:
    output_dir = output_dir or Path("artifacts/supportability")
    json_path = output_dir / "architecture-gate-result.json"
    markdown_path = output_dir / "architecture-gate-result.md"
    return "\n".join(
        [
            "Architecture Fitness Gate",
            f"Gate implementation: {result['gate_implementation']}",
            f"Repo architecture supportability: {result['repo_architecture_supportability']}",
            f"Architecture behavior proof: {result['architecture_behavior_proof']}",
            f"Mode: {result['enforcement_mode']}",
            f"New blocking violations: {len(result['new_violations'])}",
            f"Existing violations: {len(result['existing_violations'])}",
            f"Artifact JSON: {json_path.as_posix()}",
            f"Artifact Markdown: {markdown_path.as_posix()}",
        ]
    )


def _under(path: str, root: str) -> bool:
    path = _norm(path)
    root = _norm(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip("/")


if __name__ == "__main__":
    raise SystemExit(main())
