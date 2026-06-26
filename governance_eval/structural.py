from __future__ import annotations

import ast
import fnmatch
import re
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_json


DEFAULT_THRESHOLDS = {
    "module_dependency_fanout": {"max_imports": 12},
    "production_module_size_function_count": {"max_lines": 400, "max_functions": 20},
    "large_typed_god_modules": {"max_lines": 400, "max_functions": 20},
    "touched_function_complexity": {"max_complexity": 10},
}


def scan_structural_metrics(
    root: Path,
    changed_files: set[str] | None = None,
    pack: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = _config(pack)
    prod_files = _python_files(root, config["production_roots"], config["source_globs"], config["ignore_globs"])
    test_files = _python_files(root, config["test_roots"], config["source_globs"], config["ignore_globs"])
    graph = _import_graph(root, prod_files, config["production_roots"])
    fanout_threshold = _threshold(pack, "module_dependency_fanout", "max_imports")
    size_lines = _threshold(pack, "production_module_size_function_count", "max_lines")
    size_functions = _threshold(pack, "production_module_size_function_count", "max_functions")
    typed_size_lines = _threshold(pack, "large_typed_god_modules", "max_lines")
    typed_size_functions = _threshold(pack, "large_typed_god_modules", "max_functions")
    complexity_threshold = _threshold(pack, "touched_function_complexity", "max_complexity")
    module_sizes = _module_sizes(prod_files, root)
    fanout = {module: len(imports) for module, imports in graph.items()}
    return {
        "cross_module_private_references": _private_imports(prod_files, root, include_attribute_access=True),
        "private_helper_reexports": _private_reexports(prod_files, root),
        "tests_private_production_internals": _private_imports(test_files, root, include_attribute_access=True),
        "import_cycles": _cycles(graph),
        "weak_public_contracts": _weak_contracts(prod_files, root),
        "module_dependency_fanout": {
            "max": max(fanout.values(), default=0),
            "threshold": fanout_threshold,
            "over_threshold": sorted(module for module, count in fanout.items() if count > fanout_threshold),
            "by_module": fanout,
        },
        "production_module_size_function_count": {
            "threshold": {"max_lines": size_lines, "max_functions": size_functions},
            "over_threshold": sorted(
                path
                for path, data in module_sizes.items()
                if data["lines"] > size_lines or data["function_count"] > size_functions
            ),
            "by_module": module_sizes,
        },
        "large_typed_god_modules": sorted(
            path
            for path, data in module_sizes.items()
            if data["lines"] > typed_size_lines
            and data["function_count"] > typed_size_functions
            and data["has_typing"]
        ),
        "touched_function_complexity": _complexity(prod_files, root, changed_files or set(), complexity_threshold),
        "gate_scope_or_threshold_weakening": _gate_config(root, pack),
        "duplicate_compatibility_surfaces": _duplicate_surfaces(prod_files, root),
        "publicized_private_helper_renames": _function_body_index(prod_files, root),
    }


def structural_delta(
    base: dict[str, Any],
    head: dict[str, Any],
    pack: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    policies = _detector_policies(pack)
    keys = sorted(set(base) | set(head) | set(policies))
    for key in keys:
        policy = policies.get(key, _default_policy(key))
        threshold = _policy_threshold(policy, key)
        before_value = base.get(key)
        after_value = head.get(key)
        if key == "gate_scope_or_threshold_weakening":
            result[key] = _gate_delta(before_value, after_value, policy, threshold)
            continue
        if key == "publicized_private_helper_renames":
            result[key] = _rename_delta(before_value, after_value, policy, threshold)
            continue
        if _unknown(before_value) or _unknown(after_value) or before_value is None or after_value is None:
            result[key] = _unknown_delta(policy, threshold, _unknown_reason(before_value, after_value))
            continue
        before = _identity_set(before_value)
        after = _identity_set(after_value)
        result[key] = {
            "status": "MEASURED",
            "base_count": len(before),
            "head_count": len(after),
            "existing": sorted(before & after),
            "introduced": sorted(after - before),
            "removed": sorted(before - after),
            "threshold": threshold,
            "policy": policy,
            "evidence": {"base": _evidence_sample(before_value), "head": _evidence_sample(after_value)},
            "reason": "",
        }
    return result


def _config(pack: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "production_roots": list((pack or {}).get("production_roots") or ["src"]),
        "test_roots": list((pack or {}).get("test_roots") or ["tests"]),
        "source_globs": list((pack or {}).get("source_globs") or ["**/*.py"]),
        "ignore_globs": list((pack or {}).get("ignore_globs") or []),
    }


def _detector_policies(pack: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    configured = (pack or {}).get("detector_policies") or {}
    return {name: _normalize_policy(name, policy) for name, policy in configured.items()}


def _normalize_policy(name: str, policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "required": bool(policy.get("required", False)),
        "blocking": bool(policy.get("blocking", False)),
        "fail_on_unknown": bool(policy.get("fail_on_unknown", False)),
        "thresholds": dict(policy.get("thresholds") or DEFAULT_THRESHOLDS.get(name, {})),
    }


def _default_policy(name: str) -> dict[str, Any]:
    return {
        "required": False,
        "blocking": False,
        "fail_on_unknown": False,
        "thresholds": dict(DEFAULT_THRESHOLDS.get(name, {})),
    }


def _threshold(pack: dict[str, Any] | None, detector: str, key: str) -> int:
    policy = _detector_policies(pack).get(detector, _default_policy(detector))
    return int(policy.get("thresholds", {}).get(key, DEFAULT_THRESHOLDS.get(detector, {}).get(key, 0)))


def _policy_threshold(policy: dict[str, Any], detector: str) -> dict[str, Any]:
    return dict(policy.get("thresholds") or DEFAULT_THRESHOLDS.get(detector, {}))


def _python_files(root: Path, roots: list[str], source_globs: list[str], ignore_globs: list[str]) -> list[Path]:
    files: set[Path] = set()
    for relative_root in roots:
        search_root = root / relative_root
        if not search_root.exists():
            continue
        if search_root.is_file():
            candidates = [search_root]
        else:
            candidates = [path for path in search_root.rglob("*.py") if path.is_file()]
        for path in candidates:
            rel = _rel(path, root)
            if not any(fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(path.name, glob) for glob in source_globs):
                continue
            if any(fnmatch.fnmatch(rel, glob) for glob in ignore_globs):
                continue
            files.add(path)
    return sorted(files)


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))


def _module_for_path(path: Path, root: Path, production_roots: list[str]) -> str:
    best_root: Path | None = None
    for item in production_roots:
        candidate = root / item
        try:
            path.relative_to(candidate)
        except ValueError:
            continue
        if best_root is None or len(str(candidate)) > len(str(best_root)):
            best_root = candidate
    base = best_root or root
    module = path.relative_to(base).with_suffix("").as_posix().replace("/", ".")
    if module.endswith(".__init__"):
        module = module[: -len(".__init__")]
    if module == "__init__":
        module = path.parent.name
    return module


def _import_graph(root: Path, files: list[Path], production_roots: list[str]) -> dict[str, set[str]]:
    modules = {_module_for_path(path, root, production_roots): path for path in files}
    module_names = set(modules)
    graph: dict[str, set[str]] = defaultdict(set)
    for module, path in sorted(modules.items()):
        graph.setdefault(module, set())
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = _internal_module(alias.name, module_names)
                    if target:
                        graph[module].add(target)
            elif isinstance(node, ast.ImportFrom):
                for target in _import_from_targets(node, module, module_names):
                    graph[module].add(target)
    return graph


def _import_from_targets(node: ast.ImportFrom, current_module: str, module_names: set[str]) -> set[str]:
    if node.level:
        package_parts = current_module.split(".")[:-node.level]
        base = ".".join(part for part in package_parts if part)
        if node.module:
            base = ".".join(part for part in [base, node.module] if part)
    else:
        base = node.module or ""
    candidates = {base} if base else set()
    for alias in node.names:
        if alias.name == "*":
            continue
        candidates.add(".".join(part for part in [base, alias.name] if part))
    return {resolved for item in candidates if (resolved := _internal_module(item, module_names))}


def _internal_module(name: str, module_names: set[str]) -> str | None:
    if not name:
        return None
    parts = name.split(".")
    for end in range(len(parts), 0, -1):
        candidate = ".".join(parts[:end])
        if candidate in module_names:
            return candidate
    return None


def _cycles(graph: dict[str, set[str]]) -> list[str]:
    index = 0
    stack: list[str] = []
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(graph.get(node, set())):
            if target not in indexes:
                strongconnect(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[target])
        if lowlinks[node] == indexes[node]:
            component: list[str] = []
            while True:
                item = stack.pop()
                on_stack.remove(item)
                component.append(item)
                if item == node:
                    break
            if len(component) > 1 or node in graph.get(node, set()):
                components.append(sorted(component))

    for node in sorted(graph):
        if node not in indexes:
            strongconnect(node)
    return sorted("->".join(component + [component[0]]) for component in components)


def _private_imports(files: list[Path], root: Path, include_attribute_access: bool) -> list[str]:
    refs: set[str] = set()
    for path in files:
        rel = _rel(path, root)
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        imported_aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                module_private = any(part.startswith("_") for part in module.split(".") if part)
                for alias in node.names:
                    local = alias.asname or alias.name
                    imported_aliases[local] = ".".join(part for part in [module, alias.name] if part)
                    if module_private or alias.name.startswith("_"):
                        refs.add(f"{rel}:{module}:{alias.name}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    imported_aliases[local] = alias.name
                    if any(part.startswith("_") for part in alias.name.split(".")):
                        refs.add(f"{rel}:{alias.name}")
        if include_attribute_access:
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    chain = _attribute_chain(node)
                    if len(chain) >= 2 and chain[0] in imported_aliases and any(part.startswith("_") for part in chain[1:]):
                        refs.add(f"{rel}:{'.'.join(chain)}")
    return sorted(refs)


def _private_reexports(files: list[Path], root: Path) -> list[str]:
    refs: set[str] = set()
    for path in files:
        if path.stem.startswith("_") and path.name != "__init__.py":
            continue
        rel = _rel(path, root)
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        private_names: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                module_private = any(part.startswith("_") for part in module.split(".") if part)
                for alias in node.names:
                    local = alias.asname or alias.name
                    if module_private or alias.name.startswith("_"):
                        private_names.add(local)
                    if not local.startswith("_") and (module_private or alias.name.startswith("_")):
                        refs.add(f"{rel}:alias:{module}.{alias.name}->{local}")
            elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for item in node.value.elts:
                        if isinstance(item, ast.Constant) and isinstance(item.value, str) and item.value.startswith("_"):
                            refs.add(f"{rel}:__all__:{item.value}")
            elif isinstance(node, ast.Assign):
                value_name = _expr_name(node.value)
                value_private = value_name.startswith("_") or "._" in value_name or value_name in private_names
                if value_private:
                    for target in node.targets:
                        if isinstance(target, ast.Name) and not target.id.startswith("_"):
                            refs.add(f"{rel}:rebinding:{value_name}->{target.id}")
    return sorted(refs)


def _weak_contracts(files: list[Path], root: Path) -> list[str]:
    refs: set[str] = set()
    aliases: set[str] = set()
    for path in files:
        rel = _rel(path, root)
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = getattr(node, "value", None)
                targets = [node.target] if isinstance(node, ast.AnnAssign) else list(getattr(node, "targets", []))
                text = ast.unparse(value) if value is not None else ""
                if _is_weak_type_text(text):
                    for target in targets:
                        if isinstance(target, ast.Name):
                            aliases.add(target.id)
                            refs.add(f"{rel}:alias:{target.id}:{text}")
            if isinstance(node, ast.ClassDef):
                bases = {ast.unparse(base) for base in node.bases}
                if any(base.endswith("TypedDict") or base == "TypedDict" for base in bases):
                    for stmt in node.body:
                        annotation = getattr(stmt, "annotation", None)
                        if annotation is not None and "Any" in ast.unparse(annotation):
                            refs.add(f"{rel}:{node.name}.Any")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                annotations = [node.returns, *(arg.annotation for arg in node.args.args)]
                for annotation in annotations:
                    text = ast.unparse(annotation) if annotation else ""
                    if _is_weak_type_text(text) or text in aliases:
                        refs.add(f"{rel}:{node.name}:{text}")
    return sorted(refs)


def _is_weak_type_text(text: str) -> bool:
    compact = text.replace(" ", "")
    return (
        text in {"dict", "Dict", "Any"}
        or "dict[str,Any]" in compact
        or "Dict[str,Any]" in compact
        or compact.endswith("=dict[str,Any]")
        or compact.endswith("=Dict[str,Any]")
    )


def _module_sizes(files: list[Path], root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        result[_rel(path, root)] = {
            "lines": len(text.splitlines()),
            "function_count": _function_count(path),
            "has_typing": "TypedDict" in text or "typing" in text,
        }
    return result


def _function_count(path: Path) -> int:
    try:
        tree = _parse(path)
    except SyntaxError:
        return 0
    return sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))


def _complexity(files: list[Path], root: Path, changed_files: set[str], threshold: int) -> dict[str, Any]:
    over: list[str] = []
    for path in files:
        rel = _rel(path, root)
        if changed_files and rel not in changed_files:
            continue
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                score = 1 + sum(
                    isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.BoolOp, ast.IfExp, ast.ExceptHandler))
                    for child in ast.walk(node)
                )
                if score > threshold:
                    over.append(f"{rel}:{node.name}:{score}")
    return {"threshold": threshold, "over_threshold": sorted(over)}


def _gate_config(root: Path, pack: dict[str, Any] | None) -> dict[str, Any]:
    contract = (pack or {}).get("gate_contract") or {}
    required_files = list(contract.get("required_files") or [])
    if not required_files:
        required_files = ["pyproject.toml", ".github/workflows"]
    try:
        return _sets_to_lists({
            "status": "MEASURED",
            "required_files": required_files,
            "governed_roots": list(contract.get("governed_roots") or []),
            "required_commands": list(contract.get("required_commands") or []),
            "pyproject": _parse_pyproject(root / "pyproject.toml"),
            "workflows": _parse_workflows(root / ".github" / "workflows"),
            "files": {relative: (root / relative).exists() for relative in required_files if not relative.endswith("/")},
            "command_text": _gate_text(root, required_files),
        })
    except Exception as exc:
        return {"status": "UNKNOWN", "reason": f"gate contract parsing failed: {type(exc).__name__}: {exc}"}


def _parse_pyproject(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"present": False}
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
    ruff = data.get("tool", {}).get("ruff", {})
    lint = ruff.get("lint", {})
    mypy = data.get("tool", {}).get("mypy", {})
    pytest = data.get("tool", {}).get("pytest", {}).get("ini_options", {})
    coverage = data.get("tool", {}).get("coverage", {})
    return {
        "present": True,
        "ruff_select": _as_set(lint.get("select") or ruff.get("select")),
        "ruff_ignore": _as_set(lint.get("ignore") or ruff.get("ignore")),
        "ruff_include": _as_set(ruff.get("include")),
        "ruff_extend_include": _as_set(ruff.get("extend-include")),
        "ruff_exclude": _as_set(ruff.get("exclude")) | _as_set(ruff.get("extend-exclude")),
        "ruff_per_file_ignores": set((lint.get("per-file-ignores") or {}).keys()),
        "ruff_max_complexity": _int_or_none(lint.get("mccabe", {}).get("max-complexity") or ruff.get("max-complexity")),
        "mypy_files": _as_set(mypy.get("files")),
        "mypy_exclude": _as_set(mypy.get("exclude")),
        "pytest_testpaths": _as_set(pytest.get("testpaths")),
        "pytest_addopts": str(pytest.get("addopts") or ""),
        "coverage_source": _as_set(coverage.get("run", {}).get("source")),
        "coverage_omit": _as_set(coverage.get("run", {}).get("omit")),
    }


def _parse_workflows(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "present": False,
            "jobs": set(),
            "steps": set(),
            "continue_on_error": set(),
            "paths": set(),
            "paths_ignore": set(),
        }
    jobs: set[str] = set()
    steps: set[str] = set()
    continue_on_error: set[str] = set()
    paths: set[str] = set()
    paths_ignore: set[str] = set()
    for file in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
        text = file.read_text(encoding="utf-8", errors="ignore")
        in_jobs = False
        current_job = ""
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if re.match(r"^jobs:\s*$", line):
                in_jobs = True
                continue
            if in_jobs:
                job = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
                if job:
                    current_job = job.group(1)
                    jobs.add(f"{file.name}:{current_job}")
            step = re.search(r"name:\s*['\"]?([^'\"]+?)['\"]?\s*$", line)
            if step:
                steps.add(f"{file.name}:{current_job}:{step.group(1).strip()}")
            if "continue-on-error:" in line and "true" in line.lower():
                continue_on_error.add(f"{file.name}:{current_job}")
            match = re.search(r"\b(paths-ignore|paths):\s*(.*)$", line)
            if match:
                key = match.group(1)
                values = _workflow_path_values(lines, index, match.group(2))
                target = paths_ignore if key == "paths-ignore" else paths
                for value in values:
                    target.add(f"{file.name}:{value}")
    return {
        "present": True,
        "jobs": jobs,
        "steps": steps,
        "continue_on_error": continue_on_error,
        "paths": paths,
        "paths_ignore": paths_ignore,
    }


def _workflow_path_values(lines: list[str], index: int, inline: str) -> set[str]:
    values: set[str] = set()
    if inline.strip():
        text = inline.strip()
        if text.startswith("[") and text.endswith("]"):
            for item in text.strip("[]").split(","):
                cleaned = item.strip().strip("'\"")
                if cleaned:
                    values.add(cleaned)
        return values or {text.strip("'\"")}
    base_indent = len(lines[index]) - len(lines[index].lstrip(" "))
    for line in lines[index + 1 :]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent <= base_indent:
            break
        if stripped.startswith("- "):
            values.add(stripped[2:].strip().strip("'\""))
        elif ":" in stripped and not stripped.startswith("#"):
            break
    return values


def _gate_text(root: Path, required_files: list[str]) -> str:
    chunks: list[str] = []
    for relative in required_files:
        path = root / relative
        if path.is_file():
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
        elif path.is_dir():
            for file in sorted(path.rglob("*")):
                if file.is_file():
                    chunks.append(file.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(chunks)


def _gate_delta(base: Any, head: Any, policy: dict[str, Any], threshold: dict[str, Any]) -> dict[str, Any]:
    if _unknown(base) or _unknown(head) or not isinstance(base, dict) or not isinstance(head, dict):
        return _unknown_delta(policy, threshold, _unknown_reason(base, head))
    introduced: set[str] = set()
    removed: set[str] = set()
    for file, present in (base.get("files") or {}).items():
        if present and not (head.get("files") or {}).get(file, False):
            introduced.add(f"required_file_removed:{file}")
    before_py = base.get("pyproject") or {}
    after_py = head.get("pyproject") or {}
    introduced |= _removed_items("ruff.select", before_py.get("ruff_select"), after_py.get("ruff_select"))
    introduced |= _include_narrowing("ruff.include", before_py.get("ruff_include"), after_py.get("ruff_include"))
    introduced |= _removed_items("ruff.extend-include", before_py.get("ruff_extend_include"), after_py.get("ruff_extend_include"))
    introduced |= _added_items("ruff.ignore", before_py.get("ruff_ignore"), after_py.get("ruff_ignore"))
    introduced |= _added_items("ruff.exclude", before_py.get("ruff_exclude"), after_py.get("ruff_exclude"))
    introduced |= _added_items("ruff.per-file-ignores", before_py.get("ruff_per_file_ignores"), after_py.get("ruff_per_file_ignores"))
    introduced |= _added_items("mypy.exclude", before_py.get("mypy_exclude"), after_py.get("mypy_exclude"))
    introduced |= _removed_items("mypy.files", before_py.get("mypy_files"), after_py.get("mypy_files"))
    introduced |= _removed_items("pytest.testpaths", before_py.get("pytest_testpaths"), after_py.get("pytest_testpaths"))
    introduced |= _added_items("coverage.omit", before_py.get("coverage_omit"), after_py.get("coverage_omit"))
    introduced |= _removed_items("coverage.source", before_py.get("coverage_source"), after_py.get("coverage_source"))
    if before_py.get("pytest_addopts") and not after_py.get("pytest_addopts"):
        introduced.add("pytest.addopts_removed")
    before_complexity = before_py.get("ruff_max_complexity")
    after_complexity = after_py.get("ruff_max_complexity")
    if before_complexity is not None and after_complexity is not None and after_complexity > before_complexity:
        introduced.add(f"ruff.max-complexity:{before_complexity}->{after_complexity}")
    before_wf = base.get("workflows") or {}
    after_wf = head.get("workflows") or {}
    introduced |= _removed_items("workflow.job", before_wf.get("jobs"), after_wf.get("jobs"))
    introduced |= _removed_items("workflow.step", before_wf.get("steps"), after_wf.get("steps"))
    introduced |= _added_items("workflow.continue-on-error", before_wf.get("continue_on_error"), after_wf.get("continue_on_error"))
    introduced |= _workflow_paths_narrowing(before_wf.get("paths"), after_wf.get("paths"))
    introduced |= _added_items("workflow.paths-ignore", before_wf.get("paths_ignore"), after_wf.get("paths_ignore"))
    text = head.get("command_text") or ""
    for command in head.get("required_commands") or []:
        if command and command not in text:
            introduced.add(f"required_command_missing:{command}")
    for governed_root in head.get("governed_roots") or []:
        if governed_root and governed_root not in text:
            introduced.add(f"governed_root_missing_from_gates:{governed_root}")
    return {
        "status": "MEASURED",
        "base_count": 0,
        "head_count": len(introduced),
        "existing": [],
        "introduced": sorted(introduced),
        "removed": sorted(removed),
        "threshold": threshold,
        "policy": policy,
        "evidence": {"base": _sets_to_lists(base), "head": _sets_to_lists(head)},
        "reason": "",
    }


def _rename_delta(base: Any, head: Any, policy: dict[str, Any], threshold: dict[str, Any]) -> dict[str, Any]:
    if _unknown(base) or _unknown(head) or not isinstance(base, dict) or not isinstance(head, dict):
        return _unknown_delta(policy, threshold, _unknown_reason(base, head))
    before = base.get("function_bodies") or []
    after = head.get("function_bodies") or []
    before_private = {
        item["body_hash"]: item
        for item in before
        if item.get("is_private") and not item.get("name", "").startswith("__")
    }
    before_names_by_hash: dict[str, set[str]] = defaultdict(set)
    after_names_by_hash: dict[str, set[str]] = defaultdict(set)
    for item in before:
        before_names_by_hash[item["body_hash"]].add(item["name"])
    for item in after:
        after_names_by_hash[item["body_hash"]].add(item["name"])
    introduced: set[str] = set()
    for item in after:
        name = item.get("name", "")
        if name.startswith("_"):
            continue
        prior = before_private.get(item.get("body_hash"))
        if (
            prior
            and prior.get("name", "").lstrip("_") == name
            and prior["name"] not in after_names_by_hash[item["body_hash"]]
            and name not in before_names_by_hash[item["body_hash"]]
        ):
            introduced.add(f"{item['path']}:{prior['name']}->{name}")
    return {
        "status": "MEASURED",
        "base_count": len(before_private),
        "head_count": len(introduced),
        "existing": [],
        "introduced": sorted(introduced),
        "removed": [],
        "threshold": threshold,
        "policy": policy,
        "evidence": {"base": before[:20], "head": after[:20]},
        "reason": "",
    }


def _function_body_index(files: list[Path], root: Path) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for path in files:
        try:
            tree = _parse(path)
        except SyntaxError:
            return {"status": "UNKNOWN", "reason": f"syntax error in {_rel(path, root)}"}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body_dump = ast.dump(node.args, include_attributes=False) + ast.dump(
                    ast.Module(body=node.body, type_ignores=[]),
                    include_attributes=False,
                )
                items.append(
                    {
                        "path": _rel(path, root),
                        "name": node.name,
                        "is_private": node.name.startswith("_"),
                        "body_hash": sha256_json(body_dump),
                    }
                )
    return {"status": "MEASURED", "function_bodies": sorted(items, key=lambda item: (item["path"], item["name"]))}


def _duplicate_surfaces(files: list[Path], root: Path) -> list[str]:
    names: dict[str, list[str]] = defaultdict(list)
    for path in files:
        if not any(token in path.name.lower() for token in ("compat", "legacy", "wrapper", "shim")):
            continue
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                names[node.name].append(_rel(path, root))
    return sorted(f"{name}:{','.join(paths)}" for name, paths in names.items() if len(paths) > 1)


def _identity_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, set):
        return {str(item) for item in value}
    if isinstance(value, dict):
        if "over_threshold" in value:
            return {str(item) for item in value["over_threshold"]}
        if "weakened" in value:
            return {str(item) for item in value["weakened"]}
        if value.get("status") == "MEASURED" and "function_bodies" in value:
            return set()
        return {f"{key}:{val}" for key, val in _sets_to_lists(value).items() if key not in {"by_module", "threshold"}}
    return {str(value)}


def _unknown(value: Any) -> bool:
    return isinstance(value, dict) and value.get("status") in {"UNKNOWN", "UNSUPPORTED"}


def _unknown_delta(policy: dict[str, Any], threshold: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "base_count": 0,
        "head_count": 0,
        "existing": [],
        "introduced": [],
        "removed": [],
        "threshold": threshold,
        "policy": policy,
        "evidence": {},
        "reason": reason,
    }


def _unknown_reason(base: Any, head: Any) -> str:
    for value in (base, head):
        if isinstance(value, dict) and value.get("reason"):
            return str(value["reason"])
    if base is None or head is None:
        return "detector result missing"
    return "detector result unavailable"


def _evidence_sample(value: Any) -> Any:
    value = _sets_to_lists(value)
    if isinstance(value, list):
        return value[:20]
    if isinstance(value, dict):
        return {key: value[key] for key in sorted(value)[:20]}
    return value


def _sets_to_lists(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {key: _sets_to_lists(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sets_to_lists(item) for item in value]
    return value


def _as_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, tuple):
        return {str(item) for item in value}
    return {str(value)}


def _removed_items(prefix: str, before: Any, after: Any) -> set[str]:
    before_set = set(before or set())
    after_set = set(after or set())
    return {f"{prefix}_removed:{item}" for item in sorted(before_set - after_set)}


def _added_items(prefix: str, before: Any, after: Any) -> set[str]:
    before_set = set(before or set())
    after_set = set(after or set())
    return {f"{prefix}_added:{item}" for item in sorted(after_set - before_set)}


def _include_narrowing(prefix: str, before: Any, after: Any) -> set[str]:
    before_set = set(before or set())
    after_set = set(after or set())
    if not before_set and after_set:
        return {f"{prefix}_narrowed:{item}" for item in sorted(after_set)}
    return _removed_items(prefix, before_set, after_set)


def _workflow_paths_narrowing(before: Any, after: Any) -> set[str]:
    before_set = set(before or set())
    after_set = set(after or set())
    if not before_set and after_set:
        return {f"workflow.paths_added:{item}" for item in sorted(after_set)}
    return _removed_items("workflow.paths", before_set, after_set)


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _attribute_chain(node: ast.AST) -> list[str]:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return list(reversed(parts))


def _expr_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return ".".join(_attribute_chain(node))
    try:
        return ast.unparse(node)
    except Exception:
        return ""
