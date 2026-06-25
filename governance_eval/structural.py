from __future__ import annotations

import ast
import fnmatch
from collections import defaultdict
from pathlib import Path
from typing import Any


def scan_structural_metrics(root: Path, changed_files: set[str] | None = None) -> dict[str, Any]:
    src = root / "src"
    tests = root / "tests"
    py_files = sorted(path for path in src.rglob("*.py") if path.is_file()) if src.exists() else []
    test_files = sorted(path for path in tests.rglob("*.py") if path.is_file()) if tests.exists() else []
    graph = _import_graph(src)
    fanout = {module: len(imports) for module, imports in graph.items()}
    module_sizes = {
        _rel(path, root): {
            "lines": len(path.read_text(encoding="utf-8", errors="ignore").splitlines()),
            "function_count": _function_count(path),
        }
        for path in py_files
    }
    complexity = _complexity(py_files, root, changed_files or set())
    gate = _gate_config(root)
    return {
        "cross_module_private_references": _private_imports(py_files, root),
        "private_helper_reexports": _private_reexports(py_files, root),
        "tests_private_production_internals": _private_imports(test_files, root),
        "import_cycles": _cycles(graph),
        "weak_public_contracts": _weak_contracts(py_files, root),
        "module_dependency_fanout": {
            "max": max(fanout.values(), default=0),
            "over_threshold": sorted(module for module, count in fanout.items() if count > 12),
            "by_module": fanout,
        },
        "production_module_size_function_count": module_sizes,
        "large_typed_god_modules": sorted(path for path, data in module_sizes.items() if data["lines"] > 400 and data["function_count"] > 20),
        "touched_function_complexity": complexity,
        "gate_scope_or_threshold_weakening": gate,
        "duplicate_compatibility_surfaces": _duplicate_surfaces(py_files, root),
        "publicized_private_helper_renames": {
            "status": "UNKNOWN",
            "reason": "A reliable rename detector needs semantic symbol history beyond one checkout snapshot.",
        },
    }


def structural_delta(base: dict[str, Any], head: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in sorted(set(base) | set(head)):
        if _unknown(base.get(key)) or _unknown(head.get(key)):
            result[key] = {
                "base_count": 0,
                "head_count": 0,
                "existing": [],
                "introduced": [],
                "removed": [],
                "status": "UNKNOWN",
            }
            continue
        before = _identity_set(base.get(key))
        after = _identity_set(head.get(key))
        result[key] = {
            "base_count": len(before),
            "head_count": len(after),
            "existing": sorted(before & after),
            "introduced": sorted(after - before),
            "removed": sorted(before - after),
            "status": "MEASURED",
        }
    return result


def _unknown(value: Any) -> bool:
    return isinstance(value, dict) and value.get("status") == "UNKNOWN"


def _identity_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, dict):
        if "over_threshold" in value:
            return {str(item) for item in value["over_threshold"]}
        if "weakened" in value:
            return {str(item) for item in value["weakened"]}
        return {f"{key}:{val}" for key, val in value.items() if key != "by_module"}
    return {str(value)}


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))


def _private_imports(files: list[Path], root: Path) -> list[str]:
    refs: list[str] = []
    for path in files:
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if "._" in f".{module}" or any(alias.name.startswith("_") for alias in node.names):
                    refs.append(f"{_rel(path, root)}:{module}:{','.join(alias.name for alias in node.names)}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if "._" in f".{alias.name}":
                        refs.append(f"{_rel(path, root)}:{alias.name}")
    return sorted(refs)


def _private_reexports(files: list[Path], root: Path) -> list[str]:
    refs: list[str] = []
    for path in files:
        if path.stem.startswith("_") and path.name != "__init__.py":
            continue
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    refs.extend(f"{_rel(path, root)}:{item.value}" for item in node.value.elts if isinstance(item, ast.Constant) and isinstance(item.value, str) and item.value.startswith("_"))
    return sorted(refs)


def _weak_contracts(files: list[Path], root: Path) -> list[str]:
    refs: list[str] = []
    aliases: set[str] = set()
    for path in files:
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Subscript) and _name(node.value.value) in {"dict", "Dict"}:
                if "Any" in ast.unparse(node.value):
                    aliases.update(t.id for t in node.targets if isinstance(t, ast.Name))
            if isinstance(node, ast.ClassDef):
                bases = {ast.unparse(base) for base in node.bases}
                if "TypedDict" in bases:
                    for stmt in node.body:
                        if isinstance(stmt, ast.AnnAssign) and stmt.annotation and "Any" in ast.unparse(stmt.annotation):
                            refs.append(f"{_rel(path, root)}:{node.name}.Any")
            if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                annotations = [node.returns, *(arg.annotation for arg in node.args.args)]
                for annotation in annotations:
                    text = ast.unparse(annotation) if annotation else ""
                    if text in {"dict", "Dict"} or "dict[str, Any]" in text or text in aliases:
                        refs.append(f"{_rel(path, root)}:{node.name}:{text}")
    return sorted(set(refs))


def _import_graph(src: Path) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    if not src.exists():
        return {}
    for path in sorted(src.rglob("*.py")):
        module = path.relative_to(src).with_suffix("").as_posix().replace("/", ".")
        if module.endswith(".__init__"):
            module = module[: -len(".__init__")]
        graph.setdefault(module, set())
        try:
            tree = _parse(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                graph[module].add(node.module)
            elif isinstance(node, ast.Import):
                graph[module].update(alias.name for alias in node.names)
    return graph


def _cycles(graph: dict[str, set[str]]) -> list[str]:
    cycles: set[str] = set()
    for left, imports in graph.items():
        for right in imports:
            short = right.split(".")[-1]
            if short in graph and left in {item.split(".")[-1] for item in graph[short]}:
                cycles.add("->".join(sorted([left, short])))
    return sorted(cycles)


def _function_count(path: Path) -> int:
    try:
        tree = _parse(path)
    except SyntaxError:
        return 0
    return sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))


def _complexity(files: list[Path], root: Path, changed_files: set[str]) -> dict[str, Any]:
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
                score = 1 + sum(isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.BoolOp, ast.IfExp, ast.ExceptHandler)) for child in ast.walk(node))
                if score > 10:
                    over.append(f"{rel}:{node.name}:{score}")
    return {"over_threshold": sorted(over)}


def _gate_config(root: Path) -> dict[str, Any]:
    text = (root / "pyproject.toml").read_text(encoding="utf-8", errors="ignore") if (root / "pyproject.toml").exists() else ""
    weakened: list[str] = []
    if "max-complexity = " in text:
        for line in text.splitlines():
            if line.strip().startswith("max-complexity"):
                try:
                    if int(line.split("=", 1)[1].strip()) > 10:
                        weakened.append(line.strip())
                except ValueError:
                    weakened.append(line.strip())
    return {"weakened": weakened}


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


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
