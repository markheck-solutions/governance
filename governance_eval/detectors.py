from __future__ import annotations

import ast
import fnmatch
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from governance_eval.models import DetectorEvidence, EvidenceStatus, ReviewFinding
from governance_eval.lock import read_target_lock, validate_target_lock
from governance_eval.paths import repo_root

Detector = Callable[[dict[str, Any], Path], DetectorEvidence]


def run_detectors(case: dict[str, Any], root: Path) -> list[DetectorEvidence]:
    fixture_path = root / case["fixture_path"]
    evidence: list[DetectorEvidence] = []
    for detector_id in case["detectors"]:
        detector = DETECTORS.get(detector_id)
        if detector is None:
            evidence.append(_unverifiable(case, detector_id, f"unknown detector {detector_id!r}"))
            continue
        try:
            evidence.append(detector(case, fixture_path))
        except (OSError, json.JSONDecodeError, SyntaxError, ValueError, KeyError, TypeError, IndexError) as exc:
            evidence.append(_malformed(case, detector_id, str(exc)))
    return evidence


def _evidence_id(case: dict[str, Any], detector_id: str) -> str:
    return f"{case['id']}::{detector_id}"


def _unverifiable(case: dict[str, Any], detector_id: str, message: str) -> DetectorEvidence:
    return DetectorEvidence(
        evidence_id=_evidence_id(case, detector_id),
        case_id=case["id"],
        detector_id=detector_id,
        status=EvidenceStatus.UNVERIFIABLE,
        message=message,
    )


def _malformed(case: dict[str, Any], detector_id: str, message: str) -> DetectorEvidence:
    return DetectorEvidence(
        evidence_id=_evidence_id(case, detector_id),
        case_id=case["id"],
        detector_id=detector_id,
        status=EvidenceStatus.MALFORMED,
        message=message,
    )


def detect_route_interleaving(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    data = _read_json(fixture_path / "behavior.json")
    expected = data["expected_sequence"]
    rows = data["rows"]
    strategy = data["candidate_strategy"]
    actual = _route_sequence(rows, strategy)
    if actual == expected:
        return DetectorEvidence(
            evidence_id=_evidence_id(case, "route_interleaving"),
            case_id=case["id"],
            detector_id="route_interleaving",
            status=EvidenceStatus.PASS,
            message="route order matched approved oracle",
            observed={"expected_sequence": expected, "actual_sequence": actual, "strategy": strategy},
        )
    finding = ReviewFinding(
        id=f"{case['id']}-F001",
        severity="P2",
        category="behavior_regression",
        message="partial metadata route order diverged from approved interleaving",
        evidence_id=_evidence_id(case, "route_interleaving"),
    )
    return DetectorEvidence(
        evidence_id=_evidence_id(case, "route_interleaving"),
        case_id=case["id"],
        detector_id="route_interleaving",
        status=EvidenceStatus.FAIL,
        message="route order mismatch reproduced",
        observed={"expected_sequence": expected, "actual_sequence": actual, "strategy": strategy},
        findings=(finding,),
    )


def detect_target_lock(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    root = repo_root(fixture_path)
    lock_path = root / case["target_lock_path"]
    pack_path = root / case["target_pack_path"]
    problems = validate_target_lock(lock_path, pack_path, root=root)
    if problems:
        return DetectorEvidence(
            evidence_id=_evidence_id(case, "target_lock"),
            case_id=case["id"],
            detector_id="target_lock",
            status=EvidenceStatus.UNVERIFIABLE,
            message="target lock invalid",
            observed={"problems": problems, "path": str(lock_path)},
        )
    lock = read_target_lock(lock_path)
    return DetectorEvidence(
        evidence_id=_evidence_id(case, "target_lock"),
        case_id=case["id"],
        detector_id="target_lock",
        status=EvidenceStatus.PASS,
        message="target evidence pinned to exact immutable revisions",
        observed=lock.to_json(),
    )


def _route_sequence(rows: list[dict[str, Any]], strategy: str) -> list[str]:
    if strategy == "preserve_interleaving":
        ordered = sorted(rows, key=lambda row: row["original_position"])
    elif strategy == "ranked_first":
        ordered = sorted(
            rows,
            key=lambda row: (
                row["metadata_rank"] is None,
                row["metadata_rank"] if row["metadata_rank"] is not None else row["original_position"],
                row["original_position"],
            ),
        )
    else:
        raise ValueError(f"unknown route strategy {strategy!r}")
    return [row["id"] for row in ordered]


def detect_private_reexport(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    findings: list[ReviewFinding] = []
    for path in _python_files(fixture_path / "src"):
        if path.stem.startswith("_") and path.name != "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        exported_names = _exported_names(tree)
        private_imports = _imports_from_private_modules(tree)
        explicit_private_exports = exported_names & set(private_imports)
        package_exports = set(private_imports) if path.name == "__init__.py" else set()
        for name in sorted(explicit_private_exports | package_exports):
            findings.append(_finding(case, "private_reexport", "P2", "private_helper_reexport", path, name))
    return _structural_evidence(case, "private_reexport", findings, "public API exports no private helpers")


def detect_private_test_dependency(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    findings: list[ReviewFinding] = []
    for path in _python_files(fixture_path / "tests"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                imported = {alias.name for alias in node.names}
                if "._" in f".{module}" or any(name.startswith("_") for name in imported):
                    findings.append(
                        _finding(case, "private_test_dependency", "P2", "test_private_dependency", path, module)
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if "._" in f".{alias.name}":
                        findings.append(
                            _finding(case, "private_test_dependency", "P2", "test_private_dependency", path, alias.name)
                        )
    return _structural_evidence(case, "private_test_dependency", findings, "tests use public production API only")


def detect_import_cycle(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    graph = _import_graph(fixture_path / "src" / "app")
    cycle = _find_cycle(graph)
    findings: list[ReviewFinding] = []
    if cycle:
        findings.append(
            ReviewFinding(
                id=f"{case['id']}-import_cycle-F001",
                severity="P2",
                category="import_cycle",
                message=f"import cycle detected: {' -> '.join(cycle)}",
                evidence_id=_evidence_id(case, "import_cycle"),
            )
        )
    return _structural_evidence(case, "import_cycle", findings, "import graph is acyclic", {"graph": graph})


def detect_untyped_dict_boundary(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    findings: list[ReviewFinding] = []
    for path in _python_files(fixture_path / "src"):
        if path.stem.startswith("_") and path.name != "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                if node.args.vararg:
                    arguments.append(node.args.vararg)
                if node.args.kwarg:
                    arguments.append(node.args.kwarg)
                if _is_raw_dict_annotation(node.returns) or any(
                    _is_raw_dict_annotation(arg.annotation) for arg in arguments
                ):
                    findings.append(
                        _finding(case, "untyped_public_dict", "P2", "untyped_public_boundary", path, node.name)
                    )
    return _structural_evidence(case, "untyped_public_dict", findings, "public API avoids raw dict boundaries")


def detect_gate_scope(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    data = _read_json(fixture_path / "governance_gates.json")
    gates = data["gates"]
    required_files = sorted(set(data["changed_files"] + data["high_risk_files"]))
    required_gate_names = data.get("required_gate_names") or [gate.get("name") for gate in gates]
    gates_by_name = {gate.get("name"): gate for gate in gates if isinstance(gate.get("name"), str)}
    missing_coverage = [
        {"path": path, "gate": gate_name}
        for path in required_files
        for gate_name in required_gate_names
        if gate_name not in gates_by_name or not _covered_by_gate(path, gates_by_name[gate_name])
    ]
    uncovered = sorted({item["path"] for item in missing_coverage})
    findings = [
        ReviewFinding(
            id=f"{case['id']}-gate_scope-{index:03d}",
            severity="P1",
            category="narrowed_validation_scope",
            message=f"required file not covered by applicable gate {item['gate']}: {item['path']}",
            evidence_id=_evidence_id(case, "gate_scope"),
        )
        for index, item in enumerate(missing_coverage, start=1)
    ]
    observed = {
        "required_files": required_files,
        "required_gate_names": required_gate_names,
        "missing_gate_coverage": missing_coverage,
        "uncovered_files": uncovered,
        "gates": gates,
    }
    return _structural_evidence(
        case, "gate_scope", findings, "all changed and high-risk files covered by gates", observed
    )


def detect_thresholds(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    data = _read_json(fixture_path / "quality_thresholds.json")
    weakened: list[dict[str, Any]] = []
    for threshold in data["thresholds"]:
        direction = threshold["direction"]
        baseline = threshold["baseline"]
        candidate = threshold["candidate"]
        if direction == "minimum" and candidate < baseline:
            weakened.append(threshold)
        elif direction == "maximum" and candidate > baseline:
            weakened.append(threshold)
    findings = [
        ReviewFinding(
            id=f"{case['id']}-threshold-{index:03d}",
            severity="P1",
            category="weakened_validation_threshold",
            message=f"threshold weakened: {item['name']}",
            evidence_id=_evidence_id(case, "thresholds"),
        )
        for index, item in enumerate(weakened, start=1)
    ]
    return _structural_evidence(
        case, "thresholds", findings, "validation thresholds not weakened", {"weakened": weakened}
    )


def detect_required_evidence(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    manifest = fixture_path / "required_evidence.json"
    if not manifest.exists():
        return DetectorEvidence(
            evidence_id=_evidence_id(case, "required_evidence"),
            case_id=case["id"],
            detector_id="required_evidence",
            status=EvidenceStatus.UNVERIFIABLE,
            message="required evidence manifest missing",
            observed={"path": str(manifest)},
        )
    data = _read_json(manifest)
    if not data.get("verified"):
        return DetectorEvidence(
            evidence_id=_evidence_id(case, "required_evidence"),
            case_id=case["id"],
            detector_id="required_evidence",
            status=EvidenceStatus.UNKNOWN,
            message="required evidence unresolved",
            observed=data,
        )
    return DetectorEvidence(
        evidence_id=_evidence_id(case, "required_evidence"),
        case_id=case["id"],
        detector_id="required_evidence",
        status=EvidenceStatus.PASS,
        message="required evidence verified",
        observed=data,
    )


def detect_business_ambiguity(case: dict[str, Any], fixture_path: Path) -> DetectorEvidence:
    data = _read_json(fixture_path / "business_question.json")
    if data.get("requires_owner_decision") is True:
        return DetectorEvidence(
            evidence_id=_evidence_id(case, "business_ambiguity"),
            case_id=case["id"],
            detector_id="business_ambiguity",
            status=EvidenceStatus.BUSINESS_AMBIGUITY,
            message=data["question"],
            observed=data,
        )
    return DetectorEvidence(
        evidence_id=_evidence_id(case, "business_ambiguity"),
        case_id=case["id"],
        detector_id="business_ambiguity",
        status=EvidenceStatus.PASS,
        message="no business ambiguity",
        observed=data,
    )


def _structural_evidence(
    case: dict[str, Any],
    detector_id: str,
    findings: list[ReviewFinding],
    pass_message: str,
    observed: dict[str, Any] | None = None,
) -> DetectorEvidence:
    status = EvidenceStatus.FAIL if findings else EvidenceStatus.PASS
    message = f"{len(findings)} blocking finding(s)" if findings else pass_message
    return DetectorEvidence(
        evidence_id=_evidence_id(case, detector_id),
        case_id=case["id"],
        detector_id=detector_id,
        status=status,
        message=message,
        observed=observed or {"finding_count": len(findings)},
        findings=tuple(findings),
    )


def _finding(
    case: dict[str, Any], detector_id: str, severity: str, category: str, path: Path, detail: str
) -> ReviewFinding:
    digest = hashlib.sha256(f"{case['id']}|{detector_id}|{path.as_posix()}|{detail}".encode("utf-8")).hexdigest()[:12]
    return ReviewFinding(
        id=f"{case['id']}-{detector_id}-{digest}",
        severity=severity,
        category=category,
        message=f"{category}: {path.as_posix()}::{detail}",
        evidence_id=_evidence_id(case, detector_id),
    )


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _python_files(path: Path) -> list[Path]:
    if not path.exists():
        raise FileNotFoundError(path)
    return sorted(candidate for candidate in path.rglob("*.py") if candidate.is_file())


def _exported_names(tree: ast.AST) -> set[str]:
    exported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for item in node.value.elts:
                        if isinstance(item, ast.Constant) and isinstance(item.value, str):
                            exported.add(item.value)
    return exported


def _imports_from_private_modules(tree: ast.AST) -> dict[str, str]:
    imported: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        module = node.module or ""
        if module.startswith("_") or "._" in f".{module}":
            for alias in node.names:
                imported[alias.asname or alias.name] = alias.name
    return imported


def _import_graph(package_path: Path) -> dict[str, list[str]]:
    if not package_path.exists():
        raise FileNotFoundError(package_path)
    graph: dict[str, set[str]] = defaultdict(set)
    for path in sorted(package_path.rglob("*.py")):
        relative = path.relative_to(package_path).with_suffix("")
        module_name = (
            "__init__" if relative.name == "__init__" and len(relative.parts) == 1 else ".".join(relative.parts)
        )
        graph.setdefault(module_name, set())
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            graph[module_name].update(_detector_import_targets(node))
    return {key: sorted(value) for key, value in sorted(graph.items())}


def _detector_import_targets(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Import):
        return {".".join(alias.name.split(".")[1:]) for alias in node.names if alias.name.startswith("app.")}
    if not isinstance(node, ast.ImportFrom):
        return set()
    if node.module == "app":
        return {"__init__"}
    if node.module and node.module.startswith("app."):
        return {".".join(node.module.split(".")[1:])}
    if node.level == 1 and node.module:
        return {node.module.split(".")[0]}
    return set()


def _find_cycle(graph: dict[str, list[str]]) -> list[str]:
    visited: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> list[str]:
        if node in stack:
            return stack[stack.index(node) :] + [node]
        if node in visited:
            return []
        visited.add(node)
        stack.append(node)
        for neighbor in graph.get(node, []):
            cycle = visit(neighbor)
            if cycle:
                return cycle
        stack.pop()
        return []

    for node in sorted(graph):
        cycle = visit(node)
        if cycle:
            return cycle
    return []


def _is_raw_dict_annotation(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in {"dict", "Dict"}
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name):
            return node.value.id in {"dict", "Dict"}
        if isinstance(node.value, ast.Attribute):
            return node.value.attr in {"dict", "Dict"}
    return False


def _covered_by_any_gate(path: str, gates: list[dict[str, Any]]) -> bool:
    return any(_covered_by_gate(path, gate) for gate in gates)


def _covered_by_gate(path: str, gate: dict[str, Any]) -> bool:
    return any(_scope_match(path, pattern) for pattern in gate.get("scope", []))


def _scope_match(path: str, pattern: str) -> bool:
    path_parts = [part for part in path.replace("\\", "/").split("/") if part]
    pattern_parts = [part for part in pattern.replace("\\", "/").split("/") if part]

    def match_parts(path_index: int, pattern_index: int) -> bool:
        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)
        token = pattern_parts[pattern_index]
        if token == "**":
            return any(
                match_parts(next_index, pattern_index + 1) for next_index in range(path_index, len(path_parts) + 1)
            )
        if path_index >= len(path_parts):
            return False
        if not fnmatch.fnmatchcase(path_parts[path_index], token):
            return False
        return match_parts(path_index + 1, pattern_index + 1)

    return match_parts(0, 0)


DETECTORS: dict[str, Detector] = {
    "target_lock": detect_target_lock,
    "route_interleaving": detect_route_interleaving,
    "private_reexport": detect_private_reexport,
    "private_test_dependency": detect_private_test_dependency,
    "import_cycle": detect_import_cycle,
    "untyped_public_dict": detect_untyped_dict_boundary,
    "gate_scope": detect_gate_scope,
    "thresholds": detect_thresholds,
    "required_evidence": detect_required_evidence,
    "business_ambiguity": detect_business_ambiguity,
}
