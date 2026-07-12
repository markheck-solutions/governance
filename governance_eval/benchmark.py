from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from governance_eval.cases import load_cases
from governance_eval.decision import decide
from governance_eval.detectors import run_detectors
from governance_eval.hashing import sha256_json
from governance_eval.models import Decision, Label
from governance_eval.paths import repo_root
from governance_eval.schemas import validate_named
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.target_pack import dependency_lock_hash, schema_hashes
from governance_eval.target_registry import load_target_registry, registered_target_locks, registry_hash


BENCHMARK_PASS = "BENCHMARK_PASS"
BENCHMARK_FAIL = "BENCHMARK_FAIL"
GOVERNANCE_REPOSITORY_URL = "https://github.com/markheck-solutions/governance.git"


def run_benchmark(
    root: Path | None = None,
    repeat: int = 3,
    artifacts_dir: Path | None = None,
    exact_commands: list[str] | None = None,
    registered_target_evaluations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_root = repo_root(root)
    started = time.perf_counter()
    run_id = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    cases = load_cases(resolved_root)
    registry_errors: list[str] = []
    try:
        registry = load_target_registry(root=resolved_root)
        target_locks = registered_target_locks(registry, resolved_root)
    except (OSError, ValueError, KeyError) as exc:
        target_locks = []
        registry_errors.append(str(exc))

    repetitions: list[list[dict[str, Any]]] = []
    for _ in range(repeat):
        decisions = []
        for case in cases:
            evidence = run_detectors(case, resolved_root)
            decision = decide(case, evidence)
            decisions.append(
                {
                    "case": case,
                    "evidence": [item.to_json() for item in evidence],
                    "decision": decision.to_json(),
                }
            )
        repetitions.append(decisions)

    first = repetitions[0]
    case_results = [_case_result(item) for item in first]
    duration = time.perf_counter() - started
    metrics = _metrics(repetitions)
    metrics["execution_duration_seconds"] = round(duration, 6)
    acceptance_errors = _acceptance_errors(case_results, metrics, registry_errors)
    if registered_target_evaluations is not None:
        acceptance_errors.extend(registered_target_evaluations["errors"])
    phase1_decision = BENCHMARK_PASS if not acceptance_errors else BENCHMARK_FAIL
    target_lock: dict[str, Any] = target_locks[0] if target_locks else {"problems": registry_errors}
    revisions_value = target_lock.get("revisions")
    metadata_value = target_lock.get("metadata")
    revisions: dict[str, Any] = revisions_value if isinstance(revisions_value, dict) else {}
    metadata: dict[str, Any] = metadata_value if isinstance(metadata_value, dict) else {}
    output = {
        "schema_version": "1.0",
        "run_id": run_id,
        "generated_at": run_id,
        "governance_repository_url": GOVERNANCE_REPOSITORY_URL,
        "governance_evaluator_git_sha": _git_sha(resolved_root),
        "governance_target_pack_hash": registry_hash(root=resolved_root),
        "schema_hashes": schema_hashes(resolved_root),
        "dependency_lock_hash": dependency_lock_hash(resolved_root),
        "target_repository_url": target_lock.get("repository_url"),
        "target_pr_number": metadata.get("pull_request"),
        "target_base_sha": revisions.get("base_sha"),
        "target_head_sha": revisions.get("head_sha"),
        "target_merge_sha": revisions.get("merge_sha"),
        "revision_mode": "HISTORICAL_FIXED",
        "exact_commands": exact_commands or _exact_commands("benchmark", repeat, artifacts_dir),
        "operating_system": platform.platform(),
        "runner_os": os.environ.get("RUNNER_OS", platform.system()),
        "python_version": platform.python_version(),
        "review_gate": "NOT_APPLICABLE",
        "github_review_state": "NOT_APPLICABLE",
        "github_artifact_id": None,
        "github_artifact_digest": None,
        "deterministic_evidence_hash": "",
        "duration_seconds": round(duration, 6),
        "repeat_count": repeat,
        "phase1_decision": phase1_decision,
        "acceptance_errors": acceptance_errors,
        "target_lock": target_lock,
        "target_locks": target_locks,
        "registered_target_evaluations": registered_target_evaluations,
        "metrics": metrics,
        "cases": case_results,
        "artifact_content_hash": "",
    }
    output["deterministic_evidence_hash"] = sha256_json(_stable_benchmark_payload(output))
    output["artifact_content_hash"] = sha256_json({**output, "artifact_content_hash": ""})
    validate_benchmark_result(output, resolved_root)
    if artifacts_dir is not None:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifacts_dir / f"governance-benchmark-{run_id.replace(':', '').replace('-', '')}.json"
        artifact_path.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
        latest = artifacts_dir / "governance-benchmark-latest.json"
        latest.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
        output["artifact_path"] = str(artifact_path)
    return output


def validate_benchmark_result(result: dict[str, Any], root: Path | None = None) -> None:
    resolved_root = repo_root(root)
    validate_named("benchmark_run_result", result, resolved_root)
    target_lock = result["target_lock"]
    target_locks = result["target_locks"]
    if not target_locks or target_lock != target_locks[0]:
        raise SchemaValidationError("target_lock must equal first registered target lock")
    revisions = target_lock.get("revisions") or {}
    _validate_full_shas(
        {f"target_lock.revisions.{key}": revisions.get(key) for key in ("base_sha", "head_sha", "merge_sha")}
    )
    _validate_full_shas(
        {
            "governance_evaluator_git_sha": result["governance_evaluator_git_sha"],
            "target_base_sha": result["target_base_sha"],
            "target_head_sha": result["target_head_sha"],
            "target_merge_sha": result["target_merge_sha"],
        }
    )
    if result["target_repository_url"] != target_lock["repository_url"]:
        raise SchemaValidationError("target_repository_url must match target_lock.repository_url")
    if result["target_pr_number"] != target_lock["metadata"].get("pull_request"):
        raise SchemaValidationError("target_pr_number must match target lock metadata")
    revision_pairs = (
        ("target_base_sha", "base_sha"),
        ("target_head_sha", "head_sha"),
        ("target_merge_sha", "merge_sha"),
    )
    mismatch = next(
        (result_key for result_key, revision_key in revision_pairs if result[result_key] != revisions[revision_key]),
        None,
    )
    if mismatch:
        raise SchemaValidationError(f"{mismatch} must match target lock revisions")
    _validate_case_evidence(result["cases"], resolved_root)


def _validate_full_shas(values: dict[str, Any]) -> None:
    invalid = next((key for key, value in values.items() if not _is_full_sha(value)), None)
    if invalid:
        raise SchemaValidationError(f"{invalid}: expected full SHA")


def _validate_case_evidence(cases: list[dict[str, Any]], root: Path) -> None:
    for item in cases:
        validate_named("final_decision", item["decision"], root)
        for evidence in item["evidence"]:
            validate_named("detector_evidence", evidence, root)
            for finding in evidence["findings"]:
                validate_named("review_finding", finding, root)


def _is_full_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(char in "0123456789abcdef" for char in value)


def _case_result(item: dict[str, Any]) -> dict[str, Any]:
    case = item["case"]
    return {
        "id": case["id"],
        "title": case["title"],
        "category": case["category"],
        "label": case["label"],
        "critical": case["critical"],
        "expected_decision": case["expected_decision"],
        "decision": item["decision"],
        "evidence": item["evidence"],
    }


def _metrics(repetitions: list[list[dict[str, Any]]]) -> dict[str, Any]:
    first = repetitions[0]
    historical_critical = [
        item for item in first if item["case"]["critical"] and item["case"]["label"] == Label.REPRODUCED_BAD.value
    ]
    synthetic_defects = [
        item
        for item in first
        if item["case"]["category"] == "synthetic_structural" and item["case"]["label"] == Label.REPRODUCED_BAD.value
    ]
    verified_safe = [item for item in first if item["case"]["label"] == Label.VERIFIED_SAFE.value]

    stable_cases = 0
    flaking_cases = 0
    for index in range(len(first)):
        decisions = [run[index]["decision"]["decision"] for run in repetitions]
        if len(set(decisions)) == 1:
            stable_cases += 1
        evidence_signatures = [_evidence_signature(run[index]["evidence"]) for run in repetitions]
        if len(set(evidence_signatures)) != 1:
            flaking_cases += 1
        else:
            pass

    return {
        "critical_defects_blocked": _blocked_count(historical_critical),
        "critical_defect_recall": _blocked_rate(historical_critical),
        "negative_controls_blocked": _blocked_count(synthetic_defects),
        "negative_control_recall": _blocked_rate(synthetic_defects),
        "false_blocks": _false_block_count(verified_safe),
        "false_block_rate": _false_block_rate(verified_safe),
        "repeated_run_decision_stability": stable_cases / len(first) if first else 0.0,
        "deterministic_flake_rate": flaking_cases / len(first) if first else 1.0,
        "execution_duration_seconds": 0.0,
        "case_count": len(first),
        "critical_defect_count": len(historical_critical),
        "negative_control_count": len(synthetic_defects),
        "verified_safe_count": len(verified_safe),
    }


def _evidence_signature(evidence: list[dict[str, Any]]) -> str:
    return json.dumps(evidence, sort_keys=True, separators=(",", ":"))


def _blocked_rate(items: list[dict[str, Any]]) -> float:
    if not items:
        return 0.0
    return _blocked_count(items) / len(items)


def _blocked_count(items: list[dict[str, Any]]) -> int:
    return sum(1 for item in items if item["decision"]["decision"] == Decision.BLOCK_TECHNICAL.value)


def _false_block_rate(items: list[dict[str, Any]]) -> float:
    if not items:
        return 0.0
    return _false_block_count(items) / len(items)


def _false_block_count(items: list[dict[str, Any]]) -> int:
    return sum(1 for item in items if item["decision"]["decision"] == Decision.BLOCK_TECHNICAL.value)


def _acceptance_errors(
    case_results: list[dict[str, Any]], metrics: dict[str, Any], lock_problems: list[str]
) -> list[str]:
    errors = list(lock_problems)
    for result in case_results:
        actual = result["decision"]["decision"]
        expected = result["expected_decision"]
        if actual != expected:
            errors.append(f"{result['id']}: expected {expected}, got {actual}")
    expected_metrics = {
        "critical_defect_recall": 1.0,
        "critical_defects_blocked": metrics["critical_defect_count"],
        "negative_control_recall": 1.0,
        "negative_controls_blocked": metrics["negative_control_count"],
        "false_block_rate": 0.0,
        "false_blocks": 0,
        "repeated_run_decision_stability": 1.0,
        "deterministic_flake_rate": 0.0,
    }
    for name, expected in expected_metrics.items():
        if metrics[name] != expected:
            errors.append(f"{name}: expected {expected}, got {metrics[name]}")
    return errors


def _exact_commands(command: str, repeat: int, artifacts_dir: Path | None) -> list[str]:
    if artifacts_dir is None:
        return [f"python -m governance_eval {command} --repeat {repeat}"]
    return [f"python -m governance_eval {command} --repeat {repeat} --artifacts-dir {artifacts_dir.as_posix()}"]


def _stable_benchmark_payload(result: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(result.get("metrics", {}))
    metrics["execution_duration_seconds"] = 0
    return {
        **result,
        "generated_at": "",
        "run_id": "",
        "duration_seconds": 0,
        "metrics": metrics,
        "github_artifact_id": None,
        "github_artifact_digest": None,
        "deterministic_evidence_hash": "",
        "artifact_content_hash": "",
    }


def _git_sha(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:
        return "UNKNOWN"
