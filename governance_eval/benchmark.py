from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from governance_eval.cases import load_cases
from governance_eval.decision import decide
from governance_eval.detectors import run_detectors
from governance_eval.hashing import sha256_json
from governance_eval.lock import read_spaghetti_lock, validate_spaghetti_lock
from governance_eval.models import Decision, Label
from governance_eval.paths import repo_root
from governance_eval.schemas import validate_named
from governance_eval.schema_validator import SchemaValidationError


BENCHMARK_PASS = "BENCHMARK_PASS"
BENCHMARK_FAIL = "BENCHMARK_FAIL"


def run_benchmark(root: Path | None = None, repeat: int = 3, artifacts_dir: Path | None = None) -> dict[str, Any]:
    resolved_root = repo_root(root)
    started = time.perf_counter()
    run_id = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    cases = load_cases(resolved_root)
    lock_path = resolved_root / "targets" / "spaghetti.lock.toml"
    lock_problems = validate_spaghetti_lock(lock_path)
    lock = read_spaghetti_lock(lock_path) if not lock_problems else None

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
    acceptance_errors = _acceptance_errors(case_results, metrics, lock_problems)
    phase1_decision = BENCHMARK_PASS if not acceptance_errors else BENCHMARK_FAIL
    output = {
        "schema_version": "1.0",
        "run_id": run_id,
        "generated_at": run_id,
        "duration_seconds": round(duration, 6),
        "repeat_count": repeat,
        "phase1_decision": phase1_decision,
        "acceptance_errors": acceptance_errors,
        "target_lock": lock.to_json() if lock else {"problems": lock_problems},
        "metrics": metrics,
        "cases": case_results,
        "artifact_content_hash": "",
    }
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
    required_lock_fields = {"base_sha", "head_sha", "merge_commit_sha", "approved_oracle_sha", "observed_main_sha"}
    missing_lock_fields = sorted(required_lock_fields - set(target_lock))
    if missing_lock_fields:
        raise SchemaValidationError(f"target_lock missing fields: {missing_lock_fields}")
    for key in required_lock_fields:
        value = target_lock[key]
        if not (isinstance(value, str) and len(value) == 40 and all(char in "0123456789abcdef" for char in value)):
            raise SchemaValidationError(f"target_lock.{key}: expected full SHA")
    for item in result["cases"]:
        validate_named("final_decision", item["decision"], resolved_root)
        for evidence in item["evidence"]:
            validate_named("detector_evidence", evidence, resolved_root)
            for finding in evidence["findings"]:
                validate_named("review_finding", finding, resolved_root)


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


def _acceptance_errors(case_results: list[dict[str, Any]], metrics: dict[str, Any], lock_problems: list[str]) -> list[str]:
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
