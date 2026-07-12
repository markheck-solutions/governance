from __future__ import annotations

import argparse
import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.paths import repo_root
from governance_eval.schemas import validate_named
from governance_eval.structural import scan_structural_metrics, structural_delta
from governance_eval.target_eval import (
    BLOCKING,
    SHADOW,
    SHADOW_ASK_BUSINESS,
    SHADOW_BLOCK_TECHNICAL,
    SHADOW_MERGE,
    _behavior_policy,
    _behavior_status,
    _case_applies,
    _case_requires_behavior_evidence,
    _changed_files,
    _git_sha,
    _source_file_evidence,
    _source_hash_validation,
    _source_symbol_evidence,
    _stable_target_payload,
    _structural_measurement_summary,
    _target_acceptance_errors,
    _validate_expected_artifact_fields,
)
from governance_eval.target_pack import (
    dependency_lock_hash,
    load_target_pack,
    schema_hashes,
    target_pack_hash,
    validate_target_request,
)
from governance_eval.trusted_workflow import _repository_tree_hash

GITHUB_EPHEMERAL_MATRIX = "GITHUB_EPHEMERAL_JOB_MATRIX"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="governance-eval target-workflow")
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    for name in (
        "pack",
        "repository-url",
        "base-sha",
        "head-sha",
        "revision-mode",
        "enforcement-mode",
        "workflow-repository",
        "workflow-sha",
        "output",
    ):
        plan.add_argument(f"--{name}", required=True)
    plan.add_argument("--merge-sha", default="")
    plan.add_argument("--target-pr-number", type=int, default=None)
    finalize = commands.add_parser("finalize")
    for name in ("plan", "raw-dir", "base-dir", "head-dir", "workflow-repository", "workflow-sha", "output-dir"):
        finalize.add_argument(f"--{name}", required=True)
    args = parser.parse_args(argv)
    if args.command == "plan":
        result = create_target_plan(
            Path(args.pack),
            args.repository_url,
            args.base_sha,
            args.head_sha,
            args.merge_sha or None,
            args.revision_mode,
            args.enforcement_mode,
            args.workflow_repository,
            args.workflow_sha,
            args.target_pr_number,
            Path(args.output),
        )
    else:
        result = finalize_target_plan(
            Path(args.plan),
            Path(args.raw_dir),
            Path(args.base_dir),
            Path(args.head_dir),
            args.workflow_repository,
            args.workflow_sha,
            Path(args.output_dir),
        )
    print(
        json.dumps(
            {
                "status": "PASS",
                "plan_hash": result.get("plan_hash"),
                "decision": result.get("real_target_shadow_decision"),
            },
            sort_keys=True,
        )
    )
    return 0


def create_target_plan(
    pack_path: Path,
    repository_url: str,
    base_sha: str,
    head_sha: str,
    merge_sha: str | None,
    revision_mode: str,
    enforcement_mode: str,
    workflow_repository: str,
    workflow_sha: str,
    target_pr_number: int | None,
    output: Path,
) -> dict[str, Any]:
    root = repo_root(Path(__file__).resolve())
    pack = validate_target_request(pack_path, repository_url, base_sha, head_sha, merge_sha, revision_mode, root)
    if enforcement_mode not in {SHADOW, BLOCKING}:
        raise ValueError("enforcement mode must be SHADOW or BLOCKING")
    if revision_mode == "CANDIDATE_DYNAMIC" and target_pr_number is None:
        raise ValueError("CANDIDATE_DYNAMIC requires target_pr_number")
    matrix = [
        {
            "id": f"{case['id']}-{side}",
            "case_id": case["id"],
            "side": side,
            "sha": sha,
            "reproducer": case["reproducer"],
            "timeout_seconds": case.get("timeout_seconds", 60),
        }
        for case in pack["behavior_cases"]
        if _case_applies(case, revision_mode)
        for side, sha in (("base", base_sha), ("head", head_sha))
    ]
    plan: dict[str, Any] = {
        "schema_version": "1.0",
        "workflow_repository": workflow_repository,
        "workflow_sha": workflow_sha,
        "evaluator_tree_hash": _repository_tree_hash(root),
        "target_pack_path": pack_path.relative_to(root).as_posix(),
        "target_pack_hash": target_pack_hash(pack_path),
        "target_repository_url": repository_url,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "merge_sha": merge_sha,
        "revision_mode": revision_mode,
        "enforcement_mode": enforcement_mode,
        "target_pr_number": target_pr_number,
        "adapter": pack["adapter"],
        "setup_commands": pack.get("setup_commands", []),
        "matrix": matrix,
        "plan_hash": "",
    }
    plan["plan_hash"] = sha256_json({**plan, "plan_hash": ""})
    validate_named("target_execution_plan", plan, root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")
    return plan


def finalize_target_plan(
    plan_path: Path,
    raw_dir: Path,
    base_dir: Path,
    head_dir: Path,
    workflow_repository: str,
    workflow_sha: str,
    output_dir: Path,
) -> dict[str, Any]:
    root = repo_root(Path(__file__).resolve())
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    validate_named("target_execution_plan", plan, root)
    errors = _plan_binding_errors(plan, workflow_repository, workflow_sha, base_dir, head_dir)
    pack_path = root / plan["target_pack_path"]
    pack = load_target_pack(pack_path, root=root, require_governance_owned=True)
    raw = _load_raw_results(raw_dir)
    behavior, setup_results, raw_errors = _trusted_behavior_results(root, pack, plan, raw, base_dir, head_dir)
    errors.extend(raw_errors)
    changed = _changed_files(base_dir, head_dir, plan["base_sha"], plan["head_sha"])
    base_struct = scan_structural_metrics(base_dir, changed, pack)
    head_struct = scan_structural_metrics(head_dir, changed, pack)
    delta = structural_delta(base_struct, head_struct, pack)
    pr_status = (
        "PASS" if plan["revision_mode"] == "CANDIDATE_DYNAMIC" and plan["target_pr_number"] else "NOT_APPLICABLE"
    )
    validation = {
        "status": "FAIL" if errors else "PASS",
        "mode": plan["revision_mode"],
        "base_commit_exists": not errors,
        "head_commit_exists": not errors,
        "candidate_pull_request_validation": {"status": pr_status},
    }
    acceptance, business = _target_acceptance_errors(
        behavior, delta, pack, setup_results, validation, plan["revision_mode"]
    )
    acceptance = [*errors, *acceptance]
    decision = SHADOW_BLOCK_TECHNICAL if acceptance else SHADOW_ASK_BUSINESS if business else SHADOW_MERGE
    result = _target_result(
        root,
        pack_path,
        pack,
        plan,
        behavior,
        setup_results,
        validation,
        base_struct,
        head_struct,
        delta,
        acceptance,
        business,
        decision,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "target-evaluation-latest.json").write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
    )
    return result


def _plan_binding_errors(plan: dict[str, Any], repository: str, sha: str, base_dir: Path, head_dir: Path) -> list[str]:
    errors: list[str] = []
    if plan["plan_hash"] != sha256_json({**plan, "plan_hash": ""}):
        errors.append("target execution plan hash mismatch")
    if plan["workflow_repository"] != repository or plan["workflow_sha"] != sha:
        errors.append("trusted workflow identity mismatch")
    if plan["evaluator_tree_hash"] != _repository_tree_hash(repo_root(Path(__file__).resolve())):
        errors.append("trusted evaluator tree hash mismatch")
    for name, path in (("base", base_dir), ("head", head_dir)):
        actual = _git_sha(path)
        if actual != plan[f"{name}_sha"]:
            errors.append(f"{name} checkout SHA mismatch")
    return errors


def _load_raw_results(raw_dir: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for path in raw_dir.rglob("raw-result.json"):
        item = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            results[item["id"]] = item
    return results


def _trusted_behavior_results(
    root: Path,
    pack: dict[str, Any],
    plan: dict[str, Any],
    raw: dict[str, dict[str, Any]],
    base_dir: Path,
    head_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]], list[str]]:
    errors: list[str] = []
    setup: dict[str, list[dict[str, Any]]] = {"base": [], "head": []}
    behavior: list[dict[str, Any]] = []
    for case in pack["behavior_cases"]:
        if not _case_applies(case, plan["revision_mode"]):
            continue
        executions: dict[str, dict[str, Any]] = {}
        policy = _behavior_policy(case, plan["revision_mode"])
        for side, directory in (("base", base_dir), ("head", head_dir)):
            item = raw.get(f"{case['id']}-{side}")
            if item is None:
                errors.append(f"missing raw result for {case['id']} {side}")
                item = {"exit_code": 125, "observed_result": {}, "setup_results": []}
            else:
                errors.extend(_raw_result_errors(item, case["id"], side, plan[f"{side}_sha"], plan["setup_commands"]))
            setup[side].extend(item.get("setup_results", []))
            files = _source_file_evidence(directory, case.get("source_files", []), plan[f"{side}_sha"])
            symbols = _source_symbol_evidence(directory, case.get("source_symbols", []), plan[f"{side}_sha"])
            executions[side] = {
                **item,
                "source_files": files,
                "source_symbols": symbols,
                "source_hash_validation": _source_hash_validation(case, plan[f"{side}_sha"], files, symbols, policy),
            }
        expected = case.get("expected_base_result") or executions["base"]["observed_result"]
        status = _behavior_status(policy, executions["base"], executions["head"], expected)
        behavior.append(
            {
                "case_id": case["id"],
                "status": status,
                "required_behavior_evidence": _case_requires_behavior_evidence(case),
                "behavior_comparison_policy": policy,
                "provenance_classification": case["provenance_classification"],
                "classification_reason": case.get("classification_reason", ""),
                "target_repository_url": plan["target_repository_url"],
                "pull_request": case.get("pull_request"),
                "base_sha": plan["base_sha"],
                "head_sha": plan["head_sha"],
                "merge_sha": plan["merge_sha"],
                "base_execution": executions["base"],
                "head_execution": executions["head"],
                "expected_result": expected,
                "observed_result": {side: executions[side]["observed_result"] for side in ("base", "head")},
                "source_files": {side: executions[side]["source_files"] for side in ("base", "head")},
                "source_symbols": {side: executions[side]["source_symbols"] for side in ("base", "head")},
                "source_hash_validation": "PASS"
                if all(executions[side]["source_hash_validation"] == "PASS" for side in ("base", "head"))
                else "FAIL",
                "reproducer_files": [{"path": case["reproducer"], "sha256": sha256_file(root / case["reproducer"])}],
                "commands": [executions[side].get("command", "") for side in ("base", "head")],
            }
        )
    return behavior, setup, errors


def _raw_result_errors(item: dict[str, Any], case_id: str, side: str, sha: str, setup_commands: list[str]) -> list[str]:
    expected_id = f"{case_id}-{side}"
    errors: list[str] = []
    for key, expected in (("id", expected_id), ("case_id", case_id), ("side", side), ("sha", sha)):
        if item.get(key) != expected:
            errors.append(f"raw result {expected_id} has invalid {key}")
    if not isinstance(item.get("exit_code"), int) or not isinstance(item.get("timed_out"), bool):
        errors.append(f"raw result {expected_id} has malformed execution status")
    if not isinstance(item.get("observed_result"), dict):
        errors.append(f"raw result {expected_id} has malformed observed_result")
    setup = item.get("setup_results")
    commands = (
        [entry.get("command") for entry in setup]
        if isinstance(setup, list) and all(isinstance(entry, dict) for entry in setup)
        else []
    )
    if commands != setup_commands:
        errors.append(f"raw result {expected_id} setup commands do not match trusted plan")
    return errors


def _target_result(
    root: Path,
    pack_path: Path,
    pack: dict[str, Any],
    plan: dict[str, Any],
    behavior: list[dict[str, Any]],
    setup: dict[str, list[dict[str, Any]]],
    validation: dict[str, Any],
    base_struct: dict[str, Any],
    head_struct: dict[str, Any],
    delta: dict[str, Any],
    acceptance: list[str],
    business: list[str],
    decision: str,
) -> dict[str, Any]:
    required = [item for item in behavior if item["required_behavior_evidence"]]
    result: dict[str, Any] = {
        "schema_version": "1.1",
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "governance_repository_url": "https://github.com/markheck-solutions/governance.git",
        "governance_evaluator_git_sha": _git_sha(root),
        "governance_target_pack_hash": target_pack_hash(pack_path),
        "schema_hashes": schema_hashes(root),
        "dependency_lock_hash": dependency_lock_hash(root),
        "target_repository_url": plan["target_repository_url"],
        "target_pack_id": pack["id"],
        "target_pr_number": plan["target_pr_number"],
        "target_base_sha": plan["base_sha"],
        "target_head_sha": plan["head_sha"],
        "target_merge_sha": plan["merge_sha"],
        "revision_mode": plan["revision_mode"],
        "revision_validation": validation,
        "operating_system": platform.platform(),
        "runner_os": platform.system(),
        "python_version": platform.python_version(),
        "review_gate": "NOT_APPLICABLE",
        "github_review_state": "NOT_APPLICABLE",
        "enforcement_mode": plan["enforcement_mode"],
        "execution_identity": {
            "mode": GITHUB_EPHEMERAL_MATRIX,
            "workflow_repository": plan["workflow_repository"],
            "workflow_sha": plan["workflow_sha"],
            "plan_hash": plan["plan_hash"],
        },
        "real_target_shadow_decision": decision,
        "acceptance_errors": acceptance,
        "business_ambiguities": business,
        "applicable_behavior_case_count": len(required),
        "case_counts": {
            "behavior_case_count": len(behavior),
            "required_behavior_case_count": len(required),
            "advisory_behavior_case_count": len(behavior) - len(required),
            "behavior_cases_passed": sum(item["status"] == "PASS" for item in behavior),
            "behavior_cases_failed": sum(item["status"] == "FAIL" for item in behavior),
            "behavior_cases_business_ambiguous": sum(item["status"] == "BUSINESS_AMBIGUITY" for item in behavior),
        },
        "setup_results": setup,
        "behavior_results": behavior,
        "structural_metrics_before": base_struct,
        "structural_metrics_after": head_struct,
        "structural_delta": delta,
        "structural_measurements": _structural_measurement_summary(delta),
        "commands": [item.get("command", "") for results in setup.values() for item in results]
        + [command for item in behavior for command in item["commands"]],
        "github_artifact_id": None,
        "github_artifact_digest": None,
        "deterministic_evidence_hash": "",
        "artifact_content_hash": "",
    }
    _validate_expected_artifact_fields(pack, result)
    result["deterministic_evidence_hash"] = sha256_json(_stable_target_payload(result))
    result["artifact_content_hash"] = sha256_json({**result, "artifact_content_hash": ""})
    validate_named("target_evaluation_result", result, root)
    return result
