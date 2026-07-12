from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from governance_eval.benchmark import BENCHMARK_PASS
from governance_eval.benchmark import run_benchmark
from governance_eval.cases import load_cases
from governance_eval.decision import decide
from governance_eval.detectors import run_detectors
from governance_eval.architecture_gate import main as architecture_gate_main
from governance_eval.delivery_readiness import main as delivery_readiness_main
from governance_eval.delivery_readiness import validate_review_quorum_document
from governance_eval.lock import write_target_lock
from governance_eval.paths import repo_root
from governance_eval.registered_verification import run_registered_target_verification
from governance_eval.supportability import main as supportability_main
from governance_eval.target_eval import evaluate_target
from governance_eval.target_workflow import main as target_workflow_main
from governance_eval.trusted_workflow import main as trusted_workflow_main
from governance_eval.target_pack import validate_target_request


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "architecture-gate":
        return architecture_gate_main(argv)
    if argv and argv[0] == "trusted-workflow":
        return trusted_workflow_main(argv[1:])
    if argv and argv[0] == "target-workflow":
        return target_workflow_main(argv[1:])
    if argv and argv[0] in {
        "supportability-config",
        "supportability-gate",
        "copilot-review-gate",
        "delivery-receipt",
        "bootstrap-receipt",
        "verify-receipt",
    }:
        return supportability_main(argv)
    parser = argparse.ArgumentParser(prog="governance-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lock_parser = subparsers.add_parser("lock", help="write a target lock from a versioned target pack")
    lock_parser.add_argument("--root", type=Path, default=None)
    lock_parser.add_argument("--target-pack", type=Path, required=True)
    lock_parser.add_argument("--output", type=Path, required=True)
    lock_parser.add_argument("--evidence-source", required=True)
    lock_parser.add_argument("--metadata-json", default="{}")

    run_parser = subparsers.add_parser("run-case", help="run one evaluation case")
    run_parser.add_argument("case_id")
    run_parser.add_argument("--root", type=Path, default=None)

    bench_parser = subparsers.add_parser("benchmark", help="run the complete benchmark")
    bench_parser.add_argument("--root", type=Path, default=None)
    bench_parser.add_argument("--repeat", type=int, default=3)
    bench_parser.add_argument("--artifacts-dir", type=Path, default=Path("artifacts/phase1"))

    verify_parser = subparsers.add_parser("verify", help="run tests and Phase 1 benchmark")
    verify_parser.add_argument("--root", type=Path, default=None)
    verify_parser.add_argument("--repeat", type=int, default=3)
    verify_parser.add_argument("--artifacts-dir", type=Path, default=Path("artifacts/phase1"))

    target_parser = subparsers.add_parser("evaluate-target", help="run a non-blocking target shadow evaluation")
    target_parser.add_argument("--pack", type=Path, required=True)
    target_parser.add_argument("--base-sha", required=True)
    target_parser.add_argument("--head-sha", required=True)
    target_parser.add_argument("--merge-sha", default=None)
    target_parser.add_argument("--repository-url", default=None)
    target_parser.add_argument(
        "--revision-mode",
        choices=["HISTORICAL_FIXED", "SAFE_FIXED", "CANDIDATE_DYNAMIC"],
        default=None,
    )
    target_parser.add_argument("--target-pr-number", type=int, default=None)
    target_parser.add_argument("--governance-owned-pack", action="store_true")
    target_parser.add_argument(
        "--review-gate",
        choices=["GITHUB_CODEX_FINAL_REVIEW", "FALLBACK_CLEAN_ROOM_QUORUM", "NOT_APPLICABLE"],
        default=None,
    )
    target_parser.add_argument(
        "--github-review-state",
        choices=["CLEAN", "STALE", "UNAVAILABLE", "BLOCKING_FINDINGS_PRESENT", "NOT_APPLICABLE"],
        default=None,
    )
    target_parser.add_argument("--artifacts-dir", type=Path, default=Path("artifacts/target"))
    target_parser.add_argument("--enforcement-mode", choices=["SHADOW", "BLOCKING"], default="SHADOW")
    target_parser.add_argument("--cache-dir", type=Path, default=None)
    target_parser.add_argument("--offline", action="store_true")

    validate_target_parser = subparsers.add_parser(
        "validate-target-request", help="validate target pack and revision inputs"
    )
    validate_target_parser.add_argument("--pack", type=Path, required=True)
    validate_target_parser.add_argument("--repository-url", required=True)
    validate_target_parser.add_argument("--base-sha", required=True)
    validate_target_parser.add_argument("--head-sha", required=True)
    validate_target_parser.add_argument("--merge-sha", default=None)
    validate_target_parser.add_argument(
        "--revision-mode",
        choices=["HISTORICAL_FIXED", "SAFE_FIXED", "CANDIDATE_DYNAMIC"],
        required=True,
    )

    delivery_parser = subparsers.add_parser(
        "delivery-readiness", help="verify PR review/workflow readiness before merge"
    )
    delivery_parser.add_argument("--repo", required=True)
    delivery_parser.add_argument("--pr", required=True, type=int)
    delivery_parser.add_argument("--payload", default=None)
    delivery_parser.add_argument("--benchmark-artifact", default=None)
    delivery_parser.add_argument("--benchmark-artifact-digest", default=None)
    delivery_parser.add_argument("--benchmark-run-id", default=None)
    delivery_parser.add_argument("--benchmark-artifact-id", default=None)
    delivery_parser.add_argument("--benchmark-artifact-name", default="governance-benchmark-json")
    delivery_parser.add_argument("--require-github-artifact-digest", action="store_true")
    delivery_parser.add_argument("--fallback-quorum", default=None)
    delivery_parser.add_argument("--trusted-reviewer-agent", action="append", default=[])

    quorum_parser = subparsers.add_parser("validate-review-quorum", help="validate fallback review quorum JSON")
    quorum_parser.add_argument("--path", type=Path, required=True)
    quorum_parser.add_argument("--head-sha", required=True)
    quorum_parser.add_argument("--base-sha", default="")
    quorum_parser.add_argument("--trusted-reviewer-agent", action="append", default=[])

    args = parser.parse_args(argv)
    root = repo_root(getattr(args, "root", None))
    handlers = {
        "lock": _handle_lock,
        "run-case": _handle_run_case,
        "benchmark": _handle_benchmark,
        "verify": _handle_verify,
        "evaluate-target": _handle_evaluate_target,
        "validate-target-request": _handle_validate_target,
        "delivery-readiness": _handle_delivery_readiness,
        "validate-review-quorum": _handle_validate_quorum,
    }
    return handlers[args.command](args, root)


def _handle_lock(args: argparse.Namespace, root: Path) -> int:
    lock = write_target_lock(
        root / args.output,
        root / args.target_pack,
        evidence_source=args.evidence_source,
        metadata=json.loads(args.metadata_json),
        root=root,
    )
    print(json.dumps(lock.to_json(), indent=2, sort_keys=True))
    return 0


def _handle_run_case(args: argparse.Namespace, root: Path) -> int:
    return _run_case(args.case_id, root)


def _handle_benchmark(args: argparse.Namespace, root: Path) -> int:
    result = run_benchmark(
        root=root,
        repeat=args.repeat,
        artifacts_dir=root / args.artifacts_dir,
        exact_commands=[_artifact_command("benchmark", args.repeat, args.artifacts_dir)],
    )
    print(json.dumps(_summary(result), indent=2, sort_keys=True))
    return 0 if result["phase1_decision"] == BENCHMARK_PASS else 1


def _handle_verify(args: argparse.Namespace, root: Path) -> int:
    return _verify(
        root,
        args.repeat,
        root / args.artifacts_dir,
        args.artifacts_dir,
    )


def _handle_evaluate_target(args: argparse.Namespace, root: Path) -> int:
    result = evaluate_target(
        root / args.pack if not args.pack.is_absolute() else args.pack,
        args.base_sha,
        args.head_sha,
        root / args.artifacts_dir if not args.artifacts_dir.is_absolute() else args.artifacts_dir,
        args.merge_sha or None,
        args.repository_url,
        args.revision_mode,
        args.target_pr_number,
        args.governance_owned_pack,
        args.review_gate,
        args.github_review_state,
        args.enforcement_mode,
        root / args.cache_dir if args.cache_dir is not None and not args.cache_dir.is_absolute() else args.cache_dir,
        args.offline,
    )
    print(json.dumps(_target_summary(result), indent=2, sort_keys=True))
    return int(args.enforcement_mode == "BLOCKING" and result["real_target_shadow_decision"] != "SHADOW_MERGE")


def _handle_validate_target(args: argparse.Namespace, root: Path) -> int:
    pack = validate_target_request(
        root / args.pack if not args.pack.is_absolute() else args.pack,
        args.repository_url,
        args.base_sha,
        args.head_sha,
        args.merge_sha or None,
        args.revision_mode,
        root,
    )
    print(json.dumps({"status": "PASS", "target_pack_id": pack["id"]}, indent=2, sort_keys=True))
    return 0


def _handle_delivery_readiness(args: argparse.Namespace, root: Path) -> int:
    del root
    delivery_args = ["--repo", args.repo, "--pr", str(args.pr)]
    values = (
        ("payload", "--payload"),
        ("benchmark_artifact", "--benchmark-artifact"),
        ("benchmark_artifact_digest", "--benchmark-artifact-digest"),
        ("benchmark_run_id", "--benchmark-run-id"),
        ("benchmark_artifact_id", "--benchmark-artifact-id"),
        ("benchmark_artifact_name", "--benchmark-artifact-name"),
        ("fallback_quorum", "--fallback-quorum"),
    )
    for attribute, flag in values:
        if value := getattr(args, attribute):
            delivery_args.extend([flag, value])
    if args.require_github_artifact_digest:
        delivery_args.append("--require-github-artifact-digest")
    for agent_id in args.trusted_reviewer_agent:
        delivery_args.extend(["--trusted-reviewer-agent", agent_id])
    return delivery_readiness_main(delivery_args)


def _handle_validate_quorum(args: argparse.Namespace, root: Path) -> int:
    path = root / args.path if not args.path.is_absolute() else args.path
    quorum = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_review_quorum_document(quorum, args.head_sha, args.base_sha, args.trusted_reviewer_agent)
    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


def _run_case(case_id: str, root: Path) -> int:
    cases = {case["id"]: case for case in load_cases(root)}
    if case_id not in cases:
        print(f"unknown case id: {case_id}", file=sys.stderr)
        return 2
    case = cases[case_id]
    evidence = run_detectors(case, root)
    decision = decide(case, evidence)
    print(json.dumps({"decision": decision.to_json(), "evidence": [item.to_json() for item in evidence]}, indent=2))
    return 0 if decision.decision.value == case["expected_decision"] else 1


def _verify(
    root: Path,
    repeat: int,
    artifacts_dir: Path,
    command_artifacts_dir: Path,
) -> int:
    test_command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]
    tests = subprocess.run(test_command, cwd=root)
    if tests.returncode != 0:
        return tests.returncode
    target_evaluations = run_registered_target_verification(root, artifacts_dir / "targets")
    result = run_benchmark(
        root=root,
        repeat=repeat,
        artifacts_dir=artifacts_dir,
        exact_commands=[_artifact_command("verify", repeat, command_artifacts_dir)],
        registered_target_evaluations=target_evaluations,
    )
    print(json.dumps(_summary(result), indent=2, sort_keys=True))
    return 0 if result["phase1_decision"] == BENCHMARK_PASS else 1


def _artifact_command(command: str, repeat: int, artifacts_dir: Path) -> str:
    parts = ["python -m governance_eval", command]
    if repeat != 3:
        parts.extend(["--repeat", str(repeat)])
    parts.extend(["--artifacts-dir", artifacts_dir.as_posix()])
    return " ".join(parts)


def _summary(result: dict) -> dict:
    return {
        "phase1_decision": result["phase1_decision"],
        "acceptance_errors": result["acceptance_errors"],
        "metrics": result["metrics"],
        "artifact_path": result.get("artifact_path"),
    }


def _target_summary(result: dict) -> dict:
    return {
        "real_target_shadow_decision": result["real_target_shadow_decision"],
        "enforcement_mode": result["enforcement_mode"],
        "acceptance_errors": result["acceptance_errors"],
        "case_counts": result["case_counts"],
        "revision_mode": result["revision_mode"],
        "review_gate": result["review_gate"],
        "github_review_state": result["github_review_state"],
        "target_pr_number": result["target_pr_number"],
        "unknown_required_measurements": result["structural_measurements"]["unknown_required_count"],
        "unknown_advisory_measurements": result["structural_measurements"]["unknown_advisory_count"],
        "artifact_content_hash": result["artifact_content_hash"],
        "artifact_path": result.get("artifact_path"),
    }
