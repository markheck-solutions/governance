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
from governance_eval.delivery_readiness import main as delivery_readiness_main
from governance_eval.delivery_readiness import validate_review_quorum_document
from governance_eval.lock import write_spaghetti_lock
from governance_eval.paths import repo_root
from governance_eval.target_eval import evaluate_target
from governance_eval.target_pack import validate_target_request


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="governance-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lock_parser = subparsers.add_parser("lock", help="write the pinned Spaghetti lock file")
    lock_parser.add_argument("--root", type=Path, default=None)

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

    validate_target_parser = subparsers.add_parser("validate-target-request", help="validate target pack and revision inputs")
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

    delivery_parser = subparsers.add_parser("delivery-readiness", help="verify PR review/workflow readiness before merge")
    delivery_parser.add_argument("--repo", required=True)
    delivery_parser.add_argument("--pr", required=True, type=int)
    delivery_parser.add_argument("--payload", default=None)
    delivery_parser.add_argument("--benchmark-artifact", default=None)
    delivery_parser.add_argument("--benchmark-artifact-digest", default=None)
    delivery_parser.add_argument("--require-github-artifact-digest", action="store_true")
    delivery_parser.add_argument("--fallback-quorum", default=None)

    quorum_parser = subparsers.add_parser("validate-review-quorum", help="validate fallback review quorum JSON")
    quorum_parser.add_argument("--path", type=Path, required=True)
    quorum_parser.add_argument("--head-sha", required=True)
    quorum_parser.add_argument("--base-sha", default="")

    args = parser.parse_args(argv)
    root = repo_root(getattr(args, "root", None))

    if args.command == "lock":
        lock = write_spaghetti_lock(root / "targets" / "spaghetti.lock.toml")
        print(json.dumps(lock.to_json(), indent=2, sort_keys=True))
        return 0
    if args.command == "run-case":
        return _run_case(args.case_id, root)
    if args.command == "benchmark":
        result = run_benchmark(root=root, repeat=args.repeat, artifacts_dir=root / args.artifacts_dir)
        print(json.dumps(_summary(result), indent=2, sort_keys=True))
        return 0 if result["phase1_decision"] == BENCHMARK_PASS else 1
    if args.command == "verify":
        return _verify(root, args.repeat, root / args.artifacts_dir)
    if args.command == "evaluate-target":
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
        )
        print(json.dumps(_target_summary(result), indent=2, sort_keys=True))
        return 0
    if args.command == "validate-target-request":
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
    if args.command == "delivery-readiness":
        delivery_args = ["--repo", args.repo, "--pr", str(args.pr)]
        if args.payload:
            delivery_args.extend(["--payload", args.payload])
        if args.benchmark_artifact:
            delivery_args.extend(["--benchmark-artifact", args.benchmark_artifact])
        if args.benchmark_artifact_digest:
            delivery_args.extend(["--benchmark-artifact-digest", args.benchmark_artifact_digest])
        if args.require_github_artifact_digest:
            delivery_args.append("--require-github-artifact-digest")
        if args.fallback_quorum:
            delivery_args.extend(["--fallback-quorum", args.fallback_quorum])
        return delivery_readiness_main(delivery_args)
    if args.command == "validate-review-quorum":
        path = root / args.path if not args.path.is_absolute() else args.path
        quorum = json.loads(path.read_text(encoding="utf-8"))
        errors = validate_review_quorum_document(quorum, args.head_sha, args.base_sha)
        print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
        return 0 if not errors else 1
    raise AssertionError(args.command)


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


def _verify(root: Path, repeat: int, artifacts_dir: Path) -> int:
    test_command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]
    tests = subprocess.run(test_command, cwd=root)
    if tests.returncode != 0:
        return tests.returncode
    result = run_benchmark(root=root, repeat=repeat, artifacts_dir=artifacts_dir)
    print(json.dumps(_summary(result), indent=2, sort_keys=True))
    return 0 if result["phase1_decision"] == BENCHMARK_PASS else 1


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
