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
from governance_eval.lock import write_spaghetti_lock
from governance_eval.paths import repo_root


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

    args = parser.parse_args(argv)
    root = repo_root(args.root)

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
