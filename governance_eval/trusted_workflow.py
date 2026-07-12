from __future__ import annotations

import argparse
import copy
import json
import subprocess
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.schemas import validate_named
from governance_eval.supportability import STATUS_GREEN, STATUS_RED
from governance_eval.supportability import load_supportability_config, run_supportability_gate


SUCCESS = "success"
MAX_MATRIX_COMMANDS = 32


def create_trusted_plan(
    config_path: Path,
    target_repo: Path,
    base_sha: str,
    head_sha: str,
    *,
    workflow_repository: str,
    workflow_sha: str,
    repository_url: str,
    pull_request_url: str,
    output_path: Path | None = None,
) -> dict[str, Any]:
    config = load_supportability_config(config_path)
    preflight = run_supportability_gate(
        config_path,
        target_repo,
        base_sha,
        head_sha,
        repository_url=repository_url,
        pr_url=pull_request_url,
        command_runner=_planning_runner,
    )
    matrix = _command_matrix(config)
    errors = list(preflight["errors"])
    max_commands = config["execution"]["max_commands"]
    if len(matrix) > min(max_commands, MAX_MATRIX_COMMANDS):
        errors.append(
            f"execution matrix has {len(matrix)} commands; maximum is {min(max_commands, MAX_MATRIX_COMMANDS)}"
        )
    if not matrix:
        errors.append("execution matrix is empty")
    plan = {
        "schema_version": "1.0",
        "workflow_identity": {
            "repository": workflow_repository,
            "sha": workflow_sha,
            "evaluator_tree_hash": _repository_tree_hash(Path(__file__).resolve().parents[1]),
        },
        "target_identity": {
            "repository_url": repository_url,
            "pull_request_url": pull_request_url,
            "base_sha": base_sha,
            "head_sha": head_sha,
            "head_tree_sha": _git_output(target_repo, "rev-parse", f"{head_sha}^{{tree}}"),
        },
        "config_identity": {
            "path": config_path.relative_to(target_repo).as_posix(),
            "sha256": sha256_file(config_path),
        },
        "execution": {
            "adapter": config["execution"]["adapter"],
            "setup_commands": config["execution"]["setup_commands"],
            "matrix": matrix,
        },
        "preflight": {**preflight, "owner_status": STATUS_RED, "commands": []},
        "errors": errors,
        "plan_hash": "",
    }
    plan["plan_hash"] = sha256_json({**plan, "plan_hash": ""})
    validate_named("supportability_plan", plan, Path(__file__).resolve().parents[1])
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")
    return plan


def finalize_trusted_plan(
    plan: dict[str, Any],
    execution_result: str,
    *,
    workflow_repository: str,
    workflow_sha: str,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    errors = _plan_integrity_errors(plan, workflow_repository, workflow_sha)
    errors.extend(plan.get("errors") or [])
    if execution_result != SUCCESS:
        errors.append(f"untrusted execution matrix result is {execution_result!r}, expected 'success'")
    result = copy.deepcopy(plan["preflight"])
    result["commands"] = _recorded_command_results(plan, execution_result)
    result["execution_identity"] = {
        "mode": "GITHUB_EPHEMERAL_JOB_MATRIX",
        "workflow_repository": workflow_repository,
        "workflow_sha": workflow_sha,
        "evaluator_tree_hash": plan["workflow_identity"]["evaluator_tree_hash"],
        "target_tree_sha": plan["target_identity"]["head_tree_sha"],
        "config_sha256": plan["config_identity"]["sha256"],
        "plan_hash": plan["plan_hash"],
        "matrix_result": execution_result,
    }
    result["errors"] = errors
    result["owner_status"] = STATUS_RED if errors else STATUS_GREEN
    validate_named("supportability_gate_result", result, Path(__file__).resolve().parents[1])
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "supportability-gate-result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
        )
    return result


def _command_matrix(config: dict[str, Any]) -> list[dict[str, str]]:
    matrix: list[dict[str, str]] = []
    for gate, configured in config["required_gates"].items():
        if gate == "sql_supportability" and configured == "auto":
            continue
        commands = [configured] if isinstance(configured, str) else configured
        for command in commands:
            matrix.append({"id": f"gate-{len(matrix) + 1:02d}", "gate": gate, "command": command})
    return matrix


def _recorded_command_results(plan: dict[str, Any], execution_result: str) -> list[dict[str, Any]]:
    passed = execution_result == SUCCESS
    return [
        {
            "gate": item["gate"],
            "command": item["command"],
            "status": "PASS" if passed else "FAIL",
            "exit_code": 0 if passed else 1,
            "stdout": "GitHub ephemeral job completed successfully" if passed else "",
            "stderr": "" if passed else f"GitHub execution matrix result: {execution_result}",
        }
        for item in plan["execution"]["matrix"]
    ]


def _plan_integrity_errors(plan: dict[str, Any], workflow_repository: str, workflow_sha: str) -> list[str]:
    errors: list[str] = []
    expected_hash = sha256_json({**plan, "plan_hash": ""})
    if plan.get("plan_hash") != expected_hash:
        errors.append("trusted plan hash mismatch")
    identity = plan.get("workflow_identity") or {}
    if identity.get("repository") != workflow_repository:
        errors.append("trusted plan workflow repository mismatch")
    if identity.get("sha") != workflow_sha:
        errors.append("trusted plan workflow SHA mismatch")
    if identity.get("evaluator_tree_hash") != _repository_tree_hash(Path(__file__).resolve().parents[1]):
        errors.append("trusted evaluator tree hash mismatch")
    return errors


def _repository_tree_hash(root: Path) -> str:
    files = _git_output(root, "ls-files").splitlines()
    payload = [{"path": path, "sha256": sha256_file(root / path)} for path in sorted(files) if (root / path).is_file()]
    return sha256_json(payload)


def _git_output(root: Path, *args: str) -> str:
    completed = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True, timeout=60)
    return completed.stdout.strip()


def _planning_runner(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=command, returncode=0, stdout="planned only", stderr="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trusted-workflow")
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--config", type=Path, required=True)
    plan_parser.add_argument("--target-repo", type=Path, required=True)
    plan_parser.add_argument("--base-sha", required=True)
    plan_parser.add_argument("--head-sha", required=True)
    plan_parser.add_argument("--workflow-repository", required=True)
    plan_parser.add_argument("--workflow-sha", required=True)
    plan_parser.add_argument("--repository-url", required=True)
    plan_parser.add_argument("--pr-url", required=True)
    plan_parser.add_argument("--output", type=Path, required=True)
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--plan", type=Path, required=True)
    finalize_parser.add_argument("--execution-result", required=True)
    finalize_parser.add_argument("--workflow-repository", required=True)
    finalize_parser.add_argument("--workflow-sha", required=True)
    finalize_parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "plan":
        create_trusted_plan(
            args.config,
            args.target_repo,
            args.base_sha,
            args.head_sha,
            workflow_repository=args.workflow_repository,
            workflow_sha=args.workflow_sha,
            repository_url=args.repository_url,
            pull_request_url=args.pr_url,
            output_path=args.output,
        )
        return 0
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    result = finalize_trusted_plan(
        plan,
        args.execution_result,
        workflow_repository=args.workflow_repository,
        workflow_sha=args.workflow_sha,
        output_dir=args.output_dir,
    )
    return 0 if result["owner_status"] == STATUS_GREEN else 1
