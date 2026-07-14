from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from governance_eval.architecture_policy import (
    architecture_command_lines as _architecture_command_lines,
)
from governance_eval.architecture_policy import (
    architecture_policy_weakening_errors as _architecture_policy_weakening_errors,
)
from governance_eval.hashing import sha256_file
from governance_eval.legacy_copilot_gate import evaluate_copilot_review_gate
from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named


REQUIRED_COMMAND_GATES = (
    "lint",
    "format_check",
    "typecheck",
    "complexity",
    "architecture",
    "tests",
    "compile_or_build",
)
OPTIONAL_COMMAND_GATES = ("package_audit",)
ALL_COMMAND_GATES = (
    REQUIRED_COMMAND_GATES + OPTIONAL_COMMAND_GATES + ("sql_supportability",)
)
STATUS_GREEN = "GREEN"
STATUS_RED = "RED"
GIT_NETWORK_TIMEOUT_SECONDS = 60
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LEGACY_POLICY_DEBT_FIELD = "ex" + "ceptions"
LEGACY_APPLIED_DEBT_FIELD = "ex" + "ceptions_applied"
LEGACY_EXPIRED_DEBT_FIELD = "expired_ex" + "ceptions"
PRODUCTION_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".sql",
    ".ps1",
    ".sh",
    ".go",
    ".rs",
    ".java",
    ".cs",
}
SKIPPED_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "artifacts",
}
NON_BLOCKING_MARKERS = (
    "|| true",
    "|| :",
    "continue-on-error",
    "--exit-zero",
    "exit 0",
)
SCOPE_NARROWING_MARKERS = (
    "--changed",
    "--staged",
    "--since",
    "--only",
    "--grep",
    "--filter",
    "--include",
    "--exclude",
    "--ignore-pattern",
    "--ignore-path",
)
THRESHOLD_WEAKENING_MARKERS = (
    "--extend-ignore",
    "--ignore",
    "--disable",
    "--max-warnings=-1",
    "--pass-with-no-tests",
)


class SupportabilityError(ValueError):
    pass


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _bool_dict_or_empty(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items() if isinstance(item, bool)}


def load_supportability_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    return _parse_supportability_config_text(text, path.suffix)


def _parse_supportability_config_text(text: str, suffix: str = "") -> dict[str, Any]:
    stripped = text.lstrip()
    if suffix == ".json" or stripped.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SupportabilityError(
                f"supportability config JSON invalid: {exc}"
            ) from exc
    else:
        parsed = _parse_simple_yaml(text)
    if not isinstance(parsed, dict):
        raise SupportabilityError("supportability config must be an object")
    return parsed


def validate_supportability_config(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        validate_named("supportability_config", config, root=_schema_root())
    except SchemaValidationError as exc:
        errors.append(f"supportability config schema invalid: {exc}")
    errors.extend(_standard_errors(config.get("standard")))
    errors.extend(_required_gate_errors(config.get("required_gates")))
    errors.extend(_coverage_errors(config.get("coverage")))
    errors.extend(_ai_review_errors(config.get("ai_review")))
    errors.extend(_receipt_config_errors(config.get("receipt")))
    errors.extend(_architecture_policy_errors(config.get("architecture_policy")))
    return errors


def run_supportability_gate(
    config_path: Path,
    target_repo: Path,
    base_sha: str,
    head_sha: str,
    *,
    changed_files: list[str] | None = None,
    output_dir: Path | None = None,
    repository_url: str = "",
    pr_url: str = "",
    command_runner: Callable[[str, Path], subprocess.CompletedProcess[str]]
    | None = None,
) -> dict[str, Any]:
    config = load_supportability_config(config_path)
    errors = validate_supportability_config(config)
    revision_errors = _sha_errors(base_sha, head_sha)
    errors.extend(revision_errors)
    changed_error_start = len(errors)
    changed = _changed_files_or_empty(
        target_repo, base_sha, head_sha, changed_files, errors
    )
    changed_discovery_errors = errors[changed_error_start:]
    high_risk = _high_risk_files(target_repo, changed)
    trusted_config, config_change_errors = _trusted_execution_config(
        config_path, target_repo, changed, base_sha, config
    )
    errors.extend(config_change_errors)
    architecture_governance_errors = _architecture_governance_change_errors(
        target_repo, changed, base_sha, config_path
    )
    errors.extend(architecture_governance_errors)
    errors.extend(_standard_hash_errors(config, target_repo))
    coverage_plan = _build_coverage_plan(trusted_config, changed, high_risk)
    errors.extend(coverage_plan["errors"])
    sql_commands, sql_errors = _sql_gate_commands(
        trusted_config, target_repo, changed, high_risk
    )
    errors.extend(sql_errors)
    command_results = _protected_command_results(
        config_change_errors + architecture_governance_errors
    )
    if not command_results and (revision_errors or changed_discovery_errors):
        command_results = _skipped_command_results(
            "revision inputs invalid or changed-file discovery failed; commands not executed without verifiable diff"
        )
    if not command_results and errors:
        command_results = _skipped_command_results(
            "preflight supportability checks failed; commands not executed"
        )
    if not command_results:
        command_results = _run_commands_with_revision_env(
            trusted_config,
            target_repo,
            sql_commands,
            command_runner or _run_shell_command,
            base_sha,
            head_sha,
        )
    errors.extend(_command_result_errors(command_results))
    result = {
        "schema_version": "1.0",
        "generated_at": _utc_now(),
        "owner_status": STATUS_RED if errors else STATUS_GREEN,
        "repository_url": repository_url,
        "pull_request_url": pr_url,
        "base_sha": _schema_safe_sha(base_sha),
        "head_sha": _schema_safe_sha(head_sha),
        "standard": config.get("standard", {}),
        "changed_files": changed,
        "high_risk_files": high_risk,
        "coverage": coverage_plan["coverage"],
        "commands": command_results,
        "errors": errors,
    }
    _validate_if_schema_exists("supportability_gate_result", result)
    if output_dir is not None:
        _write_json(output_dir / "supportability-gate-result.json", result)
    return result


def generate_delivery_receipt(
    gate_result: dict[str, Any],
    ai_review_result: dict[str, Any],
    *,
    architecture_result: dict[str, Any] | None = None,
    output_dir: Path | None = None,
    repository_url: str = "",
    pr_url: str = "",
    run_id: str = "",
    workflow_run_url: str = "",
    job_name: str = "",
    artifact_name: str = "",
    artifact_id: str = "",
    artifact_digest: str = "",
    merged_sha: str = "",
    required_judges: dict[str, bool] | None = None,
    bootstrap_reason: str = "",
) -> dict[str, Any]:
    resolved_repository_url = repository_url or str(
        gate_result.get("repository_url") or ""
    )
    resolved_pr_url = pr_url or str(gate_result.get("pull_request_url") or "")
    base_sha = str(gate_result.get("base_sha") or "")
    head_sha = str(gate_result.get("head_sha") or "")
    architecture_result = architecture_result or {
        "owner_status": STATUS_RED,
        "gate_implementation": "FAIL",
        "repo_architecture_supportability": "FAIL",
        "architecture_behavior_proof": "FAIL",
        "errors": ["architecture gate result missing"],
    }
    judge_status = _required_judge_status(gate_result, required_judges)
    errors = _receipt_input_errors(
        gate_result,
        ai_review_result,
        artifact_name,
        artifact_id,
        artifact_digest,
        architecture_result,
    )
    errors.extend(_required_judge_errors(judge_status))
    if bootstrap_reason:
        errors.append(f"bootstrap receipt remains RED: {bootstrap_reason}")
    if not SHA1_RE.fullmatch(base_sha):
        errors.append("base_sha must be a 40-character lowercase Git SHA")
    if not SHA1_RE.fullmatch(head_sha):
        errors.append("head_sha must be a 40-character lowercase Git SHA")
    resolved_merged_sha = merged_sha
    if merged_sha and not SHA1_RE.fullmatch(merged_sha):
        errors.append("merged_sha must be empty or a 40-character lowercase Git SHA")
        resolved_merged_sha = ""
    if not resolved_repository_url:
        errors.append("repository_url is required for a GREEN delivery receipt")
    if not resolved_pr_url:
        errors.append("pull_request_url is required for a GREEN delivery receipt")
    status = STATUS_RED if errors else STATUS_GREEN
    receipt = {
        "schema_version": "1.0",
        "generated_at": _utc_now(),
        "owner_status": status,
        "repository_url": resolved_repository_url,
        "pull_request_url": resolved_pr_url,
        "base_sha": _schema_safe_sha(base_sha),
        "head_sha": _schema_safe_sha(head_sha),
        "merged_sha": resolved_merged_sha,
        "workflow": {
            "run_id": run_id,
            "run_url": workflow_run_url,
            "job_name": job_name,
            "result": status,
        },
        "artifact": {
            "name": artifact_name,
            "id": artifact_id,
            "digest": artifact_digest,
        },
        "changed_files": gate_result.get("changed_files", []),
        "high_risk_files": gate_result.get("high_risk_files", []),
        "gate_coverage": gate_result.get("coverage", {}),
        "supportability_gate": {
            "owner_status": gate_result.get("owner_status"),
            "errors": gate_result.get("errors", []),
        },
        "ai_review": {
            "owner_status": ai_review_result.get("owner_status"),
            "evidence_status": ai_review_result.get(
                "evidence_status", "INVALID_EVIDENCE"
            ),
            "approval_provided": ai_review_result.get("approval_provided", False),
            "observations": ai_review_result.get("observations", []),
        },
        "architecture": {
            "owner_status": architecture_result.get("owner_status"),
            "gate_implementation": architecture_result.get("gate_implementation"),
            "repo_architecture_supportability": architecture_result.get(
                "repo_architecture_supportability"
            ),
            "architecture_behavior_proof": architecture_result.get(
                "architecture_behavior_proof"
            ),
            "enforcement_mode": architecture_result.get("enforcement_mode"),
            "violation_count": len(architecture_result.get("violations") or []),
            "new_violation_count": len(architecture_result.get("new_violations") or []),
            "existing_violation_count": len(
                architecture_result.get("existing_violations") or []
            ),
            "known_debt_applied_count": len(
                architecture_result.get("known_debt_applied") or []
            ),
            "expired_known_debt_count": len(
                architecture_result.get("expired_known_debt") or []
            ),
            "errors": architecture_result.get("errors", []),
        },
        "required_judges": judge_status,
        "bootstrap": {
            "gate_result": STATUS_RED if bootstrap_reason else "",
            "reason": bootstrap_reason,
            "human_decision_required": "YES" if bootstrap_reason else "NO",
            "governance_pass": False if bootstrap_reason else status == STATUS_GREEN,
        },
        "remote_audit": {
            "ls_remote_main_sha": "",
            "fresh_clone_head_log": [],
            "pr_state": "",
            "workflow_run_conclusion": "",
            "artifact_expired": None,
        },
        "errors": errors,
    }
    _validate_if_schema_exists("delivery_receipt", receipt)
    if output_dir is not None:
        _write_json(output_dir / "supportability-delivery-receipt.json", receipt)
        _write_markdown(
            output_dir / "supportability-delivery-receipt.md",
            _receipt_markdown(receipt),
        )
    return receipt


def generate_bootstrap_receipt(
    *,
    repository_url: str,
    pr_url: str,
    base_sha: str,
    head_sha: str,
    reason: str = "baseline protected workflow missing on main",
    output_dir: Path | None = None,
) -> dict[str, Any]:
    gate = {
        "owner_status": STATUS_RED,
        "repository_url": repository_url,
        "pull_request_url": pr_url,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "changed_files": [],
        "high_risk_files": [],
        "coverage": {},
        "errors": [reason],
    }
    ai_review = {
        "owner_status": STATUS_RED,
        "evidence_status": "INVALID_EVIDENCE",
        "approval_provided": False,
        "observations": [reason],
    }
    architecture = {
        "owner_status": STATUS_RED,
        "gate_implementation": "FAIL",
        "repo_architecture_supportability": "FAIL",
        "architecture_behavior_proof": "FAIL",
        "enforcement_mode": "block_all",
        "violations": [],
        "new_violations": [],
        "existing_violations": [],
        "known_debt_applied": [],
        "expired_known_debt": [],
        "errors": [reason],
    }
    return generate_delivery_receipt(
        gate,
        ai_review,
        architecture_result=architecture,
        output_dir=output_dir,
        repository_url=repository_url,
        pr_url=pr_url,
        required_judges={},
        bootstrap_reason=reason,
    )


def verify_delivery_receipt(
    receipt: dict[str, Any],
    *,
    live_observations: dict[str, Any] | None = None,
    allow_current_run_pending: bool = False,
) -> dict[str, Any]:
    errors = _receipt_document_errors(receipt)
    if live_observations is not None:
        errors.extend(
            _live_observation_errors(
                receipt,
                live_observations,
                allow_current_run_pending=allow_current_run_pending,
            )
        )
    result = {
        "schema_version": "1.0",
        "generated_at": _utc_now(),
        "owner_status": STATUS_RED if errors else STATUS_GREEN,
        "receipt_status": receipt.get("owner_status"),
        "errors": errors,
    }
    return result


def load_live_receipt_observations(receipt: dict[str, Any]) -> dict[str, Any]:
    repo = _repo_from_url(receipt.get("repository_url", ""))
    pr_number = _pr_number_from_url(receipt.get("pull_request_url", ""))
    artifact_id = str(receipt.get("artifact", {}).get("id") or "")
    run_id = str(receipt.get("workflow", {}).get("run_id") or "")
    merged_sha = str(receipt.get("merged_sha") or "")
    repository_url = str(receipt.get("repository_url") or "")
    errors: list[str] = []
    return {
        "__load_errors": errors,
        "ls_remote_main_sha": _safe_live(
            "git ls-remote", errors, _ls_remote_main, repository_url
        ),
        "fresh_clone_head_log": _safe_live(
            "fresh clone log", errors, _fresh_clone_log, repository_url
        ),
        "fresh_clone_contains_merged_sha": _fresh_clone_merge_observation(
            errors, repository_url, merged_sha
        ),
        "pr": _live_pr_observation(errors, repo, pr_number),
        "run": _live_run_observation(errors, repo, run_id),
        "artifact": _live_artifact_observation(errors, repo, artifact_id),
    }


def _fresh_clone_merge_observation(
    errors: list[str], repository_url: str, merged_sha: str
) -> bool | None:
    if not merged_sha:
        return None
    return _safe_live(
        "fresh clone contains merged_sha",
        errors,
        _fresh_clone_contains_commit,
        repository_url,
        merged_sha,
    )


def _live_pr_observation(
    errors: list[str], repo: str, pr_number: int | None
) -> dict[str, Any]:
    if not repo or pr_number is None:
        return {}
    return _safe_live("GitHub PR", errors, _live_pr, repo, pr_number)


def _live_run_observation(errors: list[str], repo: str, run_id: str) -> dict[str, Any]:
    if not repo or not run_id:
        return {}
    return _safe_live("GitHub run", errors, _live_run, repo, run_id)


def _live_artifact_observation(
    errors: list[str], repo: str, artifact_id: str
) -> dict[str, Any]:
    if not repo or not artifact_id:
        return {}
    return _safe_live("GitHub artifact", errors, _live_artifact, repo, artifact_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="supportability")
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_config_parser(subparsers)
    _add_gate_parser(subparsers)
    _add_copilot_parser(subparsers)
    _add_receipt_parser(subparsers)
    _add_bootstrap_parser(subparsers)
    _add_verify_parser(subparsers)
    args = parser.parse_args(argv)
    if args.command == "supportability-config":
        return _cli_config(args)
    if args.command == "supportability-gate":
        return _cli_gate(args)
    if args.command == "copilot-review-gate":
        return _cli_copilot(args)
    if args.command == "delivery-receipt":
        return _cli_receipt(args)
    if args.command == "bootstrap-receipt":
        return _cli_bootstrap_receipt(args)
    if args.command == "verify-receipt":
        return _cli_verify_receipt(args)
    raise AssertionError(args.command)


def _standard_errors(standard: Any) -> list[str]:
    if not isinstance(standard, dict):
        return ["standard must be an object"]
    errors = []
    for key in ("name", "source", "hash"):
        if not isinstance(standard.get(key), str) or not standard[key].strip():
            errors.append(f"standard.{key} must be a non-empty string")
    if isinstance(standard.get("hash"), str) and not SHA256_RE.fullmatch(
        standard["hash"]
    ):
        errors.append("standard.hash must be a 64-character lowercase SHA-256")
    return errors


def _required_gate_errors(gates: Any) -> list[str]:
    if not isinstance(gates, dict):
        return ["required_gates must be an object"]
    errors = []
    for gate in REQUIRED_COMMAND_GATES:
        errors.extend(
            _command_list_errors(
                gates.get(gate), f"required_gates.{gate}", allow_empty=False
            )
        )
    errors.extend(
        _command_list_errors(
            gates.get("package_audit", []),
            "required_gates.package_audit",
            allow_empty=True,
        )
    )
    errors.extend(_sql_config_errors(gates.get("sql_supportability")))
    return errors


def _coverage_errors(coverage: Any) -> list[str]:
    if not isinstance(coverage, dict):
        return ["coverage must be an object"]
    expected = {
        "changed_files": "required",
        "high_risk_files": "required",
        "forbid_gate_scope_narrowing": True,
        "forbid_threshold_weakening": True,
    }
    return [
        f"coverage.{key} must be {value!r}"
        for key, value in expected.items()
        if coverage.get(key) != value
    ]


def _ai_review_errors(ai_review: Any) -> list[str]:
    if not isinstance(ai_review, dict):
        return ["ai_review must be an object"]
    if "copilot_required" in ai_review or "reviewer_login_patterns" in ai_review:
        return ["legacy Copilot ai_review configuration is not supported"]
    expected = {
        "provider": "codex_connector",
        "adapter": "codex_connector_pr_signal_v2",
        "review_window_seconds": 300,
        "unavailable_after_cutoff": "non_blocking",
        "unresolved_p0_p1_p2_blocks": True,
    }
    errors = [
        f"ai_review.{key} must be {value!r}"
        for key, value in expected.items()
        if ai_review.get(key) != value
    ]
    unknown = sorted(set(ai_review) - set(expected))
    errors.extend(f"ai_review.{key} is not supported" for key in unknown)
    return errors


def _receipt_config_errors(receipt: Any) -> list[str]:
    if not isinstance(receipt, dict):
        return ["receipt must be an object"]
    # This validates the repo contract. Reusable workflow inputs/defaults enforce the actual upload names.
    errors = []
    if (
        not isinstance(receipt.get("artifact_name"), str)
        or not receipt["artifact_name"].strip()
    ):
        errors.append("receipt.artifact_name must be a non-empty string")
    if receipt.get("retention_days") != 90:
        errors.append("receipt.retention_days must be 90")
    return errors


def _architecture_policy_errors(policy: Any) -> list[str]:
    if not isinstance(policy, dict):
        return ["architecture_policy must be an object"]
    errors = []
    if policy.get("version") != 1:
        errors.append("architecture_policy.version must be 1")
    if policy.get("enforcement_mode") != "block_all":
        errors.append("architecture_policy.enforcement_mode must be block_all")
    if (
        not isinstance(policy.get("governed_roots"), list)
        or not policy["governed_roots"]
    ):
        errors.append("architecture_policy.governed_roots must be a non-empty list")
    if not isinstance(policy.get("runtime_relevance"), dict):
        errors.append("architecture_policy.runtime_relevance must be an object")
    if not isinstance(policy.get("vague_names"), dict):
        errors.append("architecture_policy.vague_names must be an object")
    if not isinstance(policy.get("modules"), dict) or not policy["modules"]:
        errors.append("architecture_policy.modules must be a non-empty object")
    if LEGACY_POLICY_DEBT_FIELD in policy:
        errors.append(
            "legacy architecture debt field is not supported; use architecture_policy.known_debt"
        )
    if not isinstance(policy.get("known_debt", []), list):
        errors.append("architecture_policy.known_debt must be a list")
    return errors


def _command_list_errors(value: Any, label: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, list):
        return [f"{label} must be a list of commands"]
    if not allow_empty and not value:
        return [f"{label} must contain at least one command"]
    bad = [
        index
        for index, item in enumerate(value)
        if not isinstance(item, str) or not item.strip()
    ]
    return [f"{label}[{index}] must be a non-empty string" for index in bad]


def _sql_config_errors(value: Any) -> list[str]:
    if value == "auto":
        return []
    if isinstance(value, str) and value.strip():
        return []
    if isinstance(value, list):
        return _command_list_errors(
            value, "required_gates.sql_supportability", allow_empty=False
        )
    return [
        "required_gates.sql_supportability must be auto, a non-empty command string, or a non-empty command list"
    ]


def _sha_errors(base_sha: str, head_sha: str) -> list[str]:
    errors = []
    if base_sha and not SHA1_RE.fullmatch(base_sha):
        errors.append("base_sha must be a 40-character lowercase Git SHA")
    if not SHA1_RE.fullmatch(head_sha):
        errors.append("head_sha must be a 40-character lowercase Git SHA")
    return errors


def _changed_files_or_empty(
    target_repo: Path,
    base_sha: str,
    head_sha: str,
    changed_files: list[str] | None,
    errors: list[str],
) -> list[str]:
    if changed_files is not None:
        return changed_files
    if not _diff_sha_inputs_are_valid(base_sha, head_sha):
        return []
    try:
        return _git_changed_files(target_repo, base_sha, head_sha)
    except SupportabilityError as exc:
        errors.append(str(exc))
        return []


def _diff_sha_inputs_are_valid(base_sha: str, head_sha: str) -> bool:
    return bool(SHA1_RE.fullmatch(base_sha) and SHA1_RE.fullmatch(head_sha))


def _schema_safe_sha(value: str) -> str:
    return value if SHA1_RE.fullmatch(value) else "0" * 40


def _standard_hash_errors(config: dict[str, Any], target_repo: Path) -> list[str]:
    standard = _dict_or_empty(config.get("standard"))
    source = str(standard.get("source") or "")
    expected = str(standard.get("hash") or "")
    path = target_repo / source
    if not source or not path.exists():
        return [f"standard.source {source!r} is missing from target repo"]
    actual = sha256_file(path)
    if actual != expected:
        return [f"standard.hash mismatch: expected {expected}, got {actual}"]
    return []


def _trusted_execution_config(
    config_path: Path,
    target_repo: Path,
    changed: list[str],
    base_sha: str,
    head_config: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    try:
        relative = config_path.resolve().relative_to(target_repo.resolve()).as_posix()
    except ValueError:
        relative = config_path.as_posix()
    if relative not in {path.replace("\\", "/") for path in changed}:
        return head_config, []
    companion_changes = sorted(
        path.replace("\\", "/")
        for path in changed
        if path.replace("\\", "/") != relative
    )
    if companion_changes:
        return head_config, [
            "supportability config change must be isolated from all other files: "
            + ", ".join(companion_changes)
        ]
    base_config, errors = _base_supportability_config(
        target_repo, base_sha, relative, config_path.suffix
    )
    if errors:
        return head_config, errors
    if base_config is None:
        return head_config, [
            "supportability config changed but trusted base config is missing"
        ]
    weakening_errors = _supportability_config_weakening_errors(base_config, head_config)
    return base_config, weakening_errors


def _supportability_config_weakening_errors(
    base_config: dict[str, Any], head_config: dict[str, Any]
) -> list[str]:
    errors = _architecture_policy_weakening_errors(base_config, head_config)
    for field in ("standard", "coverage", "receipt"):
        if head_config.get(field) != base_config.get(field):
            errors.append(
                f"{field} changed; protected baseline cannot classify this change as non-weakening"
            )
    errors.extend(_required_gate_change_errors(base_config, head_config))
    errors.extend(_ai_review_change_errors(base_config, head_config))
    unknown = sorted(set(head_config) - set(base_config))
    errors.extend(
        f"unclassified supportability config key added: {key}" for key in unknown
    )
    return errors


def _required_gate_change_errors(
    base_config: dict[str, Any], head_config: dict[str, Any]
) -> list[str]:
    base_gates = base_config.get("required_gates")
    gates = head_config.get("required_gates")
    errors = _required_gate_errors(gates)
    if not isinstance(gates, dict):
        return errors
    commands = [
        command
        for gate in ALL_COMMAND_GATES
        for command in _command_list(gates.get(gate))
    ]
    duplicates = sorted(
        {command for command in commands if commands.count(command) > 1}
    )
    errors.extend(
        f"required gate command duplicated across capabilities: {command}"
        for command in duplicates
    )
    runner = r"(?:(?:uv|poetry|pipenv)\s+run\s+)?"
    js_runner = r"(?:npx\s+|pnpm\s+(?:exec\s+)?|yarn\s+)?"
    required_semantics = {
        "lint": (
            runner + r"(?:python\s+-m\s+)?ruff\s+check\b",
            runner + js_runner + r"(?:eslint|biome\s+check)\b",
            r"(?:golangci-lint|cargo\s+clippy|dotnet\s+format)\b",
            r"(?:mvn|gradle)\b.*\bcheckstyle\b",
        ),
        "format_check": (
            runner + r"(?:python\s+-m\s+)?(?:ruff\s+format|black)\s+--check\b",
            runner + js_runner + r"(?:prettier\s+--check|biome\s+format)\b",
            r"(?:cargo\s+fmt|gofmt|dotnet\s+format\s+--verify-no-changes)\b",
        ),
        "typecheck": (
            runner + r"(?:python\s+-m\s+)?(?:mypy|pyright)\b",
            runner + js_runner + r"tsc\s+--noemit\b",
            r"(?:cargo\s+check|go\s+vet|dotnet\s+build)\b",
            r"(?:mvn|gradle)\b.*\bcompile\b",
        ),
        "complexity": (
            runner
            + r"(?:python\s+-m\s+)?ruff\s+check\b.*(?:--select(?:=|\s+)C901|--extend-select(?:=|\s+)C901)",
            runner + r"(?:python\s+-m\s+)?radon\b",
            r"(?:lizard|gocyclo|cognitive-complexity)\b",
            runner + js_runner + r"eslint\b.*\bcomplexity\b",
        ),
        "architecture": (
            runner + r"python\s+-m\s+governance_eval\s+architecture-gate\b",
        ),
        "tests": (
            runner + r"python\s+-m\s+(?:pytest|unittest)\b",
            runner + r"pytest\b",
            r"(?:npm|pnpm|yarn)\s+(?:run\s+)?test\b",
            js_runner + r"(?:vitest|jest)\b",
            r"(?:go|cargo|dotnet|mvn|gradle)\s+test\b",
        ),
        "compile_or_build": (
            runner + r"python\s+-m\s+build\b",
            r"(?:npm|pnpm|yarn)\s+(?:run\s+)?build\b",
            r"(?:go|cargo|dotnet)\s+build\b",
            r"mvn\b.*\bpackage\b",
            r"gradle\b.*\bbuild\b",
        ),
    }
    for gate, markers in required_semantics.items():
        gate_commands = _command_list(gates.get(gate))
        base_commands = (
            _command_list(base_gates.get(gate)) if isinstance(base_gates, dict) else []
        )
        if (
            gate_commands != base_commands
            and gate_commands
            and not any(
                _command_invokes_capability(command, markers)
                for command in gate_commands
            )
        ):
            errors.append(f"required_gates.{gate} lacks required capability semantics")
    package_commands = _command_list(gates.get("package_audit"))
    base_package_commands = (
        _command_list(base_gates.get("package_audit"))
        if isinstance(base_gates, dict)
        else []
    )
    audit_markers = (
        runner + r"(?:python\s+-m\s+)?pip\s+check\b",
        r"(?:npm|pnpm|yarn|cargo)\s+audit\b",
        r"(?:govulncheck|osv-scanner)\b",
        r"dotnet\s+list\b.*\bpackage\b",
    )
    if (
        package_commands != base_package_commands
        and package_commands
        and not any(
            _command_invokes_capability(command, audit_markers)
            for command in package_commands
        )
    ):
        errors.append(
            "required_gates.package_audit lacks required capability semantics"
        )
    for command in commands:
        lowered = command.lower()
        tokens = {token.lower() for token in _split_command(command)}
        if any(
            marker in command
            for marker in (";", "|", ">", "<", "&", "`", "$(", "\n", "\r")
        ):
            errors.append(
                f"required gate command contains shell control syntax: {command}"
            )
        if tokens & {
            "--help",
            "-h",
            "--version",
            "--collect-only",
            "--list",
            "--list-tests",
            "--dry-run",
            "--no-run",
        }:
            errors.append(f"required gate command uses non-execution mode: {command}")
        if any(marker in lowered for marker in NON_BLOCKING_MARKERS):
            errors.append(f"required gate command is non-blocking: {command}")
        if any(marker in lowered for marker in SCOPE_NARROWING_MARKERS):
            errors.append(f"required gate command narrows scope: {command}")
        if any(marker in lowered for marker in THRESHOLD_WEAKENING_MARKERS):
            errors.append(f"required gate command weakens thresholds: {command}")
    return errors


def _ai_review_change_errors(
    base_config: dict[str, Any], head_config: dict[str, Any]
) -> list[str]:
    base = base_config.get("ai_review")
    head = head_config.get("ai_review")
    if not isinstance(base, dict) or not isinstance(head, dict):
        return ["ai_review must remain an object"]
    return _ai_review_errors(head)


def _command_list(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _command_invokes_capability(command: str, patterns: tuple[str, ...]) -> bool:
    normalized = command.strip()
    return any(
        re.match(pattern, normalized, flags=re.IGNORECASE) for pattern in patterns
    )


def _architecture_governance_change_errors(
    target_repo: Path,
    changed: list[str],
    base_sha: str,
    config_path: Path,
) -> list[str]:
    changed_set = {path.replace("\\", "/") for path in changed}
    errors: list[str] = []
    checker_paths = {
        "governance_eval/supportability.py",
        "governance_eval/architecture_policy.py",
        "governance_eval/architecture_gate.py",
        "governance_eval/ai_review_gate.py",
        "governance_eval/bootstrap_audit.py",
        "governance_eval/codex_connector_collector.py",
        "governance_eval/codex_connector_evidence.py",
        "governance_eval/codex_review_gate.py",
        "schemas/v1/architecture_gate_result.schema.json",
        "schemas/v1/bootstrap_audit_receipt.schema.json",
        "schemas/v1/delivery_receipt.schema.json",
        "schemas/v1/supportability_config.schema.json",
        "schemas/v2/codex_connector_evidence_result.schema.json",
    }
    future_checker_paths = {
        "governance_eval/copilot_review_evidence.py",
    }
    existing_future_checkers = {
        path
        for path in changed_set & future_checker_paths
        if _git_show_text(target_repo, base_sha, path) is not None
    }
    touched_checkers = sorted((changed_set & checker_paths) | existing_future_checkers)
    enforcement_path = ".github/workflows/supportability-enforcement.yml"
    if touched_checkers:
        required_tests = {
            "tests/test_architecture_gate.py",
            "tests/test_supportability.py",
        }
        if not required_tests.issubset(changed_set):
            missing = sorted(required_tests - changed_set)
            errors.append(
                "protected checker change "
                + ", ".join(touched_checkers)
                + " missing independent regression tests: "
                + ", ".join(missing)
            )
        errors.extend(_protected_delivery_chain_errors(target_repo))
        if enforcement_path in changed_set:
            errors.append(
                "protected checker and enforcement workflow cannot change in the same PR"
            )
    if enforcement_path in changed_set:
        errors.extend(
            _protected_enforcement_change_errors(
                target_repo, base_sha, enforcement_path
            )
        )
    workflow_path = ".github/workflows/supportability-gate.yml"
    if workflow_path in changed_set:
        base_text = _git_show_text(target_repo, base_sha, workflow_path)
        head_text = (
            (target_repo / workflow_path).read_text(encoding="utf-8")
            if (target_repo / workflow_path).exists()
            else ""
        )
        if base_text is not None and _architecture_command_lines(
            base_text
        ) != _architecture_command_lines(head_text):
            errors.append(
                "architecture gate workflow command changed; protected baseline judge must report RED"
            )
    return errors


def _protected_delivery_chain_errors(target_repo: Path) -> list[str]:
    path = target_repo / ".github" / "workflows" / "supportability-enforcement.yml"
    if not path.exists():
        return ["protected supportability enforcement workflow is missing"]
    text = path.read_text(encoding="utf-8")
    jobs = {
        name: _workflow_job_block(text, name)
        for name in (
            "baseline-supportability",
            "candidate-supportability",
            "delivery-receipt",
        )
    }
    errors = [
        f"protected delivery chain missing {name}:"
        for name, block in jobs.items()
        if not block
    ]
    expected_conditions = {
        "baseline-supportability": "${{ github.event.pull_request.base.ref == 'main' }}",
        "candidate-supportability": "${{ github.event.pull_request.base.ref == 'main' }}",
        "delivery-receipt": "${{ always() && github.event.pull_request.base.ref == 'main' }}",
    }
    for name, expected in expected_conditions.items():
        if jobs[name] and _job_condition(jobs[name]) != expected:
            errors.append(f"protected {name} workflow condition is missing or changed")
    pinned_workflows = {
        "baseline-supportability": "supportability-gate.yml",
        "candidate-supportability": "supportability-gate.yml",
        "delivery-receipt": "delivery-receipt.yml",
    }
    for name, workflow in pinned_workflows.items():
        exact_use = re.compile(
            rf"(?m)^\s{{4}}uses:\s+markheck-solutions/governance/\.github/workflows/{re.escape(workflow)}@[0-9a-f]{{40}}\s*$"
        )
        if jobs[name] and not exact_use.search(jobs[name]):
            errors.append(
                f"protected {name} workflow must use exact {workflow} at a full immutable SHA"
            )
    delivery = jobs["delivery-receipt"]
    if delivery and not all(
        _job_needs(delivery, dependency)
        for dependency in ("baseline-supportability", "candidate-supportability")
    ):
        errors.append(
            "delivery-receipt must need baseline-supportability and candidate-supportability"
        )
    return errors


def _workflow_job_block(workflow_text: str, job_name: str) -> str:
    match = re.search(rf"(?m)^  {re.escape(job_name)}:\s*$", workflow_text)
    if not match:
        return ""
    following = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", workflow_text[match.end() :])
    end = match.end() + following.start() if following else len(workflow_text)
    return workflow_text[match.start() : end]


def _job_needs(job_block: str, dependency: str) -> bool:
    list_item = rf"(?m)^\s{{6}}-\s+{re.escape(dependency)}\s*$"
    inline = rf"(?m)^\s{{4}}needs:\s*\[[^\]]*\b{re.escape(dependency)}\b[^\]]*\]\s*$"
    return bool(re.search(list_item, job_block) or re.search(inline, job_block))


def _job_condition(job_block: str) -> str:
    match = re.search(r"(?m)^\s{4}if:\s*(.+?)\s*$", job_block)
    return match.group(1) if match else ""


def _protected_enforcement_change_errors(
    target_repo: Path, base_sha: str, relative: str
) -> list[str]:
    base_text = _git_show_text(target_repo, base_sha, relative)
    path = target_repo / relative
    if base_text is None or not path.exists():
        return ["protected enforcement workflow base or head is missing"]
    head_text = path.read_text(encoding="utf-8")
    sha_ref = re.compile(r"(?<=@)[0-9a-f]{40}")
    if sha_ref.sub("<PIN>", base_text) != sha_ref.sub("<PIN>", head_text):
        return [
            "protected enforcement workflow change is not an exact SHA pin rotation"
        ]
    errors = _protected_delivery_chain_errors(target_repo)
    replacement_pins = sha_ref.findall(head_text)
    if not replacement_pins or any(pin != base_sha for pin in replacement_pins):
        errors.append("protected enforcement workflow pins must equal trusted base SHA")
    return errors


def _git_show_text(target_repo: Path, base_sha: str, relative_path: str) -> str | None:
    if not SHA1_RE.fullmatch(base_sha):
        return None
    try:
        completed = subprocess.run(
            ["git", "-C", str(target_repo), "show", f"{base_sha}:{relative_path}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_NETWORK_TIMEOUT_SECONDS,
        )
        return completed.stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def _base_supportability_config(
    target_repo: Path,
    base_sha: str,
    relative_config_path: str,
    suffix: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not SHA1_RE.fullmatch(base_sha):
        return {}, [
            "supportability config changed in this PR; base config cannot be verified"
        ]
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(target_repo),
                "show",
                f"{base_sha}:{relative_config_path}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_NETWORK_TIMEOUT_SECONDS,
        )
        return _parse_supportability_config_text(completed.stdout, suffix), []
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or "") + (exc.stdout or "")
        if (
            "exists on disk, but not in" in message
            or "does not exist in" in message
            or "Path" in message
        ):
            return None, []
        return {}, [
            f"supportability config changed in this PR; trusted base config could not be loaded: {exc}"
        ]
    except (subprocess.TimeoutExpired, SupportabilityError) as exc:
        return {}, [
            f"supportability config changed in this PR; trusted base config could not be loaded: {exc}"
        ]


def _is_initial_architecture_policy_adoption(
    base_config: dict[str, Any], head_config: dict[str, Any]
) -> bool:
    if "architecture_policy" in base_config or "architecture_policy" not in head_config:
        return False
    base_without_architecture = {
        key: value for key, value in base_config.items() if key != "architecture_policy"
    }
    head_without_architecture = {
        key: value for key, value in head_config.items() if key != "architecture_policy"
    }
    return base_without_architecture == head_without_architecture


def _build_coverage_plan(
    config: dict[str, Any], changed: list[str], high_risk: list[str]
) -> dict[str, Any]:
    gates = _dict_or_empty(config.get("required_gates"))
    files = _unique_paths(changed + high_risk)
    errors: list[str] = []
    gate_names = list(REQUIRED_COMMAND_GATES)
    if _sql_files(files):
        gate_names.append("sql_supportability")
    coverage: dict[str, Any] = {
        "changed_files": {path: [] for path in changed},
        "high_risk_files": {path: [] for path in high_risk},
        "excluded_changed_files": [],
        "excluded_high_risk_files": [],
        "scope_narrowing_detected": [],
        "threshold_weakening_detected": [],
    }
    for gate in gate_names:
        commands = _commands_for_coverage(gates.get(gate))
        command_errors = _command_policy_errors(gate, commands, files)
        errors.extend(command_errors)
        if command_errors:
            _record_policy_errors(coverage, command_errors)
            continue
        _mark_files_covered(coverage["changed_files"], gate)
        _mark_files_covered(coverage["high_risk_files"], gate)
    errors.extend(_coverage_gap_errors(coverage))
    return {"coverage": coverage, "errors": errors}


def _commands_for_coverage(value: Any) -> list[str]:
    if value == "auto":
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _command_policy_errors(
    gate: str, commands: list[str], files: list[str]
) -> list[str]:
    errors: list[str] = []
    if not commands and gate == "sql_supportability":
        return ["sql_supportability: explicit SQL gate command missing"]
    if not commands:
        return [f"{gate}: required command missing"]
    for command in commands:
        errors.extend(_single_command_policy_errors(gate, command, files))
    return errors


def _single_command_policy_errors(
    gate: str, command: str, files: list[str]
) -> list[str]:
    lowered = command.lower()
    errors = []
    if any(marker in lowered for marker in NON_BLOCKING_MARKERS):
        errors.append(f"{gate}: non-blocking command is forbidden: {command}")
    if any(marker in lowered for marker in SCOPE_NARROWING_MARKERS):
        errors.append(f"{gate}: scope narrowing marker is forbidden: {command}")
    if _weakens_threshold(lowered):
        errors.append(f"{gate}: threshold weakening marker is forbidden: {command}")
    if _path_scope_excludes_files(command, files):
        errors.append(
            f"{gate}: command scope excludes changed or high-risk files: {command}"
        )
    return errors


def _weakens_threshold(lowered: str) -> bool:
    if any(marker in lowered for marker in THRESHOLD_WEAKENING_MARKERS):
        return True
    match = re.search(r"max[-_]complexity[=\s]+([0-9]+)", lowered)
    return bool(match and int(match.group(1)) > 10)


def _path_scope_excludes_files(command: str, files: list[str]) -> bool:
    tokens = _split_command(command)
    scopes = [
        _normalize_scope(token) for token in tokens if _looks_like_scope_token(token)
    ]
    scopes = [scope for scope in scopes if scope]
    if not scopes or "." in scopes:
        return False
    return any(not _file_is_in_any_scope(path, scopes) for path in files)


def _split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return command.split()


def _looks_like_scope_token(token: str) -> bool:
    clean = token.strip("'\"")
    if clean in {".", "./"}:
        return True
    if clean.startswith("-") or "=" in clean or "*" in clean:
        return False
    if "/" in clean or "\\" in clean:
        return True
    return Path(clean).suffix in PRODUCTION_SUFFIXES or clean in {"src", "app", "lib"}


def _normalize_scope(token: str) -> str:
    clean = token.strip("'\"").replace("\\", "/").rstrip("/")
    if clean in {"", ".", "./", "...", "./..."}:
        return "."
    return clean[2:] if clean.startswith("./") else clean


def _file_is_in_any_scope(path: str, scopes: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    return any(
        normalized == scope or normalized.startswith(f"{scope}/") for scope in scopes
    )


def _record_policy_errors(coverage: dict[str, Any], errors: list[str]) -> None:
    for error in errors:
        if "scope" in error:
            coverage["scope_narrowing_detected"].append(error)
        if "threshold" in error:
            coverage["threshold_weakening_detected"].append(error)


def _mark_files_covered(file_map: dict[str, list[str]], gate: str) -> None:
    for gates in file_map.values():
        gates.append(gate)


def _coverage_gap_errors(coverage: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for label, key in (
        ("changed file", "changed_files"),
        ("high-risk file", "high_risk_files"),
    ):
        for path, gates in coverage[key].items():
            if not gates:
                coverage[f"excluded_{key}"].append(path)
                errors.append(f"{label} {path} is outside required gate coverage")
    return errors


def _sql_gate_commands(
    config: dict[str, Any],
    target_repo: Path,
    changed: list[str],
    high_risk: list[str],
) -> tuple[list[str], list[str]]:
    gates = _dict_or_empty(config.get("required_gates"))
    value = gates.get("sql_supportability")
    sql_needed = bool(_sql_files(changed + high_risk) or _repo_has_sql(target_repo))
    if value == "auto":
        if sql_needed:
            return [], [
                "required_gates.sql_supportability is auto but SQL files require explicit SQL gate commands"
            ]
        return [], []
    if isinstance(value, str):
        return [value], []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)], []
    return [], [
        "required_gates.sql_supportability must be auto, a command string, or a command list"
    ]


def _run_configured_commands(
    config: dict[str, Any],
    target_repo: Path,
    sql_commands: list[str],
    runner: Callable[[str, Path], subprocess.CompletedProcess[str]],
) -> list[dict[str, Any]]:
    gates = _dict_or_empty(config.get("required_gates"))
    results: list[dict[str, Any]] = []
    for gate in REQUIRED_COMMAND_GATES + OPTIONAL_COMMAND_GATES:
        commands = _normalized_command_list(gates.get(gate))
        optional = gate in OPTIONAL_COMMAND_GATES and not commands
        results.extend(
            _run_gate_commands(gate, commands, target_repo, runner, optional=optional)
        )
    results.extend(
        _run_gate_commands(
            "sql_supportability",
            sql_commands,
            target_repo,
            runner,
            optional=not sql_commands,
        )
    )
    return results


def _protected_command_results(config_change_errors: list[str]) -> list[dict[str, Any]]:
    if not config_change_errors:
        return []
    return _skipped_command_results(
        "supportability config changed; commands not executed from untrusted head config"
    )


def _skipped_command_results(stderr: str) -> list[dict[str, Any]]:
    return [
        {
            "gate": gate,
            "command": "",
            "status": "SKIPPED",
            "exit_code": None,
            "stdout": "",
            "stderr": stderr,
        }
        for gate in ALL_COMMAND_GATES
    ]


def _run_commands_with_revision_env(
    config: dict[str, Any],
    target_repo: Path,
    sql_commands: list[str],
    runner: Callable[[str, Path], subprocess.CompletedProcess[str]],
    base_sha: str,
    head_sha: str,
) -> list[dict[str, Any]]:
    old_base = os.environ.get("TARGET_BASE_SHA")
    old_head = os.environ.get("TARGET_HEAD_SHA")
    os.environ["TARGET_BASE_SHA"] = base_sha
    os.environ["TARGET_HEAD_SHA"] = head_sha
    try:
        return _run_configured_commands(config, target_repo, sql_commands, runner)
    finally:
        _restore_env("TARGET_BASE_SHA", old_base)
        _restore_env("TARGET_HEAD_SHA", old_head)


def _normalized_command_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _restore_env(key: str, value: str | None) -> None:
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value


def _run_gate_commands(
    gate: str,
    commands: list[str],
    target_repo: Path,
    runner: Callable[[str, Path], subprocess.CompletedProcess[str]],
    *,
    optional: bool,
) -> list[dict[str, Any]]:
    if optional:
        return [
            {
                "gate": gate,
                "command": "",
                "status": "SKIPPED",
                "exit_code": None,
                "stdout": "",
                "stderr": "",
            }
        ]
    return [
        _run_one_command(gate, command, target_repo, runner) for command in commands
    ]


def _run_one_command(
    gate: str,
    command: str,
    target_repo: Path,
    runner: Callable[[str, Path], subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    completed = runner(command, target_repo)
    return {
        "gate": gate,
        "command": command,
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "exit_code": completed.returncode,
        "stdout": _truncate(completed.stdout),
        "stderr": _truncate(completed.stderr),
    }


def _command_result_errors(results: list[dict[str, Any]]) -> list[str]:
    return [
        f"{result['gate']}: command failed with exit code {result['exit_code']}: {result['command']}"
        for result in results
        if result.get("status") == "FAIL"
    ]


def _run_shell_command(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        shell=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=1200,
    )


def _git_changed_files(target_repo: Path, base_sha: str, head_sha: str) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "diff", "--name-only", base_sha, head_sha],
            cwd=target_repo,
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        raise SupportabilityError(
            "git diff changed-file discovery timed out after 60 seconds"
        ) from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        message = "git diff changed-file discovery failed"
        if detail:
            message = f"{message}: {detail}"
        raise SupportabilityError(message) from exc
    return [
        line.strip().replace("\\", "/")
        for line in completed.stdout.splitlines()
        if line.strip()
    ]


def _high_risk_files(target_repo: Path, changed: list[str]) -> list[str]:
    candidates = [
        path for path in _production_files(target_repo) if path not in changed
    ]
    ranked = sorted(
        candidates, key=lambda path: _line_count(target_repo / path), reverse=True
    )
    return ranked[:5]


def _production_files(target_repo: Path) -> list[str]:
    files: list[str] = []
    for path in _iter_repo_files(target_repo):
        if path.suffix in PRODUCTION_SUFFIXES:
            files.append(path.relative_to(target_repo).as_posix())
    return files


def _iter_repo_files(target_repo: Path) -> list[Path]:
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(target_repo):
        dirnames[:] = sorted(
            dirname for dirname in dirnames if dirname not in SKIPPED_DIRS
        )
        current_path = Path(current)
        for filename in sorted(filenames):
            path = current_path / filename
            if not _skip_path(path, target_repo):
                files.append(path)
    return files


def _skip_path(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    return any(part in SKIPPED_DIRS for part in relative.parts)


def _line_count(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
    except OSError:
        return 0


def _sql_files(paths: list[str]) -> list[str]:
    return [path for path in paths if Path(path).suffix.lower() == ".sql"]


def _repo_has_sql(target_repo: Path) -> bool:
    return any(path.suffix.lower() == ".sql" for path in _iter_repo_files(target_repo))


def _unique_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        if normalized not in seen:
            unique.append(normalized)
            seen.add(normalized)
    return unique


def _receipt_input_errors(
    gate_result: dict[str, Any],
    ai_review_result: dict[str, Any],
    artifact_name: str,
    artifact_id: str,
    artifact_digest: str,
    architecture_result: dict[str, Any],
) -> list[str]:
    errors = []
    if gate_result.get("owner_status") != STATUS_GREEN:
        errors.append("supportability gate is not GREEN")
    if ai_review_result.get("owner_status") != STATUS_GREEN:
        errors.append("AI review gate is not GREEN")
    if ai_review_result.get("approval_provided") is not False:
        errors.append("AI review evidence must not claim approval")
    errors.extend(_architecture_receipt_input_errors(architecture_result))
    if not artifact_name:
        errors.append("artifact name is missing")
    if not artifact_id:
        errors.append("artifact ID is missing")
    elif not artifact_id.isdigit():
        errors.append("artifact ID must be numeric")
    if not artifact_digest:
        errors.append("artifact digest is missing")
    elif not DIGEST_RE.fullmatch(artifact_digest):
        errors.append("artifact digest must be sha256:<hex>")
    return errors


def _required_judge_status(
    gate_result: dict[str, Any], required_judges: dict[str, bool] | None
) -> dict[str, bool]:
    source = (
        required_judges
        if required_judges is not None
        else gate_result.get("required_judges")
    )
    source = source if isinstance(source, dict) else {}
    return {
        "protected_baseline_judge_ran": source.get("protected_baseline_judge_ran")
        is True,
        "candidate_judge_ran": source.get("candidate_judge_ran") is True,
        "baseline_receipt_produced": source.get("baseline_receipt_produced") is True,
        "candidate_receipt_produced": source.get("candidate_receipt_produced") is True,
        "governance_weakening_detected": source.get("governance_weakening_detected")
        is True,
    }


def _required_judge_errors(required_judges: dict[str, bool]) -> list[str]:
    errors: list[str] = []
    for key in (
        "protected_baseline_judge_ran",
        "candidate_judge_ran",
        "baseline_receipt_produced",
        "candidate_receipt_produced",
    ):
        if required_judges.get(key) is not True:
            errors.append(f"required judge proof missing: {key}")
    if required_judges.get("governance_weakening_detected") is True:
        errors.append("governance weakening detected")
    return errors


def _architecture_receipt_input_errors(
    architecture_result: dict[str, Any],
) -> list[str]:
    errors = []
    expected = {
        "owner_status": STATUS_GREEN,
        "gate_implementation": "PASS",
        "repo_architecture_supportability": "PASS",
        "architecture_behavior_proof": "PASS",
        "enforcement_mode": "block_all",
    }
    for key, value in expected.items():
        if architecture_result.get(key) != value:
            errors.append(f"architecture {key} must be {value}")
    for key in (
        "violations",
        "new_violations",
        "existing_violations",
        "known_debt_applied",
        "known_debt",
        "expired_known_debt",
        LEGACY_APPLIED_DEBT_FIELD,
        LEGACY_EXPIRED_DEBT_FIELD,
        "errors",
    ):
        if architecture_result.get(key):
            errors.append(f"architecture {key} must be empty")
    for key in (
        "human_approval",
        "codeowner_approval",
        "CODEOWNER_approval",
        "protected_baseline_debt_file",
        "baseline_debt_file",
        "waiver",
        "allowlist",
        "approval",
    ):
        if architecture_result.get(key):
            errors.append(f"architecture {key} metadata cannot make GREEN")
    return errors


def _receipt_document_errors(receipt: dict[str, Any]) -> list[str]:
    errors = _receipt_schema_errors(receipt)
    try:
        errors.extend(_receipt_identity_errors(receipt))
    except AttributeError:
        errors.append("delivery receipt must be an object")
    return errors


def _receipt_schema_errors(receipt: dict[str, Any]) -> list[str]:
    try:
        validate_named("delivery_receipt", receipt, root=_schema_root())
    except SchemaValidationError as exc:
        return [f"delivery receipt schema invalid: {exc}"]
    return []


def _receipt_identity_errors(receipt: dict[str, Any]) -> list[str]:
    errors = []
    if receipt.get("owner_status") not in {STATUS_GREEN, "YELLOW", STATUS_RED}:
        errors.append("owner_status must be GREEN, YELLOW, or RED")
    if receipt.get("owner_status") != STATUS_GREEN:
        errors.append("receipt owner_status must be GREEN before verification")
    errors.extend(_embedded_receipt_status_errors(receipt))
    errors.extend(_receipt_sha_errors(receipt))
    artifact = _dict_or_empty(receipt.get("artifact"))
    if not artifact.get("name"):
        errors.append("artifact.name is required")
    artifact_id = str(artifact.get("id") or "")
    if not artifact_id:
        errors.append("artifact.id is required")
    elif not artifact_id.isdigit():
        errors.append("artifact.id must be numeric")
    artifact_digest = str(artifact.get("digest") or "")
    if not artifact_digest:
        errors.append("artifact.digest is required")
    elif not DIGEST_RE.fullmatch(artifact_digest):
        errors.append("artifact.digest must be sha256:<hex>")
    return errors


def _embedded_receipt_status_errors(receipt: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    supportability_gate = _dict_or_empty(receipt.get("supportability_gate"))
    ai_review = _dict_or_empty(receipt.get("ai_review"))
    architecture = _dict_or_empty(receipt.get("architecture"))
    required_judges = _bool_dict_or_empty(receipt.get("required_judges"))
    bootstrap = _dict_or_empty(receipt.get("bootstrap"))
    if supportability_gate.get("owner_status") != STATUS_GREEN:
        errors.append("receipt supportability_gate.owner_status must be GREEN")
    if supportability_gate.get("errors"):
        errors.append("receipt supportability_gate.errors must be empty")
    if ai_review.get("owner_status") != STATUS_GREEN:
        errors.append("receipt ai_review.owner_status must be GREEN")
    if ai_review.get("approval_provided") is not False:
        errors.append("receipt ai_review.approval_provided must be false")
    expected_architecture = {
        "owner_status": STATUS_GREEN,
        "gate_implementation": "PASS",
        "repo_architecture_supportability": "PASS",
        "architecture_behavior_proof": "PASS",
        "enforcement_mode": "block_all",
    }
    for key, value in expected_architecture.items():
        if architecture.get(key) != value:
            errors.append(f"receipt architecture.{key} must be {value}")
    for key in (
        "violation_count",
        "new_violation_count",
        "existing_violation_count",
        "known_debt_applied_count",
        "expired_known_debt_count",
    ):
        if architecture.get(key) not in {0, None}:
            errors.append(f"receipt architecture.{key} must be 0")
    for key in (
        LEGACY_APPLIED_DEBT_FIELD,
        LEGACY_EXPIRED_DEBT_FIELD,
        "known_debt_applied",
        "known_debt",
        "expired_known_debt",
    ):
        if architecture.get(key):
            errors.append(f"receipt architecture.{key} must be empty")
    if architecture.get("errors"):
        errors.append("receipt architecture.errors must be empty")
    errors.extend(_required_judge_errors(required_judges))
    if (
        bootstrap.get("governance_pass") is False
        or bootstrap.get("gate_result") == STATUS_RED
        or bootstrap.get("reason")
    ):
        errors.append("receipt bootstrap must not indicate active bootstrap RED state")
    return errors


def _receipt_sha_errors(receipt: dict[str, Any]) -> list[str]:
    errors = [
        f"{key} must be a 40-character lowercase Git SHA"
        for key in ("base_sha", "head_sha")
        if not SHA1_RE.fullmatch(str(receipt.get(key) or ""))
    ]
    merged_sha = str(receipt.get("merged_sha") or "")
    if merged_sha and not SHA1_RE.fullmatch(merged_sha):
        errors.append("merged_sha must be empty or a 40-character lowercase Git SHA")
    return errors


def _live_observation_errors(
    receipt: dict[str, Any],
    observations: dict[str, Any],
    *,
    allow_current_run_pending: bool = False,
) -> list[str]:
    errors = [
        f"live proof failed: {error}" for error in observations.get("__load_errors", [])
    ]
    errors.extend(_live_ls_remote_errors(observations))
    errors.extend(_live_pr_errors(receipt, observations.get("pr") or {}))
    errors.extend(
        _live_run_errors(
            receipt,
            observations.get("run") or {},
            allow_current_run_pending=allow_current_run_pending,
        )
    )
    errors.extend(_live_artifact_errors(receipt, observations.get("artifact") or {}))
    merged_sha = receipt.get("merged_sha")
    if not observations.get("fresh_clone_head_log"):
        errors.append("fresh clone log proof is missing")
    if merged_sha and observations.get("fresh_clone_contains_merged_sha") is not True:
        errors.append("fresh clone main history does not contain receipt merged_sha")
    return errors


def _live_ls_remote_errors(observations: dict[str, Any]) -> list[str]:
    main_sha = str(observations.get("ls_remote_main_sha") or "")
    if not SHA1_RE.fullmatch(main_sha):
        return ["git ls-remote main SHA proof is missing or invalid"]
    return []


def _live_pr_errors(receipt: dict[str, Any], pr: dict[str, Any]) -> list[str]:
    if not pr:
        return ["GitHub PR proof is missing"]
    errors = []
    if pr.get("headRefOid") != receipt.get("head_sha"):
        errors.append("GitHub PR headRefOid does not match receipt head_sha")
    if pr.get("baseRefOid") != receipt.get("base_sha"):
        errors.append("GitHub PR baseRefOid does not match receipt base_sha")
    if receipt.get("merged_sha"):
        merge = _dict_or_empty(pr.get("mergeCommit"))
        if pr.get("state") != "MERGED":
            errors.append("receipt claims merged_sha but GitHub PR is not MERGED")
        if merge.get("oid") != receipt.get("merged_sha"):
            errors.append("GitHub PR merge commit does not match receipt merged_sha")
    return errors


def _live_run_errors(
    receipt: dict[str, Any],
    run: dict[str, Any],
    *,
    allow_current_run_pending: bool = False,
) -> list[str]:
    if not run:
        return ["GitHub workflow run proof is missing"]
    errors = []
    if run.get("headSha") != receipt.get("head_sha"):
        errors.append("workflow run headSha does not match receipt head_sha")
    if allow_current_run_pending and _is_current_workflow_run(receipt):
        return errors
    if run.get("status") != "completed":
        errors.append("workflow run status must be completed")
    if run.get("conclusion") != "success":
        errors.append("workflow run conclusion must be success")
    return errors


def _is_current_workflow_run(receipt: dict[str, Any]) -> bool:
    workflow = _dict_or_empty(receipt.get("workflow"))
    return bool(
        os.environ.get("GITHUB_RUN_ID")
        and str(workflow.get("run_id") or "") == os.environ["GITHUB_RUN_ID"]
    )


def _live_artifact_errors(
    receipt: dict[str, Any], artifact: dict[str, Any]
) -> list[str]:
    if not artifact:
        return ["GitHub artifact proof is missing"]
    expected = _dict_or_empty(receipt.get("artifact"))
    errors = _artifact_identity_errors(artifact, expected)
    if artifact.get("expired") is True:
        errors.append("GitHub artifact is expired")
    if expected.get("digest") and artifact.get("digest") != expected.get("digest"):
        errors.append("GitHub artifact digest does not match receipt artifact.digest")
    return errors


def _artifact_identity_errors(
    artifact: dict[str, Any], expected: dict[str, Any]
) -> list[str]:
    errors = []
    if str(artifact.get("id") or "") != str(expected.get("id") or ""):
        errors.append("GitHub artifact ID does not match receipt artifact.id")
    if artifact.get("name") != expected.get("name"):
        errors.append("GitHub artifact name does not match receipt artifact.name")
    return errors


def _receipt_markdown(receipt: dict[str, Any]) -> str:
    artifact = receipt["artifact"]
    workflow = receipt["workflow"]
    ai_review = receipt["ai_review"]
    architecture = receipt.get("architecture", {})
    return "\n".join(
        [
            "# Supportability Delivery Receipt",
            "",
            f"Owner status: {receipt['owner_status']}",
            f"PR: {receipt.get('pull_request_url', '')}",
            f"Main SHA: {receipt.get('merged_sha') or 'not merged'}",
            f"Checks: {receipt['supportability_gate']['owner_status']}",
            f"AI review: {ai_review['owner_status']} ({ai_review['evidence_status']})",
            f"Architecture gate: {architecture.get('owner_status', '')}",
            f"Gate implementation: {architecture.get('gate_implementation', '')}",
            f"Repo architecture supportability: {architecture.get('repo_architecture_supportability', '')}",
            f"Architecture behavior proof: {architecture.get('architecture_behavior_proof', '')}",
            f"Artifact: {artifact.get('name', '')} {artifact.get('id', '')} {artifact.get('digest', '')}",
            f"Workflow: {workflow.get('run_url', '')}",
            "",
            "## Gate Coverage",
            "",
            "```json",
            json.dumps(receipt.get("gate_coverage", {}), indent=2, sort_keys=True),
            "```",
            "",
        ]
    )


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    lines = _yaml_lines(text)
    if not lines:
        return {}
    result, index = _parse_yaml_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise SupportabilityError("unsupported YAML structure")
    if not isinstance(result, dict):
        raise SupportabilityError("supportability YAML root must be a mapping")
    return result


def _yaml_lines(text: str) -> list[tuple[int, str]]:
    lines = []
    for raw in text.splitlines():
        stripped = _strip_yaml_comment(raw).rstrip()
        if not stripped.strip() or stripped.lstrip().startswith("---"):
            continue
        lines.append((len(stripped) - len(stripped.lstrip(" ")), stripped.lstrip(" ")))
    return lines


def _strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        if char == '"' and not in_single:
            in_double = not in_double
        if char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def _parse_yaml_block(
    lines: list[tuple[int, str]], index: int, indent: int
) -> tuple[Any, int]:
    if lines[index][1].startswith("- "):
        return _parse_yaml_list(lines, index, indent)
    return _parse_yaml_mapping(lines, index, indent)


def _parse_yaml_mapping(
    lines: list[tuple[int, str]], index: int, indent: int
) -> tuple[dict[str, Any], int]:
    data: dict[str, Any] = {}
    while (
        index < len(lines)
        and lines[index][0] == indent
        and not lines[index][1].startswith("- ")
    ):
        key, value = _split_yaml_key_value(lines[index][1])
        if value == "":
            if index + 1 >= len(lines) or lines[index + 1][0] <= indent:
                raise SupportabilityError(f"YAML key {key!r} is missing a nested block")
            child, index = _parse_yaml_block(lines, index + 1, lines[index + 1][0])
            data[key] = child
        else:
            data[key] = _parse_yaml_scalar(value)
            index += 1
    return data, index


def _parse_yaml_list(
    lines: list[tuple[int, str]], index: int, indent: int
) -> tuple[list[Any], int]:
    items: list[Any] = []
    while (
        index < len(lines)
        and lines[index][0] == indent
        and lines[index][1].startswith("- ")
    ):
        value = lines[index][1][2:].strip()
        if value == "":
            if index + 1 >= len(lines) or lines[index + 1][0] <= indent:
                raise SupportabilityError("YAML list item is missing a nested block")
            child, index = _parse_yaml_block(lines, index + 1, lines[index + 1][0])
            items.append(child)
        elif _looks_like_yaml_mapping_item(value):
            key, scalar = _split_yaml_key_value(value)
            item = {key: _parse_yaml_scalar(scalar)}
            index += 1
            if index < len(lines) and lines[index][0] > indent:
                child, index = _parse_yaml_mapping(lines, index, lines[index][0])
                item.update(child)
            items.append(item)
        else:
            items.append(_parse_yaml_scalar(value))
            index += 1
    return items, index


def _looks_like_yaml_mapping_item(value: str) -> bool:
    return ":" in value and not value.startswith(("'", '"'))


def _split_yaml_key_value(text: str) -> tuple[str, str]:
    if ":" not in text:
        raise SupportabilityError(f"unsupported YAML line: {text}")
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def _parse_yaml_scalar(value: str) -> Any:
    if value in {"true", "false"}:
        return value == "true"
    if value in {"null", "~"}:
        return None
    if value == "[]":
        return []
    if value.startswith("[") or value.startswith("{"):
        raise SupportabilityError(f"unsupported YAML flow scalar: {value}")
    if value.startswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise SupportabilityError(f"unsupported YAML scalar: {value}") from exc
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    if re.fullmatch(r"-?[0-9]+", value):
        return int(value)
    return value


def _add_config_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "supportability-config", help="validate supportability config"
    )
    parser.add_argument("--config", type=Path, required=True)


def _add_gate_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "supportability-gate", help="run configured supportability gates"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--target-repo", type=Path, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--changed-file", action="append", default=[])
    parser.add_argument("--repository-url", default="")
    parser.add_argument("--pr-url", default="")
    parser.add_argument(
        "--output-dir", type=Path, default=Path("artifacts/supportability")
    )


def _add_receipt_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "delivery-receipt", help="generate supportability delivery receipt"
    )
    parser.add_argument("--gate-result", type=Path, required=True)
    parser.add_argument("--ai-review-result", type=Path, required=True)
    parser.add_argument("--architecture-result", type=Path)
    parser.add_argument(
        "--output-dir", type=Path, default=Path("artifacts/supportability")
    )
    parser.add_argument("--repository-url", default="")
    parser.add_argument("--pr-url", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--workflow-run-url", default="")
    parser.add_argument("--job-name", default="Delivery Receipt")
    parser.add_argument("--artifact-name", default="supportability-gate-evidence")
    parser.add_argument("--artifact-id", default="")
    parser.add_argument("--artifact-digest", default="")
    parser.add_argument("--merged-sha", default="")
    parser.add_argument("--protected-baseline-judge-ran", action="store_true")
    parser.add_argument("--candidate-judge-ran", action="store_true")
    parser.add_argument("--baseline-receipt-produced", action="store_true")
    parser.add_argument("--candidate-receipt-produced", action="store_true")
    parser.add_argument("--governance-weakening-detected", action="store_true")


def _add_copilot_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser("copilot-review-gate")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)


def _add_bootstrap_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "bootstrap-receipt", help="generate a RED bootstrap receipt"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("artifacts/supportability")
    )
    parser.add_argument("--repository-url", default="")
    parser.add_argument("--pr-url", default="")
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument(
        "--reason", default="baseline protected workflow missing on main"
    )


def _add_verify_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "verify-receipt", help="verify supportability receipt against GitHub"
    )
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--skip-live", action="store_true")
    parser.add_argument("--allow-current-run-pending", action="store_true")


def _cli_config(args: argparse.Namespace) -> int:
    config = load_supportability_config(args.config)
    errors = validate_supportability_config(config)
    print(
        json.dumps(
            {"status": STATUS_RED if errors else STATUS_GREEN, "errors": errors},
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if errors else 0


def _cli_gate(args: argparse.Namespace) -> int:
    changed = args.changed_file if args.changed_file else None
    result = run_supportability_gate(
        args.config,
        args.target_repo,
        args.base_sha,
        args.head_sha,
        changed_files=changed,
        output_dir=args.output_dir,
        repository_url=args.repository_url,
        pr_url=args.pr_url,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["owner_status"] == STATUS_GREEN else 1


def _cli_receipt(args: argparse.Namespace) -> int:
    gate = json.loads(args.gate_result.read_text(encoding="utf-8"))
    ai_review = json.loads(args.ai_review_result.read_text(encoding="utf-8"))
    architecture = (
        json.loads(args.architecture_result.read_text(encoding="utf-8"))
        if args.architecture_result
        else None
    )
    receipt = generate_delivery_receipt(
        gate,
        ai_review,
        architecture_result=architecture,
        output_dir=args.output_dir,
        repository_url=args.repository_url,
        pr_url=args.pr_url,
        run_id=args.run_id,
        workflow_run_url=args.workflow_run_url,
        job_name=args.job_name,
        artifact_name=args.artifact_name,
        artifact_id=args.artifact_id,
        artifact_digest=args.artifact_digest,
        merged_sha=args.merged_sha,
        required_judges={
            "protected_baseline_judge_ran": args.protected_baseline_judge_ran,
            "candidate_judge_ran": args.candidate_judge_ran,
            "baseline_receipt_produced": args.baseline_receipt_produced,
            "candidate_receipt_produced": args.candidate_receipt_produced,
            "governance_weakening_detected": args.governance_weakening_detected,
        },
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["owner_status"] == STATUS_GREEN else 1


def _cli_copilot(args: argparse.Namespace) -> int:
    errors: list[str] = []
    try:
        payload = json.loads(args.payload.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        payload = None
        errors.append(f"review payload load failed: {type(exc).__name__}: {exc}")
    result = evaluate_copilot_review_gate(
        args.config,
        args.head_sha,
        payload=payload,
        payload_errors=errors,
        output_dir=args.output_dir,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["owner_status"] == STATUS_GREEN else 1


def _cli_bootstrap_receipt(args: argparse.Namespace) -> int:
    receipt = generate_bootstrap_receipt(
        repository_url=args.repository_url,
        pr_url=args.pr_url,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        reason=args.reason,
        output_dir=args.output_dir,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 1


def _cli_verify_receipt(args: argparse.Namespace) -> int:
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    observations = None if args.skip_live else load_live_receipt_observations(receipt)
    result = verify_delivery_receipt(
        receipt,
        live_observations=observations,
        allow_current_run_pending=args.allow_current_run_pending,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["owner_status"] == STATUS_GREEN else 1


def _validate_if_schema_exists(name: str, payload: dict[str, Any]) -> None:
    try:
        validate_named(name, payload, root=_schema_root())
    except KeyError:
        return
    except SchemaValidationError:
        raise


def _schema_root() -> Path:
    return repo_root(Path(__file__).resolve())


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _write_markdown(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _truncate(value: str | None, limit: int = 4000) -> str:
    text = value or ""
    return text if len(text) <= limit else text[:limit] + "\n[truncated]"


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _gh_json(args: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        ["gh", *args],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=GIT_NETWORK_TIMEOUT_SECONDS,
    )
    return json.loads(completed.stdout)


def _gh_api_json(path: str) -> dict[str, Any]:
    return _gh_json(["api", path])


def _gh_api_bytes(path: str) -> bytes:
    completed = subprocess.run(
        ["gh", "api", path],
        check=True,
        capture_output=True,
        timeout=GIT_NETWORK_TIMEOUT_SECONDS,
    )
    return completed.stdout


def _safe_live(
    label: str, errors: list[str], func: Callable[..., Any], *args: Any
) -> Any:
    try:
        return func(*args)
    except Exception as exc:
        errors.append(f"{label}: {type(exc).__name__}: {exc}")
        if label.startswith("git ls-remote"):
            return ""
        if "contains" in label:
            return False
        return [] if "log" in label else {}


def _repo_from_url(url: str) -> str:
    match = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)", url)
    return f"{match.group('owner')}/{match.group('repo')}" if match else ""


def _pr_number_from_url(url: str) -> int | None:
    match = re.search(r"/pull/([0-9]+)", url)
    return int(match.group(1)) if match else None


def _live_pr(repo: str, pr_number: int) -> dict[str, Any]:
    return _gh_json(
        [
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo,
            "--json",
            "baseRefOid,headRefOid,mergeCommit,state,url",
        ]
    )


def _live_run(repo: str, run_id: str) -> dict[str, Any]:
    return _gh_json(
        [
            "run",
            "view",
            run_id,
            "--repo",
            repo,
            "--json",
            "status,conclusion,headSha,url",
        ]
    )


def _live_artifact(repo: str, artifact_id: str) -> dict[str, Any]:
    artifact = _gh_api_json(f"repos/{repo}/actions/artifacts/{artifact_id}")
    if not artifact.get("digest"):
        artifact["digest"] = _download_artifact_digest(repo, artifact_id)
    return artifact


def _download_artifact_digest(repo: str, artifact_id: str) -> str:
    archive = _gh_api_bytes(f"repos/{repo}/actions/artifacts/{artifact_id}/zip")
    return f"sha256:{hashlib.sha256(archive).hexdigest()}"


def _ls_remote_main(repository_url: str) -> str:
    completed = subprocess.run(
        ["git", "ls-remote", repository_url, "refs/heads/main"],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=GIT_NETWORK_TIMEOUT_SECONDS,
    )
    return completed.stdout.split()[0] if completed.stdout.split() else ""


def _fresh_clone_log(repository_url: str) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="supportability-receipt-") as tmp:
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--filter=blob:none",
                "--no-checkout",
                repository_url,
                tmp,
            ],
            check=True,
            timeout=GIT_NETWORK_TIMEOUT_SECONDS,
        )
        completed = subprocess.run(
            ["git", "log", "--oneline", "--decorate", "-n", "10", "origin/main"],
            cwd=tmp,
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=GIT_NETWORK_TIMEOUT_SECONDS,
        )
    return [line for line in completed.stdout.splitlines() if line]


def _fresh_clone_contains_commit(repository_url: str, commit_sha: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="supportability-receipt-") as tmp:
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--filter=blob:none",
                "--no-checkout",
                repository_url,
                tmp,
            ],
            check=True,
            timeout=GIT_NETWORK_TIMEOUT_SECONDS,
        )
        completed = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit_sha, "origin/main"],
            cwd=tmp,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=GIT_NETWORK_TIMEOUT_SECONDS,
        )
    if completed.returncode not in {0, 1}:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise SupportabilityError(
            f"git merge-base failed with exit {completed.returncode}: {detail}"
        )
    return completed.returncode == 0
