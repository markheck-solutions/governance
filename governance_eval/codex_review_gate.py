from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import stat
import time
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

from governance_eval.ai_review_gate import evaluate_ai_review_gate
from governance_eval.codex_connector_collector import (
    collect_codex_connector_snapshot,
    serialize_codex_connector_snapshot,
)
from governance_eval.codex_connector_evidence import (
    TrustedCodexConnectorContext,
    TrustedWorkflowRequestReceipt,
    evaluate_codex_connector_evidence,
    serialize_codex_connector_evidence_result,
)
from governance_eval.hashing import sha256_json
from governance_eval.supportability import (
    parse_supportability_config_bytes,
    validate_supportability_config,
)


Collector = Callable[[str, int, str], dict[str, Any]]
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def bind_supportability_config(
    *,
    source_path: Path,
    bound_path: Path,
    repository: str,
    target_head_sha: str,
    source_relative_path: str,
) -> dict[str, str]:
    _validate_config_identity(repository, target_head_sha, source_relative_path)
    raw = _read_regular_file(source_path, label="source supportability config")
    config = parse_supportability_config_bytes(raw, suffix=source_path.suffix)
    errors = validate_supportability_config(config)
    if errors:
        raise ValueError("supportability config invalid: " + "; ".join(errors))

    bound_path.parent.mkdir(parents=True, exist_ok=True)
    with bound_path.open("xb") as bound_file:
        bound_file.write(raw)
    written = _read_regular_file(bound_path, label="bound supportability config")
    if written != raw:
        raise ValueError("bound supportability config verification failed")

    record = _config_binding_record(
        repository=repository,
        target_head_sha=target_head_sha,
        source_relative_path=source_relative_path,
        raw=raw,
    )
    return {
        **record,
        "binding_sha256": "sha256:" + sha256_json(record),
        "bound_config_path": str(bound_path.resolve()),
    }


def _validate_config_identity(
    repository: str, target_head_sha: str, source_relative_path: str
) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository identity is invalid")
    if not SHA1_RE.fullmatch(target_head_sha):
        raise ValueError("target head SHA is invalid")
    parts = source_relative_path.split("/")
    if (
        not source_relative_path
        or source_relative_path.startswith("/")
        or "\\" in source_relative_path
        or ":" in source_relative_path
        or any(part in {"", ".", ".."} for part in parts)
        or not source_relative_path.lower().endswith((".yml", ".yaml"))
    ):
        raise ValueError("supportability config source path is invalid")


def _read_regular_file(path: Path, *, label: str) -> bytes:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(path_stat.st_mode):
        raise ValueError(f"{label} must not be a symbolic link")
    if not stat.S_ISREG(path_stat.st_mode):
        raise ValueError(f"{label} must be a regular file")
    try:
        with path.open("rb") as source_file:
            opened_stat = os.fstat(source_file.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                raise ValueError(f"{label} must be a regular file")
            if (path_stat.st_dev, path_stat.st_ino) != (
                opened_stat.st_dev,
                opened_stat.st_ino,
            ):
                raise ValueError(f"{label} changed while opening")
            return source_file.read()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {path}") from exc


def _config_binding_record(
    *,
    repository: str,
    target_head_sha: str,
    source_relative_path: str,
    raw: bytes,
) -> dict[str, str]:
    return {
        "binding_version": "1.0",
        "repository": repository,
        "target_head_sha": target_head_sha,
        "source_path": source_relative_path,
        "content_sha256": "sha256:" + sha256(raw).hexdigest(),
    }


def run_codex_review_gate(
    *,
    config_path: Path,
    config_source_path: str,
    config_binding_digest: str,
    repository: str,
    pull_request_number: int,
    base_sha: str,
    head_sha: str,
    governance_sha: str,
    review_window_started_at: str,
    output_dir: Path,
    workflow_request_receipt: TrustedWorkflowRequestReceipt | None = None,
    collector: Collector = collect_codex_connector_snapshot,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if workflow_request_receipt is None:
        raise ValueError("automatic workflow request receipt is required")
    unavailable_after_cutoff, config_binding = _load_bound_supportability_policy(
        config_path=config_path,
        repository=repository,
        target_head_sha=head_sha,
        source_relative_path=config_source_path,
        expected_binding_digest=config_binding_digest,
    )
    started = _timestamp(review_window_started_at)
    deadline = started + timedelta(seconds=300)
    snapshot = collector(repository, pull_request_number, governance_sha)
    captured = _timestamp(snapshot.get("captured_at"))
    if captured < deadline:
        sleeper((deadline - captured).total_seconds() + 2)
        snapshot = collector(repository, pull_request_number, governance_sha)
        captured = _timestamp(snapshot.get("captured_at"))
    if captured < deadline:
        raise ValueError("final Codex collection is before the review deadline")

    raw = serialize_codex_connector_snapshot(snapshot)
    pull_request = snapshot["pull_request"]
    context = TrustedCodexConnectorContext(
        snapshot_file_sha256="sha256:" + sha256(raw).hexdigest(),
        repository_id=snapshot["repository"]["id"],
        repository_full_name=repository,
        pull_request_number=pull_request_number,
        pull_request_node_id=pull_request["node_id"],
        pull_request_created_at=pull_request["created_at"],
        base_sha=base_sha,
        head_sha=head_sha,
        governance_evaluator_sha=governance_sha,
        review_window_started_at=_format_timestamp(started),
        review_deadline_at=_format_timestamp(deadline),
        resolved_clean_commit_sha=head_sha,
        workflow_request_receipt=workflow_request_receipt,
    )
    codex_result = evaluate_codex_connector_evidence(raw, context)
    gate_result = dict(
        evaluate_ai_review_gate(
            head_sha,
            codex_result=codex_result,
            raw_snapshot_bytes=raw,
            trusted_context=context,
            unavailable_after_cutoff=unavailable_after_cutoff,
        )
    )
    gate_result["supportability_config_binding"] = config_binding
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "codex-connector-snapshot.json").write_bytes(raw)
    (output_dir / "codex-connector-evidence-result.json").write_bytes(
        serialize_codex_connector_evidence_result(codex_result)
    )
    (output_dir / "ai-review-gate-result.json").write_text(
        json.dumps(gate_result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return gate_result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codex-review-gate")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--config-source-path", required=True)
    parser.add_argument("--config-binding-digest", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--governance-sha", required=True)
    parser.add_argument("--review-window-started-at", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--request-workflow-ref")
    parser.add_argument("--request-workflow-sha")
    parser.add_argument("--request-event-name")
    parser.add_argument("--request-event-action")
    parser.add_argument("--request-run-id", type=int)
    parser.add_argument("--request-run-attempt", type=int)
    parser.add_argument("--request-repository-id", type=int)
    parser.add_argument("--request-outcome")
    parser.add_argument("--request-transport-exit-code", type=int)
    parser.add_argument("--request-transport-error-sha256")
    parser.add_argument("--request-comment-id", type=int)
    parser.add_argument("--request-comment-created-at")
    args = parser.parse_args(argv)
    try:
        workflow_request_receipt = _workflow_request_receipt_from_args(args)
        if workflow_request_receipt is None:
            raise ValueError("automatic workflow request receipt is required")
        result = run_codex_review_gate(
            config_path=args.config,
            config_source_path=args.config_source_path,
            config_binding_digest=args.config_binding_digest,
            repository=args.repo,
            pull_request_number=args.pr,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            governance_sha=args.governance_sha,
            review_window_started_at=args.review_window_started_at,
            output_dir=args.output_dir,
            workflow_request_receipt=workflow_request_receipt,
        )
    except (OSError, TypeError, ValueError) as exc:
        parser.exit(2, f"Codex review gate failed: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["owner_status"] == "GREEN" else 1


def _workflow_request_receipt_from_args(
    args: argparse.Namespace,
) -> TrustedWorkflowRequestReceipt | None:
    core_values = (
        args.request_workflow_ref,
        args.request_workflow_sha,
        args.request_event_name,
        args.request_event_action,
        args.request_run_id,
        args.request_run_attempt,
        args.request_repository_id,
        args.request_outcome,
        args.request_transport_exit_code,
    )
    if all(value is None for value in core_values):
        return None
    if any(value is None for value in core_values):
        raise ValueError("workflow request receipt inputs must be supplied together")
    request_body = (
        f"@codex review\n\nGovernance review request for exact head `{args.head_sha}`."
    )
    return TrustedWorkflowRequestReceipt(
        workflow_ref=args.request_workflow_ref,
        workflow_sha=args.request_workflow_sha,
        event_name=args.request_event_name,
        event_action=args.request_event_action,
        run_id=args.request_run_id,
        run_attempt=args.request_run_attempt,
        repository_id=args.request_repository_id,
        repository_full_name=args.repo,
        pull_request_number=args.pr,
        head_sha=args.head_sha,
        review_window_started_at=args.review_window_started_at,
        job_id="request-codex-review",
        request_endpoint=f"repos/{args.repo}/issues/{args.pr}/comments",
        request_body_sha256="sha256:"
        + sha256(request_body.encode("utf-8")).hexdigest(),
        outcome=args.request_outcome,
        transport_exit_code=args.request_transport_exit_code,
        transport_error_sha256=args.request_transport_error_sha256,
        comment_id=args.request_comment_id,
        comment_created_at=args.request_comment_created_at,
    )


def _load_bound_supportability_policy(
    *,
    config_path: Path,
    repository: str,
    target_head_sha: str,
    source_relative_path: str,
    expected_binding_digest: str,
) -> tuple[str, dict[str, str]]:
    _validate_config_identity(repository, target_head_sha, source_relative_path)
    if not DIGEST_RE.fullmatch(expected_binding_digest):
        raise ValueError("supportability config binding digest is invalid")
    raw = _read_regular_file(config_path, label="bound supportability config")
    record = _config_binding_record(
        repository=repository,
        target_head_sha=target_head_sha,
        source_relative_path=source_relative_path,
        raw=raw,
    )
    actual_binding_digest = "sha256:" + sha256_json(record)
    if not hmac.compare_digest(actual_binding_digest, expected_binding_digest):
        raise ValueError("supportability config binding digest mismatch")
    config = parse_supportability_config_bytes(
        raw, suffix=Path(source_relative_path).suffix
    )
    errors = validate_supportability_config(config)
    if errors:
        raise ValueError("supportability config invalid: " + "; ".join(errors))
    ai_review = config.get("ai_review")
    if not isinstance(ai_review, dict):
        raise ValueError("supportability config invalid: ai_review must be an object")
    policy = ai_review.get("unavailable_after_cutoff")
    if not isinstance(policy, str):
        raise ValueError(
            "supportability config invalid: "
            "ai_review.unavailable_after_cutoff must be a string"
        )
    return policy, {**record, "binding_sha256": actual_binding_digest}


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("Codex timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("Codex timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("Codex timestamp is invalid")
    return parsed.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
