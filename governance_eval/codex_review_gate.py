from __future__ import annotations

import argparse
import json
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
    evaluate_codex_connector_evidence,
    serialize_codex_connector_evidence_result,
)


Collector = Callable[[str, int, str], dict[str, Any]]


def run_codex_review_gate(
    *,
    repository: str,
    pull_request_number: int,
    base_sha: str,
    head_sha: str,
    governance_sha: str,
    review_window_started_at: str,
    output_dir: Path,
    collector: Collector = collect_codex_connector_snapshot,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
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
    )
    codex_result = evaluate_codex_connector_evidence(raw, context)
    gate_result = evaluate_ai_review_gate(
        head_sha,
        codex_result=codex_result,
        raw_snapshot_bytes=raw,
        trusted_context=context,
    )
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
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--governance-sha", required=True)
    parser.add_argument("--review-window-started-at", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = run_codex_review_gate(
            repository=args.repo,
            pull_request_number=args.pr,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            governance_sha=args.governance_sha,
            review_window_started_at=args.review_window_started_at,
            output_dir=args.output_dir,
        )
    except (OSError, TypeError, ValueError) as exc:
        parser.exit(2, f"Codex review gate failed: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["owner_status"] == "GREEN" else 1


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
