from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named


BLOCKING_RE = re.compile(r"\bP[0-2]\b|\[P[0-2]\]|severity:\s*P[0-2]", re.IGNORECASE)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SUCCESS_CONCLUSIONS = {"SUCCESS", "SKIPPED", "NEUTRAL"}
SUCCESS_STATES = {"SUCCESS", "SKIPPED", "NEUTRAL"}
FINAL_REVIEW_AUTHORS = {"chatgpt-codex-connector"}
GOVERNANCE_CONTEXT_RE = re.compile(r"governance|phase 1 shadow", re.IGNORECASE)
REVIEW_GATE_GITHUB = "GITHUB_CODEX_FINAL_REVIEW"
REVIEW_GATE_FALLBACK = "FALLBACK_CLEAN_ROOM_QUORUM"
GITHUB_REVIEW_CLEAN = "CLEAN"
GITHUB_REVIEW_STALE = "STALE"
GITHUB_REVIEW_UNAVAILABLE = "UNAVAILABLE"
GITHUB_REVIEW_BLOCKING = "BLOCKING_FINDINGS_PRESENT"


def evaluate_readiness(payload: dict[str, Any]) -> dict[str, Any]:
    latest_head_sha = payload.get("headRefOid") or ""
    latest_head_committed_at = payload.get("latestHeadCommittedAt") or ""
    reviews = payload.get("reviews") or []
    unresolved = payload.get("unresolvedThreads") or []
    unresolved_blocking = [thread for thread in unresolved if _thread_is_p0_p2(thread)]
    workflow_result = _workflow_result(payload.get("workflowContexts") or [])
    merge_state = payload.get("mergeStateStatus") or ""
    merge_eligible = (
        payload.get("state") == "OPEN"
        and not payload.get("isDraft", False)
        and merge_state not in {"BLOCKED", "DIRTY", "DRAFT", "UNKNOWN"}
    )
    benchmark_result = _benchmark_result(payload)
    review_result = _review_gate_result(payload, latest_head_sha, latest_head_committed_at, unresolved_blocking)
    ready = bool(
        latest_head_sha
        and review_result["review_gate"]
        and not unresolved_blocking
        and workflow_result["has_workflow_evidence"]
        and not workflow_result["failed_workflow_contexts"]
        and benchmark_result["valid"]
        and merge_eligible
    )
    return {
        "ready": ready,
        "latest_head_sha": latest_head_sha,
        "latest_head_committed_at": latest_head_committed_at,
        "final_review_timestamp": review_result["final_review_timestamp"],
        "final_review_commit": latest_head_sha if review_result["github_final_review"] else None,
        "review_gate": review_result["review_gate"],
        "github_review_state": review_result["github_review_state"],
        "fallback_quorum_valid": review_result["fallback_quorum_valid"],
        "fallback_quorum_errors": review_result["fallback_quorum_errors"],
        "later_blocking_review_count": review_result["later_blocking_review_count"],
        "unresolved_p0_count": _count_severity(unresolved_blocking, "P0"),
        "unresolved_p1_count": _count_severity(unresolved_blocking, "P1"),
        "unresolved_p2_count": _count_severity(unresolved_blocking, "P2"),
        "failed_workflow_contexts": workflow_result["failed_workflow_contexts"],
        "missing_workflow_evidence": not workflow_result["has_workflow_evidence"],
        "governance_workflow_contexts": workflow_result["successful_governance_contexts"],
        "benchmark_evidence_valid": benchmark_result["valid"],
        "benchmark_evidence_errors": benchmark_result["errors"],
        "benchmark_phase1_decision": benchmark_result["phase1_decision"],
        "benchmark_artifact_content_hash": benchmark_result["artifact_content_hash"],
        "benchmark_artifact_digest": benchmark_result["artifact_digest"],
        "merge_eligible": merge_eligible,
        "merge_state_status": merge_state,
    }


def load_github_payload(repo: str, pr_number: int) -> dict[str, Any]:
    owner, name = repo.split("/", 1)
    completed = subprocess.run(
        [
            "gh",
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo,
            "--json",
            "baseRefOid,commits,reviews,statusCheckRollup,headRefOid,isDraft,mergeStateStatus,state,url",
        ],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    pr = json.loads(completed.stdout)
    latest_commit = (pr.get("commits") or [{}])[-1]
    threads = _load_review_threads(owner, name, pr_number)
    contexts = []
    for node in pr.get("statusCheckRollup") or []:
        contexts.append(
            {
                "name": node.get("name") or node.get("context"),
                "workflowName": node.get("workflowName"),
                "status": node.get("status"),
                "conclusion": node.get("conclusion"),
                "state": node.get("state"),
                "url": node.get("detailsUrl") or node.get("targetUrl"),
            }
        )
    reviews = []
    for review in pr.get("reviews") or []:
        commit = review.get("commit") if isinstance(review.get("commit"), dict) else {}
        author = review.get("author") if isinstance(review.get("author"), dict) else {}
        reviews.append(
            {
                "state": review.get("state"),
                "submittedAt": review.get("submittedAt"),
                "commitOid": review.get("commitOid") or commit.get("oid"),
                "author": author.get("login") or review.get("author"),
                "body": review.get("body"),
            }
        )
    return {
        "url": pr.get("url"),
        "state": pr.get("state"),
        "isDraft": pr.get("isDraft"),
        "mergeStateStatus": pr.get("mergeStateStatus"),
        "baseRefOid": pr.get("baseRefOid"),
        "headRefOid": pr.get("headRefOid"),
        "latestHeadCommittedAt": latest_commit.get("committedDate"),
        "reviews": reviews,
        "unresolvedThreads": threads,
        "workflowContexts": contexts,
    }


def _load_review_threads(owner: str, name: str, pr_number: int) -> list[dict[str, Any]]:
    query = """
    query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          reviewThreads(first: 100, after: $cursor) {
            nodes {
              isResolved
              path
              line
              comments(first: 100) {
                nodes {
                  body
                }
              }
            }
            pageInfo {
              hasNextPage
              endCursor
            }
          }
        }
      }
    }
    """
    threads: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        args = [
            "gh",
            "api",
            "graphql",
            "-f",
            f"owner={owner}",
            "-f",
            f"name={name}",
            "-F",
            f"number={pr_number}",
            "-f",
            f"query={query}",
        ]
        if cursor:
            args.extend(["-f", f"cursor={cursor}"])
        completed = subprocess.run(
            args,
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        connection = _review_threads_connection(json.loads(completed.stdout))
        threads.extend(_unresolved_threads(connection.get("nodes", [])))
        page_info = connection.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
        if not cursor:
            raise RuntimeError("GitHub reviewThreads pagination did not return endCursor")
    return threads


def _review_threads_connection(payload: dict[str, Any]) -> dict[str, Any]:
    return (
        payload.get("data", {})
        .get("repository", {})
        .get("pullRequest", {})
        .get("reviewThreads", {})
    )


def _unresolved_threads(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    threads: list[dict[str, Any]] = []
    for thread in nodes:
        if thread.get("isResolved"):
            continue
        bodies = [
            comment.get("body", "")
            for comment in (thread.get("comments", {}) or {}).get("nodes", [])
        ]
        threads.append(
            {
                "path": thread.get("path"),
                "line": thread.get("line"),
                "body": "\n".join(bodies),
            }
        )
    return threads


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="delivery-readiness")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--payload", help="read a fixture payload instead of querying GitHub")
    parser.add_argument("--benchmark-artifact", help="benchmark JSON evidence path")
    parser.add_argument("--benchmark-artifact-digest", help="GitHub artifact digest, sha256:<hex>")
    parser.add_argument("--require-github-artifact-digest", action="store_true")
    parser.add_argument("--fallback-quorum", help="fallback clean-room review quorum JSON path")
    args = parser.parse_args(argv)
    payload = json.loads(open(args.payload, encoding="utf-8").read()) if args.payload else load_github_payload(args.repo, args.pr)
    if args.benchmark_artifact:
        payload["benchmarkEvidence"] = _read_json_or_error(Path(args.benchmark_artifact))
    if args.benchmark_artifact_digest:
        payload["benchmarkArtifactDigest"] = args.benchmark_artifact_digest
    if args.require_github_artifact_digest:
        payload["requireGithubArtifactDigest"] = True
    if args.fallback_quorum:
        payload["fallbackQuorum"] = _read_json_or_error(Path(args.fallback_quorum))
    result = evaluate_readiness(payload)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] else 1


def _workflow_result(workflow_contexts: list[dict[str, Any]]) -> dict[str, Any]:
    governance_contexts = [item for item in workflow_contexts if _is_governance_context(item)]
    successful_governance_contexts = [item for item in governance_contexts if _is_executed_success_context(item)]
    failed_contexts = [item for item in workflow_contexts if not _is_success_context(item)]
    return {
        "successful_governance_contexts": successful_governance_contexts,
        "failed_workflow_contexts": failed_contexts,
        "has_workflow_evidence": bool(successful_governance_contexts),
    }


def _review_gate_result(
    payload: dict[str, Any],
    latest_head_sha: str,
    latest_head_committed_at: str,
    unresolved_blocking: list[dict[str, Any]],
) -> dict[str, Any]:
    reviews = payload.get("reviews") or []
    same_head_reviews = [
        review
        for review in reviews
        if _review_is_on_latest_after_commit(review, latest_head_sha, latest_head_committed_at)
    ]
    clean_github_reviews = [
        review
        for review in same_head_reviews
        if review.get("state") not in {"CHANGES_REQUESTED", "DISMISSED"}
        and not BLOCKING_RE.search(review.get("body") or "")
        and review.get("author") in FINAL_REVIEW_AUTHORS
        and _review_references_head(review, latest_head_sha)
    ]
    blocking_reviews = [
        review
        for review in same_head_reviews
        if _review_is_blocking(review)
    ]
    latest_clean = _latest_review(clean_github_reviews)
    later_blocking = [
        review
        for review in blocking_reviews
        if latest_clean is None or _dt(review["submittedAt"]) > _dt(latest_clean["submittedAt"])
    ]
    github_final_review = latest_clean is not None and not later_blocking and not unresolved_blocking
    github_review_state = _github_review_state(payload, github_final_review, later_blocking, unresolved_blocking)
    fallback_result = _fallback_quorum_result(payload.get("fallbackQuorum"), payload.get("baseRefOid") or "", latest_head_sha)
    fallback_allowed = (
        github_review_state in {GITHUB_REVIEW_STALE, GITHUB_REVIEW_UNAVAILABLE}
        and not unresolved_blocking
        and not later_blocking
        and fallback_result["valid"]
    )
    review_gate = REVIEW_GATE_GITHUB if github_final_review else REVIEW_GATE_FALLBACK if fallback_allowed else None
    return {
        "review_gate": review_gate,
        "github_review_state": github_review_state,
        "github_final_review": github_final_review,
        "final_review_timestamp": latest_clean.get("submittedAt") if github_final_review else None,
        "fallback_quorum_valid": fallback_result["valid"],
        "fallback_quorum_errors": fallback_result["errors"],
        "later_blocking_review_count": len(later_blocking),
    }


def _benchmark_result(payload: dict[str, Any]) -> dict[str, Any]:
    evidence = payload.get("benchmarkEvidence")
    digest = payload.get("benchmarkArtifactDigest")
    errors: list[str] = []
    if not isinstance(evidence, dict):
        errors.append("benchmark evidence missing or malformed")
        return _benchmark_result_payload(False, errors, None, None, digest)
    if evidence.get("__load_error"):
        errors.append(f"benchmark evidence malformed JSON: {evidence['__load_error']}")
        return _benchmark_result_payload(False, errors, None, None, digest)
    phase1_decision = evidence.get("phase1_decision")
    if phase1_decision != "BENCHMARK_PASS":
        errors.append(f"phase1_decision expected BENCHMARK_PASS, got {phase1_decision!r}")
    acceptance_errors = evidence.get("acceptance_errors")
    if acceptance_errors != []:
        errors.append("acceptance_errors must be []")
    artifact_hash = evidence.get("artifact_content_hash")
    if not (isinstance(artifact_hash, str) and SHA256_RE.match(artifact_hash)):
        errors.append("artifact_content_hash must be a 64-character lowercase hex SHA-256")
    metrics = evidence.get("metrics")
    if not isinstance(metrics, dict):
        errors.append("metrics missing or malformed")
    else:
        errors.extend(_metric_errors(metrics))
    artifact_digest = digest or evidence.get("github_artifact_digest")
    if payload.get("requireGithubArtifactDigest") and not (
        isinstance(artifact_digest, str) and DIGEST_RE.match(artifact_digest)
    ):
        errors.append("github artifact digest required in sha256:<hex> format")
    return _benchmark_result_payload(not errors, errors, phase1_decision, artifact_hash, artifact_digest)


def _benchmark_result_payload(
    valid: bool,
    errors: list[str],
    phase1_decision: str | None,
    artifact_hash: str | None,
    artifact_digest: str | None,
) -> dict[str, Any]:
    return {
        "valid": valid,
        "errors": errors,
        "phase1_decision": phase1_decision,
        "artifact_content_hash": artifact_hash,
        "artifact_digest": artifact_digest,
    }


def _metric_errors(metrics: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "case_count",
        "critical_defects_blocked",
        "critical_defect_count",
        "negative_controls_blocked",
        "negative_control_count",
        "false_blocks",
        "verified_safe_count",
    }
    for name in sorted(required):
        if not isinstance(metrics.get(name), int):
            errors.append(f"metrics.{name} missing or not an integer")
    if errors:
        return errors
    positive_denominators = ("case_count", "critical_defect_count", "negative_control_count", "verified_safe_count")
    for name in positive_denominators:
        if metrics[name] <= 0:
            errors.append(f"metrics.{name} must be greater than zero")
    bounded_pairs = (
        ("critical_defects_blocked", "critical_defect_count"),
        ("negative_controls_blocked", "negative_control_count"),
        ("false_blocks", "verified_safe_count"),
    )
    for numerator, denominator in bounded_pairs:
        if metrics[numerator] < 0 or metrics[numerator] > metrics[denominator]:
            errors.append(f"metrics.{numerator} must be between 0 and metrics.{denominator}")
    if metrics["critical_defects_blocked"] != metrics["critical_defect_count"]:
        errors.append("metrics.critical_defects_blocked must equal metrics.critical_defect_count")
    if metrics["negative_controls_blocked"] != metrics["negative_control_count"]:
        errors.append("metrics.negative_controls_blocked must equal metrics.negative_control_count")
    if metrics["false_blocks"] != 0:
        errors.append("metrics.false_blocks must be zero")
    scalar_expectations = {
        "critical_defect_recall": 1.0,
        "negative_control_recall": 1.0,
        "false_block_rate": 0.0,
        "repeated_run_decision_stability": 1.0,
        "deterministic_flake_rate": 0.0,
    }
    for name, expected in scalar_expectations.items():
        if name in metrics and metrics[name] != expected:
            errors.append(f"metrics.{name} expected {expected}, got {metrics[name]!r}")
    return errors


def _fallback_quorum_result(quorum: Any, expected_base_sha: str, expected_head_sha: str) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(quorum, dict):
        return {"valid": False, "errors": ["fallback quorum missing or malformed"]}
    if quorum.get("__load_error"):
        return {"valid": False, "errors": [f"fallback quorum malformed JSON: {quorum['__load_error']}"]}
    try:
        validate_named("review_quorum", quorum)
    except SchemaValidationError as exc:
        errors.append(f"fallback quorum schema invalid: {exc}")
    if quorum.get("review_gate") != REVIEW_GATE_FALLBACK:
        errors.append("fallback quorum review_gate must be FALLBACK_CLEAN_ROOM_QUORUM")
    reviewers = quorum.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) < 2:
        errors.append("fallback quorum requires at least two reviewers")
        reviewers = []
    reviewer_ids: set[str] = set()
    for index, reviewer in enumerate(reviewers):
        if not isinstance(reviewer, dict):
            errors.append(f"reviewers[{index}] malformed")
            continue
        reviewer_id = reviewer.get("reviewer_id")
        if not isinstance(reviewer_id, str) or not reviewer_id:
            errors.append(f"reviewers[{index}].reviewer_id missing")
        elif reviewer_id in reviewer_ids:
            errors.append(f"reviewers[{index}].reviewer_id duplicated")
        else:
            reviewer_ids.add(reviewer_id)
        reviewed_head = reviewer.get("reviewed_head_sha") or quorum.get("reviewed_head_sha")
        reviewed_base = reviewer.get("reviewed_base_sha") or quorum.get("reviewed_base_sha")
        if reviewed_head != expected_head_sha:
            errors.append(f"reviewers[{index}].reviewed_head_sha does not match latest head")
        if expected_base_sha and reviewed_base != expected_base_sha:
            errors.append(f"reviewers[{index}].reviewed_base_sha does not match base")
        if reviewer.get("final_verdict") != "CLEAN":
            errors.append(f"reviewers[{index}].final_verdict must be CLEAN")
        findings = reviewer.get("findings") or []
        if not isinstance(findings, list):
            errors.append(f"reviewers[{index}].findings malformed")
            continue
        for finding_index, finding in enumerate(findings):
            severity = finding.get("severity") if isinstance(finding, dict) else None
            if severity in {"P0", "P1", "P2"}:
                errors.append(f"reviewers[{index}].findings[{finding_index}] reports blocking {severity}")
    return {"valid": not errors, "errors": errors}


def _github_review_state(
    payload: dict[str, Any],
    github_final_review: bool,
    later_blocking: list[dict[str, Any]],
    unresolved_blocking: list[dict[str, Any]],
) -> str:
    if later_blocking or unresolved_blocking:
        return GITHUB_REVIEW_BLOCKING
    if github_final_review:
        return GITHUB_REVIEW_CLEAN
    if payload.get("githubReviewUnavailable"):
        return GITHUB_REVIEW_UNAVAILABLE
    return GITHUB_REVIEW_STALE


def _read_json_or_error(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"__load_error": str(exc)}


def _review_is_on_latest_after_commit(review: dict[str, Any], latest_head_sha: str, latest_head_committed_at: str) -> bool:
    return bool(
        review.get("submittedAt")
        and review.get("commitOid") == latest_head_sha
        and _dt(review["submittedAt"]) >= _dt(latest_head_committed_at)
    )


def _review_is_blocking(review: dict[str, Any]) -> bool:
    if review.get("state") == "DISMISSED":
        return False
    return review.get("state") == "CHANGES_REQUESTED" or bool(BLOCKING_RE.search(review.get("body") or ""))


def _review_references_head(review: dict[str, Any], latest_head_sha: str) -> bool:
    body = review.get("body") or ""
    return latest_head_sha in body or latest_head_sha[:10] in body


def _latest_review(reviews: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not reviews:
        return None
    return max(reviews, key=lambda item: _dt(item["submittedAt"]))


def _thread_is_p0_p2(thread: dict[str, Any]) -> bool:
    return bool(BLOCKING_RE.search(thread.get("body") or ""))


def _is_success_context(item: dict[str, Any]) -> bool:
    return item.get("conclusion") in SUCCESS_CONCLUSIONS or item.get("state") in SUCCESS_STATES


def _is_executed_success_context(item: dict[str, Any]) -> bool:
    return item.get("conclusion") == "SUCCESS" or item.get("state") == "SUCCESS"


def _is_governance_context(item: dict[str, Any]) -> bool:
    text = " ".join(
        str(item.get(field) or "")
        for field in ("name", "workflowName", "context")
    )
    return bool(GOVERNANCE_CONTEXT_RE.search(text))


def _count_severity(threads: list[dict[str, Any]], severity: str) -> int:
    pattern = re.compile(rf"\b{severity}\b|\[{severity}\]|severity:\s*{severity}", re.IGNORECASE)
    return sum(1 for thread in threads if pattern.search(thread.get("body") or ""))


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


if __name__ == "__main__":
    raise SystemExit(main())
