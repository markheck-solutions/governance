from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from governance_eval.benchmark import validate_benchmark_result
from governance_eval.cases import load_cases
from governance_eval.hashing import sha256_json
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
    blocking_comments = [
        comment
        for comment in payload.get("comments", []) or []
        if _comment_is_blocking(comment, latest_head_committed_at)
    ]
    workflow_result = _workflow_result(payload.get("workflowContexts") or [])
    merge_state = payload.get("mergeStateStatus") or ""
    merge_eligible = (
        payload.get("state") == "OPEN"
        and not payload.get("isDraft", False)
        and merge_state not in {"BLOCKED", "DIRTY", "DRAFT", "UNKNOWN"}
    )
    benchmark_result = _benchmark_result(payload)
    review_result = _review_gate_result(
        payload,
        latest_head_sha,
        latest_head_committed_at,
        unresolved_blocking,
        blocking_comments,
    )
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
        "blocking_pr_comment_count": len(blocking_comments),
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
            "baseRefOid,commits,comments,reviews,statusCheckRollup,headRefOid,isDraft,mergeStateStatus,state,url",
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
    comments = []
    for comment in pr.get("comments") or []:
        author = comment.get("author") if isinstance(comment.get("author"), dict) else {}
        comments.append(
            {
                "createdAt": comment.get("createdAt"),
                "author": author.get("login") or comment.get("author"),
                "body": comment.get("body"),
                "isMinimized": comment.get("isMinimized"),
                "minimizedReason": comment.get("minimizedReason"),
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
        "comments": comments,
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
    parser.add_argument("--benchmark-run-id", help="GitHub Actions run ID that produced the benchmark artifact")
    parser.add_argument("--benchmark-artifact-id", help="GitHub artifact ID for the benchmark artifact")
    parser.add_argument("--benchmark-artifact-name", default="governance-benchmark-json")
    parser.add_argument("--require-github-artifact-digest", action="store_true")
    parser.add_argument("--fallback-quorum", help="fallback clean-room review quorum JSON path")
    parser.add_argument("--trusted-reviewer-agent", action="append", default=[])
    args = parser.parse_args(argv)
    payload = json.loads(open(args.payload, encoding="utf-8").read()) if args.payload else load_github_payload(args.repo, args.pr)
    if args.benchmark_artifact:
        payload["benchmarkEvidence"] = _read_json_or_error(Path(args.benchmark_artifact))
    if args.benchmark_artifact_digest:
        payload["benchmarkArtifactDigest"] = args.benchmark_artifact_digest
    if args.benchmark_artifact_name:
        payload["benchmarkArtifactName"] = args.benchmark_artifact_name
    if args.benchmark_run_id or args.benchmark_artifact_id:
        if args.benchmark_run_id and args.benchmark_artifact_id:
            binding = _load_github_artifact_binding(args.repo, args.benchmark_run_id, args.benchmark_artifact_id)
            payload["benchmarkArtifactBinding"] = binding
            if not args.benchmark_artifact_digest and isinstance(binding, dict):
                digest = binding.get("artifact_digest")
                if isinstance(digest, str):
                    payload["benchmarkArtifactDigest"] = digest
        else:
            payload["benchmarkArtifactBinding"] = {
                "__load_error": "--benchmark-run-id and --benchmark-artifact-id must be supplied together"
            }
    if args.require_github_artifact_digest:
        payload["requireGithubArtifactDigest"] = True
    if args.fallback_quorum:
        payload["fallbackQuorum"] = _read_json_or_error(Path(args.fallback_quorum))
    if args.trusted_reviewer_agent:
        payload["trustedReviewerAgentIds"] = args.trusted_reviewer_agent
    result = evaluate_readiness(payload)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] else 1


def _load_github_artifact_binding(repo: str, run_id: str, artifact_id: str) -> dict[str, Any]:
    try:
        run = _gh_api_json(f"repos/{repo}/actions/runs/{run_id}")
        artifact = _gh_api_json(f"repos/{repo}/actions/artifacts/{artifact_id}")
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        return {"__load_error": f"{type(exc).__name__}: {exc}"}
    artifact_run = artifact.get("workflow_run") if isinstance(artifact.get("workflow_run"), dict) else {}
    return {
        "workflow_run_id": str(run.get("id") or ""),
        "workflow_head_sha": run.get("head_sha"),
        "workflow_status": run.get("status"),
        "workflow_conclusion": run.get("conclusion"),
        "workflow_event": run.get("event"),
        "workflow_url": run.get("html_url"),
        "artifact_id": str(artifact.get("id") or ""),
        "artifact_name": artifact.get("name"),
        "artifact_digest": artifact.get("digest"),
        "artifact_expired": artifact.get("expired"),
        "artifact_workflow_run_id": str(artifact_run.get("id") or ""),
        "artifact_workflow_head_sha": artifact_run.get("head_sha"),
    }


def _gh_api_json(path: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["gh", "api", path],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    return json.loads(completed.stdout)


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
    blocking_comments: list[dict[str, Any]],
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
    github_final_review = latest_clean is not None and not later_blocking and not unresolved_blocking and not blocking_comments
    github_review_state = _github_review_state(
        payload,
        github_final_review,
        later_blocking,
        unresolved_blocking,
        blocking_comments,
    )
    fallback_quorum = _with_trusted_reviewers(payload.get("fallbackQuorum"), payload.get("trustedReviewerAgentIds"))
    fallback_result = _fallback_quorum_result(fallback_quorum, payload.get("baseRefOid") or "", latest_head_sha)
    fallback_allowed = (
        github_review_state in {GITHUB_REVIEW_STALE, GITHUB_REVIEW_UNAVAILABLE}
        and not unresolved_blocking
        and not blocking_comments
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
    try:
        validate_benchmark_result(evidence)
    except SchemaValidationError as exc:
        errors.append(f"benchmark schema invalid: {exc}")
    phase1_decision = evidence.get("phase1_decision")
    if phase1_decision != "BENCHMARK_PASS":
        errors.append(f"phase1_decision expected BENCHMARK_PASS, got {phase1_decision!r}")
    acceptance_errors = evidence.get("acceptance_errors")
    if acceptance_errors != []:
        errors.append("acceptance_errors must be []")
    artifact_hash = evidence.get("artifact_content_hash")
    if not (isinstance(artifact_hash, str) and SHA256_RE.match(artifact_hash)):
        errors.append("artifact_content_hash must be a 64-character lowercase hex SHA-256")
    else:
        expected_hash = sha256_json({**evidence, "artifact_content_hash": ""})
        if artifact_hash != expected_hash:
            errors.append("artifact_content_hash does not match benchmark evidence content")
    metrics = evidence.get("metrics")
    if not isinstance(metrics, dict):
        errors.append("metrics missing or malformed")
    else:
        errors.extend(_metric_errors(metrics))
        errors.extend(_case_evidence_errors(evidence, metrics))
    artifact_digest = digest or evidence.get("github_artifact_digest")
    if payload.get("requireGithubArtifactDigest") and not (
        isinstance(artifact_digest, str) and DIGEST_RE.match(artifact_digest)
    ):
        errors.append("github artifact digest required in sha256:<hex> format")
    errors.extend(_artifact_binding_errors(payload, artifact_digest))
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
    count_required = {
        "case_count",
        "critical_defects_blocked",
        "critical_defect_count",
        "negative_controls_blocked",
        "negative_control_count",
        "false_blocks",
        "verified_safe_count",
    }
    scalar_required = {
        "critical_defect_recall",
        "negative_control_recall",
        "false_block_rate",
        "repeated_run_decision_stability",
        "deterministic_flake_rate",
        "execution_duration_seconds",
    }
    for name in sorted(count_required):
        if not isinstance(metrics.get(name), int):
            errors.append(f"metrics.{name} missing or not an integer")
    for name in sorted(scalar_required):
        if not isinstance(metrics.get(name), (int, float)) or isinstance(metrics.get(name), bool):
            errors.append(f"metrics.{name} missing or not a number")
    if errors:
        return errors
    if metrics["execution_duration_seconds"] < 0:
        errors.append("metrics.execution_duration_seconds must be nonnegative")
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


def _case_evidence_errors(evidence: dict[str, Any], metrics: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    cases = evidence.get("cases")
    if not isinstance(cases, list):
        return ["cases missing or malformed"]
    errors.extend(_case_manifest_errors(cases))
    if metrics.get("case_count") != len(cases):
        errors.append("metrics.case_count must equal len(cases)")
    recomputed = {
        "critical_defects_blocked": 0,
        "critical_defect_count": 0,
        "negative_controls_blocked": 0,
        "negative_control_count": 0,
        "false_blocks": 0,
        "verified_safe_count": 0,
    }
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"cases[{index}] malformed")
            continue
        expected = case.get("expected_decision")
        decision = case.get("decision")
        actual = decision.get("decision") if isinstance(decision, dict) else None
        if actual != expected:
            errors.append(f"cases[{index}].decision expected {expected!r}, got {actual!r}")
        label = case.get("label")
        category = case.get("category")
        if case.get("critical") is True and label == "REPRODUCED_BAD":
            recomputed["critical_defect_count"] += 1
            if actual == "BLOCK_TECHNICAL":
                recomputed["critical_defects_blocked"] += 1
        if category == "synthetic_structural" and label == "REPRODUCED_BAD":
            recomputed["negative_control_count"] += 1
            if actual == "BLOCK_TECHNICAL":
                recomputed["negative_controls_blocked"] += 1
        if label == "VERIFIED_SAFE":
            recomputed["verified_safe_count"] += 1
            if actual == "BLOCK_TECHNICAL":
                recomputed["false_blocks"] += 1
    for name, value in recomputed.items():
        if metrics.get(name) != value:
            errors.append(f"metrics.{name} expected recomputed value {value}, got {metrics.get(name)!r}")
    return errors


def _artifact_binding_errors(payload: dict[str, Any], artifact_digest: str | None) -> list[str]:
    binding = payload.get("benchmarkArtifactBinding")
    if not payload.get("requireGithubArtifactDigest") and not isinstance(binding, dict):
        return []
    if not isinstance(binding, dict):
        return ["github artifact binding required when github artifact digest is required"]
    if binding.get("__load_error"):
        return [f"github artifact binding could not be loaded: {binding['__load_error']}"]

    errors: list[str] = []
    expected_head = payload.get("headRefOid") or ""
    expected_name = payload.get("benchmarkArtifactName") or "governance-benchmark-json"
    run_id = str(binding.get("workflow_run_id") or "")
    artifact_run_id = str(binding.get("artifact_workflow_run_id") or "")
    artifact_id = str(binding.get("artifact_id") or "")
    if not run_id:
        errors.append("github artifact binding workflow_run_id missing")
    if not artifact_id:
        errors.append("github artifact binding artifact_id missing")
    if artifact_run_id and run_id and artifact_run_id != run_id:
        errors.append("github artifact binding artifact workflow_run_id does not match workflow_run_id")
    if binding.get("workflow_status") != "completed":
        errors.append("github artifact binding workflow_status must be completed")
    if binding.get("workflow_conclusion") != "success":
        errors.append("github artifact binding workflow_conclusion must be success")
    if binding.get("workflow_head_sha") != expected_head:
        errors.append("github artifact binding workflow_head_sha does not match latest head")
    artifact_head = binding.get("artifact_workflow_head_sha")
    if artifact_head and artifact_head != expected_head:
        errors.append("github artifact binding artifact_workflow_head_sha does not match latest head")
    if binding.get("artifact_name") != expected_name:
        errors.append(f"github artifact binding artifact_name must be {expected_name}")
    if binding.get("artifact_expired") is True:
        errors.append("github artifact binding artifact is expired")
    if binding.get("artifact_digest") != artifact_digest:
        errors.append("github artifact binding artifact_digest does not match supplied digest")
    if not (isinstance(binding.get("artifact_digest"), str) and DIGEST_RE.match(binding["artifact_digest"])):
        errors.append("github artifact binding artifact_digest must be sha256:<hex>")
    return errors


def _case_manifest_errors(cases: list[Any]) -> list[str]:
    try:
        manifest_cases = load_cases()
    except Exception as exc:
        return [f"benchmark case manifest could not be loaded: {type(exc).__name__}: {exc}"]

    manifest_fields = ("id", "title", "category", "label", "critical", "expected_decision")
    expected_manifest = [{field: case.get(field) for field in manifest_fields} for case in manifest_cases]
    actual_manifest = [
        {field: case.get(field) for field in manifest_fields}
        for case in cases
        if isinstance(case, dict)
    ]
    if actual_manifest == expected_manifest:
        return []

    errors: list[str] = []
    expected_ids = [case["id"] for case in expected_manifest]
    actual_ids = [case.get("id") for case in actual_manifest]
    if actual_ids != expected_ids:
        errors.append(f"benchmark cases must match governed manifest ids {expected_ids!r}, got {actual_ids!r}")
        return errors
    for index, (actual, expected) in enumerate(zip(actual_manifest, expected_manifest, strict=True)):
        for field in manifest_fields:
            if actual.get(field) != expected.get(field):
                errors.append(
                    f"benchmark cases[{index}].{field} must match governed manifest "
                    f"{expected.get(field)!r}, got {actual.get(field)!r}"
                )
    return errors


def _fallback_quorum_result(quorum: Any, expected_base_sha: str, expected_head_sha: str) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(quorum, dict):
        return {"valid": False, "errors": ["fallback quorum missing or malformed"]}
    if quorum.get("__load_error"):
        return {"valid": False, "errors": [f"fallback quorum malformed JSON: {quorum['__load_error']}"]}
    trusted_agents = quorum.get("_trustedReviewerAgentIds")
    public_quorum = {key: value for key, value in quorum.items() if key != "_trustedReviewerAgentIds"}
    try:
        validate_named("review_quorum", public_quorum)
    except SchemaValidationError as exc:
        errors.append(f"fallback quorum schema invalid: {exc}")
    if quorum.get("review_gate") != REVIEW_GATE_FALLBACK:
        errors.append("fallback quorum review_gate must be FALLBACK_CLEAN_ROOM_QUORUM")
    if quorum.get("reviewed_head_sha") != expected_head_sha:
        errors.append("fallback quorum reviewed_head_sha does not match latest head")
    if expected_base_sha and quorum.get("reviewed_base_sha") != expected_base_sha:
        errors.append("fallback quorum reviewed_base_sha does not match base")
    provenance = quorum.get("provenance")
    provenance_outputs = _quorum_provenance_outputs(provenance, expected_base_sha, expected_head_sha, trusted_agents)
    errors.extend(provenance_outputs["errors"])
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
        if isinstance(reviewer_id, str) and reviewer_id:
            output = provenance_outputs["by_reviewer"].get(reviewer_id)
            if output is None:
                errors.append(f"reviewers[{index}].reviewer_id missing from provenance reviewer_outputs")
            else:
                if not isinstance(output.get("agent_id"), str) or not output["agent_id"]:
                    errors.append(f"reviewers[{index}] provenance agent_id missing")
                elif isinstance(trusted_agents, set) and output["agent_id"] not in trusted_agents:
                    errors.append(f"reviewers[{index}] provenance agent_id is not trusted")
                response_hash = output.get("response_sha256")
                if not (isinstance(response_hash, str) and SHA256_RE.match(response_hash)):
                    errors.append(f"reviewers[{index}] provenance response_sha256 invalid")
                elif response_hash != sha256_json(reviewer):
                    errors.append(f"reviewers[{index}] provenance response_sha256 does not match reviewer JSON")
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


def validate_review_quorum_document(
    quorum: dict[str, Any],
    expected_head_sha: str,
    expected_base_sha: str = "",
    trusted_reviewer_agent_ids: list[str] | None = None,
) -> list[str]:
    quorum_with_trust = dict(quorum)
    if trusted_reviewer_agent_ids:
        quorum_with_trust["_trustedReviewerAgentIds"] = set(trusted_reviewer_agent_ids)
    return _fallback_quorum_result(quorum_with_trust, expected_base_sha, expected_head_sha)["errors"]


def _with_trusted_reviewers(quorum: Any, trusted_reviewer_agent_ids: Any) -> Any:
    if not isinstance(quorum, dict):
        return quorum
    trusted = {item for item in trusted_reviewer_agent_ids or [] if isinstance(item, str) and item}
    if not trusted:
        return quorum
    wrapped = dict(quorum)
    wrapped["_trustedReviewerAgentIds"] = trusted
    return wrapped


def _quorum_provenance_outputs(
    provenance: Any,
    expected_base_sha: str,
    expected_head_sha: str,
    trusted_agents: Any = None,
) -> dict[str, Any]:
    errors: list[str] = []
    by_reviewer: dict[str, dict[str, Any]] = {}
    if not isinstance(provenance, dict):
        return {"errors": ["fallback quorum provenance missing or malformed"], "by_reviewer": by_reviewer}
    if provenance.get("source") != "codex_multi_agent_v1_clean_room_review":
        errors.append("fallback quorum provenance source must be codex_multi_agent_v1_clean_room_review")
    if provenance.get("reviewed_head_sha") != expected_head_sha:
        errors.append("fallback quorum provenance reviewed_head_sha does not match latest head")
    if expected_base_sha and provenance.get("reviewed_base_sha") != expected_base_sha:
        errors.append("fallback quorum provenance reviewed_base_sha does not match base")
    if not isinstance(trusted_agents, set) or len(trusted_agents) < 2:
        errors.append("fallback quorum requires at least two trusted reviewer agent IDs outside quorum JSON")
    outputs = provenance.get("reviewer_outputs")
    if not isinstance(outputs, list) or len(outputs) < 2:
        errors.append("fallback quorum provenance requires at least two reviewer_outputs")
        return {"errors": errors, "by_reviewer": by_reviewer}
    for index, output in enumerate(outputs):
        if not isinstance(output, dict):
            errors.append(f"provenance.reviewer_outputs[{index}] malformed")
            continue
        reviewer_id = output.get("reviewer_id")
        if not isinstance(reviewer_id, str) or not reviewer_id:
            errors.append(f"provenance.reviewer_outputs[{index}].reviewer_id missing")
            continue
        if reviewer_id in by_reviewer:
            errors.append(f"provenance.reviewer_outputs[{index}].reviewer_id duplicated")
            continue
        agent_id = output.get("agent_id")
        if isinstance(trusted_agents, set) and isinstance(agent_id, str) and agent_id not in trusted_agents:
            errors.append(f"provenance.reviewer_outputs[{index}].agent_id is not trusted")
        by_reviewer[reviewer_id] = output
    return {"errors": errors, "by_reviewer": by_reviewer}


def _github_review_state(
    payload: dict[str, Any],
    github_final_review: bool,
    later_blocking: list[dict[str, Any]],
    unresolved_blocking: list[dict[str, Any]],
    blocking_comments: list[dict[str, Any]],
) -> str:
    if later_blocking or unresolved_blocking or blocking_comments:
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


def _comment_is_blocking(comment: dict[str, Any], latest_head_committed_at: str) -> bool:
    body = comment.get("body") or ""
    if not _body_has_blocking_finding(body):
        return False
    if comment.get("isMinimized"):
        return False
    created_at = comment.get("createdAt")
    if created_at and latest_head_committed_at and _dt(created_at) < _dt(latest_head_committed_at):
        return False
    return True


def _body_has_blocking_finding(body: str) -> bool:
    if not BLOCKING_RE.search(body):
        return False
    normalized = re.sub(r"\s+", " ", body.lower())
    if "@codex review" in normalized:
        return False
    if re.search(r"\bunresolved\b", normalized):
        return True
    if re.search(r"\bresolved\b", normalized) and ("p0/p1/p2" in normalized or "p0-p2" in normalized):
        return False
    return True


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
