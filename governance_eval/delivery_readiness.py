from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from governance_eval.benchmark import validate_benchmark_result
from governance_eval.cases import load_cases
from governance_eval.copilot_review_evidence import latest_clean_structured_review_evidence
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
    benchmark_result = _benchmark_result(payload, latest_head_sha)
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
            "baseRefOid,commits,statusCheckRollup,headRefOid,isDraft,mergeStateStatus,state,url",
        ],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    pr = json.loads(completed.stdout)
    raw_reviews = _gh_paginated_json_list(f"repos/{owner}/{name}/pulls/{pr_number}/reviews?per_page=100")
    raw_comments = _gh_paginated_json_list(f"repos/{owner}/{name}/issues/{pr_number}/comments?per_page=100")
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
    for review in raw_reviews:
        commit_value = review.get("commit")
        commit: dict[str, Any] = commit_value if isinstance(commit_value, dict) else {}
        author_value = review.get("user")
        author: dict[str, Any] = author_value if isinstance(author_value, dict) else {}
        reviews.append(
            {
                "state": review.get("state"),
                "submittedAt": review.get("submitted_at"),
                "commitOid": review.get("commit_id") or commit.get("oid"),
                "author": author.get("login"),
                "body": review.get("body"),
            }
        )
    comments = []
    for comment in raw_comments:
        author_value = comment.get("user")
        author = author_value if isinstance(author_value, dict) else {}
        comments.append(
            {
                "createdAt": comment.get("created_at"),
                "author": author.get("login"),
                "body": comment.get("body"),
                "isMinimized": False,
                "minimizedReason": None,
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


def _gh_paginated_json_list(path: str) -> list[dict[str, Any]]:
    completed = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", path],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    pages = json.loads(completed.stdout)
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise ValueError("paginated GitHub API response must be a list of pages")
    records = [item for page in pages for item in page]
    if not all(isinstance(item, dict) for item in records):
        raise ValueError("GitHub API pages must contain only objects")
    return records


def _load_review_threads(owner: str, name: str, pr_number: int) -> list[dict[str, Any]]:
    query = """
    query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          reviewThreads(first: 100, after: $cursor) {
            nodes {
              id
              isResolved
              path
              line
              comments(first: 100) {
                nodes {
                  body
                }
                pageInfo {
                  hasNextPage
                  endCursor
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
        complete_nodes = [_complete_review_thread(node) for node in connection.get("nodes", [])]
        threads.extend(_unresolved_threads(complete_nodes))
        page_info = connection.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
        if not cursor:
            raise RuntimeError("GitHub reviewThreads pagination did not return endCursor")
    return threads


def _complete_review_thread(node: dict[str, Any]) -> dict[str, Any]:
    thread_id = node.get("id")
    if not isinstance(thread_id, str) or not thread_id:
        raise RuntimeError("GitHub review thread ID is missing")
    complete = json.loads(json.dumps(node))
    connection = _validated_connection(complete.get("comments"), "review comment")
    comments = list(connection["nodes"])
    page = connection["pageInfo"]
    cursor = str(page.get("endCursor") or "")
    while page.get("hasNextPage"):
        if not cursor:
            raise RuntimeError("GitHub review comment pagination did not return endCursor")
        payload = _load_thread_comment_page(thread_id, cursor)
        if payload.get("errors"):
            raise RuntimeError("GitHub review comment GraphQL response contains errors")
        data = payload.get("data")
        graph_node = data.get("node") if isinstance(data, dict) else None
        if not isinstance(graph_node, dict) or graph_node.get("id") != thread_id:
            raise RuntimeError("GitHub review comment page has the wrong thread identity")
        connection = _validated_connection(graph_node.get("comments"), "review comment")
        comments.extend(connection["nodes"])
        page = connection["pageInfo"]
        next_cursor = str(page.get("endCursor") or "")
        if page.get("hasNextPage") and (not next_cursor or next_cursor == cursor):
            raise RuntimeError("GitHub review comment pagination did not advance")
        cursor = next_cursor
    complete["comments"] = {"nodes": comments, "pageInfo": page}
    return complete


def _load_thread_comment_page(thread_id: str, cursor: str) -> dict[str, Any]:
    if not thread_id:
        raise RuntimeError("GitHub review thread ID is missing")
    query = """
    query($id: ID!, $cursor: String!) {
      node(id: $id) {
        ... on PullRequestReviewThread {
          id
          comments(first: 100, after: $cursor) {
            nodes { body }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
    """
    completed = subprocess.run(
        [
            "gh",
            "api",
            "graphql",
            "-f",
            f"id={thread_id}",
            "-f",
            f"cursor={cursor}",
            "-f",
            f"query={query}",
        ],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    return json.loads(completed.stdout)


def _review_threads_connection(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("errors"):
        raise RuntimeError("GitHub review thread GraphQL response contains errors")
    try:
        connection = payload["data"]["repository"]["pullRequest"]["reviewThreads"]
    except (KeyError, TypeError) as exc:
        raise RuntimeError("GitHub review thread GraphQL response is malformed") from exc
    return _validated_connection(connection, "review thread")


def _validated_connection(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"GitHub {label} connection is missing")
    nodes = value.get("nodes")
    page = value.get("pageInfo")
    if not isinstance(nodes, list) or not all(isinstance(node, dict) for node in nodes):
        raise RuntimeError(f"GitHub {label} nodes must be a list of objects")
    if not isinstance(page, dict) or not isinstance(page.get("hasNextPage"), bool):
        raise RuntimeError(f"GitHub {label} pageInfo is malformed")
    if page["hasNextPage"] and not isinstance(page.get("endCursor"), str):
        raise RuntimeError(f"GitHub {label} pageInfo is missing endCursor")
    return {"nodes": nodes, "pageInfo": page}


def _unresolved_threads(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    threads: list[dict[str, Any]] = []
    for thread in nodes:
        if thread.get("isResolved"):
            continue
        bodies = [comment.get("body", "") for comment in (thread.get("comments", {}) or {}).get("nodes", [])]
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
    payload = _payload_from_args(args)
    result = evaluate_readiness(payload)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] else 1


def _payload_from_args(args: argparse.Namespace) -> dict[str, Any]:
    payload = (
        json.loads(open(args.payload, encoding="utf-8").read())
        if args.payload
        else load_github_payload(args.repo, args.pr)
    )
    if args.benchmark_artifact:
        payload["benchmarkEvidence"] = _read_json_or_error(Path(args.benchmark_artifact))
    if args.benchmark_artifact_digest:
        payload["benchmarkArtifactDigest"] = args.benchmark_artifact_digest
    if args.benchmark_artifact_name:
        payload["benchmarkArtifactName"] = args.benchmark_artifact_name
    _add_artifact_binding(payload, args)
    if args.require_github_artifact_digest:
        payload["requireGithubArtifactDigest"] = True
    if args.fallback_quorum:
        payload["fallbackQuorum"] = _read_json_or_error(Path(args.fallback_quorum))
    if args.trusted_reviewer_agent:
        payload["trustedReviewerAgentIds"] = args.trusted_reviewer_agent
    return payload


def _add_artifact_binding(payload: dict[str, Any], args: argparse.Namespace) -> None:
    if not (args.benchmark_run_id or args.benchmark_artifact_id):
        return
    if not (args.benchmark_run_id and args.benchmark_artifact_id):
        payload["benchmarkArtifactBinding"] = {
            "__load_error": "--benchmark-run-id and --benchmark-artifact-id must be supplied together"
        }
        return
    binding = _load_github_artifact_binding(
        args.repo, args.benchmark_run_id, args.benchmark_artifact_id, args.benchmark_artifact_name
    )
    payload["benchmarkArtifactBinding"] = binding
    digest = binding.get("artifact_digest") if isinstance(binding, dict) else None
    if not args.benchmark_artifact_digest and isinstance(digest, str):
        payload["benchmarkArtifactDigest"] = digest


def _load_github_artifact_binding(repo: str, run_id: str, artifact_id: str, artifact_name: str) -> dict[str, Any]:
    try:
        run = _gh_api_json(f"repos/{repo}/actions/runs/{run_id}")
        artifact = _gh_api_json(f"repos/{repo}/actions/artifacts/{artifact_id}")
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        return {"__load_error": f"{type(exc).__name__}: {exc}"}
    artifact_run_value = artifact.get("workflow_run")
    artifact_run = artifact_run_value if isinstance(artifact_run_value, dict) else {}
    binding = {
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
    binding.update(_download_artifact_evidence(repo, run_id, artifact_name))
    return binding


def _download_artifact_evidence(repo: str, run_id: str, artifact_name: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="governance-artifact-") as tmp:
        temp_dir = Path(tmp)
        try:
            subprocess.run(
                ["gh", "run", "download", run_id, "--repo", repo, "--name", artifact_name, "--dir", str(temp_dir)],
                check=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            return {"artifact_evidence_error": f"{type(exc).__name__}: {exc.stderr or exc.stdout}"}
        candidates = sorted(temp_dir.glob("governance-benchmark-latest.json"))
        if not candidates:
            return {"artifact_evidence_error": "governance-benchmark-latest.json missing from artifact"}
        try:
            data = json.loads(candidates[0].read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return {"artifact_evidence_error": f"artifact benchmark JSON malformed: {exc}"}
        return {
            "artifact_evidence_content_hash": data.get("artifact_content_hash"),
            "artifact_evidence_phase1_decision": data.get("phase1_decision"),
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
        review for review in reviews if _review_applies_to_latest(review, latest_head_sha, latest_head_committed_at)
    ]
    structured_clean = latest_clean_structured_review_evidence(
        {"reviews": same_head_reviews, "comments": []},
        latest_head_sha,
        sorted(FINAL_REVIEW_AUTHORS),
        _final_review_author_matches,
    )
    clean_github_reviews = [structured_clean] if structured_clean is not None else []
    blocking_reviews = [review for review in same_head_reviews if _review_is_blocking(review)]
    latest_clean = _latest_review(clean_github_reviews)
    later_blocking = [
        review
        for review in blocking_reviews
        if latest_clean is None or _dt(review["submittedAt"]) > _dt(latest_clean["submittedAt"])
    ]
    github_final_review = (
        latest_clean is not None and not later_blocking and not unresolved_blocking and not blocking_comments
    )
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
        "final_review_timestamp": latest_clean["submittedAt"]
        if latest_clean is not None and github_final_review
        else None,
        "fallback_quorum_valid": fallback_result["valid"],
        "fallback_quorum_errors": fallback_result["errors"],
        "later_blocking_review_count": len(later_blocking),
    }


def _benchmark_result(payload: dict[str, Any], latest_head_sha: str = "") -> dict[str, Any]:
    evidence = payload.get("benchmarkEvidence")
    digest = payload.get("benchmarkArtifactDigest")
    errors: list[str] = []
    if not isinstance(evidence, dict):
        errors.append("benchmark evidence missing or malformed")
        return _benchmark_result_payload(False, errors, None, None, digest)
    if evidence.get("__load_error"):
        errors.append(f"benchmark evidence malformed JSON: {evidence['__load_error']}")
        return _benchmark_result_payload(False, errors, None, None, digest)
    errors.extend(_benchmark_content_errors(evidence, latest_head_sha))
    phase1_decision = evidence.get("phase1_decision")
    artifact_hash = evidence.get("artifact_content_hash")
    errors.extend(_artifact_content_hash_errors(evidence, artifact_hash))
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
    errors.extend(_artifact_binding_errors(payload, artifact_digest, artifact_hash))
    return _benchmark_result_payload(not errors, errors, phase1_decision, artifact_hash, artifact_digest)


def _benchmark_content_errors(evidence: dict[str, Any], latest_head_sha: str) -> list[str]:
    errors: list[str] = []
    try:
        validate_benchmark_result(evidence)
    except SchemaValidationError as exc:
        errors.append(f"benchmark schema invalid: {exc}")
    if evidence.get("phase1_decision") != "BENCHMARK_PASS":
        errors.append(f"phase1_decision expected BENCHMARK_PASS, got {evidence.get('phase1_decision')!r}")
    if latest_head_sha and evidence.get("governance_evaluator_git_sha") != latest_head_sha:
        errors.append(
            f"governance_evaluator_git_sha must match latest head {latest_head_sha}, got {evidence.get('governance_evaluator_git_sha')!r}"
        )
    if evidence.get("acceptance_errors") != []:
        errors.append("acceptance_errors must be []")
    return errors


def _artifact_content_hash_errors(evidence: dict[str, Any], artifact_hash: Any) -> list[str]:
    if not (isinstance(artifact_hash, str) and SHA256_RE.match(artifact_hash)):
        return ["artifact_content_hash must be a 64-character lowercase hex SHA-256"]
    if artifact_hash != sha256_json({**evidence, "artifact_content_hash": ""}):
        return ["artifact_content_hash does not match benchmark evidence content"]
    return []


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
    errors.extend(_metric_range_errors(metrics))
    errors.extend(_metric_acceptance_errors(metrics))
    return errors


def _metric_range_errors(metrics: dict[str, Any]) -> list[str]:
    errors = (
        ["metrics.execution_duration_seconds must be nonnegative"] if metrics["execution_duration_seconds"] < 0 else []
    )
    errors.extend(
        f"metrics.{name} must be greater than zero"
        for name in ("case_count", "critical_defect_count", "negative_control_count", "verified_safe_count")
        if metrics[name] <= 0
    )
    for numerator, denominator in (
        ("critical_defects_blocked", "critical_defect_count"),
        ("negative_controls_blocked", "negative_control_count"),
        ("false_blocks", "verified_safe_count"),
    ):
        if metrics[numerator] < 0 or metrics[numerator] > metrics[denominator]:
            errors.append(f"metrics.{numerator} must be between 0 and metrics.{denominator}")
    return errors


def _metric_acceptance_errors(metrics: dict[str, Any]) -> list[str]:
    errors: list[str] = []
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
        if metrics[name] != expected:
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
        case_errors, counts = _single_case_evidence(case, index)
        errors.extend(case_errors)
        for name, value in counts.items():
            recomputed[name] += value
    for name, value in recomputed.items():
        if metrics.get(name) != value:
            errors.append(f"metrics.{name} expected recomputed value {value}, got {metrics.get(name)!r}")
    return errors


def _single_case_evidence(case: Any, index: int) -> tuple[list[str], dict[str, int]]:
    counts = {
        name: 0
        for name in (
            "critical_defects_blocked",
            "critical_defect_count",
            "negative_controls_blocked",
            "negative_control_count",
            "false_blocks",
            "verified_safe_count",
        )
    }
    if not isinstance(case, dict):
        return [f"cases[{index}] malformed"], counts
    decision = case.get("decision")
    actual = decision.get("decision") if isinstance(decision, dict) else None
    errors = (
        [f"cases[{index}].decision expected {case.get('expected_decision')!r}, got {actual!r}"]
        if actual != case.get("expected_decision")
        else []
    )
    evidence_ids, evidence_errors = _detector_evidence_ids(case, index)
    errors.extend(evidence_errors)
    refs = decision.get("evidence_refs") if isinstance(decision, dict) else None
    if not isinstance(refs, list) or not refs:
        errors.append(f"cases[{index}].decision.evidence_refs must cite detector evidence")
    elif not set(refs).issubset(evidence_ids):
        errors.append(f"cases[{index}].decision.evidence_refs must match detector evidence ids")
    _increment_case_counts(case, actual, counts)
    return errors, counts


def _detector_evidence_ids(case: dict[str, Any], index: int) -> tuple[set[str], list[str]]:
    evidence = case.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return set(), [f"cases[{index}].evidence must contain detector evidence"]
    ids = {
        str(item["evidence_id"])
        for item in evidence
        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    }
    errors = (
        [f"cases[{index}].evidence entries must have unique evidence_id values"] if len(ids) != len(evidence) else []
    )
    for evidence_index, item in enumerate(evidence):
        if not isinstance(item, dict):
            errors.append(f"cases[{index}].evidence[{evidence_index}] malformed")
        elif item.get("case_id") != case.get("id"):
            errors.append(f"cases[{index}].evidence[{evidence_index}].case_id must match case id")
    return ids, errors


def _increment_case_counts(case: dict[str, Any], actual: Any, counts: dict[str, int]) -> None:
    label = case.get("label")
    if case.get("critical") is True and label == "REPRODUCED_BAD":
        counts["critical_defect_count"] += 1
        counts["critical_defects_blocked"] += actual == "BLOCK_TECHNICAL"
    if case.get("category") == "synthetic_structural" and label == "REPRODUCED_BAD":
        counts["negative_control_count"] += 1
        counts["negative_controls_blocked"] += actual == "BLOCK_TECHNICAL"
    if label == "VERIFIED_SAFE":
        counts["verified_safe_count"] += 1
        counts["false_blocks"] += actual == "BLOCK_TECHNICAL"


def _artifact_binding_errors(
    payload: dict[str, Any], artifact_digest: str | None, artifact_hash: str | None
) -> list[str]:
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
    errors.extend(_artifact_identity_errors(binding, run_id, artifact_run_id, artifact_id, expected_head))
    errors.extend(
        _artifact_evidence_binding_errors(binding, artifact_digest, artifact_hash, expected_head, expected_name)
    )
    return errors


def _artifact_evidence_binding_errors(
    binding: dict[str, Any], digest: str | None, content_hash: str | None, head: str, name: str
) -> list[str]:
    artifact_head = binding.get("artifact_workflow_head_sha")
    checks = (
        (
            bool(artifact_head and artifact_head != head),
            "github artifact binding artifact_workflow_head_sha does not match latest head",
        ),
        (binding.get("artifact_name") != name, f"github artifact binding artifact_name must be {name}"),
        (binding.get("artifact_expired") is True, "github artifact binding artifact is expired"),
        (
            binding.get("artifact_digest") != digest,
            "github artifact binding artifact_digest does not match supplied digest",
        ),
        (
            not (isinstance(binding.get("artifact_digest"), str) and DIGEST_RE.match(binding["artifact_digest"])),
            "github artifact binding artifact_digest must be sha256:<hex>",
        ),
        (
            bool(binding.get("artifact_evidence_error")),
            f"github artifact evidence could not be loaded: {binding.get('artifact_evidence_error')}",
        ),
        (
            binding.get("artifact_evidence_content_hash") != content_hash,
            "github artifact evidence content hash does not match supplied benchmark JSON",
        ),
        (
            binding.get("artifact_evidence_phase1_decision") != "BENCHMARK_PASS",
            "github artifact evidence phase1_decision must be BENCHMARK_PASS",
        ),
    )
    return [message for failed, message in checks if failed]


def _artifact_identity_errors(
    binding: dict[str, Any], run_id: str, artifact_run_id: str, artifact_id: str, expected_head: str
) -> list[str]:
    checks = (
        (not run_id, "github artifact binding workflow_run_id missing"),
        (not artifact_id, "github artifact binding artifact_id missing"),
        (
            bool(artifact_run_id and run_id and artifact_run_id != run_id),
            "github artifact binding artifact workflow_run_id does not match workflow_run_id",
        ),
        (binding.get("workflow_status") != "completed", "github artifact binding workflow_status must be completed"),
        (
            binding.get("workflow_conclusion") != "success",
            "github artifact binding workflow_conclusion must be success",
        ),
        (
            binding.get("workflow_head_sha") != expected_head,
            "github artifact binding workflow_head_sha does not match latest head",
        ),
    )
    return [message for failed, message in checks if failed]


def _case_manifest_errors(cases: list[Any]) -> list[str]:
    try:
        manifest_cases = load_cases()
    except Exception as exc:
        return [f"benchmark case manifest could not be loaded: {type(exc).__name__}: {exc}"]

    manifest_fields = ("id", "title", "category", "label", "critical", "expected_decision")
    expected_manifest = [{field: case.get(field) for field in manifest_fields} for case in manifest_cases]
    actual_manifest = [
        {field: case.get(field) for field in manifest_fields} for case in cases if isinstance(case, dict)
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
    reviewer_agent_ids: set[str] = set()
    for index, reviewer in enumerate(reviewers):
        errors.extend(
            _reviewer_errors(
                reviewer,
                index,
                quorum,
                expected_base_sha,
                expected_head_sha,
                trusted_agents,
                provenance_outputs["by_reviewer"],
                reviewer_ids,
                reviewer_agent_ids,
            )
        )
    return {"valid": not errors, "errors": errors}


def _reviewer_errors(
    reviewer: Any,
    index: int,
    quorum: dict[str, Any],
    base: str,
    head: str,
    trusted: Any,
    outputs: dict[str, Any],
    reviewer_ids: set[str],
    agent_ids: set[str],
) -> list[str]:
    if not isinstance(reviewer, dict):
        return [f"reviewers[{index}] malformed"]
    errors: list[str] = []
    reviewer_id = reviewer.get("reviewer_id")
    if not isinstance(reviewer_id, str) or not reviewer_id:
        errors.append(f"reviewers[{index}].reviewer_id missing")
    elif reviewer_id in reviewer_ids:
        errors.append(f"reviewers[{index}].reviewer_id duplicated")
    else:
        reviewer_ids.add(reviewer_id)
        errors.extend(_reviewer_provenance_errors(reviewer, index, outputs.get(reviewer_id), trusted, agent_ids))
    if (reviewer.get("reviewed_head_sha") or quorum.get("reviewed_head_sha")) != head:
        errors.append(f"reviewers[{index}].reviewed_head_sha does not match latest head")
    if base and (reviewer.get("reviewed_base_sha") or quorum.get("reviewed_base_sha")) != base:
        errors.append(f"reviewers[{index}].reviewed_base_sha does not match base")
    if reviewer.get("final_verdict") != "CLEAN":
        errors.append(f"reviewers[{index}].final_verdict must be CLEAN")
    findings = reviewer.get("findings") or []
    if not isinstance(findings, list):
        errors.append(f"reviewers[{index}].findings malformed")
    else:
        errors.extend(
            f"reviewers[{index}].findings[{position}] reports blocking {finding.get('severity')}"
            for position, finding in enumerate(findings)
            if isinstance(finding, dict) and finding.get("severity") in {"P0", "P1", "P2"}
        )
    return errors


def _reviewer_provenance_errors(
    reviewer: dict[str, Any], index: int, output: Any, trusted: Any, agent_ids: set[str]
) -> list[str]:
    if not isinstance(output, dict):
        return [f"reviewers[{index}].reviewer_id missing from provenance reviewer_outputs"]
    agent_id = output.get("agent_id")
    errors: list[str] = []
    if not isinstance(agent_id, str) or not agent_id:
        errors.append(f"reviewers[{index}] provenance agent_id missing")
    elif isinstance(trusted, set) and agent_id not in trusted:
        errors.append(f"reviewers[{index}] provenance agent_id is not trusted")
    elif agent_id in agent_ids:
        errors.append(f"reviewers[{index}] provenance agent_id duplicated")
    else:
        agent_ids.add(agent_id)
    response_hash = output.get("response_sha256")
    if not (isinstance(response_hash, str) and SHA256_RE.match(response_hash)):
        errors.append(f"reviewers[{index}] provenance response_sha256 invalid")
    elif response_hash != sha256_json(reviewer):
        errors.append(f"reviewers[{index}] provenance response_sha256 does not match reviewer JSON")
    return errors


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
        errors.extend(_provenance_output_errors(output, index, trusted_agents, by_reviewer))
    return {"errors": errors, "by_reviewer": by_reviewer}


def _provenance_output_errors(
    output: Any, index: int, trusted: Any, by_reviewer: dict[str, dict[str, Any]]
) -> list[str]:
    if not isinstance(output, dict):
        return [f"provenance.reviewer_outputs[{index}] malformed"]
    reviewer_id = output.get("reviewer_id")
    if not isinstance(reviewer_id, str) or not reviewer_id:
        return [f"provenance.reviewer_outputs[{index}].reviewer_id missing"]
    if reviewer_id in by_reviewer:
        return [f"provenance.reviewer_outputs[{index}].reviewer_id duplicated"]
    by_reviewer[reviewer_id] = output
    agent_id = output.get("agent_id")
    if isinstance(trusted, set) and isinstance(agent_id, str) and agent_id not in trusted:
        return [f"provenance.reviewer_outputs[{index}].agent_id is not trusted"]
    return []


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


def _review_is_on_latest_after_commit(
    review: dict[str, Any], latest_head_sha: str, latest_head_committed_at: str
) -> bool:
    return bool(
        review.get("submittedAt")
        and review.get("commitOid") == latest_head_sha
        and _dt(review["submittedAt"]) >= _dt(latest_head_committed_at)
    )


def _review_applies_to_latest(review: dict[str, Any], latest_head_sha: str, latest_head_committed_at: str) -> bool:
    if _review_is_on_latest_after_commit(review, latest_head_sha, latest_head_committed_at):
        return True
    if not _review_is_blocking(review):
        return False
    return bool(
        review.get("submittedAt")
        and not review.get("commitOid")
        and _dt(review["submittedAt"]) >= _dt(latest_head_committed_at)
    )


def _review_is_blocking(review: dict[str, Any]) -> bool:
    if review.get("state") == "DISMISSED":
        return False
    return review.get("state") == "CHANGES_REQUESTED" or bool(BLOCKING_RE.search(review.get("body") or ""))


def _review_references_head(review: dict[str, Any], latest_head_sha: str) -> bool:
    body = review.get("body") or ""
    return latest_head_sha in body or latest_head_sha[:10] in body


def _final_review_author_matches(author: Any, approved: list[str]) -> bool:
    return isinstance(author, str) and author in approved


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
    if _is_pure_codex_review_trigger(normalized):
        return False
    if re.search(r"\bunresolved\b", normalized):
        return True
    if re.search(r"\bresolved\b", normalized) and ("p0/p1/p2" in normalized or "p0-p2" in normalized):
        return False
    return True


def _is_pure_codex_review_trigger(normalized_body: str) -> bool:
    stripped = normalized_body.strip().strip(".")
    if not stripped.startswith("@codex review"):
        return False
    allowed_prefixes = (
        "@codex review",
        "@codex review final head",
        "@codex review final verification requested",
    )
    return any(stripped.startswith(prefix) for prefix in allowed_prefixes) and not BLOCKING_RE.search(stripped)


def _is_success_context(item: dict[str, Any]) -> bool:
    return item.get("conclusion") in SUCCESS_CONCLUSIONS or item.get("state") in SUCCESS_STATES


def _is_executed_success_context(item: dict[str, Any]) -> bool:
    return item.get("conclusion") == "SUCCESS" or item.get("state") == "SUCCESS"


def _is_governance_context(item: dict[str, Any]) -> bool:
    text = " ".join(str(item.get(field) or "") for field in ("name", "workflowName", "context"))
    return bool(GOVERNANCE_CONTEXT_RE.search(text))


def _count_severity(threads: list[dict[str, Any]], severity: str) -> int:
    pattern = re.compile(rf"\b{severity}\b|\[{severity}\]|severity:\s*{severity}", re.IGNORECASE)
    return sum(1 for thread in threads if pattern.search(thread.get("body") or ""))


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


if __name__ == "__main__":
    raise SystemExit(main())
