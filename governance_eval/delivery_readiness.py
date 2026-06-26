from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime
from typing import Any


BLOCKING_RE = re.compile(r"\bP[0-2]\b|\[P[0-2]\]|severity:\s*P[0-2]", re.IGNORECASE)
SUCCESS_CONCLUSIONS = {"SUCCESS", "SKIPPED", "NEUTRAL"}
SUCCESS_STATES = {"SUCCESS", "SKIPPED", "NEUTRAL"}
FINAL_REVIEW_AUTHORS = {"chatgpt-codex-connector"}


def evaluate_readiness(payload: dict[str, Any]) -> dict[str, Any]:
    latest_head_sha = payload.get("headRefOid") or ""
    latest_head_committed_at = payload.get("latestHeadCommittedAt") or ""
    reviews = payload.get("reviews") or []
    final_reviews = [
        review
        for review in reviews
        if review.get("submittedAt")
        and review.get("commitOid") == latest_head_sha
        and _dt(review["submittedAt"]) >= _dt(latest_head_committed_at)
        and review.get("state") not in {"CHANGES_REQUESTED", "DISMISSED"}
        and not BLOCKING_RE.search(review.get("body") or "")
        and review.get("author") in FINAL_REVIEW_AUTHORS
    ]
    unresolved = payload.get("unresolvedThreads") or []
    unresolved_blocking = [thread for thread in unresolved if _thread_is_p0_p2(thread)]
    workflow_contexts = payload.get("workflowContexts") or []
    has_workflow_evidence = bool(workflow_contexts)
    failed_contexts = [
        item
        for item in workflow_contexts
        if item.get("conclusion") not in SUCCESS_CONCLUSIONS and item.get("state") not in SUCCESS_STATES
    ]
    merge_state = payload.get("mergeStateStatus") or ""
    merge_eligible = (
        payload.get("state") == "OPEN"
        and not payload.get("isDraft", False)
        and merge_state not in {"BLOCKED", "DIRTY", "DRAFT", "UNKNOWN"}
    )
    ready = bool(
        latest_head_sha
        and final_reviews
        and not unresolved_blocking
        and has_workflow_evidence
        and not failed_contexts
        and merge_eligible
    )
    return {
        "ready": ready,
        "latest_head_sha": latest_head_sha,
        "latest_head_committed_at": latest_head_committed_at,
        "final_review_timestamp": max((review["submittedAt"] for review in final_reviews), default=None),
        "final_review_commit": latest_head_sha if final_reviews else None,
        "unresolved_p0_count": _count_severity(unresolved_blocking, "P0"),
        "unresolved_p1_count": _count_severity(unresolved_blocking, "P1"),
        "unresolved_p2_count": _count_severity(unresolved_blocking, "P2"),
        "failed_workflow_contexts": failed_contexts,
        "missing_workflow_evidence": not has_workflow_evidence,
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
            "commits,reviews,statusCheckRollup,headRefOid,isDraft,mergeStateStatus,state,url",
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
    args = parser.parse_args(argv)
    payload = json.loads(open(args.payload, encoding="utf-8").read()) if args.payload else load_github_payload(args.repo, args.pr)
    result = evaluate_readiness(payload)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] else 1


def _thread_is_p0_p2(thread: dict[str, Any]) -> bool:
    return bool(BLOCKING_RE.search(thread.get("body") or ""))


def _count_severity(threads: list[dict[str, Any]], severity: str) -> int:
    pattern = re.compile(rf"\b{severity}\b|\[{severity}\]|severity:\s*{severity}", re.IGNORECASE)
    return sum(1 for thread in threads if pattern.search(thread.get("body") or ""))


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


if __name__ == "__main__":
    raise SystemExit(main())
