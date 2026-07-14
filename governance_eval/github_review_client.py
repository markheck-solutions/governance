from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any


GITHUB_NETWORK_TIMEOUT_SECONDS = 60
GITHUB_GRAPHQL_MAX_PAGES = 100
GITHUB_GRAPHQL_MAX_NODES = 10_000
GITHUB_EVIDENCE_MAX_REQUESTS = 300
GITHUB_EVIDENCE_MAX_NODES = 20_000
GITHUB_EVIDENCE_MAX_BYTES = 20 * 1024 * 1024
GITHUB_EVIDENCE_MAX_SECONDS = 55.0


class GitHubReviewTransportError(RuntimeError):
    pass


@dataclass
class EvidenceBudget:
    requests: int = 0
    nodes: int = 0
    response_bytes: int = 0
    started_at: float = field(default_factory=time.monotonic)

    def consume_response(self, payload: dict[str, Any]) -> None:
        self.requests += 1
        self.response_bytes += len(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        self._check()

    def consume_nodes(self, count: int) -> None:
        self.nodes += count
        self._check()

    def _check(self) -> None:
        if self.requests > GITHUB_EVIDENCE_MAX_REQUESTS:
            raise GitHubReviewTransportError("GitHub evidence request budget exceeded")
        if self.nodes > GITHUB_EVIDENCE_MAX_NODES:
            raise GitHubReviewTransportError(
                "GitHub evidence aggregate node budget exceeded"
            )
        if self.response_bytes > GITHUB_EVIDENCE_MAX_BYTES:
            raise GitHubReviewTransportError(
                "GitHub evidence response byte budget exceeded"
            )
        if time.monotonic() - self.started_at > GITHUB_EVIDENCE_MAX_SECONDS:
            raise GitHubReviewTransportError(
                "GitHub evidence elapsed-time budget exceeded"
            )


def load_copilot_payload(repo: str, pr_number: int) -> dict[str, Any]:
    budget = EvidenceBudget()
    metadata = _gh_json(
        [
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo,
            "--json",
            "baseRefOid,headRefOid,state,url",
        ]
    )
    budget.consume_response(metadata)
    owner, name = repo.split("/", 1)
    return {
        "url": metadata.get("url"),
        "state": metadata.get("state"),
        "baseRefOid": metadata.get("baseRefOid"),
        "headRefOid": metadata.get("headRefOid"),
        "reviews": _load_reviews(owner, name, pr_number, budget),
        "comments": _load_comments(owner, name, pr_number, budget),
        "reviewThreads": _load_review_threads(owner, name, pr_number, budget),
    }


def _load_reviews(
    owner: str,
    name: str,
    pr_number: int,
    budget: EvidenceBudget | None = None,
) -> list[dict[str, Any]]:
    query = """
    query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          reviews(first: 100, after: $cursor) {
            nodes { state submittedAt commit { oid } author { login } body }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
    """
    return _normalize_reviews(
        _paginate_pr_nodes(
            owner,
            name,
            pr_number,
            query,
            "reviews",
            budget or EvidenceBudget(),
        )
    )


def _load_comments(
    owner: str,
    name: str,
    pr_number: int,
    budget: EvidenceBudget | None = None,
) -> list[dict[str, Any]]:
    query = """
    query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          comments(first: 100, after: $cursor) {
            nodes { author { login } body createdAt isMinimized }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
    """
    return _normalize_comments(
        _paginate_pr_nodes(
            owner,
            name,
            pr_number,
            query,
            "comments",
            budget or EvidenceBudget(),
        )
    )


def _load_review_threads(
    owner: str,
    name: str,
    pr_number: int,
    budget: EvidenceBudget | None = None,
) -> list[dict[str, Any]]:
    query = """
    query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          reviewThreads(first: 100, after: $cursor) {
            nodes {
              id
              isResolved
              path
              comments(first: 100) {
                nodes { body author { login } }
                pageInfo { hasNextPage endCursor }
              }
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
    """
    shared_budget = budget or EvidenceBudget()
    nodes = _paginate_pr_nodes(
        owner,
        name,
        pr_number,
        query,
        "reviewThreads",
        shared_budget,
    )
    return _normalize_threads(_complete_thread_comments(nodes, shared_budget))


def _paginate_pr_nodes(
    owner: str,
    name: str,
    pr_number: int,
    query: str,
    field: str,
    budget: EvidenceBudget,
) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    cursor = ""
    seen_cursors = {cursor}
    for _page_number in range(GITHUB_GRAPHQL_MAX_PAGES):
        payload = _gh_graphql(owner, name, pr_number, query, cursor)
        _validate_graphql_payload(payload)
        budget.consume_response(payload)
        connection = _pull_request_connection(payload, field)
        page_nodes = _page_nodes(connection, field)
        budget.consume_nodes(len(page_nodes))
        nodes.extend(page_nodes)
        if len(nodes) > GITHUB_GRAPHQL_MAX_NODES:
            raise GitHubReviewTransportError(
                f"GitHub {field} pagination exceeded node limit"
            )
        cursor = _next_page_cursor(connection, field, seen_cursors)
        if not cursor:
            return nodes
        seen_cursors.add(cursor)
    raise GitHubReviewTransportError(f"GitHub {field} pagination exceeded page limit")


def _pull_request_connection(payload: dict[str, Any], field: str) -> dict[str, Any]:
    try:
        connection = payload["data"]["repository"]["pullRequest"][field]
    except (KeyError, TypeError) as exc:
        raise GitHubReviewTransportError(
            f"GitHub {field} response is missing required data"
        ) from exc
    if not isinstance(connection, dict):
        raise GitHubReviewTransportError(f"GitHub {field} response is not a connection")
    return connection


def _page_nodes(connection: dict[str, Any], field: str) -> list[dict[str, Any]]:
    nodes = connection.get("nodes")
    if not isinstance(nodes, list) or not all(isinstance(node, dict) for node in nodes):
        raise GitHubReviewTransportError(f"GitHub {field} page has invalid nodes")
    return nodes


def _next_page_cursor(
    connection: dict[str, Any],
    field: str,
    seen_cursors: set[str],
) -> str:
    page = connection.get("pageInfo")
    if not isinstance(page, dict) or not isinstance(page.get("hasNextPage"), bool):
        raise GitHubReviewTransportError(
            f"GitHub {field} pageInfo is missing or invalid"
        )
    if not page["hasNextPage"]:
        return ""
    next_cursor = page.get("endCursor")
    if (
        not isinstance(next_cursor, str)
        or not next_cursor
        or next_cursor in seen_cursors
    ):
        raise GitHubReviewTransportError(f"GitHub {field} pagination did not advance")
    return next_cursor


def _complete_thread_comments(
    nodes: list[dict[str, Any]],
    budget: EvidenceBudget,
) -> list[dict[str, Any]]:
    for node in nodes:
        connection = node.get("comments")
        if not isinstance(connection, dict):
            raise GitHubReviewTransportError(
                "GitHub review thread comments are missing"
            )
        initial_nodes = _page_nodes(connection, "review thread comments")
        budget.consume_nodes(len(initial_nodes))
        page = connection.get("pageInfo")
        if not isinstance(page, dict) or not isinstance(page.get("hasNextPage"), bool):
            raise GitHubReviewTransportError(
                "GitHub review thread comment pageInfo is missing or invalid"
            )
        if page["hasNextPage"]:
            thread_id = node.get("id")
            if not isinstance(thread_id, str) or not thread_id:
                raise GitHubReviewTransportError(
                    "GitHub paginated review thread is missing its ID"
                )
            connection["nodes"] = _load_all_thread_comment_nodes(
                thread_id,
                connection,
                budget,
            )
    return nodes


def _load_all_thread_comment_nodes(
    thread_id: str,
    initial_connection: dict[str, Any],
    budget: EvidenceBudget,
) -> list[dict[str, Any]]:
    query = """
    query($threadId: ID!, $cursor: String) {
      node(id: $threadId) {
        ... on PullRequestReviewThread {
          comments(first: 100, after: $cursor) {
            nodes { body author { login } }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
    """
    nodes = _page_nodes(initial_connection, "review thread comments")
    cursor = _next_page_cursor(initial_connection, "review thread comments", {""})
    seen_cursors = {"", cursor}
    for _page_number in range(1, GITHUB_GRAPHQL_MAX_PAGES):
        payload = _gh_graphql_thread_comments(thread_id, query, cursor)
        _validate_graphql_payload(payload)
        budget.consume_response(payload)
        connection = _thread_comment_connection(payload)
        page_nodes = _page_nodes(connection, "review thread comments")
        budget.consume_nodes(len(page_nodes))
        nodes.extend(page_nodes)
        if len(nodes) > GITHUB_GRAPHQL_MAX_NODES:
            raise GitHubReviewTransportError(
                "GitHub review thread comments exceeded node limit"
            )
        cursor = _next_page_cursor(connection, "review thread comments", seen_cursors)
        if not cursor:
            return nodes
        seen_cursors.add(cursor)
    raise GitHubReviewTransportError(
        "GitHub review thread comment pagination exceeded page limit"
    )


def _thread_comment_connection(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        connection = payload["data"]["node"]["comments"]
    except (KeyError, TypeError) as exc:
        raise GitHubReviewTransportError(
            "GitHub review thread comment response is missing required data"
        ) from exc
    if not isinstance(connection, dict):
        raise GitHubReviewTransportError(
            "GitHub review thread comments response is not a connection"
        )
    return connection


def _validate_graphql_payload(payload: dict[str, Any]) -> None:
    if "errors" not in payload:
        return
    errors = payload["errors"]
    if not isinstance(errors, list) or errors:
        raise GitHubReviewTransportError(
            "GitHub GraphQL response is partial or invalid"
        )


def _normalize_reviews(reviews: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for review in reviews:
        raw_author = review.get("author")
        raw_commit = review.get("commit")
        author: dict[str, Any] = raw_author if isinstance(raw_author, dict) else {}
        commit: dict[str, Any] = raw_commit if isinstance(raw_commit, dict) else {}
        normalized.append(
            {
                "state": review.get("state"),
                "submittedAt": review.get("submittedAt"),
                "commitOid": review.get("commitOid") or commit.get("oid"),
                "author": author.get("login") or review.get("author"),
                "body": str(review.get("body") or ""),
            }
        )
    return normalized


def _normalize_comments(comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for comment in comments:
        raw_author = comment.get("author")
        author: dict[str, Any] = raw_author if isinstance(raw_author, dict) else {}
        body = comment.get("body")
        created_at = comment.get("createdAt")
        is_minimized = comment.get("isMinimized")
        if not isinstance(body, str):
            raise GitHubReviewTransportError(
                "GitHub issue comment body must be a string"
            )
        if not isinstance(created_at, str) or not created_at:
            raise GitHubReviewTransportError(
                "GitHub issue comment createdAt must be a non-empty string"
            )
        if not isinstance(is_minimized, bool):
            raise GitHubReviewTransportError(
                "GitHub issue comment isMinimized must be boolean"
            )
        normalized.append(
            {
                "author": author.get("login") or comment.get("author"),
                "body": body,
                "createdAt": created_at,
                "isMinimized": is_minimized,
            }
        )
    return normalized


def _normalize_threads(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_normalize_thread(node) for node in nodes]


def _normalize_thread(node: dict[str, Any]) -> dict[str, Any]:
    is_resolved = node.get("isResolved")
    if not isinstance(is_resolved, bool):
        raise GitHubReviewTransportError(
            "GitHub review thread isResolved must be boolean"
        )
    path = node.get("path")
    if not isinstance(path, str) or not path:
        raise GitHubReviewTransportError(
            "GitHub review thread path must be a non-empty string"
        )
    connection = node.get("comments")
    if not isinstance(connection, dict):
        raise GitHubReviewTransportError("GitHub review thread comments are missing")
    comments = _page_nodes(connection, "review thread comments")
    if not comments:
        raise GitHubReviewTransportError(
            "GitHub review thread must contain at least one comment"
        )
    normalized_comments = [_normalize_thread_comment(comment) for comment in comments]
    return {
        "isResolved": is_resolved,
        "path": path,
        "body": "\n".join(comment["body"] for comment in normalized_comments),
        "authors": [comment["author"] for comment in normalized_comments],
    }


def _normalize_thread_comment(comment: dict[str, Any]) -> dict[str, str]:
    body = comment.get("body")
    if not isinstance(body, str):
        raise GitHubReviewTransportError(
            "GitHub review thread comment body must be a string"
        )
    author = comment.get("author")
    login = author.get("login") if isinstance(author, dict) else None
    if not isinstance(login, str) or not login:
        raise GitHubReviewTransportError(
            "GitHub review thread comment author login is missing or invalid"
        )
    return {"body": body, "author": login}


def _gh_graphql(
    owner: str, name: str, pr_number: int, query: str, cursor: str
) -> dict[str, Any]:
    args = [
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
    return _gh_json(args)


def _gh_graphql_thread_comments(
    thread_id: str, query: str, cursor: str
) -> dict[str, Any]:
    args = ["api", "graphql", "-f", f"threadId={thread_id}", "-f", f"query={query}"]
    if cursor:
        args.extend(["-f", f"cursor={cursor}"])
    return _gh_json(args)


def _gh_json(args: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        ["gh", *args],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=GITHUB_NETWORK_TIMEOUT_SECONDS,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise GitHubReviewTransportError("GitHub response must be a JSON object")
    return payload
