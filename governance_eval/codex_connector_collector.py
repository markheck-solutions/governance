from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping

from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named


COLLECTOR_ID = "github_rest_codex_connector_v1"
_API_ROOT = "https://api.github.com"
_MAX_PAGES = 100
_PAGE_SIZE = 100
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_LINK_RE = re.compile(r'<(?P<url>[^>]+)>;\s*rel="(?P<rel>[^"]+)"')


class CodexConnectorCollectionError(ValueError):
    pass


@dataclass(frozen=True)
class ApiResponse:
    payload: Any
    headers: Mapping[str, str]


RequestJson = Callable[[str], ApiResponse]


def collect_codex_connector_snapshot(
    repository_full_name: str,
    pull_request_number: int,
    governance_evaluator_sha: str,
    *,
    request_json: RequestJson | None = None,
) -> dict[str, Any]:
    if not _REPOSITORY_RE.fullmatch(repository_full_name):
        raise CodexConnectorCollectionError("repository name is invalid")
    if not isinstance(pull_request_number, int) or pull_request_number < 1:
        raise CodexConnectorCollectionError("pull request number is invalid")
    if not _SHA_RE.fullmatch(governance_evaluator_sha):
        raise CodexConnectorCollectionError("governance evaluator SHA is invalid")
    request = request_json or _request_json
    repository_url = f"{_API_ROOT}/repos/{repository_full_name}"
    repository = request(repository_url).payload
    pull_request_url = f"{repository_url}/pulls/{pull_request_number}"
    pull_request_response = request(pull_request_url)
    pull_request = pull_request_response.payload
    if not isinstance(repository, dict) or not isinstance(pull_request, dict):
        raise CodexConnectorCollectionError("GitHub identity response is invalid")
    evidence_cutoff_at = _github_response_timestamp(pull_request_response.headers)
    initial_pull_request = _normalize_pull_request(pull_request)
    endpoints = {
        "issue_comments": f"{repository_url}/issues/{pull_request_number}/comments",
        "issue_reactions": f"{repository_url}/issues/{pull_request_number}/reactions",
        "pull_request_reviews": f"{repository_url}/pulls/{pull_request_number}/reviews",
        "review_comments": f"{repository_url}/pulls/{pull_request_number}/comments",
        "pull_request_events": f"{repository_url}/issues/{pull_request_number}/events",
    }
    collections: dict[str, list[dict[str, Any]]] = {}
    receipts: dict[str, dict[str, Any]] = {}
    for name, endpoint in endpoints.items():
        items, receipt = _collect_paginated(endpoint, name, request)
        collections[name] = items
        receipts[name] = receipt
    final_pull_request_payload = request(pull_request_url).payload
    if not isinstance(final_pull_request_payload, dict):
        raise CodexConnectorCollectionError("final pull request response is invalid")
    final_pull_request = _normalize_pull_request(final_pull_request_payload)
    if final_pull_request != initial_pull_request:
        raise CodexConnectorCollectionError("pull request changed during collection")
    snapshot = {
        "schema_version": "2.0",
        "collector": {
            "id": COLLECTOR_ID,
            "governance_evaluator_sha": governance_evaluator_sha,
        },
        "collection_complete": True,
        # Server-sourced cutoff captured before any evidence surface is read.
        # Items created later belong to the next collection window.
        "captured_at": evidence_cutoff_at,
        "collection_receipts": receipts,
        "repository": {
            "id": repository.get("id"),
            "full_name": repository.get("full_name"),
        },
        "pull_request": final_pull_request,
        **collections,
    }
    validate_named("codex_connector_snapshot_v2", snapshot)
    return snapshot


def serialize_codex_connector_snapshot(snapshot: dict[str, Any]) -> bytes:
    validate_named("codex_connector_snapshot_v2", snapshot)
    return (json.dumps(snapshot, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _collect_paginated(
    endpoint: str,
    collection_name: str,
    request: RequestJson,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    expected_path = urllib.parse.urlsplit(endpoint).path
    url = f"{endpoint}?per_page={_PAGE_SIZE}&page=1"
    items: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []
    for page_number in range(1, _MAX_PAGES + 1):
        _validate_page_url(url, expected_path, page_number)
        response = request(url)
        if not isinstance(response.payload, list):
            raise CodexConnectorCollectionError(
                f"{collection_name} page {page_number} is not an array"
            )
        page_items = [
            _normalize_item(collection_name, item) for item in response.payload
        ]
        next_url = _next_link(response.headers)
        if next_url is not None:
            _validate_page_url(next_url, expected_path, page_number + 1)
            next_url = (
                f"{_API_ROOT}{expected_path}?per_page={_PAGE_SIZE}"
                f"&page={page_number + 1}"
            )
        pages.append(
            {
                "page": page_number,
                "item_count": len(page_items),
                "page_sha256": sha256_json(
                    _semantic_order(collection_name, page_items)
                ),
                "next_url": next_url,
                "terminal": next_url is None,
            }
        )
        items.extend(page_items)
        if next_url is None:
            return items, {
                "complete": True,
                "item_count": len(items),
                "items_sha256": sha256_json(_semantic_order(collection_name, items)),
                "pages": pages,
            }
        url = next_url
    raise CodexConnectorCollectionError(f"{collection_name} exceeds {_MAX_PAGES} pages")


def _normalize_item(collection_name: str, item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise CodexConnectorCollectionError(
            f"{collection_name} contains a non-object item"
        )
    if collection_name == "issue_comments":
        app = item.get("performed_via_github_app")
        return {
            "id": item.get("id"),
            "created_at": item.get("created_at"),
            "body": item.get("body") or "",
            "user": _normalize_user(item.get("user")),
            "performed_via_github_app": _normalize_app(app) if app else None,
        }
    if collection_name == "issue_reactions":
        return {
            "id": item.get("id"),
            "node_id": item.get("node_id"),
            "created_at": item.get("created_at"),
            "content": item.get("content"),
            "user": _normalize_user(item.get("user")),
        }
    if collection_name == "pull_request_reviews":
        return {
            "id": item.get("id"),
            "submitted_at": item.get("submitted_at"),
            "state": item.get("state"),
            "commit_id": item.get("commit_id"),
            "body": item.get("body") or "",
            "user": _normalize_user(item.get("user")),
        }
    if collection_name == "review_comments":
        return {
            "id": item.get("id"),
            "pull_request_review_id": item.get("pull_request_review_id"),
            "created_at": item.get("created_at"),
            "commit_id": item.get("commit_id"),
            "original_commit_id": item.get("original_commit_id"),
            "path": item.get("path"),
            "line": item.get("line"),
            "body": item.get("body") or "",
            "user": _normalize_user(item.get("user")),
        }
    if collection_name == "pull_request_events":
        return {
            "id": item.get("id"),
            "node_id": item.get("node_id"),
            "event": item.get("event"),
            "created_at": item.get("created_at"),
        }
    raise CodexConnectorCollectionError(f"unsupported collection {collection_name}")


def _semantic_order(
    collection_name: str, items: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    timestamp_field = (
        "submitted_at" if collection_name == "pull_request_reviews" else "created_at"
    )
    return sorted(
        items,
        key=lambda item: (str(item[timestamp_field]), int(item["id"])),
    )


def _normalize_user(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CodexConnectorCollectionError("GitHub user is missing")
    return {key: value.get(key) for key in ("login", "id", "node_id", "type")}


def _normalize_app(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CodexConnectorCollectionError("GitHub App identity is invalid")
    return {key: value.get(key) for key in ("id", "node_id", "slug")}


def _next_link(headers: Mapping[str, str]) -> str | None:
    value = next(
        (
            header_value
            for key, header_value in headers.items()
            if key.lower() == "link"
        ),
        "",
    )
    links = {
        match.group("rel"): match.group("url") for match in _LINK_RE.finditer(value)
    }
    return links.get("next")


def _validate_page_url(url: str, expected_path: str, expected_page: int) -> None:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "api.github.com"
        or parsed.path != expected_path
        or query != {"per_page": [str(_PAGE_SIZE)], "page": [str(expected_page)]}
    ):
        raise CodexConnectorCollectionError("pagination next URL is not trusted")


def _request_json(url: str) -> ApiResponse:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise CodexConnectorCollectionError("GITHUB_TOKEN is required")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "markheck-solutions-governance",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            headers = dict(response.headers.items())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise CodexConnectorCollectionError(
            f"GitHub API request failed: {exc}"
        ) from exc
    return ApiResponse(payload, headers)


def _nested(value: dict[str, Any], key: str, nested_key: str) -> Any:
    nested = value.get(key)
    return nested.get(nested_key) if isinstance(nested, dict) else None


def _normalize_pull_request(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": value.get("number"),
        "node_id": value.get("node_id"),
        "created_at": value.get("created_at"),
        "state": value.get("state"),
        "draft": value.get("draft"),
        "base_sha": _nested(value, "base", "sha"),
        "head_sha": _nested(value, "head", "sha"),
    }


def _github_response_timestamp(headers: Mapping[str, str]) -> str:
    value = next(
        (
            header_value
            for key, header_value in headers.items()
            if key.lower() == "date"
        ),
        None,
    )
    if not value:
        raise CodexConnectorCollectionError("GitHub response Date header is missing")
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError) as exc:
        raise CodexConnectorCollectionError(
            "GitHub response Date header is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise CodexConnectorCollectionError("GitHub response Date header is invalid")
    safe_cutoff = parsed.astimezone(UTC).replace(microsecond=0) - timedelta(seconds=1)
    return safe_cutoff.isoformat().replace("+00:00", "Z")
