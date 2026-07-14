from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Any

from governance_eval.ai_review_failures import is_ai_review_service_failure
from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named


ADAPTER_ID = "codex_connector_pr_signal_v2"
_MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
_MAX_COLLECTION_ITEMS = 10_000
_MAX_REVIEW_WINDOW_SECONDS = 300
_COLLECTOR_ID = "github_rest_codex_connector_v1"
_COLLECTION_FIELDS = (
    "issue_comments",
    "issue_reactions",
    "pull_request_reviews",
    "review_comments",
    "pull_request_events",
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_NODE_ID_RE = re.compile(r"^[A-Za-z0-9_=-]+$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_CLEAN_RE = re.compile(
    r"\ACodex Review: Didn't find any major issues\."
    r"(?P<suffix>[^\r\n]*)\n\n"
    r"\*\*Reviewed commit:\*\* `(?P<prefix>[0-9a-f]{10})`"
    r"(?P<trailer>\n\n<details>[\s\S]*</details>)?\Z"
)
_AUTOMATIC_SUMMARY_START_RE = re.compile(r"\A### Summary[ \t]*\n")
_TESTING_HEADING_RE = re.compile(r"(?m)^(?:\*\*Testing\*\*|### Testing)[ \t]*$")
_TOP_LEVEL_BULLET_RE = re.compile(r"(?m)^[*-][ \t]+(?P<text>[^\r\n]+)$")
_INLINE_FULL_SHA_RE = re.compile(r"`([0-9a-f]{40})`")
_TASK_LINK_RE = re.compile(r"\[View task →\]\(https://chatgpt\.com/s/[A-Za-z0-9_-]+\)")
_REVIEW_COMPLETION = (
    "No code changes were needed, so I did **not** create a commit or open a new PR."
)
_REVIEW_OUTCOME_SUBJECT_RE = re.compile(
    r"(?:^|\b(?:the|this|code|pull request)\s+)review\b", re.IGNORECASE
)
_MANUAL_REQUEST_RE = re.compile(r"@codex\b", re.IGNORECASE)
_BLOCKING_SEVERITY_RE = re.compile(r"\bP[0-2]\b", re.IGNORECASE)
_APPROVED_CLEAN_SUFFIXES = {
    "",
    " Bravo.",
    " Can't wait for the next one!",
    " Already looking forward to the next diff.",
    " Another round soon, please!",
}
_PRODUCT_TRAILER = """<details> <summary>ℹ️ About Codex in GitHub</summary>
<br/>
[Your team has set up Codex to review pull requests in this repo](https://chatgpt.com/codex/cloud/settings/general). Reviews are triggered when you
- Open a pull request for review
- Mark a draft as ready
- Comment "@codex review".
If Codex has suggestions, it will comment; otherwise it will react with 👍.
Codex can also answer questions or update the PR. Try commenting "@codex address that feedback".
</details>"""
_CONNECTOR_USER = {
    "login": "chatgpt-codex-connector[bot]",
    "id": 199175422,
    "node_id": "BOT_kgDOC98s_g",
    "type": "Bot",
}
_CONNECTOR_REACTION_USER = {
    "login": "chatgpt-codex-connector[bot]",
    "id": 199175422,
    "node_id": "BOT_kgDOC98s_g",
    "type": "User",
}
_CONNECTOR_APP = {
    "id": 1144995,
    "node_id": "A_kwHOAOQ6Gs4AEXij",
    "slug": "chatgpt-codex-connector",
}
_CONNECTOR_RESULT_IDENTITY = {
    "login": _CONNECTOR_USER["login"],
    "user_id": _CONNECTOR_USER["id"],
    "user_node_id": _CONNECTOR_USER["node_id"],
}


@dataclass(frozen=True)
class TrustedCodexConnectorContext:
    snapshot_file_sha256: str
    repository_id: int
    repository_full_name: str
    pull_request_number: int
    pull_request_node_id: str
    pull_request_created_at: str
    base_sha: str
    head_sha: str
    governance_evaluator_sha: str
    review_window_started_at: str
    review_deadline_at: str
    resolved_clean_commit_sha: str | None

    def __post_init__(self) -> None:
        if not _DIGEST_RE.fullmatch(self.snapshot_file_sha256):
            raise ValueError("snapshot file digest is invalid")
        if not _positive_int(self.repository_id):
            raise ValueError("repository ID is invalid")
        if not _REPOSITORY_RE.fullmatch(self.repository_full_name):
            raise ValueError("repository name is invalid")
        if not _positive_int(self.pull_request_number):
            raise ValueError("pull request number is invalid")
        if not _NODE_ID_RE.fullmatch(self.pull_request_node_id):
            raise ValueError("pull request node ID is invalid")
        if not _valid_timestamp(self.pull_request_created_at):
            raise ValueError("pull request creation timestamp is invalid")
        if not all(
            _SHA_RE.fullmatch(value)
            for value in (self.base_sha, self.head_sha, self.governance_evaluator_sha)
        ):
            raise ValueError("trusted commit identity is invalid")
        if not _valid_timestamp(self.review_window_started_at):
            raise ValueError("review window timestamp is invalid")
        if not _valid_timestamp(self.review_deadline_at):
            raise ValueError("review deadline timestamp is invalid")
        review_window_seconds = (
            _timestamp(self.review_deadline_at)
            - _timestamp(self.review_window_started_at)
        ).total_seconds()
        if not 0 < review_window_seconds <= _MAX_REVIEW_WINDOW_SECONDS:
            raise ValueError("review deadline exceeds bounded review window")
        if self.resolved_clean_commit_sha is not None and not _SHA_RE.fullmatch(
            self.resolved_clean_commit_sha
        ):
            raise ValueError("resolved clean commit identity is invalid")


def evaluate_codex_connector_evidence(
    raw_snapshot_bytes: bytes,
    trusted: TrustedCodexConnectorContext,
) -> dict[str, Any]:
    return _evaluate(raw_snapshot_bytes, trusted)


def validate_codex_connector_evidence_result(
    result: dict[str, Any],
    raw_snapshot_bytes: bytes,
    trusted: TrustedCodexConnectorContext,
) -> None:
    _validate_result_shape(result)
    if result != _evaluate(raw_snapshot_bytes, trusted):
        raise ValueError(
            "Codex connector evidence result does not match trusted source"
        )


def serialize_codex_connector_evidence_result(result: dict[str, Any]) -> bytes:
    _validate_result_shape(result)
    return (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _evaluate(
    raw: Any,
    trusted: TrustedCodexConnectorContext,
) -> dict[str, Any]:
    observed_digest = _file_digest(raw)
    snapshot, parse_reasons = _load_snapshot(raw)
    reasons = list(parse_reasons)
    if observed_digest != trusted.snapshot_file_sha256:
        reasons.append("SNAPSHOT_FILE_DIGEST_MISMATCH")
    normalized_digest = None
    response = None
    reviewed_head = None
    if snapshot is not None:
        schema_valid = _snapshot_schema_valid(snapshot)
        if not schema_valid:
            reasons.append("SNAPSHOT_SCHEMA_INVALID")
        else:
            normalized_digest = _normalized_snapshot_digest(snapshot)
            response, evidence_reasons, reviewed_head = _evaluate_snapshot(
                snapshot, trusted
            )
            reasons.extend(evidence_reasons)
    reasons = sorted(set(reasons))
    review_state = _classify_review_state(
        reasons, reviewed_head, response, trusted.head_sha
    )
    passed = review_state in {"CLEAN", "AI_REVIEW_UNAVAILABLE"}
    reconciled = review_state != "INVALID_EVIDENCE"
    result_reviewed_head = (
        trusted.head_sha
        if review_state in {"CLEAN", "BLOCKING_FINDINGS_PRESENT"}
        else None
    )
    if review_state == "AI_REVIEW_UNAVAILABLE":
        response = None
    result = {
        "schema_version": "2.0",
        "capability": "CODEX_CONNECTOR_REVIEW_EVIDENCE",
        "adapter_id": ADAPTER_ID,
        "repository": {
            "id": trusted.repository_id,
            "full_name": trusted.repository_full_name,
        },
        "pull_request": {
            "number": trusted.pull_request_number,
            "node_id": trusted.pull_request_node_id,
            "created_at": trusted.pull_request_created_at,
            "base_sha": trusted.base_sha,
            "head_sha": trusted.head_sha,
        },
        "governance_evaluator_sha": trusted.governance_evaluator_sha,
        "review_window_started_at": trusted.review_window_started_at,
        "review_deadline_at": trusted.review_deadline_at,
        "evidence_cutoff_at": (
            snapshot.get("captured_at") if normalized_digest is not None else None
        ),
        "snapshot_file_sha256": observed_digest,
        "normalized_snapshot_sha256": normalized_digest,
        "resolved_clean_commit_sha": trusted.resolved_clean_commit_sha,
        "connector_identity": deepcopy(_CONNECTOR_RESULT_IDENTITY),
        "review_state": review_state,
        "capability_status": "PASS" if passed else "BLOCK_TECHNICAL",
        "reconciled_head_sha": trusted.head_sha if reconciled else None,
        "reviewed_head_sha": result_reviewed_head,
        "response": response,
        "reasons": [] if review_state == "CLEAN" else reasons,
        "result_content_hash": "",
    }
    result["result_content_hash"] = sha256_json(result)
    _validate_result_shape(result)
    return result


def _classify_review_state(
    reasons: list[str],
    reviewed_head: str | None,
    response: dict[str, Any] | None,
    head_sha: str,
) -> str:
    if not reasons and reviewed_head == head_sha and response is not None:
        return "CLEAN"
    reason_set = set(reasons)
    if "BLOCKING_FINDINGS_PRESENT" in reason_set and reason_set <= {
        "BLOCKING_FINDINGS_PRESENT",
        "RESPONSE_BODY_UNRECOGNIZED",
    }:
        return "BLOCKING_FINDINGS_PRESENT"
    if reason_set and reason_set <= {"NO_IN_WINDOW_RESPONSE", "ONLY_LATE_RESPONSE"}:
        return "AI_REVIEW_UNAVAILABLE"
    if "CONNECTOR_FAILURE_PRESENT" in reason_set and reason_set <= {
        "CONNECTOR_FAILURE_PRESENT",
        "RESPONSE_BODY_UNRECOGNIZED",
    }:
        return "AI_REVIEW_UNAVAILABLE"
    return "INVALID_EVIDENCE"


def _load_snapshot(raw: Any) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_SNAPSHOT_BYTES:
        return None, ["SNAPSHOT_BYTES_INVALID"]
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        canonical = (json.dumps(parsed, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None, ["SNAPSHOT_JSON_INVALID"]
    if not isinstance(parsed, dict):
        return None, ["SNAPSHOT_JSON_INVALID"]
    return parsed, [] if raw == canonical else ["SNAPSHOT_BYTES_NONCANONICAL"]


def _evaluate_snapshot(
    snapshot: dict[str, Any], trusted: TrustedCodexConnectorContext
) -> tuple[dict[str, Any] | None, list[str], str | None]:
    comments = snapshot["issue_comments"]
    reviews = snapshot["pull_request_reviews"]
    review_comments = snapshot["review_comments"]
    events = snapshot.get("pull_request_events", [])
    reasons = _collection_reasons(
        snapshot,
        trusted,
        comments,
        reviews,
        review_comments,
        snapshot.get("issue_reactions", []),
        events,
    )
    responses = [
        ("issue_comment", item)
        for item in comments
        if _exact_connector_issue_comment(item)
    ] + [
        ("pull_request_review", item) for item in reviews if _exact_connector_user(item)
    ]
    valid_responses = [
        item
        for item in responses
        if _valid_timestamp(_response_timestamp(item[0], item[1]))
    ]
    in_window_responses = [
        item
        for item in valid_responses
        if _timestamp(trusted.review_window_started_at)
        < _timestamp(_response_timestamp(item[0], item[1]))
        <= _timestamp(trusted.review_deadline_at)
    ]
    if not in_window_responses:
        reasons.append(
            "ONLY_LATE_RESPONSE"
            if any(
                _timestamp(_response_timestamp(item[0], item[1]))
                > _timestamp(trusted.review_deadline_at)
                for item in valid_responses
            )
            else "NO_IN_WINDOW_RESPONSE"
        )
        return None, reasons, None
    response_type, latest = max(
        in_window_responses,
        key=lambda item: (
            _timestamp(_response_timestamp(item[0], item[1])),
            item[1]["id"],
            item[0],
        ),
    )
    app_provenance = (
        "NOT_EXPOSED_BY_GITHUB_API"
        if response_type == "pull_request_review"
        else "VERIFIED_PERFORMED_VIA_GITHUB_APP"
    )
    response = {
        "response_type": response_type,
        "response_id": latest["id"],
        "response_node_id": latest.get("node_id"),
        "created_at": _response_timestamp(response_type, latest),
        "payload_sha256": sha256(latest["body"].encode("utf-8")).hexdigest(),
        "user_type": latest["user"]["type"],
        "app_provenance": app_provenance,
        "app_id": None
        if app_provenance == "NOT_EXPOSED_BY_GITHUB_API"
        else _CONNECTOR_APP["id"],
        "app_node_id": None
        if app_provenance == "NOT_EXPOSED_BY_GITHUB_API"
        else _CONNECTOR_APP["node_id"],
        "app_slug": None
        if app_provenance == "NOT_EXPOSED_BY_GITHUB_API"
        else _CONNECTOR_APP["slug"],
    }
    if response_type == "pull_request_review":
        if latest["commit_id"] != trusted.head_sha:
            reasons.append("REVIEWED_COMMIT_NOT_HEAD")
        elif _review_has_blocking_finding(latest, review_comments):
            reasons.append("BLOCKING_FINDINGS_PRESENT")
        else:
            reasons.append("RESPONSE_BODY_UNRECOGNIZED")
        return response, reasons, None
    commit_identity = _clean_commit_identity(latest["body"])
    if commit_identity is None:
        reasons.append("RESPONSE_BODY_UNRECOGNIZED")
        return response, reasons, None
    resolved = trusted.resolved_clean_commit_sha
    if resolved is None or not resolved.startswith(commit_identity):
        reasons.append("COMMIT_RESOLUTION_MISMATCH")
        return response, reasons, None
    if len(commit_identity) == 40 and commit_identity != trusted.head_sha:
        reasons.append("REVIEWED_COMMIT_NOT_HEAD")
        return response, reasons, None
    if resolved != trusted.head_sha:
        reasons.append("REVIEWED_COMMIT_NOT_HEAD")
        return response, reasons, None
    return response, reasons, trusted.head_sha


def _collection_reasons(
    snapshot: dict[str, Any],
    trusted: TrustedCodexConnectorContext,
    comments: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    review_comments: list[dict[str, Any]],
    reactions: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> list[str]:
    reasons = _snapshot_identity_reasons(snapshot, trusted)
    expected_collector = {
        "id": _COLLECTOR_ID,
        "governance_evaluator_sha": trusted.governance_evaluator_sha,
    }
    if snapshot["collector"] != expected_collector:
        reasons.append("COLLECTOR_IDENTITY_MISMATCH")
    if _collection_receipts_invalid(snapshot):
        reasons.append("COLLECTION_RECEIPT_INVALID")
    snapshot_commit_ids = [
        snapshot["pull_request"]["base_sha"],
        snapshot["pull_request"]["head_sha"],
        *(review["commit_id"] for review in reviews),
        *(comment["commit_id"] for comment in review_comments),
        *(comment["original_commit_id"] for comment in review_comments),
    ]
    if any(not _SHA_RE.fullmatch(value) for value in snapshot_commit_ids):
        reasons.append("SNAPSHOT_COMMIT_IDENTITY_INVALID")
    collections = (comments, reviews, review_comments, reactions, events)
    if any(len(items) > _MAX_COLLECTION_ITEMS for items in collections):
        reasons.append("SNAPSHOT_LIMIT_EXCEEDED")
    if any(_duplicate_ids(items) for items in collections):
        reasons.append("DUPLICATE_RESPONSE_ID")
    if any(_duplicate_node_ids(items) for items in (reactions, events)):
        reasons.append("DUPLICATE_RESPONSE_NODE_ID")
    timestamps = [
        item["created_at"] for item in comments + review_comments + reactions + events
    ]
    timestamps.extend(item["submitted_at"] for item in reviews)
    if any(not _valid_timestamp(value) for value in timestamps):
        reasons.append("SNAPSHOT_TIMESTAMP_INVALID")
    captured_at = snapshot.get("captured_at")
    if (
        not isinstance(captured_at, str)
        or not _valid_timestamp(captured_at)
        or _timestamp(captured_at) < _timestamp(trusted.review_deadline_at)
    ):
        reasons.append("EVIDENCE_CUTOFF_BEFORE_DEADLINE")
    if (
        isinstance(captured_at, str)
        and _valid_timestamp(captured_at)
        and any(
            _valid_timestamp(value) and _timestamp(value) > _timestamp(captured_at)
            for value in timestamps
        )
    ):
        reasons.append("SNAPSHOT_ITEM_AFTER_CAPTURE")
    if _manual_request_present(comments, trusted.head_sha):
        reasons.append("MANUAL_REVIEW_REQUEST_PRESENT")

    def in_window(value: str) -> bool:
        return _valid_timestamp(value) and _timestamp(
            trusted.review_window_started_at
        ) < _timestamp(value) <= _timestamp(trusted.review_deadline_at)

    connector_failure = any(
        _exact_connector_issue_comment(comment)
        and is_ai_review_service_failure(comment["body"])
        and in_window(comment["created_at"])
        for comment in comments
    ) or any(
        _exact_connector_user(review)
        and is_ai_review_service_failure(review["body"])
        and in_window(review["submitted_at"])
        for review in reviews
    )
    if connector_failure:
        reasons.append("CONNECTOR_FAILURE_PRESENT")
    if any(
        _exact_connector_issue_comment(comment)
        and _BLOCKING_SEVERITY_RE.search(comment["body"])
        and in_window(comment["created_at"])
        for comment in comments
    ):
        reasons.append("BLOCKING_FINDINGS_PRESENT")
    connector_reactions = [
        reaction
        for reaction in reactions
        if _exact_connector_reaction_user(reaction)
        and in_window(reaction["created_at"])
    ]
    if any(
        reaction["user"] != _CONNECTOR_REACTION_USER
        and any(
            reaction["user"].get(field) == _CONNECTOR_REACTION_USER[field]
            for field in ("login", "id", "node_id")
        )
        for reaction in reactions
    ):
        reasons.append("CONNECTOR_IDENTITY_MISMATCH")
    if len(connector_reactions) > 1:
        reasons.append("CONNECTOR_REACTION_AMBIGUOUS")
    if any(reaction["content"] != "+1" for reaction in connector_reactions):
        reasons.append("CONNECTOR_REACTION_UNRECOGNIZED")
    current_connector_review_ids = {
        review["id"]
        for review in reviews
        if _exact_connector_user(review) and review["commit_id"] == trusted.head_sha
    }
    if any(
        _exact_connector_user(comment)
        and comment["commit_id"] == trusted.head_sha
        and comment["pull_request_review_id"] not in current_connector_review_ids
        for comment in review_comments
    ):
        reasons.append("ORPHANED_REVIEW_COMMENT")
    if _blocking_finding_present(
        reviews,
        review_comments,
        trusted.head_sha,
        trusted.review_window_started_at,
        trusted.review_deadline_at,
    ):
        reasons.append("BLOCKING_FINDINGS_PRESENT")
    return reasons


def _blocking_finding_present(
    reviews: list[dict[str, Any]],
    comments: list[dict[str, Any]],
    head_sha: str,
    window_started_at: str,
    deadline_at: str,
) -> bool:
    def in_window(value: str) -> bool:
        return _valid_timestamp(value) and _timestamp(window_started_at) < _timestamp(
            value
        ) <= _timestamp(deadline_at)

    current = {
        review["id"]: review
        for review in reviews
        if _exact_connector_user(review)
        and review["commit_id"] == head_sha
        and in_window(review["submitted_at"])
    }
    parent_blocking = any(
        review["state"] == "CHANGES_REQUESTED"
        or _BLOCKING_SEVERITY_RE.search(review["body"])
        for review in current.values()
    )
    inline_blocking = any(
        _exact_connector_user(comment)
        and comment["commit_id"] == head_sha
        and in_window(comment["created_at"])
        and _BLOCKING_SEVERITY_RE.search(comment["body"])
        for comment in comments
    )
    return parent_blocking or inline_blocking


def _review_has_blocking_finding(
    review: dict[str, Any], comments: list[dict[str, Any]]
) -> bool:
    return bool(
        review["state"] == "CHANGES_REQUESTED"
        or _BLOCKING_SEVERITY_RE.search(review["body"])
        or any(
            comment["pull_request_review_id"] == review["id"]
            and _exact_connector_user(comment)
            and _BLOCKING_SEVERITY_RE.search(comment["body"])
            for comment in comments
        )
    )


def _snapshot_identity_reasons(
    snapshot: dict[str, Any], trusted: TrustedCodexConnectorContext
) -> list[str]:
    expected_repository = {
        "id": trusted.repository_id,
        "full_name": trusted.repository_full_name,
    }
    expected_pr = {
        "number": trusted.pull_request_number,
        "node_id": trusted.pull_request_node_id,
        "created_at": trusted.pull_request_created_at,
        "base_sha": trusted.base_sha,
        "head_sha": trusted.head_sha,
    }
    pull_request = snapshot["pull_request"]
    actual_pr = {key: pull_request[key] for key in expected_pr}
    reasons = []
    if snapshot["repository"] != expected_repository:
        reasons.append("REPOSITORY_MISMATCH")
    if actual_pr != expected_pr:
        reasons.append("PULL_REQUEST_MISMATCH")
    if pull_request["state"] != "open" or pull_request["draft"] is not False:
        reasons.append("PULL_REQUEST_NOT_REVIEWABLE")
    if snapshot["collection_complete"] is not True:
        reasons.append("COLLECTION_INCOMPLETE")
    return reasons


def _clean_commit_identity(body: str) -> str | None:
    automatic_head = _automatic_summary_head(body)
    if automatic_head is not None:
        return automatic_head
    match = _CLEAN_RE.fullmatch(body)
    if match is None:
        return None
    suffix = match.group("suffix")
    if suffix not in _APPROVED_CLEAN_SUFFIXES:
        return None
    trailer = match.group("trailer")
    if trailer and not _safe_product_trailer(trailer):
        return None
    return str(match.group("prefix"))


def _automatic_summary_head(body: str) -> str | None:
    if (
        _AUTOMATIC_SUMMARY_START_RE.match(body) is None
        or _BLOCKING_SEVERITY_RE.search(body)
        or is_ai_review_service_failure(body)
        or "```" in body
        or "<details" in body.lower()
    ):
        return None
    testing_heading = _TESTING_HEADING_RE.search(body)
    if testing_heading is None:
        return None
    summary = body[: testing_heading.start()]
    testing = body[testing_heading.end() :]
    summary_items: list[str] = []
    for line in summary.splitlines():
        stripped = line.strip()
        if not stripped or stripped == "### Summary":
            continue
        bullet = re.fullmatch(r"[*-][ \t]+(?P<text>.+)", line)
        if bullet is None:
            return None
        summary_items.append(bullet.group("text"))
    if summary_items.count(_REVIEW_COMPLETION) != 1:
        return None
    for item in summary_items:
        without_inline_code = re.sub(r"`[^`]*`", "", item)
        if item != _REVIEW_COMPLETION and _REVIEW_OUTCOME_SUBJECT_RE.search(
            without_inline_code
        ):
            return None
    attestations: list[str] = []
    for match in _TOP_LEVEL_BULLET_RE.finditer(summary):
        text = match.group("text")
        lowered = text.lower()
        if (
            re.search(r"\b(?:pr|pull request)?\s*head\b", lowered)
            and "`head_ref`" in lowered
            and re.search(r"\b(?:match(?:es|ed|ing)?|equal(?:s|ed|ing)?)\b", lowered)
        ):
            shas = _INLINE_FULL_SHA_RE.findall(text)
            if len(shas) != 1:
                return None
            attestations.append(shas[0])
    if len(attestations) != 1:
        return None
    visible_inline_shas = _INLINE_FULL_SHA_RE.findall(summary + testing)
    if any(sha != attestations[0] for sha in visible_inline_shas):
        return None
    test_items: list[str] = []
    for line in testing.splitlines():
        stripped = line.strip()
        if not stripped or _TASK_LINK_RE.fullmatch(stripped):
            continue
        bullet = re.fullmatch(r"[*-][ \t]+(?P<text>.+)", line)
        if bullet is None:
            return None
        test_items.append(bullet.group("text"))
    if not test_items or any(
        not _successful_test_item(item, attestations[0]) for item in test_items
    ):
        return None
    return attestations[0]


def _successful_test_item(item: str, head_sha: str) -> bool:
    exact_items = {
        f"✅ `git rev-parse HEAD` — returned `{head_sha}`.",
        "✅ `git status --porcelain=v1` — clean working tree.",
        "✅ Focused positive and negative controls passed.",
    }
    if item in exact_items:
        return True
    command = r"`[^`\r\n]+`"
    positive_count = r"[1-9][0-9]*"
    if re.fullmatch(rf"✅ {command} — {positive_count}(?: tests?)? passed\.", item):
        return True
    return bool(
        re.fullmatch(
            rf"✅ {command} — {positive_count} tests passed; "
            r"`phase1_decision` was `BENCHMARK_PASS`; generated `[^`\r\n]+`\.",
            item,
        )
    )


def _safe_product_trailer(trailer: str) -> bool:
    normalized = "\n".join(
        line.strip() for line in trailer.strip().splitlines() if line.strip()
    )
    return normalized == _PRODUCT_TRAILER


def _manual_request_present(comments: list[dict[str, Any]], head_sha: str) -> bool:
    return any(
        not _exact_connector_issue_comment(comment)
        and not _authorized_workflow_request(comment, head_sha)
        and _MANUAL_REQUEST_RE.search(comment["body"])
        for comment in comments
    )


def _authorized_workflow_request(comment: dict[str, Any], head_sha: str) -> bool:
    user = comment.get("user") if isinstance(comment.get("user"), dict) else {}
    app = (
        comment.get("performed_via_github_app")
        if isinstance(comment.get("performed_via_github_app"), dict)
        else {}
    )
    expected_body = (
        f"@codex review\n\nGovernance review request for exact head `{head_sha}`."
    )
    return bool(
        user.get("login") == "github-actions[bot]"
        and user.get("type") == "Bot"
        and app.get("slug") == "github-actions"
        and comment.get("body") == expected_body
    )


def _exact_connector_issue_comment(comment: dict[str, Any]) -> bool:
    return bool(
        comment.get("user") == _CONNECTOR_USER
        and comment.get("performed_via_github_app") == _CONNECTOR_APP
    )


def _exact_connector_user(item: dict[str, Any]) -> bool:
    return item.get("user") == _CONNECTOR_USER


def _exact_connector_reaction_user(item: dict[str, Any]) -> bool:
    return item.get("user") == _CONNECTOR_REACTION_USER


def _response_timestamp(response_type: str, response: dict[str, Any]) -> str:
    return str(
        response["created_at"]
        if response_type in {"issue_comment", "pull_request_reaction"}
        else response["submitted_at"]
    )


def _duplicate_ids(items: list[dict[str, Any]]) -> bool:
    ids = [item["id"] for item in items]
    return len(ids) != len(set(ids))


def _duplicate_node_ids(items: list[dict[str, Any]]) -> bool:
    node_ids = [item["node_id"] for item in items]
    return len(node_ids) != len(set(node_ids))


def _collection_receipts_invalid(snapshot: dict[str, Any]) -> bool:
    receipts = snapshot["collection_receipts"]
    repository = snapshot["repository"]["full_name"]
    pull_request_number = snapshot["pull_request"]["number"]
    endpoints = {
        "issue_comments": f"issues/{pull_request_number}/comments",
        "issue_reactions": f"issues/{pull_request_number}/reactions",
        "pull_request_reviews": f"pulls/{pull_request_number}/reviews",
        "review_comments": f"pulls/{pull_request_number}/comments",
        "pull_request_events": f"issues/{pull_request_number}/events",
    }
    for field in _COLLECTION_FIELDS:
        source_items = snapshot[field]
        items = _semantic_order(field, source_items)
        receipt = receipts[field]
        pages = receipt["pages"]
        if (
            receipt["complete"] is not True
            or receipt["item_count"] != len(items)
            or receipt["items_sha256"] != sha256_json(items)
            or sum(page["item_count"] for page in pages) != len(items)
        ):
            return True
        offset = 0
        for index, page in enumerate(pages, start=1):
            terminal = index == len(pages)
            item_count = page["item_count"]
            expected_next = None
            if not terminal:
                expected_next = (
                    f"https://api.github.com/repos/{repository}/"
                    f"{endpoints[field]}?per_page=100&page={index + 1}"
                )
            page_items = _semantic_order(
                field,
                source_items[offset : offset + item_count],
            )
            if (
                page["page"] != index
                or page["terminal"] is not terminal
                or page["next_url"] != expected_next
                or page["page_sha256"] != sha256_json(page_items)
                or (not terminal and item_count != 100)
            ):
                return True
            offset += item_count
        if offset != len(items):
            return True
    return False


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


def _snapshot_schema_valid(snapshot: dict[str, Any]) -> bool:
    try:
        validate_named("codex_connector_snapshot_v2", snapshot)
    except (KeyError, TypeError, ValueError, RecursionError):
        return False
    return True


def _validate_result_shape(result: dict[str, Any]) -> None:
    validate_named("codex_connector_evidence_result_v2", result)
    if not _valid_timestamp(result["review_window_started_at"]) or not _valid_timestamp(
        result["review_deadline_at"]
    ):
        raise ValueError("Codex connector evidence review window is invalid")
    review_window_seconds = (
        _timestamp(result["review_deadline_at"])
        - _timestamp(result["review_window_started_at"])
    ).total_seconds()
    if not 0 < review_window_seconds <= _MAX_REVIEW_WINDOW_SECONDS:
        raise ValueError("Codex connector evidence review window exceeds limit")
    expected_hash = sha256_json({**result, "result_content_hash": ""})
    if result["result_content_hash"] != expected_hash:
        raise ValueError("Codex connector evidence result hash is invalid")
    passed = result["capability_status"] == "PASS"
    response = result["response"]
    if isinstance(response, dict):
        response_type = response["response_type"]
        if response_type == "issue_comment":
            provenance_valid = (
                response["user_type"] == "Bot"
                and response["app_provenance"] == "VERIFIED_PERFORMED_VIA_GITHUB_APP"
                and response["app_id"] == _CONNECTOR_APP["id"]
                and response["app_node_id"] == _CONNECTOR_APP["node_id"]
                and response["app_slug"] == _CONNECTOR_APP["slug"]
            )
        elif response_type == "pull_request_reaction":
            provenance_valid = (
                response["user_type"] == "User"
                and response["app_provenance"] == "NOT_EXPOSED_BY_GITHUB_API"
                and response["response_node_id"] is not None
                and response["app_id"] is None
                and response["app_node_id"] is None
                and response["app_slug"] is None
            )
        else:
            provenance_valid = (
                response["user_type"] == "Bot"
                and response["app_provenance"] == "NOT_EXPOSED_BY_GITHUB_API"
                and response["app_id"] is None
                and response["app_node_id"] is None
                and response["app_slug"] is None
            )
        if not provenance_valid:
            raise ValueError("Codex connector evidence provenance is invalid")
    response_type = (
        response.get("response_type") if isinstance(response, dict) else None
    )
    resolution_valid = (
        result["resolved_clean_commit_sha"] == result["pull_request"]["head_sha"]
        if response_type == "issue_comment"
        else result["resolved_clean_commit_sha"] is None
    )
    final_collection = (
        result["normalized_snapshot_sha256"] is not None
        and isinstance(result["evidence_cutoff_at"], str)
        and _valid_timestamp(result["evidence_cutoff_at"])
        and _timestamp(result["evidence_cutoff_at"])
        >= _timestamp(result["review_deadline_at"])
    )
    clean_semantics = (
        result["review_state"] == "CLEAN"
        and result["reasons"] == []
        and result["reviewed_head_sha"] == result["pull_request"]["head_sha"]
        and result["reconciled_head_sha"] == result["pull_request"]["head_sha"]
        and isinstance(response, dict)
        and response.get("response_type") in {"issue_comment", "pull_request_reaction"}
        and resolution_valid
        and final_collection
    )
    unavailable_semantics = (
        result["review_state"] == "AI_REVIEW_UNAVAILABLE"
        and bool(result["reasons"])
        and result["reviewed_head_sha"] is None
        and result["reconciled_head_sha"] == result["pull_request"]["head_sha"]
        and response is None
        and final_collection
    )
    blocking_semantics = (
        result["review_state"] == "BLOCKING_FINDINGS_PRESENT"
        and "BLOCKING_FINDINGS_PRESENT" in result["reasons"]
        and result["reviewed_head_sha"] == result["pull_request"]["head_sha"]
        and result["reconciled_head_sha"] == result["pull_request"]["head_sha"]
        and final_collection
    )
    invalid_semantics = (
        result["review_state"] == "INVALID_EVIDENCE"
        and bool(result["reasons"])
        and result["reviewed_head_sha"] is None
        and result["reconciled_head_sha"] is None
    )
    if (passed and not (clean_semantics or unavailable_semantics)) or (
        not passed and not (blocking_semantics or invalid_semantics)
    ):
        raise ValueError("Codex connector evidence result semantics are invalid")


def _normalized_snapshot_digest(snapshot: dict[str, Any]) -> str:
    normalized = deepcopy(snapshot)
    order_fields = {
        "issue_comments": "created_at",
        "pull_request_reviews": "submitted_at",
        "review_comments": "created_at",
        "issue_reactions": "created_at",
        "pull_request_events": "created_at",
    }
    for field, timestamp_field in order_fields.items():
        if field not in normalized:
            continue
        normalized[field] = sorted(
            normalized[field],
            key=lambda item: (str(item[timestamp_field]), int(item["id"])),
        )
    return sha256_json(normalized)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _file_digest(raw: Any) -> str:
    content = raw if isinstance(raw, bytes) else b""
    return "sha256:" + sha256(content).hexdigest()


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _valid_timestamp(value: str) -> bool:
    if not _TIMESTAMP_RE.fullmatch(value):
        return False
    try:
        _timestamp(value)
    except ValueError:
        return False
    return True


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0
