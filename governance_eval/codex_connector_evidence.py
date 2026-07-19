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
_CODEX_REVIEW_RE = re.compile(
    r"\A\s*### 💡 Codex Review[ \t]*\n\n"
    r"Here are some automated review suggestions for this pull request\.[ \t]*\n\n"
    r"\*\*Reviewed commit:\*\* `(?P<prefix>[0-9a-f]{10})`"
    r"(?P<trailer>[\s\S]*)\Z"
)
_MANUAL_REQUEST_RE = re.compile(r"@codex\b", re.IGNORECASE)
_BLOCKING_SEVERITY_RE = re.compile(r"\bP[0-2]\b", re.IGNORECASE)
_NONBLOCKING_SEVERITY_RE = re.compile(r"\bP3\b", re.IGNORECASE)
_REVIEWED_COMMIT_MARKER_RE = re.compile(
    r"(?m)^\*\*Reviewed commit:\*\* `([0-9a-f]{10}|[0-9a-f]{40})`[ \t]*$"
)
_APPROVED_CLEAN_SUFFIXES = {
    "",
    " Bravo.",
    " Can't wait for the next one!",
    " Already looking forward to the next diff.",
    " Another round soon, please!",
    " :tada:",
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
_CONNECTOR_REACTION_CONTENTS = frozenset({"+1", "eyes"})
_CONNECTOR_APP = {
    "id": 1144995,
    "node_id": "A_kwHOAOQ6Gs4AEXij",
    "slug": "chatgpt-codex-connector",
}
_GITHUB_ACTIONS_USER = {
    "login": "github-actions[bot]",
    "id": 41898282,
    "node_id": "MDM6Qm90NDE4OTgyODI=",
    "type": "Bot",
}
_GITHUB_ACTIONS_APP = {
    "id": 15368,
    "node_id": "MDM6QXBwMTUzNjg=",
    "slug": "github-actions",
}
_PROTECTED_REQUEST_WORKFLOW_PATH = ".github/workflows/supportability-enforcement.yml"
_AUTOMATIC_REQUEST_EVENT_ACTIONS = frozenset(
    {"opened", "reopened", "synchronize", "ready_for_review"}
)
_REQUEST_TRANSPORT_TIMEOUT_SECONDS = 30
_CONNECTOR_RESULT_IDENTITY = {
    "login": _CONNECTOR_USER["login"],
    "user_id": _CONNECTOR_USER["id"],
    "user_node_id": _CONNECTOR_USER["node_id"],
}


@dataclass(frozen=True)
class TrustedWorkflowRequestReceipt:
    workflow_ref: str
    workflow_sha: str
    event_name: str
    event_action: str
    run_id: int
    run_attempt: int
    repository_id: int
    repository_full_name: str
    pull_request_number: int
    head_sha: str
    review_window_started_at: str
    job_id: str
    request_endpoint: str
    request_body_sha256: str
    outcome: str
    transport_command: list[str]
    transport_started_at: str
    transport_completed_at: str
    transport_timeout_seconds: int
    transport_timed_out: bool
    transport_exit_code: int | None
    transport_error_sha256: str | None
    response_validation_error_sha256: str | None
    comment_id: int | None
    comment_created_at: str | None

    def __post_init__(self) -> None:
        _validate_request_caller(self)
        _validate_request_subject(self)
        _validate_request_binding(self)
        _validate_request_transport(self)
        _validate_request_outcome(self)


def _validate_request_caller(receipt: TrustedWorkflowRequestReceipt) -> None:
    expected_ref = (
        f"{receipt.repository_full_name}/{_PROTECTED_REQUEST_WORKFLOW_PATH}"
        "@refs/heads/main"
    )
    if receipt.workflow_ref != expected_ref:
        raise ValueError("workflow request ref is not the protected caller")
    if not _SHA_RE.fullmatch(receipt.workflow_sha):
        raise ValueError("workflow request commit identity is invalid")
    if receipt.event_name != "pull_request_target":
        raise ValueError("workflow request event is not automatic")
    if receipt.event_action not in _AUTOMATIC_REQUEST_EVENT_ACTIONS:
        raise ValueError("workflow request event action is invalid")
    if not _positive_int(receipt.run_id):
        raise ValueError("workflow request run ID is invalid")
    if not _positive_int(receipt.run_attempt) or receipt.run_attempt != 1:
        raise ValueError("workflow request must come from the first run attempt")


def _validate_request_subject(receipt: TrustedWorkflowRequestReceipt) -> None:
    if not _positive_int(receipt.repository_id):
        raise ValueError("workflow request repository ID is invalid")
    if not _REPOSITORY_RE.fullmatch(receipt.repository_full_name):
        raise ValueError("workflow request repository name is invalid")
    if not _positive_int(receipt.pull_request_number):
        raise ValueError("workflow request pull request number is invalid")
    if not _SHA_RE.fullmatch(receipt.head_sha):
        raise ValueError("workflow request head identity is invalid")
    if not _valid_timestamp(receipt.review_window_started_at):
        raise ValueError("workflow request review window is invalid")
    if receipt.job_id != "request-codex-review":
        raise ValueError("workflow request job identity is invalid")


def _validate_request_binding(receipt: TrustedWorkflowRequestReceipt) -> None:
    endpoint = (
        f"repos/{receipt.repository_full_name}/issues/"
        f"{receipt.pull_request_number}/comments"
    )
    if receipt.request_endpoint != endpoint:
        raise ValueError("workflow request endpoint is invalid")
    if receipt.request_body_sha256 != _workflow_request_body_digest(receipt.head_sha):
        raise ValueError("workflow request body digest is invalid")
    if receipt.transport_command != _workflow_request_command(
        receipt.repository_full_name,
        receipt.pull_request_number,
        receipt.head_sha,
    ):
        raise ValueError("workflow request transport command is invalid")


def _validate_request_transport(receipt: TrustedWorkflowRequestReceipt) -> None:
    if not _valid_timestamp(receipt.transport_started_at) or not _valid_timestamp(
        receipt.transport_completed_at
    ):
        raise ValueError("workflow request transport timestamps are invalid")
    if _timestamp(receipt.transport_completed_at) < _timestamp(
        receipt.transport_started_at
    ):
        raise ValueError("workflow request transport timestamps are reversed")
    if (
        not isinstance(receipt.transport_timeout_seconds, int)
        or isinstance(receipt.transport_timeout_seconds, bool)
        or receipt.transport_timeout_seconds != _REQUEST_TRANSPORT_TIMEOUT_SECONDS
    ):
        raise ValueError("workflow request transport timeout is invalid")
    if type(receipt.transport_timed_out) is not bool:
        raise ValueError("workflow request transport timeout state is invalid")
    valid_exit_code = receipt.transport_exit_code is None or (
        isinstance(receipt.transport_exit_code, int)
        and not isinstance(receipt.transport_exit_code, bool)
        and 0 <= receipt.transport_exit_code <= 255
    )
    if not valid_exit_code:
        raise ValueError("workflow request transport exit code is invalid")
    if receipt.transport_timed_out and receipt.transport_exit_code != 124:
        raise ValueError("workflow request transport timeout evidence is invalid")


def _validate_request_outcome(receipt: TrustedWorkflowRequestReceipt) -> None:
    if receipt.outcome == "POSTED":
        _validate_posted_request(receipt)
    elif receipt.outcome == "TRANSPORT_UNAVAILABLE":
        _validate_unavailable_request(receipt)
    elif receipt.outcome == "RESPONSE_INVALID":
        _validate_invalid_response_request(receipt)
    else:
        raise ValueError("workflow request outcome is invalid")


def _validate_posted_request(receipt: TrustedWorkflowRequestReceipt) -> None:
    if (
        receipt.transport_exit_code != 0
        or receipt.transport_timed_out
        or receipt.transport_error_sha256 is not None
        or receipt.response_validation_error_sha256 is not None
        or not _positive_int(receipt.comment_id)
        or not isinstance(receipt.comment_created_at, str)
        or not _valid_timestamp(receipt.comment_created_at)
    ):
        raise ValueError("posted workflow request receipt is invalid")


def _validate_unavailable_request(receipt: TrustedWorkflowRequestReceipt) -> None:
    if (
        receipt.transport_exit_code == 0
        or not isinstance(receipt.transport_error_sha256, str)
        or not _DIGEST_RE.fullmatch(receipt.transport_error_sha256)
        or receipt.response_validation_error_sha256 is not None
        or receipt.comment_id is not None
        or receipt.comment_created_at is not None
    ):
        raise ValueError("unavailable workflow request receipt is invalid")


def _validate_invalid_response_request(
    receipt: TrustedWorkflowRequestReceipt,
) -> None:
    if (
        receipt.transport_exit_code != 0
        or receipt.transport_timed_out
        or receipt.transport_error_sha256 is not None
        or not isinstance(receipt.response_validation_error_sha256, str)
        or not _DIGEST_RE.fullmatch(receipt.response_validation_error_sha256)
        or receipt.comment_id is not None
        or receipt.comment_created_at is not None
    ):
        raise ValueError("invalid-response workflow request receipt is invalid")


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
    workflow_request_receipt: TrustedWorkflowRequestReceipt

    def __post_init__(self) -> None:
        _validate_context_subject(self)
        _validate_context_window(self)
        _validate_context_request(self)


def _validate_context_subject(context: TrustedCodexConnectorContext) -> None:
    if not _DIGEST_RE.fullmatch(context.snapshot_file_sha256):
        raise ValueError("snapshot file digest is invalid")
    if not _positive_int(context.repository_id):
        raise ValueError("repository ID is invalid")
    if not _REPOSITORY_RE.fullmatch(context.repository_full_name):
        raise ValueError("repository name is invalid")
    if not _positive_int(context.pull_request_number):
        raise ValueError("pull request number is invalid")
    if not _NODE_ID_RE.fullmatch(context.pull_request_node_id):
        raise ValueError("pull request node ID is invalid")
    if not _valid_timestamp(context.pull_request_created_at):
        raise ValueError("pull request creation timestamp is invalid")
    if not all(
        _SHA_RE.fullmatch(value)
        for value in (
            context.base_sha,
            context.head_sha,
            context.governance_evaluator_sha,
        )
    ):
        raise ValueError("trusted commit identity is invalid")


def _validate_context_window(context: TrustedCodexConnectorContext) -> None:
    if not _valid_timestamp(context.review_window_started_at):
        raise ValueError("review window timestamp is invalid")
    if not _valid_timestamp(context.review_deadline_at):
        raise ValueError("review deadline timestamp is invalid")
    review_window_seconds = (
        _timestamp(context.review_deadline_at)
        - _timestamp(context.review_window_started_at)
    ).total_seconds()
    if not 0 < review_window_seconds <= _MAX_REVIEW_WINDOW_SECONDS:
        raise ValueError("review deadline exceeds bounded review window")
    if context.resolved_clean_commit_sha is not None and not _SHA_RE.fullmatch(
        context.resolved_clean_commit_sha
    ):
        raise ValueError("resolved clean commit identity is invalid")


def _validate_context_request(context: TrustedCodexConnectorContext) -> None:
    request = context.workflow_request_receipt
    if request is None:
        raise ValueError("automatic workflow request receipt is required")
    expected_identity = (
        context.repository_id,
        context.repository_full_name,
        context.pull_request_number,
        context.head_sha,
    )
    actual_identity = (
        request.repository_id,
        request.repository_full_name,
        request.pull_request_number,
        request.head_sha,
    )
    if actual_identity != expected_identity:
        raise ValueError("workflow request identity does not match trusted context")
    if request.review_window_started_at != context.review_window_started_at:
        raise ValueError("workflow request review window does not match context")
    if request.comment_created_at is not None and _timestamp(
        request.comment_created_at
    ) < _timestamp(context.review_window_started_at):
        raise ValueError("workflow request comment predates review window")


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
    passed = review_state == "CLEAN"
    reconciled = review_state != "INVALID_EVIDENCE"
    result_reviewed_head = (
        trusted.head_sha
        if review_state in {"CLEAN", "BLOCKING_FINDINGS_PRESENT"}
        else None
    )
    if review_state == "AI_REVIEW_UNAVAILABLE":
        response = None
    evidence_cutoff = (
        snapshot.get("captured_at")
        if snapshot is not None and normalized_digest is not None
        else None
    )
    result = {
        "schema_version": "4.0",
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
        "evidence_cutoff_at": evidence_cutoff,
        "snapshot_file_sha256": observed_digest,
        "normalized_snapshot_sha256": normalized_digest,
        "resolved_clean_commit_sha": trusted.resolved_clean_commit_sha,
        "workflow_request_receipt": _workflow_request_record(
            trusted.workflow_request_receipt
        ),
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
        "HEAD_ATTRIBUTION_AMBIGUOUS",
        "MANUAL_REVIEW_REQUEST_PRESENT",
        "NO_IN_WINDOW_RESPONSE",
        "ONLY_LATE_RESPONSE",
        "RESPONSE_BODY_UNRECOGNIZED",
        "CONNECTOR_FAILURE_PRESENT",
        "CONNECTOR_IDENTITY_MISMATCH",
        "CONNECTOR_REACTION_AMBIGUOUS",
        "CONNECTOR_REACTION_UNRECOGNIZED",
        "ORPHANED_REVIEW_COMMENT",
        "COMMIT_RESOLUTION_MISMATCH",
        "REVIEWED_COMMIT_NOT_HEAD",
        "WORKFLOW_REQUEST_POSTED_AFTER_DEADLINE",
        "WORKFLOW_REQUEST_RESPONSE_INVALID",
    }:
        return "BLOCKING_FINDINGS_PRESENT"
    if reason_set and reason_set <= {
        "HEAD_ATTRIBUTION_AMBIGUOUS",
        "MANUAL_REVIEW_REQUEST_PRESENT",
        "NO_IN_WINDOW_RESPONSE",
        "ONLY_LATE_RESPONSE",
        "WORKFLOW_REQUEST_POSTED_AFTER_DEADLINE",
        "WORKFLOW_REQUEST_RESPONSE_INVALID",
    }:
        return "AI_REVIEW_UNAVAILABLE"
    if reason_set & {
        "HEAD_ATTRIBUTION_AMBIGUOUS",
        "MANUAL_REVIEW_REQUEST_PRESENT",
    } and reason_set <= {
        "HEAD_ATTRIBUTION_AMBIGUOUS",
        "MANUAL_REVIEW_REQUEST_PRESENT",
        "NO_IN_WINDOW_RESPONSE",
        "ONLY_LATE_RESPONSE",
        "RESPONSE_BODY_UNRECOGNIZED",
        "WORKFLOW_REQUEST_POSTED_AFTER_DEADLINE",
        "WORKFLOW_REQUEST_RESPONSE_INVALID",
    }:
        return "AI_REVIEW_UNAVAILABLE"
    if "CONNECTOR_FAILURE_PRESENT" in reason_set and reason_set <= {
        "CONNECTOR_FAILURE_PRESENT",
        "HEAD_ATTRIBUTION_AMBIGUOUS",
        "MANUAL_REVIEW_REQUEST_PRESENT",
        "RESPONSE_BODY_UNRECOGNIZED",
        "WORKFLOW_REQUEST_POSTED_AFTER_DEADLINE",
        "WORKFLOW_REQUEST_RESPONSE_INVALID",
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
    selected, absence_reason = _latest_in_window_response(comments, reviews, trusted)
    if selected is None:
        reasons.append(str(absence_reason))
        return None, reasons, None
    response_type, latest = selected

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
        if _review_has_blocking_finding(
            latest,
            review_comments,
            trusted.head_sha,
            trusted.pull_request_created_at,
            trusted.review_deadline_at,
        ):
            reasons.append("BLOCKING_FINDINGS_PRESENT")
        else:
            reviewed_prefix = _clean_review_commit_identity(latest)
            if reviewed_prefix is None or not trusted.head_sha.startswith(
                reviewed_prefix
            ):
                reasons.append("RESPONSE_BODY_UNRECOGNIZED")
            else:
                return response, reasons, trusted.head_sha
        return response, reasons, None
    commit_identity = _clean_commit_identity(latest["body"])
    if commit_identity is None:
        commit_identity = _nonblocking_issue_comment_identity(latest, trusted.head_sha)
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


def _latest_in_window_response(
    comments: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    trusted: TrustedCodexConnectorContext,
) -> tuple[tuple[str, dict[str, Any]] | None, str | None]:
    responses = [
        ("issue_comment", item)
        for item in comments
        if _exact_connector_issue_comment(item)
        and _issue_comment_head_state(item, trusted.head_sha) != "STALE"
    ] + [
        ("pull_request_review", item)
        for item in reviews
        if _exact_connector_user(item) and item["commit_id"] == trusted.head_sha
    ]
    valid_responses = [
        item
        for item in responses
        if _valid_timestamp(_response_timestamp(item[0], item[1]))
    ]
    in_window_responses = [
        item
        for item in valid_responses
        if _timestamp_in_window(
            _response_timestamp(item[0], item[1]),
            trusted.review_window_started_at,
            trusted.review_deadline_at,
            include_lower=item[0] == "pull_request_review",
        )
    ]
    if not in_window_responses:
        absence_reason = (
            "ONLY_LATE_RESPONSE"
            if any(
                _timestamp(_response_timestamp(item[0], item[1]))
                > _timestamp(trusted.review_deadline_at)
                for item in valid_responses
            )
            else "NO_IN_WINDOW_RESPONSE"
        )
        return None, absence_reason
    return max(
        in_window_responses,
        key=lambda item: (
            _timestamp(_response_timestamp(item[0], item[1])),
            item[1]["id"],
            item[0],
        ),
    ), None


def _collection_reasons(
    snapshot: dict[str, Any],
    trusted: TrustedCodexConnectorContext,
    comments: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    review_comments: list[dict[str, Any]],
    reactions: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> list[str]:
    reasons = _collection_integrity_reasons(
        snapshot, trusted, comments, reviews, review_comments, reactions, events
    )
    reasons.extend(_workflow_request_reasons(trusted, comments))

    reasons.extend(_attribution_issue_reasons(trusted, comments, reviews, reactions))
    reasons.extend(
        _reaction_review_reasons(trusted, reviews, review_comments, reactions)
    )
    return reasons


def _collection_integrity_reasons(
    snapshot: dict[str, Any],
    trusted: TrustedCodexConnectorContext,
    comments: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    review_comments: list[dict[str, Any]],
    reactions: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> list[str]:
    collections = (comments, reviews, review_comments, reactions, events)
    reasons = _snapshot_identity_reasons(snapshot, trusted)
    reasons.extend(
        _collection_structure_reasons(
            snapshot, trusted, reviews, review_comments, reactions, events, collections
        )
    )
    reasons.extend(_collection_time_reasons(snapshot, trusted, collections))
    return reasons


def _collection_structure_reasons(
    snapshot: dict[str, Any],
    trusted: TrustedCodexConnectorContext,
    reviews: list[dict[str, Any]],
    review_comments: list[dict[str, Any]],
    reactions: list[dict[str, Any]],
    events: list[dict[str, Any]],
    collections: tuple[list[dict[str, Any]], ...],
) -> list[str]:
    reasons: list[str] = []
    expected_collector = {
        "id": _COLLECTOR_ID,
        "governance_evaluator_sha": trusted.governance_evaluator_sha,
    }
    if snapshot["collector"] != expected_collector:
        reasons.append("COLLECTOR_IDENTITY_MISMATCH")
    if _collection_receipts_invalid(snapshot):
        reasons.append("COLLECTION_RECEIPT_INVALID")
    commit_ids = [
        snapshot["pull_request"]["base_sha"],
        snapshot["pull_request"]["head_sha"],
        *(review["commit_id"] for review in reviews),
        *(comment["commit_id"] for comment in review_comments),
        *(comment["original_commit_id"] for comment in review_comments),
    ]
    if any(not _SHA_RE.fullmatch(value) for value in commit_ids):
        reasons.append("SNAPSHOT_COMMIT_IDENTITY_INVALID")
    if any(len(items) > _MAX_COLLECTION_ITEMS for items in collections):
        reasons.append("SNAPSHOT_LIMIT_EXCEEDED")
    if any(_duplicate_ids(items) for items in collections):
        reasons.append("DUPLICATE_RESPONSE_ID")
    if any(_duplicate_node_ids(items) for items in (reactions, events)):
        reasons.append("DUPLICATE_RESPONSE_NODE_ID")
    return reasons


def _collection_time_reasons(
    snapshot: dict[str, Any],
    trusted: TrustedCodexConnectorContext,
    collections: tuple[list[dict[str, Any]], ...],
) -> list[str]:
    comments, reviews, review_comments, reactions, events = collections
    timestamps = [
        item["created_at"] for item in comments + review_comments + reactions + events
    ]
    timestamps.extend(item["submitted_at"] for item in reviews)
    reasons = []
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
    return reasons


def _workflow_request_reasons(
    trusted: TrustedCodexConnectorContext, comments: list[dict[str, Any]]
) -> list[str]:
    reasons: list[str] = []
    request = trusted.workflow_request_receipt
    if request.outcome == "POSTED" and not any(
        _authorized_workflow_request(comment, request) for comment in comments
    ):
        reasons.append("WORKFLOW_REQUEST_RECEIPT_MISMATCH")
    if (
        request.outcome == "POSTED"
        and request.comment_created_at is not None
        and _timestamp(request.comment_created_at)
        > _timestamp(trusted.review_deadline_at)
    ):
        reasons.append("WORKFLOW_REQUEST_POSTED_AFTER_DEADLINE")
    if request.outcome == "RESPONSE_INVALID":
        reasons.append("WORKFLOW_REQUEST_RESPONSE_INVALID")
    if _manual_request_present(comments, trusted):
        reasons.append("MANUAL_REVIEW_REQUEST_PRESENT")
    return reasons


def _issue_in_window(value: str, trusted: TrustedCodexConnectorContext) -> bool:
    return _timestamp_in_window(
        value,
        trusted.review_window_started_at,
        trusted.review_deadline_at,
        include_lower=False,
    )


def _review_in_window(value: str, trusted: TrustedCodexConnectorContext) -> bool:
    return _timestamp_in_window(
        value,
        trusted.review_window_started_at,
        trusted.review_deadline_at,
        include_lower=True,
    )


def _review_for_current_head(value: str, trusted: TrustedCodexConnectorContext) -> bool:
    return _timestamp_in_window(
        value,
        trusted.pull_request_created_at,
        trusted.review_deadline_at,
        include_lower=True,
    )


def _attribution_issue_reasons(
    trusted: TrustedCodexConnectorContext,
    comments: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    reactions: list[dict[str, Any]],
) -> list[str]:
    reasons: list[str] = []
    if _head_attribution_ambiguous(trusted, comments, reactions):
        reasons.append("HEAD_ATTRIBUTION_AMBIGUOUS")
    if _connector_failure_present(trusted, comments, reviews):
        reasons.append("CONNECTOR_FAILURE_PRESENT")
    if _issue_blocker_present(trusted, comments):
        reasons.append("BLOCKING_FINDINGS_PRESENT")
    return reasons


def _head_attribution_ambiguous(
    trusted: TrustedCodexConnectorContext,
    comments: list[dict[str, Any]],
    reactions: list[dict[str, Any]],
) -> bool:
    issue_boundary = any(
        _exact_connector_issue_comment(comment)
        and _issue_comment_head_state(comment, trusted.head_sha) != "STALE"
        and _timestamp_at_boundary(
            comment["created_at"], trusted.review_window_started_at
        )
        for comment in comments
    )
    unbound_blocker = any(
        _exact_connector_issue_comment(comment)
        and _BLOCKING_SEVERITY_RE.search(comment["body"])
        and _issue_comment_head_state(comment, trusted.head_sha) == "UNBOUND"
        and _review_for_current_head(comment["created_at"], trusted)
        for comment in comments
    )
    reaction_boundary = any(
        _exact_connector_reaction_user(reaction)
        and _timestamp_at_boundary(
            reaction["created_at"], trusted.review_window_started_at
        )
        for reaction in reactions
    )
    return issue_boundary or unbound_blocker or reaction_boundary


def _connector_failure_present(
    trusted: TrustedCodexConnectorContext,
    comments: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
) -> bool:
    issue_failure = any(
        _exact_connector_issue_comment(comment)
        and _issue_comment_head_state(comment, trusted.head_sha) != "STALE"
        and is_ai_review_service_failure(comment["body"])
        and _issue_in_window(comment["created_at"], trusted)
        for comment in comments
    )
    review_failure = any(
        _exact_connector_user(review)
        and review["commit_id"] == trusted.head_sha
        and is_ai_review_service_failure(review["body"])
        and _review_in_window(review["submitted_at"], trusted)
        for review in reviews
    )
    return issue_failure or review_failure


def _issue_blocker_present(
    trusted: TrustedCodexConnectorContext, comments: list[dict[str, Any]]
) -> bool:
    return any(
        _exact_connector_issue_comment(comment)
        and _BLOCKING_SEVERITY_RE.search(comment["body"])
        and _issue_comment_head_state(comment, trusted.head_sha) == "CURRENT"
        and _review_for_current_head(comment["created_at"], trusted)
        for comment in comments
    )


def _reaction_review_reasons(
    trusted: TrustedCodexConnectorContext,
    reviews: list[dict[str, Any]],
    review_comments: list[dict[str, Any]],
    reactions: list[dict[str, Any]],
) -> list[str]:
    reasons = _connector_reaction_reasons(trusted, reactions)
    if _orphaned_review_comment_present(trusted, reviews, review_comments):
        reasons.append("ORPHANED_REVIEW_COMMENT")
    if _blocking_finding_present(
        reviews,
        review_comments,
        trusted.head_sha,
        trusted.pull_request_created_at,
        trusted.review_deadline_at,
    ):
        reasons.append("BLOCKING_FINDINGS_PRESENT")
    return reasons


def _connector_reaction_reasons(
    trusted: TrustedCodexConnectorContext, reactions: list[dict[str, Any]]
) -> list[str]:
    reasons: list[str] = []
    connector_reactions = [
        reaction
        for reaction in reactions
        if _exact_connector_reaction_user(reaction)
        and _issue_in_window(reaction["created_at"], trusted)
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
    if any(
        reaction["content"] not in _CONNECTOR_REACTION_CONTENTS
        for reaction in connector_reactions
    ):
        reasons.append("CONNECTOR_REACTION_UNRECOGNIZED")
    return reasons


def _orphaned_review_comment_present(
    trusted: TrustedCodexConnectorContext,
    reviews: list[dict[str, Any]],
    comments: list[dict[str, Any]],
) -> bool:
    current_review_ids = {
        review["id"]
        for review in reviews
        if _exact_connector_user(review)
        and review["commit_id"] == trusted.head_sha
        and _review_for_current_head(review["submitted_at"], trusted)
    }
    return any(
        _exact_connector_user(comment)
        and comment["commit_id"] == trusted.head_sha
        and comment["original_commit_id"] == trusted.head_sha
        and _review_for_current_head(comment["created_at"], trusted)
        and comment["pull_request_review_id"] not in current_review_ids
        for comment in comments
    )


def _blocking_finding_present(
    reviews: list[dict[str, Any]],
    comments: list[dict[str, Any]],
    head_sha: str,
    window_started_at: str,
    deadline_at: str,
) -> bool:
    def in_window(value: str) -> bool:
        return _valid_timestamp(value) and _timestamp(window_started_at) <= _timestamp(
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
        and comment["original_commit_id"] == head_sha
        and in_window(comment["created_at"])
        and _BLOCKING_SEVERITY_RE.search(comment["body"])
        for comment in comments
    )
    return parent_blocking or inline_blocking


def _review_has_blocking_finding(
    review: dict[str, Any],
    comments: list[dict[str, Any]],
    head_sha: str,
    window_started_at: str,
    deadline_at: str,
) -> bool:
    def current_comment(comment: dict[str, Any]) -> bool:
        return bool(
            comment["commit_id"] == head_sha
            and comment["original_commit_id"] == head_sha
            and _valid_timestamp(comment["created_at"])
            and _timestamp(window_started_at)
            <= _timestamp(comment["created_at"])
            <= _timestamp(deadline_at)
        )

    return bool(
        review["state"] == "CHANGES_REQUESTED"
        or _BLOCKING_SEVERITY_RE.search(review["body"])
        or any(
            comment["pull_request_review_id"] == review["id"]
            and _exact_connector_user(comment)
            and current_comment(comment)
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


def _issue_comment_head_state(comment: dict[str, Any], head_sha: str) -> str:
    identities = _REVIEWED_COMMIT_MARKER_RE.findall(comment["body"])
    if len(identities) != 1:
        return "UNBOUND"
    identity = identities[0]
    current = (
        identity == head_sha if len(identity) == 40 else head_sha.startswith(identity)
    )
    return "CURRENT" if current else "STALE"


def _nonblocking_issue_comment_identity(
    comment: dict[str, Any], head_sha: str
) -> str | None:
    if (
        _issue_comment_head_state(comment, head_sha) != "CURRENT"
        or _BLOCKING_SEVERITY_RE.search(comment["body"])
        or not _NONBLOCKING_SEVERITY_RE.search(comment["body"])
    ):
        return None
    return _REVIEWED_COMMIT_MARKER_RE.findall(comment["body"])[0]


def _clean_review_commit_identity(review: dict[str, Any]) -> str | None:
    if review["state"] != "COMMENTED":
        return None
    match = _CODEX_REVIEW_RE.fullmatch(review["body"])
    if match is None:
        return None
    trailer = match.group("trailer")
    if not trailer.strip() or not _safe_product_trailer(trailer):
        return None
    return str(match.group("prefix"))


def _safe_product_trailer(trailer: str) -> bool:
    normalized = "\n".join(
        line.strip() for line in trailer.strip().splitlines() if line.strip()
    )
    return normalized == _PRODUCT_TRAILER


def _manual_request_present(
    comments: list[dict[str, Any]],
    trusted: TrustedCodexConnectorContext,
) -> bool:
    return any(
        not _exact_connector_issue_comment(comment)
        and not _authorized_workflow_request(comment, trusted.workflow_request_receipt)
        and _MANUAL_REQUEST_RE.search(comment["body"])
        and _timestamp_in_window(
            comment["created_at"],
            trusted.pull_request_created_at,
            trusted.review_deadline_at,
            include_lower=True,
        )
        for comment in comments
    )


def _authorized_workflow_request(
    comment: dict[str, Any], receipt: TrustedWorkflowRequestReceipt | None
) -> bool:
    if receipt is None:
        return False
    if receipt.outcome != "POSTED":
        return False
    expected_body = _workflow_request_body(receipt.head_sha)
    return bool(
        comment.get("id") == receipt.comment_id
        and comment.get("created_at") == receipt.comment_created_at
        and comment.get("user") == _GITHUB_ACTIONS_USER
        and comment.get("performed_via_github_app") == _GITHUB_ACTIONS_APP
        and comment.get("body") == expected_body
    )


def _workflow_request_body(head_sha: str) -> str:
    return f"@codex review\n\nGovernance review request for exact head `{head_sha}`."


def _workflow_request_body_digest(head_sha: str) -> str:
    return (
        "sha256:" + sha256(_workflow_request_body(head_sha).encode("utf-8")).hexdigest()
    )


def _workflow_request_command(
    repository_full_name: str, pull_request_number: int, head_sha: str
) -> list[str]:
    return [
        "gh",
        "api",
        "--method",
        "POST",
        f"repos/{repository_full_name}/issues/{pull_request_number}/comments",
        "-f",
        f"body={_workflow_request_body(head_sha)}",
    ]


def _workflow_request_record(
    receipt: TrustedWorkflowRequestReceipt | None,
) -> dict[str, Any] | None:
    if receipt is None:
        return None
    return {
        "workflow_ref": receipt.workflow_ref,
        "workflow_sha": receipt.workflow_sha,
        "event_name": receipt.event_name,
        "event_action": receipt.event_action,
        "run_id": receipt.run_id,
        "run_attempt": receipt.run_attempt,
        "repository_id": receipt.repository_id,
        "repository_full_name": receipt.repository_full_name,
        "pull_request_number": receipt.pull_request_number,
        "head_sha": receipt.head_sha,
        "review_window_started_at": receipt.review_window_started_at,
        "job_id": receipt.job_id,
        "request_endpoint": receipt.request_endpoint,
        "request_body_sha256": receipt.request_body_sha256,
        "outcome": receipt.outcome,
        "transport_command": receipt.transport_command,
        "transport_started_at": receipt.transport_started_at,
        "transport_completed_at": receipt.transport_completed_at,
        "transport_timeout_seconds": receipt.transport_timeout_seconds,
        "transport_timed_out": receipt.transport_timed_out,
        "transport_exit_code": receipt.transport_exit_code,
        "transport_error_sha256": receipt.transport_error_sha256,
        "response_validation_error_sha256": (receipt.response_validation_error_sha256),
        "comment_id": receipt.comment_id,
        "comment_created_at": receipt.comment_created_at,
    }


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
        if response_type == "issue_comment"
        else response["submitted_at"]
    )


def _timestamp_in_window(
    value: str,
    lower: str,
    upper: str,
    *,
    include_lower: bool,
) -> bool:
    if not _valid_timestamp(value):
        return False
    observed = _timestamp(value)
    lower_bound = _timestamp(lower)
    lower_valid = observed >= lower_bound if include_lower else observed > lower_bound
    return lower_valid and observed <= _timestamp(upper)


def _timestamp_at_boundary(value: str, boundary: str) -> bool:
    return bool(
        _valid_timestamp(value)
        and _valid_timestamp(boundary)
        and _timestamp(value) == _timestamp(boundary)
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
    validate_named("codex_connector_evidence_result_v4", result)
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
    request = TrustedWorkflowRequestReceipt(**result["workflow_request_receipt"])
    expected_identity = (
        result["repository"]["id"],
        result["repository"]["full_name"],
        result["pull_request"]["number"],
        result["pull_request"]["head_sha"],
    )
    actual_identity = (
        request.repository_id,
        request.repository_full_name,
        request.pull_request_number,
        request.head_sha,
    )
    comment_time_valid = request.comment_created_at is None or _timestamp(
        request.comment_created_at
    ) >= _timestamp(result["review_window_started_at"])
    if (
        actual_identity != expected_identity
        or request.review_window_started_at != result["review_window_started_at"]
        or not comment_time_valid
    ):
        raise ValueError("Codex workflow request receipt binding is invalid")
    expected_hash = sha256_json({**result, "result_content_hash": ""})
    if result["result_content_hash"] != expected_hash:
        raise ValueError("Codex connector evidence result hash is invalid")
    passed = result["capability_status"] == "PASS"
    response = result["response"]
    _validate_response_provenance(response)
    response_type = (
        response.get("response_type") if isinstance(response, dict) else None
    )
    if response_type == "issue_comment":
        resolution_valid = (
            result["resolved_clean_commit_sha"] == result["pull_request"]["head_sha"]
        )
    elif response_type == "pull_request_review":
        resolution_valid = result["resolved_clean_commit_sha"] in {
            None,
            result["pull_request"]["head_sha"],
        }
    else:
        resolution_valid = result["resolved_clean_commit_sha"] is None
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
        and response.get("response_type") in {"issue_comment", "pull_request_review"}
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
    if (passed and not clean_semantics) or (
        not passed
        and not (unavailable_semantics or blocking_semantics or invalid_semantics)
    ):
        raise ValueError("Codex connector evidence result semantics are invalid")


def _validate_response_provenance(response: Any) -> None:
    if not isinstance(response, dict):
        return
    if response["response_type"] == "issue_comment":
        provenance_valid = (
            response["user_type"] == "Bot"
            and response["app_provenance"] == "VERIFIED_PERFORMED_VIA_GITHUB_APP"
            and response["app_id"] == _CONNECTOR_APP["id"]
            and response["app_node_id"] == _CONNECTOR_APP["node_id"]
            and response["app_slug"] == _CONNECTOR_APP["slug"]
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
