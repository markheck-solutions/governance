from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from governance_eval.codex_connector_evidence import (
    TrustedCodexConnectorContext,
    validate_codex_connector_evidence_result,
)


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_VALID_STATES = {
    "CLEAN",
    "BLOCKING_FINDINGS_PRESENT",
    "AI_REVIEW_UNAVAILABLE",
    "INVALID_EVIDENCE",
}
_UNAVAILABLE_POLICIES = {"non_blocking"}


def evaluate_ai_review_gate(
    head_sha: str,
    *,
    codex_result: Any,
    raw_snapshot_bytes: bytes,
    trusted_context: TrustedCodexConnectorContext,
    unavailable_after_cutoff: str = "non_blocking",
) -> dict[str, Any]:
    valid, state, reasons = _validated_codex_state(
        head_sha, codex_result, raw_snapshot_bytes, trusted_context
    )
    policy_valid = (
        isinstance(unavailable_after_cutoff, str)
        and unavailable_after_cutoff in _UNAVAILABLE_POLICIES
    )
    if not policy_valid:
        valid = False
        reasons = ["AI review unavailability policy is invalid"]
    if not valid:
        state = "INVALID_EVIDENCE"
    blocking = state == "BLOCKING_FINDINGS_PRESENT"
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "owner_status": "RED" if blocking or state == "INVALID_EVIDENCE" else "GREEN",
        "head_sha": head_sha if _SHA_RE.fullmatch(head_sha) else "0" * 40,
        "provider": "codex_connector",
        "unavailable_after_cutoff": (
            unavailable_after_cutoff if policy_valid else "invalid"
        ),
        "evidence_status": state,
        "approval_provided": False,
        "blocking_findings_present": blocking,
        "codex_result_content_hash": (
            codex_result.get("result_content_hash", "")
            if isinstance(codex_result, dict)
            else ""
        ),
        "observations": reasons,
    }


def _validated_codex_state(
    head_sha: str,
    value: Any,
    raw_snapshot_bytes: bytes,
    trusted_context: TrustedCodexConnectorContext,
) -> tuple[bool, str, list[str]]:
    if not _SHA_RE.fullmatch(head_sha) or not isinstance(value, dict):
        return False, "INVALID_EVIDENCE", ["Codex evidence result missing or invalid"]
    if trusted_context.head_sha != head_sha:
        return False, "INVALID_EVIDENCE", ["Codex trusted head binding is invalid"]
    try:
        validate_codex_connector_evidence_result(
            value, raw_snapshot_bytes, trusted_context
        )
    except (TypeError, ValueError):
        return False, "INVALID_EVIDENCE", ["Codex evidence source replay failed"]
    state = value.get("review_state")
    capability = value.get("capability_status")
    reasons = value.get("reasons")
    reconciled = value.get("reconciled_head_sha")
    reviewed = value.get("reviewed_head_sha")
    digest = value.get("result_content_hash")
    if (
        state not in _VALID_STATES
        or capability not in {"PASS", "BLOCK_TECHNICAL"}
        or not isinstance(reasons, list)
        or not all(isinstance(reason, str) for reason in reasons)
        or reconciled != head_sha
        or not isinstance(digest, str)
        or not _DIGEST_RE.fullmatch(digest)
    ):
        return False, "INVALID_EVIDENCE", ["Codex evidence result binding is invalid"]
    if state == "CLEAN":
        valid = capability == "PASS" and reviewed == head_sha and not reasons
    elif state == "BLOCKING_FINDINGS_PRESENT":
        valid = (
            capability == "BLOCK_TECHNICAL"
            and reviewed == head_sha
            and "BLOCKING_FINDINGS_PRESENT" in reasons
        )
    elif state == "AI_REVIEW_UNAVAILABLE":
        availability_reasons = {
            "NO_IN_WINDOW_RESPONSE",
            "ONLY_LATE_RESPONSE",
            "CONNECTOR_FAILURE_PRESENT",
        }
        valid = (
            capability == "BLOCK_TECHNICAL"
            and reviewed is None
            and bool(reasons)
            and set(reasons).issubset(availability_reasons)
        )
    else:
        valid = capability == "BLOCK_TECHNICAL"
    return valid, state, list(reasons)
