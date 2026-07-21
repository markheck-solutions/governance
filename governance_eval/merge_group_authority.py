from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from governance_eval.schemas import validate_named
from governance_eval.schema_validator import SchemaValidationError


_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_PATH_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
_DIGEST_RE = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_RECEIPT_VERSION = "governance_merge_group_receipt.v1"
_ENFORCEMENT_TRANSITION = (
    "e7dcc678d0391535a5befc148c63f3a41029c6a020645b855514ff408bd85e1d",
    "4fc59fe8d102ced45dc14f49343a22a0130af32ddbb6afec63c9ce09b005adc7",
)


class MergeGroupAuthorityError(ValueError):
    pass


def protected_delivery_conditions() -> dict[str, set[str]]:
    pull_request = "${{ github.event.pull_request.base.ref == 'main' }}"
    resolved = "${{ needs.resolve-authority.outputs.base-ref == 'main' }}"
    return {
        "baseline-supportability": {pull_request, resolved},
        "candidate-supportability": {pull_request, resolved},
        "delivery-receipt": {
            "${{ always() && github.event.pull_request.base.ref == 'main' }}",
            "${{ always() && needs.resolve-authority.outputs.base-ref == 'main' }}",
        },
    }


def enforcement_transition_allowed(
    digests: tuple[str, str], legacy_transition: tuple[str, str]
) -> bool:
    return digests in {legacy_transition, _ENFORCEMENT_TRANSITION}


def resolve_merge_group_authority(
    event: Mapping[str, Any], pull_requests: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Return fail-closed merge-group and constituent-PR authority data."""
    repository = _repository_identity(event.get("repository"))
    merge_group = _merge_group_identity(event.get("merge_group"))
    pull_request = _single_pull_request(pull_requests)
    _validate_constituent_binding(merge_group, pull_request)
    return {
        "repository": repository,
        "merge_group": merge_group,
        "pull_request": pull_request,
    }


def validate_merge_group_artifact(
    authority: Mapping[str, Any], artifact: Mapping[str, Any]
) -> None:
    """Reject evidence not bound to this exact merge group and pull request."""
    expected_repository = _repository_from_authority(authority)
    expected_group = _merge_group_from_authority(authority)
    expected_pr = _pull_request_from_authority(authority)
    actual_repository = _repository_identity(artifact.get("repository"))
    actual_group = _artifact_merge_group(artifact.get("merge_group"))
    actual_pr = _artifact_pull_request(artifact.get("pull_request"))
    _require_equal(
        expected_repository["id"], actual_repository["id"], "artifact repository id"
    )
    _require_equal(
        expected_repository["full_name"],
        actual_repository["full_name"],
        "artifact repository full name",
    )
    _require_equal(
        expected_group["sha"], actual_group["sha"], "artifact merge-group sha"
    )
    _require_equal(
        expected_group["ref"], actual_group["ref"], "artifact merge-group ref"
    )
    _require_equal(
        expected_group["base_sha"],
        actual_group["base_sha"],
        "artifact merge-group base sha",
    )
    _require_equal(
        expected_pr["number"], actual_pr["number"], "artifact pull-request number"
    )
    _require_equal(
        expected_pr["head_sha"],
        actual_pr["head_sha"],
        "artifact pull-request head sha",
    )
    _require_equal(
        expected_pr["base_sha"],
        actual_pr["base_sha"],
        "artifact pull-request base sha",
    )


def create_merge_group_receipt(
    authority: Mapping[str, Any], evidence: Mapping[str, Any]
) -> dict[str, Any]:
    """Create deterministic exact-merge-group authority receipt."""
    repository = _repository_from_authority(authority)
    merge_group = _merge_group_from_authority(authority)
    pull_request = _pull_request_from_authority(authority)
    normalized = _normalize_evidence(evidence)
    _validate_time_order(
        normalized["event_created_at"], normalized["verification_time"]
    )
    receipt = {
        "schema_version": _RECEIPT_VERSION,
        "repository": repository,
        "base_branch": merge_group["base_ref"],
        "base_sha": merge_group["base_sha"],
        "merge_group": {
            **merge_group,
            "event_id": normalized["event_id"],
            "event_created_at": normalized["event_created_at"],
        },
        "pull_request": pull_request,
        "evaluator_sha": normalized["evaluator_sha"],
        "caller_workflow": {
            "path": normalized["caller_workflow_path"],
            "sha256": normalized["caller_workflow_sha256"],
        },
        "reusable_workflow": {
            "path": normalized["reusable_workflow_path"],
            "sha256": normalized["reusable_workflow_sha256"],
        },
        "workflow": {
            "run_id": normalized["workflow_run_id"],
            "run_attempt": normalized["workflow_run_attempt"],
            "check_run_id": normalized["check_run_id"],
            "github_app_id": normalized["github_app_id"],
        },
        "config_sha256": normalized["config_sha256"],
        "standard_sha256": normalized["standard_sha256"],
        "transaction_id": normalized["transaction_id"],
        "artifact_digest": normalized["artifact_digest"],
        "verification_time": normalized["verification_time"],
        "receipt_id": "",
    }
    receipt["receipt_id"] = _content_sha256(receipt)
    validate_named("governance_merge_group_receipt", receipt)
    return receipt


def verify_merge_group_receipt(
    receipt: Mapping[str, Any],
    authority: Mapping[str, Any],
    expected_evidence: Mapping[str, Any],
) -> None:
    """Verify exact current authority, evidence bindings, and receipt digest."""
    if not isinstance(receipt, Mapping):
        raise MergeGroupAuthorityError("merge-group receipt is missing")
    try:
        validate_named("governance_merge_group_receipt", dict(receipt))
    except SchemaValidationError as exc:
        raise MergeGroupAuthorityError("merge-group receipt schema is invalid") from exc
    if receipt.get("schema_version") != _RECEIPT_VERSION:
        raise MergeGroupAuthorityError("merge-group receipt schema is invalid")
    validate_merge_group_artifact(authority, receipt)
    merge_group = _merge_group_from_authority(authority)
    _require_equal(merge_group["base_ref"], receipt.get("base_branch"), "base branch")
    _require_equal(merge_group["base_sha"], receipt.get("base_sha"), "base sha")
    expected = create_merge_group_receipt(authority, expected_evidence)
    for field in (
        "evaluator_sha",
        "caller_workflow",
        "reusable_workflow",
        "workflow",
        "config_sha256",
        "standard_sha256",
        "transaction_id",
        "artifact_digest",
        "verification_time",
    ):
        _require_equal(expected[field], receipt.get(field), field.replace("_", " "))
    _require_equal(
        expected["merge_group"]["event_id"],
        _mapping(receipt.get("merge_group"), "merge-group receipt").get("event_id"),
        "merge-group event id",
    )
    _require_equal(
        expected["merge_group"]["event_created_at"],
        _mapping(receipt.get("merge_group"), "merge-group receipt").get(
            "event_created_at"
        ),
        "merge-group event creation time",
    )
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt_id):
        raise MergeGroupAuthorityError("merge-group receipt id is invalid")
    if receipt_id != _content_sha256(dict(receipt)):
        raise MergeGroupAuthorityError("merge-group receipt id does not match content")


def _normalize_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MergeGroupAuthorityError("merge-group evidence is missing")
    return {
        "event_id": _required_identifier(value.get("event_id"), "event id"),
        "event_created_at": _required_timestamp(
            value.get("event_created_at"), "event creation time"
        ),
        "verification_time": _required_timestamp(
            value.get("verification_time"), "verification time"
        ),
        "evaluator_sha": _required_sha(value.get("evaluator_sha"), "evaluator sha"),
        "caller_workflow_path": _required_path(
            value.get("caller_workflow_path"), "caller workflow path"
        ),
        "caller_workflow_sha256": _required_digest(
            value.get("caller_workflow_sha256"), "caller workflow hash"
        ),
        "reusable_workflow_path": _required_path(
            value.get("reusable_workflow_path"), "reusable workflow path"
        ),
        "reusable_workflow_sha256": _required_digest(
            value.get("reusable_workflow_sha256"), "reusable workflow hash"
        ),
        "workflow_run_id": _required_positive_int(
            value.get("workflow_run_id"), "workflow run id"
        ),
        "workflow_run_attempt": _required_positive_int(
            value.get("workflow_run_attempt"), "workflow run attempt"
        ),
        "check_run_id": _required_positive_int(
            value.get("check_run_id"), "check-run id"
        ),
        "github_app_id": _required_positive_int(
            value.get("github_app_id"), "GitHub App id"
        ),
        "config_sha256": _required_digest(
            value.get("config_sha256"), "configuration hash"
        ),
        "standard_sha256": _required_digest(
            value.get("standard_sha256"), "Supportability Standard hash"
        ),
        "transaction_id": _required_identifier(
            value.get("transaction_id"), "transaction id"
        ),
        "artifact_digest": _required_digest(
            value.get("artifact_digest"), "artifact digest"
        ),
    }


def _content_sha256(receipt: Mapping[str, Any]) -> str:
    payload = {**receipt, "receipt_id": ""}
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MergeGroupAuthorityError(f"{label} is missing")
    return value


def _required_positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise MergeGroupAuthorityError(f"{label} is invalid")
    return value


def _required_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise MergeGroupAuthorityError(f"{label} is invalid")
    return value


def _required_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _PATH_RE.fullmatch(value):
        raise MergeGroupAuthorityError(f"{label} is invalid")
    return value


def _required_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise MergeGroupAuthorityError(f"{label} is invalid")
    return value.removeprefix("sha256:")


def _required_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise MergeGroupAuthorityError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MergeGroupAuthorityError(f"{label} is invalid") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise MergeGroupAuthorityError(f"{label} must be UTC")
    return parsed.isoformat().replace("+00:00", "Z")


def _validate_time_order(event_created_at: str, verification_time: str) -> None:
    event_time = datetime.fromisoformat(event_created_at.replace("Z", "+00:00"))
    verified = datetime.fromisoformat(verification_time.replace("Z", "+00:00"))
    if verified < event_time:
        raise MergeGroupAuthorityError("verification time precedes merge-group event")


def _repository_from_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    return _repository_identity(value.get("repository"))


def _merge_group_from_authority(value: Mapping[str, Any]) -> dict[str, str]:
    return _artifact_merge_group(value.get("merge_group"))


def _artifact_merge_group(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise MergeGroupAuthorityError("artifact merge group is missing")
    return {
        "ref": _required_ref(value.get("ref"), "artifact merge-group ref"),
        "sha": _required_sha(value.get("sha"), "artifact merge-group sha"),
        "base_ref": _required_ref(
            value.get("base_ref"), "artifact merge-group base ref"
        ),
        "base_sha": _required_sha(
            value.get("base_sha"), "artifact merge-group base sha"
        ),
    }


def _pull_request_from_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    return _artifact_pull_request(value.get("pull_request"))


def _artifact_pull_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MergeGroupAuthorityError("artifact pull request is missing")
    number = value.get("number")
    url = value.get("url")
    if type(number) is not int or number < 1:
        raise MergeGroupAuthorityError("artifact pull-request number is invalid")
    if not isinstance(url, str) or not url.startswith("https://github.com/"):
        raise MergeGroupAuthorityError("artifact pull-request URL is invalid")
    return {
        "number": number,
        "url": url,
        "head_sha": _required_sha(
            value.get("head_sha"), "artifact pull-request head sha"
        ),
        "base_sha": _required_sha(
            value.get("base_sha"), "artifact pull-request base sha"
        ),
        "base_ref": _required_ref(
            value.get("base_ref"), "artifact pull-request base ref"
        ),
    }


def _require_equal(expected: Any, actual: Any, label: str) -> None:
    if actual != expected:
        raise MergeGroupAuthorityError(f"{label} differs from current merge group")


def _repository_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MergeGroupAuthorityError("merge-group repository is missing")
    repository_id = value.get("id")
    full_name = value.get("full_name")
    if type(repository_id) is not int or repository_id < 1:
        raise MergeGroupAuthorityError("merge-group repository id is invalid")
    if not isinstance(full_name, str) or not _REPOSITORY_RE.fullmatch(full_name):
        raise MergeGroupAuthorityError("merge-group repository full name is invalid")
    return {"id": repository_id, "full_name": full_name}


def _merge_group_identity(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise MergeGroupAuthorityError("merge-group identity is missing")
    ref = _required_ref(value.get("head_ref"), "merge-group ref")
    sha = _required_sha(value.get("head_sha"), "merge-group sha")
    base_ref = _required_ref(value.get("base_ref"), "merge-group base ref")
    base_sha = _required_sha(value.get("base_sha"), "merge-group base sha")
    return {"ref": ref, "sha": sha, "base_ref": base_ref, "base_sha": base_sha}


def _single_pull_request(
    pull_requests: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if isinstance(pull_requests, (str, bytes)) or len(pull_requests) != 1:
        raise MergeGroupAuthorityError(
            "merge group must resolve exactly one pull request"
        )
    value = pull_requests[0]
    if not isinstance(value, Mapping):
        raise MergeGroupAuthorityError("merge-group pull request is invalid")
    number = value.get("number")
    url = value.get("html_url")
    head = value.get("head")
    base = value.get("base")
    if type(number) is not int or number < 1:
        raise MergeGroupAuthorityError("merge-group pull request number is invalid")
    if not isinstance(url, str) or not url.startswith("https://github.com/"):
        raise MergeGroupAuthorityError("merge-group pull request URL is invalid")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        raise MergeGroupAuthorityError("merge-group pull request refs are invalid")
    return {
        "number": number,
        "url": url,
        "head_sha": _required_sha(head.get("sha"), "pull-request head sha"),
        "base_sha": _required_sha(base.get("sha"), "pull-request base sha"),
        "base_ref": _required_ref(base.get("ref"), "pull-request base ref"),
    }


def _validate_constituent_binding(
    merge_group: Mapping[str, str], pull_request: Mapping[str, Any]
) -> None:
    if pull_request["base_ref"] != merge_group["base_ref"]:
        raise MergeGroupAuthorityError("pull-request base ref differs from merge group")
    if pull_request["base_sha"] != merge_group["base_sha"]:
        raise MergeGroupAuthorityError("pull-request base sha differs from merge group")


def _required_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise MergeGroupAuthorityError(f"{label} is invalid")
    return value


def _required_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise MergeGroupAuthorityError(f"{label} is invalid")
    return value
