from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


class MergeGroupAuthorityError(ValueError):
    pass


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
