from __future__ import annotations

import base64
import binascii
import json
import os
import re
import subprocess
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Mapping
from urllib.parse import quote, urlparse

from governance_eval.docker_toolchain import (
    CERTIFIED_TOOLCHAIN_BUNDLE_ID,
    PYTHON_IMAGE,
)
from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_packaged_named
from governance_eval.supportability import (
    SupportabilityError,
    parse_supportability_config_bytes,
)
from governance_eval.supportability_config_v2 import (
    TYPED_CAPABILITIES,
    ExecutableConfigError,
    validate_executable_supportability_config_bytes,
)

_CONFIG_PATH = ".github/governance/supportability.yml"
_CALLER_PATH = ".github/workflows/supportability-enforcement.yml"
_EVALUATOR_PATH = ".github/workflows/supportability-gate.yml"
_EVALUATOR_REPOSITORY = "markheck-solutions/governance"
_RESOURCE_KEYS = {
    "target_repository",
    "evaluator_repository",
    "pull_request",
    "base_commit",
    "head_commit",
    "evaluator_commit",
    "workflow_run",
    "effective_base_rules",
}
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_MAX_HTTP_BODY = 4 * 1024 * 1024
_MAX_JSON_DEPTH = 128
_MAX_JSON_INTEGER_DIGITS = 128
_RESOURCE_TIME_WINDOW = timedelta(minutes=5)
EvaluationRole = Literal["BASELINE", "CANDIDATE"]


class CheckoutReceiptError(ValueError):
    pass


@dataclass(frozen=True)
class HttpJsonEvidence:
    url: str
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class CheckoutReceipt:
    schema_version: str
    receipt_kind: str
    receipt_id: str
    evaluation_role: EvaluationRole
    repository: dict[str, Any]
    pull_request: dict[str, Any]
    evaluation_target: dict[str, str]
    policy: dict[str, Any]
    evaluator: dict[str, Any]
    workflows: dict[str, Any]
    github_resources: dict[str, Any]
    runtime: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return deepcopy(
            {
                "schema_version": self.schema_version,
                "receipt_kind": self.receipt_kind,
                "receipt_id": self.receipt_id,
                "evaluation_role": self.evaluation_role,
                "repository": self.repository,
                "pull_request": self.pull_request,
                "evaluation_target": self.evaluation_target,
                "policy": self.policy,
                "evaluator": self.evaluator,
                "workflows": self.workflows,
                "github_resources": self.github_resources,
                "runtime": self.runtime,
            }
        )


def bind_checkout(
    *,
    evaluation_role: EvaluationRole,
    target_root: Path,
    evaluator_root: Path,
    event_payload: Mapping[str, object],
    github_context: Mapping[str, object],
    job_context: Mapping[str, object],
    github_resources: Mapping[str, HttpJsonEvidence],
    runtime: Mapping[str, object],
) -> CheckoutReceipt:
    if evaluation_role not in {"BASELINE", "CANDIDATE"}:
        raise CheckoutReceiptError("evaluation role is invalid")
    target_root = target_root.resolve(strict=True)
    evaluator_root = evaluator_root.resolve(strict=True)
    runtime_identity = _runtime_identity(runtime)
    git = Path(runtime_identity["git"]["path"])
    projections, bodies = _collect_resources(github_resources)
    if not isinstance(bodies["effective_base_rules"], list):
        raise CheckoutReceiptError("effective base rules resource must be an array")
    repository = _repository_identity(_body_object(bodies, "target_repository"))
    evaluator_repository = _repository_identity(
        _body_object(bodies, "evaluator_repository")
    )
    pull_request = _pull_request_identity(_body_object(bodies, "pull_request"))
    if (
        pull_request["base"]["repository_id"],
        pull_request["base"]["repository_full_name"],
    ) != (repository["id"], repository["full_name"]):
        raise CheckoutReceiptError("pull request base repository differs from API")
    _bind_commit_trees(pull_request, bodies)
    _validate_resource_urls(
        repository,
        evaluator_repository,
        pull_request,
        projections,
        bodies,
    )
    _validate_event(event_payload, repository, pull_request)
    _validate_contexts(
        github_context,
        job_context,
        repository,
        evaluator_repository,
        pull_request,
    )
    _validate_run_resource(
        _body_object(bodies, "workflow_run"),
        github_context,
        job_context,
        repository,
        pull_request,
    )
    _validate_checkouts(
        target_root,
        evaluator_root,
        repository,
        evaluator_repository,
        pull_request,
        job_context,
        git,
    )
    policy = _policy_identity(
        evaluation_role,
        target_root,
        pull_request,
        repository["full_name"],
        git,
    )
    workflows = _workflow_identities(
        evaluation_role,
        target_root,
        evaluator_root,
        repository,
        evaluator_repository,
        pull_request,
        github_context,
        job_context,
        event_payload,
        projections["workflow_run"]["observed_at"],
        git,
    )
    evaluator_sha = workflows["evaluator"]["commit_sha"]
    evaluator_commit = _body_object(bodies, "evaluator_commit")
    if evaluator_commit.get("sha") != evaluator_sha:
        raise CheckoutReceiptError("evaluator commit differs between job and API")
    evaluator_tree = _commit_tree(evaluator_commit)
    if evaluator_tree != workflows["evaluator"]["tree_sha"]:
        raise CheckoutReceiptError("evaluator tree differs between Git and API")
    receipt = CheckoutReceipt(
        schema_version="1.0",
        receipt_kind="checkout_receipt.v1",
        receipt_id="",
        evaluation_role=evaluation_role,
        repository=repository,
        pull_request=pull_request,
        evaluation_target={
            "commit_sha": pull_request["head"]["commit_sha"],
            "tree_sha": pull_request["head"]["tree_sha"],
            "diff_base_commit_sha": pull_request["base"]["commit_sha"],
            "diff_base_tree_sha": pull_request["base"]["tree_sha"],
        },
        policy=policy,
        evaluator={
            "repository_id": evaluator_repository["id"],
            "repository_full_name": evaluator_repository["full_name"],
            "commit_sha": evaluator_sha,
            "tree_sha": evaluator_tree,
        },
        workflows=workflows,
        github_resources=projections,
        runtime=runtime_identity,
    )
    receipt = replace(receipt, receipt_id=sha256_json(_unsigned(receipt)))
    _validate_receipt_schema(receipt)
    return receipt


def validate_checkout_receipt(receipt: CheckoutReceipt) -> dict[str, Any]:
    if not isinstance(receipt, CheckoutReceipt):
        raise CheckoutReceiptError("checkout receipt type is invalid")
    return validate_checkout_receipt_v1(receipt)


def validate_checkout_receipt_v1(
    payload: Mapping[str, object] | CheckoutReceipt,
) -> dict[str, Any]:
    if isinstance(payload, CheckoutReceipt):
        candidate = payload.to_json()
    elif isinstance(payload, Mapping):
        candidate = deepcopy(dict(payload))
    else:
        raise CheckoutReceiptError("checkout receipt must be an object")
    try:
        validate_packaged_named("checkout_receipt", candidate)
    except (KeyError, OSError, SchemaValidationError, ValueError) as exc:
        raise CheckoutReceiptError(
            f"checkout receipt schema is invalid: {exc}"
        ) from exc
    unsigned = deepcopy(candidate)
    receipt_id = unsigned.pop("receipt_id")
    if receipt_id != sha256_json(unsigned):
        raise CheckoutReceiptError("checkout receipt integrity is invalid")
    _validate_receipt_semantics(candidate)
    return candidate


def _validate_receipt_semantics(payload: Mapping[str, Any]) -> None:
    _validate_policy_projection(payload)
    _validate_target_projection(payload)
    _validate_repository_projection(payload)
    _validate_workflow_projection(payload)
    _validate_resource_projection(payload)
    _validate_resource_bodies(payload)
    _validate_receipt_timestamps(payload)
    _validate_runtime_projection(payload["runtime"])


def _validate_policy_projection(payload: Mapping[str, Any]) -> None:
    role = payload["evaluation_role"]
    expected_source = "BASE" if role == "BASELINE" else "HEAD"
    expected_policy = payload["pull_request"][expected_source.lower()]
    if payload["policy"]["source"] != expected_source:
        raise CheckoutReceiptError("checkout receipt policy source is invalid")
    if payload["policy"]["commit_sha"] != expected_policy["commit_sha"]:
        raise CheckoutReceiptError("checkout receipt policy commit is invalid")
    if payload["policy"]["tree_sha"] != expected_policy["tree_sha"]:
        raise CheckoutReceiptError("checkout receipt policy tree is invalid")
    if payload["policy"]["config"]["path"] != _CONFIG_PATH:
        raise CheckoutReceiptError("checkout receipt config path is invalid")
    profile = payload["policy"]["execution_profile"]
    expected_source_version = "1.0" if profile["mode"] == "legacy_v1_exact" else "2.0"
    if profile["source_schema_version"] != expected_source_version:
        raise CheckoutReceiptError("checkout receipt config mode is invalid")
    if profile["capabilities"] != TYPED_CAPABILITIES:
        raise CheckoutReceiptError("checkout receipt capability profile is invalid")
    if profile["profile_id"] != sha256_json(TYPED_CAPABILITIES):
        raise CheckoutReceiptError("checkout receipt capability identity is invalid")
    _canonical_git_path(payload["policy"]["standard"]["path"])


def _validate_target_projection(payload: Mapping[str, Any]) -> None:
    target = payload["evaluation_target"]
    head = payload["pull_request"]["head"]
    base = payload["pull_request"]["base"]
    if (target["commit_sha"], target["tree_sha"]) != (
        head["commit_sha"],
        head["tree_sha"],
    ):
        raise CheckoutReceiptError("checkout receipt evaluation target is invalid")
    if (target["diff_base_commit_sha"], target["diff_base_tree_sha"]) != (
        base["commit_sha"],
        base["tree_sha"],
    ):
        raise CheckoutReceiptError("checkout receipt diff base is invalid")


def _validate_repository_projection(payload: Mapping[str, Any]) -> None:
    repository = payload["repository"]
    base = payload["pull_request"]["base"]
    if (repository["id"], repository["full_name"]) != (
        base["repository_id"],
        base["repository_full_name"],
    ):
        raise CheckoutReceiptError("checkout receipt base repository is invalid")
    if (
        repository["api_url"]
        != f"https://api.github.com/repos/{repository['full_name']}"
    ):
        raise CheckoutReceiptError("checkout receipt repository API URL is invalid")
    if repository["html_url"] != f"https://github.com/{repository['full_name']}":
        raise CheckoutReceiptError("checkout receipt repository HTML URL is invalid")


def _validate_workflow_projection(payload: Mapping[str, Any]) -> None:
    repository = payload["repository"]
    pull_request = payload["pull_request"]
    evaluator = payload["evaluator"]
    workflows = payload["workflows"]
    caller = workflows["caller"]
    called = workflows["evaluator"]
    expected_caller_ref = (
        f"{repository['full_name']}/{_CALLER_PATH}@refs/heads/"
        f"{pull_request['base']['ref']}"
    )
    expected_evaluator_ref = (
        f"{evaluator['repository_full_name']}/{_EVALUATOR_PATH}@"
        f"{evaluator['commit_sha']}"
    )
    caller_identity = (
        caller["repository_id"],
        caller["repository_full_name"],
        caller["path"],
        caller["workflow_ref"],
        caller["commit_sha"],
        caller["tree_sha"],
    )
    expected_caller = (
        repository["id"],
        repository["full_name"],
        _CALLER_PATH,
        expected_caller_ref,
        pull_request["base"]["commit_sha"],
        pull_request["base"]["tree_sha"],
    )
    if caller_identity != expected_caller:
        raise CheckoutReceiptError("checkout receipt caller workflow is invalid")
    called_identity = (
        called["repository_id"],
        called["repository_full_name"],
        called["path"],
        called["workflow_ref"],
        called["commit_sha"],
        called["tree_sha"],
    )
    expected_called = (
        evaluator["repository_id"],
        evaluator["repository_full_name"],
        _EVALUATOR_PATH,
        expected_evaluator_ref,
        evaluator["commit_sha"],
        evaluator["tree_sha"],
    )
    if called_identity != expected_called:
        raise CheckoutReceiptError("checkout receipt evaluator workflow is invalid")
    expected_artifact = (
        f"{payload['evaluation_role'].lower()}-supportability-gate-evidence"
    )
    if workflows["run"]["artifact_name"] != expected_artifact:
        raise CheckoutReceiptError("checkout receipt role artifact is invalid")
    expected_run_url = f"{repository['api_url']}/actions/runs/{workflows['run']['id']}"
    if workflows["run"]["api_url"] != expected_run_url:
        raise CheckoutReceiptError("checkout receipt workflow run URL is invalid")


def _validate_resource_projection(payload: Mapping[str, Any]) -> None:
    repository = payload["repository"]
    pull_request = payload["pull_request"]
    evaluator = payload["evaluator"]
    run = payload["workflows"]["run"]
    expected = {
        "target_repository": repository["api_url"],
        "evaluator_repository": (
            f"https://api.github.com/repos/{evaluator['repository_full_name']}"
        ),
        "pull_request": pull_request["api_url"],
        "base_commit": _commit_api_url(pull_request["base"]),
        "head_commit": _commit_api_url(pull_request["head"]),
        "evaluator_commit": (
            f"https://api.github.com/repos/{evaluator['repository_full_name']}/commits/"
            f"{evaluator['commit_sha']}"
        ),
        "workflow_run": run["api_url"],
        "effective_base_rules": (
            f"{repository['api_url']}/rules/branches/"
            f"{quote(pull_request['base']['ref'], safe='')}"
        ),
    }
    mismatch = next(
        (
            name
            for name, url in expected.items()
            if payload["github_resources"][name]["url"] != url
        ),
        None,
    )
    if mismatch:
        raise CheckoutReceiptError(f"checkout receipt {mismatch} URL is invalid")


def _validate_resource_bodies(payload: Mapping[str, Any]) -> None:
    bodies = {
        name: _receipt_resource_body(resource)
        for name, resource in payload["github_resources"].items()
    }
    repository = _repository_identity(_body_object(bodies, "target_repository"))
    evaluator_repository = _repository_identity(
        _body_object(bodies, "evaluator_repository")
    )
    pull_request = _pull_request_identity(_body_object(bodies, "pull_request"))
    _bind_commit_trees(pull_request, bodies)
    if repository != payload["repository"] or pull_request != payload["pull_request"]:
        raise CheckoutReceiptError("checkout receipt API projection is invalid")
    evaluator = payload["evaluator"]
    if (
        evaluator_repository["id"],
        evaluator_repository["full_name"],
    ) != (evaluator["repository_id"], evaluator["repository_full_name"]):
        raise CheckoutReceiptError(
            "checkout receipt evaluator API projection is invalid"
        )
    evaluator_commit = _body_object(bodies, "evaluator_commit")
    if (
        evaluator_commit.get("sha"),
        _commit_tree(evaluator_commit),
    ) != (evaluator["commit_sha"], evaluator["tree_sha"]):
        raise CheckoutReceiptError(
            "checkout receipt evaluator commit projection is invalid"
        )
    _validate_receipt_run_body(_body_object(bodies, "workflow_run"), payload)
    if not isinstance(bodies["effective_base_rules"], list):
        raise CheckoutReceiptError("checkout receipt effective rules body is invalid")


def _receipt_resource_body(resource: Mapping[str, Any]) -> object:
    try:
        raw = base64.b64decode(resource["body_base64"], validate=True)
    except (binascii.Error, KeyError, TypeError, ValueError) as exc:
        raise CheckoutReceiptError("checkout receipt resource body is invalid") from exc
    if len(raw) > _MAX_HTTP_BODY or sha256(raw).hexdigest() != resource["body_sha256"]:
        raise CheckoutReceiptError("checkout receipt resource body digest is invalid")
    return _strict_json(raw)


def _validate_receipt_run_body(
    run: Mapping[str, object], payload: Mapping[str, Any]
) -> None:
    repository = payload["repository"]
    pull_request = payload["pull_request"]
    workflow = payload["workflows"]
    run_repository = _mapping(run.get("repository"), "workflow run repository")
    expected = {
        "id": workflow["run"]["id"],
        "run_attempt": workflow["run"]["attempt"],
        "event": "pull_request_target",
        "path": _CALLER_PATH,
        "head_sha": pull_request["base"]["commit_sha"],
    }
    if any(run.get(name) != value for name, value in expected.items()):
        raise CheckoutReceiptError(
            "checkout receipt workflow run projection is invalid"
        )
    if (run_repository.get("id"), run_repository.get("full_name")) != (
        repository["id"],
        repository["full_name"],
    ):
        raise CheckoutReceiptError(
            "checkout receipt workflow run repository is invalid"
        )
    _validate_receipt_referenced_workflow(run, payload["evaluator"])


def _validate_receipt_referenced_workflow(
    run: Mapping[str, object], evaluator: Mapping[str, Any]
) -> None:
    references = run.get("referenced_workflows")
    expected_path = (
        f"{evaluator['repository_full_name']}/{_EVALUATOR_PATH}@"
        f"{evaluator['commit_sha']}"
    )
    if not isinstance(references, list):
        raise CheckoutReceiptError("checkout receipt reusable workflow is missing")
    matches = [
        item
        for item in references
        if isinstance(item, Mapping)
        and item.get("path") == expected_path
        and item.get("sha") == evaluator["commit_sha"]
    ]
    if len(matches) != 1:
        raise CheckoutReceiptError("checkout receipt reusable workflow is invalid")


def _validate_receipt_timestamps(payload: Mapping[str, Any]) -> None:
    run_time = _timestamp(payload["workflows"]["run"]["observed_at"])
    for name, resource in payload["github_resources"].items():
        observed = _timestamp(resource["observed_at"])
        if abs(observed - run_time) > _RESOURCE_TIME_WINDOW:
            raise CheckoutReceiptError(
                f"checkout receipt {name} observation is outside the run window"
            )


def _validate_runtime_projection(runtime: Mapping[str, Any]) -> None:
    for name in ("git", "python", "docker"):
        path = Path(runtime[name]["path"])
        if not path.is_absolute() or path != Path(os.path.normpath(path)):
            raise CheckoutReceiptError(
                f"checkout receipt runtime {name} path is invalid"
            )
    if runtime["container_image"]["reference"] != PYTHON_IMAGE:
        raise CheckoutReceiptError("checkout receipt container image is not certified")
    if runtime["toolchain"]["bundle_id"] != CERTIFIED_TOOLCHAIN_BUNDLE_ID:
        raise CheckoutReceiptError("checkout receipt toolchain is not certified")


def _collect_resources(
    evidence: Mapping[str, HttpJsonEvidence],
) -> tuple[dict[str, Any], dict[str, object]]:
    if set(evidence) != _RESOURCE_KEYS:
        raise CheckoutReceiptError("GitHub resource evidence set is incomplete")
    projections: dict[str, Any] = {}
    bodies: dict[str, object] = {}
    for name in sorted(_RESOURCE_KEYS):
        projection, body = _read_resource(evidence[name])
        projections[name] = projection
        bodies[name] = body
    return projections, bodies


def _read_resource(evidence: HttpJsonEvidence) -> tuple[dict[str, Any], object]:
    if not isinstance(evidence, HttpJsonEvidence):
        raise CheckoutReceiptError("GitHub resource evidence type is invalid")
    if evidence.status != 200 or not evidence.url.startswith("https://api.github.com/"):
        raise CheckoutReceiptError("GitHub resource response is invalid")
    if len(evidence.body) > _MAX_HTTP_BODY:
        raise CheckoutReceiptError("GitHub resource body exceeds limit")
    headers = {str(key).lower(): str(value) for key, value in evidence.headers.items()}
    etag = headers.get("etag")
    observed_at = _github_timestamp(headers.get("date", ""))
    if etag is not None and (not etag or len(etag) > 512):
        raise CheckoutReceiptError("GitHub resource ETag is invalid")
    body = _strict_json(evidence.body)
    return (
        {
            "url": evidence.url,
            "status": evidence.status,
            "etag": etag,
            "observed_at": observed_at,
            "body_sha256": sha256(evidence.body).hexdigest(),
            "body_base64": base64.b64encode(evidence.body).decode("ascii"),
        },
        body,
    )


def _strict_json(raw: bytes) -> object:
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_int=_bounded_json_integer,
        )
        _validate_json_depth(parsed)
        return parsed
    except CheckoutReceiptError:
        raise
    except (
        RecursionError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise CheckoutReceiptError("GitHub resource JSON is malformed") from exc


def _bounded_json_integer(value: str) -> int:
    if len(value.lstrip("-")) > _MAX_JSON_INTEGER_DIGITS:
        raise ValueError("JSON integer exceeds limit")
    return int(value)


def _validate_json_depth(payload: object) -> None:
    pending = [(payload, 1)]
    while pending:
        value, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON nesting exceeds limit")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise CheckoutReceiptError("GitHub resource JSON has duplicate keys")
        payload[key] = value
    return payload


def _reject_constant(value: str) -> None:
    raise CheckoutReceiptError(f"GitHub resource JSON constant is invalid: {value}")


def _github_timestamp(value: str) -> str:
    try:
        timestamp = parsedate_to_datetime(value)
    except (TypeError, ValueError) as exc:
        raise CheckoutReceiptError("GitHub resource Date is invalid") from exc
    if timestamp.tzinfo is None:
        raise CheckoutReceiptError("GitHub resource Date lacks timezone")
    return (
        timestamp.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CheckoutReceiptError("checkout receipt timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CheckoutReceiptError("checkout receipt timestamp is invalid") from exc
    if parsed.utcoffset() != timedelta(0):
        raise CheckoutReceiptError("checkout receipt timestamp is invalid")
    return parsed


def _body_object(bodies: Mapping[str, object], name: str) -> Mapping[str, object]:
    body = bodies[name]
    if not isinstance(body, Mapping):
        raise CheckoutReceiptError(f"GitHub {name} resource must be an object")
    return body


def _repository_identity(body: Mapping[str, object]) -> dict[str, Any]:
    repository_id = _positive_int(body, "id")
    full_name = _repository_name(body.get("full_name"), "repository full_name")
    default_branch = _nonempty(body.get("default_branch"), "default branch")
    api_url = _exact_text(body.get("url"), f"https://api.github.com/repos/{full_name}")
    html_url = _exact_text(body.get("html_url"), f"https://github.com/{full_name}")
    return {
        "id": repository_id,
        "full_name": full_name,
        "default_branch": default_branch,
        "api_url": api_url,
        "html_url": html_url,
    }


def _pull_request_identity(body: Mapping[str, object]) -> dict[str, Any]:
    number = _positive_int(body, "number")
    base = _pull_ref(body.get("base"), "base")
    head = _pull_ref(body.get("head"), "head")
    repository = base["repository_full_name"]
    return {
        "number": number,
        "api_url": _exact_text(
            body.get("url"),
            f"https://api.github.com/repos/{repository}/pulls/{number}",
        ),
        "html_url": _exact_text(
            body.get("html_url"), f"https://github.com/{repository}/pull/{number}"
        ),
        "base": base,
        "head": head,
    }


def _pull_ref(value: object, label: str) -> dict[str, Any]:
    payload = _mapping(value, f"pull request {label}")
    repository = _mapping(payload.get("repo"), f"pull request {label} repository")
    return {
        "repository_id": _positive_int(repository, "id"),
        "repository_full_name": _repository_name(
            repository.get("full_name"), f"pull request {label} repository"
        ),
        "ref": _nonempty(payload.get("ref"), f"pull request {label} ref"),
        "commit_sha": _sha(payload.get("sha"), f"pull request {label} SHA"),
        "tree_sha": "",
    }


def _bind_commit_trees(
    pull_request: dict[str, Any], bodies: Mapping[str, object]
) -> None:
    for role in ("base", "head"):
        body = _body_object(bodies, f"{role}_commit")
        sha = _sha(body.get("sha"), f"{role} commit resource SHA")
        if sha != pull_request[role]["commit_sha"]:
            raise CheckoutReceiptError(f"pull request {role} SHA differs from API")
        pull_request[role]["tree_sha"] = _commit_tree(body)


def _commit_tree(body: Mapping[str, object]) -> str:
    commit = _mapping(body.get("commit"), "commit resource commit")
    tree = _mapping(commit.get("tree"), "commit resource tree")
    return _sha(tree.get("sha"), "commit resource tree SHA")


def _validate_resource_urls(
    repository: Mapping[str, Any],
    evaluator_repository: Mapping[str, Any],
    pull_request: Mapping[str, Any],
    projections: Mapping[str, Any],
    bodies: Mapping[str, object],
) -> None:
    run = _body_object(bodies, "workflow_run")
    run_id = _positive_int(run, "id")
    evaluator_sha = _sha(
        _body_object(bodies, "evaluator_commit").get("sha"),
        "evaluator commit resource SHA",
    )
    expected = {
        "target_repository": repository["api_url"],
        "evaluator_repository": evaluator_repository["api_url"],
        "pull_request": pull_request["api_url"],
        "base_commit": _commit_api_url(pull_request["base"]),
        "head_commit": _commit_api_url(pull_request["head"]),
        "evaluator_commit": (
            f"{evaluator_repository['api_url']}/commits/{evaluator_sha}"
        ),
        "workflow_run": f"{repository['api_url']}/actions/runs/{run_id}",
        "effective_base_rules": (
            f"{repository['api_url']}/rules/branches/"
            f"{quote(pull_request['base']['ref'], safe='')}"
        ),
    }
    for name, url in expected.items():
        if projections[name]["url"] != url:
            raise CheckoutReceiptError(f"GitHub {name} resource URL is invalid")


def _commit_api_url(reference: Mapping[str, Any]) -> str:
    return (
        f"https://api.github.com/repos/{reference['repository_full_name']}/commits/"
        f"{reference['commit_sha']}"
    )


def _validate_event(
    event: Mapping[str, object],
    repository: Mapping[str, Any],
    pull_request: Mapping[str, Any],
) -> None:
    event_repository = _repository_identity(
        _mapping(event.get("repository"), "event repository")
    )
    event_pull_request = _pull_request_identity(
        _mapping(event.get("pull_request"), "event pull request")
    )
    if event_repository != repository:
        raise CheckoutReceiptError("event repository differs from API")
    for role in ("base", "head"):
        if event_pull_request[role]["commit_sha"] != pull_request[role]["commit_sha"]:
            raise CheckoutReceiptError(f"event pull request {role} differs from API")
    if event_pull_request["number"] != pull_request["number"]:
        raise CheckoutReceiptError("event pull request number differs from API")
    _nonempty(event.get("action"), "event action")


def _validate_contexts(
    github: Mapping[str, object],
    job: Mapping[str, object],
    repository: Mapping[str, Any],
    evaluator_repository: Mapping[str, Any],
    pull_request: Mapping[str, Any],
) -> None:
    caller_ref = (
        f"{repository['full_name']}/{_CALLER_PATH}@refs/heads/"
        f"{pull_request['base']['ref']}"
    )
    evaluator_sha = _sha(job.get("workflow_sha"), "job workflow SHA")
    evaluator_ref = f"{_EVALUATOR_REPOSITORY}/{_EVALUATOR_PATH}@{evaluator_sha}"
    expected = {
        "github.repository": (github.get("repository"), repository["full_name"]),
        "github.repository_id": (github.get("repository_id"), repository["id"]),
        "github.workflow_ref": (github.get("workflow_ref"), caller_ref),
        "github.workflow_sha": (
            github.get("workflow_sha"),
            pull_request["base"]["commit_sha"],
        ),
        "github.event_name": (github.get("event_name"), "pull_request_target"),
        "job.workflow_repository": (
            job.get("workflow_repository"),
            _EVALUATOR_REPOSITORY,
        ),
        "job.workflow_file_path": (job.get("workflow_file_path"), _EVALUATOR_PATH),
        "job.workflow_ref": (job.get("workflow_ref"), evaluator_ref),
        "evaluator repository": (
            evaluator_repository["full_name"],
            _EVALUATOR_REPOSITORY,
        ),
    }
    mismatch = next(
        (name for name, values in expected.items() if values[0] != values[1]), None
    )
    if mismatch:
        raise CheckoutReceiptError(f"{mismatch} identity is invalid")
    _positive_int(github, "run_id")
    _positive_int(github, "run_attempt")


def _validate_run_resource(
    run: Mapping[str, object],
    github: Mapping[str, object],
    job: Mapping[str, object],
    repository: Mapping[str, Any],
    pull_request: Mapping[str, Any],
) -> None:
    run_repository = _mapping(run.get("repository"), "workflow run repository")
    expected = {
        "id": (_positive_int(run, "id"), _positive_int(github, "run_id")),
        "attempt": (
            _positive_int(run, "run_attempt"),
            _positive_int(github, "run_attempt"),
        ),
        "event": (run.get("event"), "pull_request_target"),
        "path": (run.get("path"), _CALLER_PATH),
        "head_sha": (run.get("head_sha"), pull_request["base"]["commit_sha"]),
        "repository": (run_repository.get("id"), repository["id"]),
    }
    mismatch = next(
        (name for name, values in expected.items() if values[0] != values[1]), None
    )
    if mismatch:
        raise CheckoutReceiptError(f"workflow run {mismatch} is invalid")
    _validate_referenced_workflow(run, job)


def _validate_referenced_workflow(
    run: Mapping[str, object], job: Mapping[str, object]
) -> None:
    references = run.get("referenced_workflows")
    evaluator_sha = _sha(job.get("workflow_sha"), "job workflow SHA")
    expected_path = f"{_EVALUATOR_REPOSITORY}/{_EVALUATOR_PATH}@{evaluator_sha}"
    if not isinstance(references, list):
        raise CheckoutReceiptError("workflow run reusable workflow evidence is missing")
    matches = [
        item
        for item in references
        if isinstance(item, Mapping)
        and item.get("path") == expected_path
        and item.get("sha") == evaluator_sha
    ]
    if len(matches) != 1:
        raise CheckoutReceiptError("workflow run reusable evaluator is invalid")


def _validate_checkouts(
    target_root: Path,
    evaluator_root: Path,
    repository: Mapping[str, Any],
    evaluator_repository: Mapping[str, Any],
    pull_request: Mapping[str, Any],
    job: Mapping[str, object],
    git: Path,
) -> None:
    _validate_checkout(target_root, "target", git)
    _validate_checkout(evaluator_root, "evaluator", git)
    if (
        _git_text(git, target_root, "rev-parse", "HEAD")
        != pull_request["head"]["commit_sha"]
    ):
        raise CheckoutReceiptError("target checkout head differs from pull request")
    _git_text(
        git,
        target_root,
        "cat-file",
        "-e",
        f"{pull_request['base']['commit_sha']}^{{commit}}",
    )
    evaluator_sha = _sha(job.get("workflow_sha"), "job workflow SHA")
    if _git_text(git, evaluator_root, "rev-parse", "HEAD") != evaluator_sha:
        raise CheckoutReceiptError("evaluator checkout differs from called workflow")
    for role in ("base", "head"):
        actual_tree = _git_text(
            git,
            target_root,
            "rev-parse",
            f"{pull_request[role]['commit_sha']}^{{tree}}",
        )
        if actual_tree != pull_request[role]["tree_sha"]:
            raise CheckoutReceiptError(f"target {role} tree differs from API")
    if _origin_repository(git, target_root) != repository["full_name"].lower():
        raise CheckoutReceiptError("target origin differs from repository")
    if (
        _origin_repository(git, evaluator_root)
        != evaluator_repository["full_name"].lower()
    ):
        raise CheckoutReceiptError("evaluator origin differs from repository")


def _validate_checkout(root: Path, label: str, git: Path) -> None:
    status = _git_text(
        git,
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    )
    if status:
        raise CheckoutReceiptError(f"{label} checkout is dirty")
    for line in _git_text(git, root, "ls-files", "--stage").splitlines():
        if line.split(maxsplit=1)[0] not in {"100644", "100755"}:
            raise CheckoutReceiptError(f"{label} checkout has unsupported Git mode")


def _policy_identity(
    role: EvaluationRole,
    target_root: Path,
    pull_request: Mapping[str, Any],
    repository_full_name: str,
    git: Path,
) -> dict[str, Any]:
    source = "BASE" if role == "BASELINE" else "HEAD"
    reference = pull_request[source.lower()]
    config, raw_config = _git_file(
        git, target_root, reference["commit_sha"], _CONFIG_PATH
    )
    try:
        executable = validate_executable_supportability_config_bytes(
            raw_config,
            repository_full_name=repository_full_name,
            path=_CONFIG_PATH,
        )
    except ExecutableConfigError as exc:
        raise CheckoutReceiptError(
            "authenticated supportability config is invalid"
        ) from exc
    parsed = executable["source"]
    standard_config = _mapping(parsed.get("standard"), "supportability standard")
    standard_path = _canonical_git_path(standard_config.get("source"))
    standard, raw_standard = _git_file(
        git, target_root, reference["commit_sha"], standard_path
    )
    declared_hash = standard_config.get("hash")
    if declared_hash != sha256(raw_standard).hexdigest():
        raise CheckoutReceiptError("authenticated supportability standard hash differs")
    return {
        "source": source,
        "commit_sha": reference["commit_sha"],
        "tree_sha": reference["tree_sha"],
        "config": config,
        "standard": standard,
        "execution_profile": {
            "mode": executable["mode"],
            "source_schema_version": executable["source_schema_version"],
            "effective_schema_version": executable["effective_schema_version"],
            "profile_id": sha256_json(TYPED_CAPABILITIES),
            "capabilities": deepcopy(TYPED_CAPABILITIES),
        },
    }


def _workflow_identities(
    role: EvaluationRole,
    target_root: Path,
    evaluator_root: Path,
    repository: Mapping[str, Any],
    evaluator_repository: Mapping[str, Any],
    pull_request: Mapping[str, Any],
    github: Mapping[str, object],
    job: Mapping[str, object],
    event: Mapping[str, object],
    observed_at: str,
    git: Path,
) -> dict[str, Any]:
    base = pull_request["base"]
    evaluator_sha = _sha(job.get("workflow_sha"), "job workflow SHA")
    caller_file, caller_bytes = _git_file(
        git, target_root, base["commit_sha"], _CALLER_PATH
    )
    evaluator_file, _ = _git_file(git, evaluator_root, evaluator_sha, _EVALUATOR_PATH)
    _validate_role_binding(role, caller_bytes, job, evaluator_sha)
    caller = {
        "repository_id": repository["id"],
        "repository_full_name": repository["full_name"],
        "workflow_ref": github["workflow_ref"],
        "commit_sha": base["commit_sha"],
        "tree_sha": base["tree_sha"],
        **caller_file,
    }
    evaluator = {
        "repository_id": evaluator_repository["id"],
        "repository_full_name": evaluator_repository["full_name"],
        "workflow_ref": job["workflow_ref"],
        "commit_sha": evaluator_sha,
        "tree_sha": _git_text(
            git, evaluator_root, "rev-parse", f"{evaluator_sha}^{{tree}}"
        ),
        **evaluator_file,
    }
    return {
        "caller": caller,
        "evaluator": evaluator,
        "run": {
            "id": _positive_int(github, "run_id"),
            "attempt": _positive_int(github, "run_attempt"),
            "api_url": (
                f"https://api.github.com/repos/{repository['full_name']}/actions/runs/"
                f"{github['run_id']}"
            ),
            "event": "pull_request_target",
            "action": _nonempty(event.get("action"), "event action"),
            "artifact_name": _nonempty(job.get("artifact_name"), "artifact name"),
            "observed_at": observed_at,
        },
    }


def _validate_role_binding(
    role: EvaluationRole,
    caller_bytes: bytes,
    job: Mapping[str, object],
    evaluator_sha: str,
) -> None:
    expected_artifact = f"{role.lower()}-supportability-gate-evidence"
    if job.get("artifact_name") != expected_artifact:
        raise CheckoutReceiptError("evaluation role differs from artifact identity")
    try:
        caller = parse_supportability_config_bytes(caller_bytes, suffix=".yml")
    except SupportabilityError as exc:
        raise CheckoutReceiptError("caller workflow is not valid YAML") from exc
    job_name = (
        "baseline-supportability" if role == "BASELINE" else "candidate-supportability"
    )
    jobs = _mapping(caller.get("jobs"), "caller workflow jobs")
    selected = _mapping(jobs.get(job_name), "caller workflow role job")
    inputs = _mapping(selected.get("with"), "caller workflow role inputs")
    expected_uses = f"{_EVALUATOR_REPOSITORY}/{_EVALUATOR_PATH}@{evaluator_sha}"
    if (
        selected.get("uses") != expected_uses
        or inputs.get("governance-ref") != evaluator_sha
        or inputs.get("artifact-name") != expected_artifact
    ):
        raise CheckoutReceiptError("caller workflow role binding is invalid")


def _git_file(
    git: Path, root: Path, commit: str, path: str
) -> tuple[dict[str, str], bytes]:
    canonical = _canonical_git_path(path)
    entry = _git_text(git, root, "ls-tree", commit, "--", canonical)
    if not entry.startswith(("100644 blob ", "100755 blob ")):
        raise CheckoutReceiptError(f"Git evidence file mode is invalid: {canonical}")
    blob = _git_text(git, root, "rev-parse", f"{commit}:{canonical}")
    raw = _git_bytes(git, root, "show", f"{commit}:{canonical}")
    if len(raw) > _MAX_HTTP_BODY:
        raise CheckoutReceiptError(f"Git evidence file exceeds limit: {canonical}")
    return (
        {
            "path": canonical,
            "git_blob_sha": _sha(blob, "Git blob SHA"),
            "content_sha256": sha256(raw).hexdigest(),
        },
        raw,
    )


def _runtime_identity(runtime: Mapping[str, object]) -> dict[str, Any]:
    payload = deepcopy(dict(runtime))
    for name in ("git", "python", "docker"):
        raw_executable = payload.get(name)
        if not isinstance(raw_executable, dict):
            raise CheckoutReceiptError(f"runtime {name} must be an object")
        executable: dict[str, Any] = raw_executable
        path = Path(_nonempty(executable.get("path"), f"runtime {name} path")).resolve(
            strict=True
        )
        if not path.is_file() or sha256_file(path) != executable.get("sha256"):
            raise CheckoutReceiptError(f"runtime {name} executable digest is invalid")
        executable["path"] = str(path)
    image = _mapping(payload.get("container_image"), "runtime container image")
    toolchain = _mapping(payload.get("toolchain"), "runtime toolchain")
    if image.get("reference") != PYTHON_IMAGE:
        raise CheckoutReceiptError("runtime container image is not certified")
    if toolchain.get("bundle_id") != CERTIFIED_TOOLCHAIN_BUNDLE_ID:
        raise CheckoutReceiptError("runtime toolchain bundle is not certified")
    return payload


def _validate_receipt_schema(receipt: CheckoutReceipt) -> None:
    try:
        validate_packaged_named("checkout_receipt", receipt.to_json())
    except (KeyError, OSError, SchemaValidationError, ValueError) as exc:
        raise CheckoutReceiptError(
            f"checkout receipt schema is invalid: {exc}"
        ) from exc


def _git_text(git: Path, root: Path, *arguments: str) -> str:
    try:
        return _git_bytes(git, root, *arguments).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise CheckoutReceiptError("Git text evidence is not UTF-8") from exc


def _git_bytes(git: Path, root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            [str(git), f"--git-dir={root / '.git'}", f"--work-tree={root}", *arguments],
            check=True,
            capture_output=True,
            timeout=10,
            env=_git_environment(git),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CheckoutReceiptError(
            f"Git evidence unavailable: {' '.join(arguments)}"
        ) from exc
    return completed.stdout


def _git_environment(git: Path) -> dict[str, str]:
    environment = {
        "PATH": str(git.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    system_root = os.environ.get("SystemRoot")
    if system_root:
        environment["SystemRoot"] = system_root
    return environment


def _origin_repository(git: Path, root: Path) -> str:
    remote = _git_text(git, root, "remote", "get-url", "origin").removesuffix(".git")
    if remote.startswith("git@github.com:"):
        return remote.removeprefix("git@github.com:").lower()
    parsed = urlparse(remote)
    if parsed.hostname == "github.com" and parsed.path.strip("/"):
        return parsed.path.strip("/").lower()
    raise CheckoutReceiptError("repository origin is not GitHub")


def _canonical_git_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CheckoutReceiptError("Git evidence path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CheckoutReceiptError("Git evidence path is invalid")
    canonical = path.as_posix()
    if canonical != value or any(
        character in value for character in ("\r", "\n", "\0")
    ):
        raise CheckoutReceiptError("Git evidence path is invalid")
    return canonical


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CheckoutReceiptError(f"{label} must be an object")
    return value


def _positive_int(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CheckoutReceiptError(f"{field} must be a positive integer")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise CheckoutReceiptError(f"{label} is invalid")
    return value


def _exact_text(value: object, expected: str) -> str:
    if value != expected:
        raise CheckoutReceiptError(f"URL is invalid: expected {expected}")
    return expected


def _repository_name(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REPOSITORY_RE.fullmatch(value):
        raise CheckoutReceiptError(f"{label} is invalid")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise CheckoutReceiptError(f"{label} is invalid")
    return value


def _unsigned(receipt: CheckoutReceipt) -> dict[str, Any]:
    payload = receipt.to_json()
    payload.pop("receipt_id")
    return payload
