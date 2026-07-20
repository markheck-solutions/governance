from __future__ import annotations

import base64
import json
from copy import deepcopy
from hashlib import sha256
from typing import Any

from governance_eval.capability_catalog import CapabilityAdapter
from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.docker_toolchain import (
    CERTIFIED_TOOLCHAIN_BUNDLE_ID,
    PYTHON_IMAGE,
)
from governance_eval.hashing import sha256_json
from governance_eval.supportability_config_v2 import TYPED_CAPABILITIES


def strict_receipt(role: str = "BASELINE") -> CheckoutReceipt:
    base_sha = "a" * 40
    head_sha = "b" * 40
    base_tree = "c" * 40
    head_tree = "d" * 40
    evaluator_sha = "e" * 40
    evaluator_tree = "f" * 40
    artifact_name = f"{role.lower()}-supportability-gate-evidence"
    bodies = _resource_bodies(
        base_sha,
        head_sha,
        base_tree,
        head_tree,
        evaluator_sha,
        evaluator_tree,
    )
    resources = {
        name: _resource(url, bodies[name])
        for name, url in _resource_urls(base_sha, head_sha, evaluator_sha).items()
    }
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "receipt_kind": "checkout_receipt.v1",
        "receipt_id": "",
        "evaluation_role": role,
        "repository": {
            "id": 101,
            "full_name": "example/target",
            "default_branch": "main",
            "api_url": "https://api.github.com/repos/example/target",
            "html_url": "https://github.com/example/target",
        },
        "pull_request": {
            "number": 84,
            "api_url": "https://api.github.com/repos/example/target/pulls/84",
            "html_url": "https://github.com/example/target/pull/84",
            "base": _pull_ref(101, "example/target", "main", base_sha, base_tree),
            "head": _pull_ref(101, "example/target", "feature", head_sha, head_tree),
        },
        "evaluation_target": {
            "commit_sha": head_sha,
            "tree_sha": head_tree,
            "diff_base_commit_sha": base_sha,
            "diff_base_tree_sha": base_tree,
        },
        "policy": {
            "source": "BASE" if role == "BASELINE" else "HEAD",
            "commit_sha": base_sha if role == "BASELINE" else head_sha,
            "tree_sha": base_tree if role == "BASELINE" else head_tree,
            "config": _policy_file(".github/governance/supportability.yml", "1", "2"),
            "standard": _policy_file(
                "docs/reference/supportability-standard.md", "3", "4"
            ),
            "execution_profile": {
                "mode": "typed_v2",
                "source_schema_version": "2.0",
                "effective_schema_version": "2.0",
                "profile_id": sha256_json(TYPED_CAPABILITIES),
                "capabilities": deepcopy(TYPED_CAPABILITIES),
            },
        },
        "evaluator": {
            "repository_id": 202,
            "repository_full_name": "markheck-solutions/governance",
            "commit_sha": evaluator_sha,
            "tree_sha": evaluator_tree,
        },
        "workflows": {
            "caller": _workflow(
                101,
                "example/target",
                ".github/workflows/supportability-enforcement.yml",
                "example/target/.github/workflows/supportability-enforcement.yml@refs/heads/main",
                base_sha,
                base_tree,
                "5",
                "6",
            ),
            "evaluator": _workflow(
                202,
                "markheck-solutions/governance",
                ".github/workflows/supportability-gate.yml",
                f"markheck-solutions/governance/.github/workflows/supportability-gate.yml@{evaluator_sha}",
                evaluator_sha,
                evaluator_tree,
                "7",
                "8",
            ),
            "run": {
                "id": 999,
                "attempt": 1,
                "api_url": "https://api.github.com/repos/example/target/actions/runs/999",
                "event": "pull_request_target",
                "action": "synchronize",
                "artifact_name": artifact_name,
                "observed_at": "2026-07-19T17:00:00Z",
            },
        },
        "github_resources": resources,
        "runtime": {
            "git": _executable("C:/trusted/git.exe", "9", "git version 2.54.0"),
            "python": {
                "path": "C:/trusted/python.exe",
                "sha256": "a" * 64,
                "implementation": "CPython",
                "version": "3.12.13",
                "cache_tag": "cpython-312",
            },
            "docker": {
                "path": "C:/trusted/docker.exe",
                "sha256": "b" * 64,
                "host": "npipe:////./pipe/docker_engine",
                "client_version": "29.5.2",
                "server_version": "29.5.2",
                "server_api_version": "1.54",
                "os": "linux",
                "architecture": "amd64",
            },
            "container_image": {
                "reference": PYTHON_IMAGE,
                "image_id": "sha256:" + "c" * 64,
            },
            "toolchain": {
                "bundle_id": CERTIFIED_TOOLCHAIN_BUNDLE_ID,
                "manifest_sha256": "d" * 64,
                "lock_sha256": "e" * 64,
            },
        },
    }
    payload["receipt_id"] = sha256_json(
        {key: value for key, value in payload.items() if key != "receipt_id"}
    )
    return CheckoutReceipt(**payload)


def scope_manifest(
    receipt: CheckoutReceipt, adapter: CapabilityAdapter
) -> dict[str, Any]:
    source = _scope_source(receipt, adapter.scope_rule_id)
    entries: list[dict[str, Any]] = []
    if adapter.scope_rule_id != "verified-wheel.v1":
        path = _scope_path(adapter.scope_rule_id)
        entries.append(
            {"path": path, "mode": "100644", "blob_sha": "1" * 40, "size_bytes": 12}
        )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "manifest_id": "",
        "rule_id": adapter.scope_rule_id,
        "source": source,
        "entries": entries,
    }
    payload["manifest_id"] = sha256_json(
        {key: value for key, value in payload.items() if key != "manifest_id"}
    )
    return payload


def toolchain_binding(receipt: CheckoutReceipt) -> dict[str, str]:
    return {
        "bundle_id": CERTIFIED_TOOLCHAIN_BUNDLE_ID,
        "manifest_sha256": receipt.runtime["toolchain"]["manifest_sha256"],
        "lock_sha256": receipt.runtime["toolchain"]["lock_sha256"],
        "image": receipt.runtime["container_image"]["reference"],
    }


def _resource(url: str, body: object) -> dict[str, Any]:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {
        "url": url,
        "status": 200,
        "etag": '"fixture"',
        "observed_at": "2026-07-19T17:00:00Z",
        "body_sha256": sha256(raw).hexdigest(),
        "body_base64": base64.b64encode(raw).decode("ascii"),
    }


def _resource_urls(base: str, head: str, evaluator: str) -> dict[str, str]:
    target = "https://api.github.com/repos/example/target"
    governance = "https://api.github.com/repos/markheck-solutions/governance"
    return {
        "target_repository": target,
        "evaluator_repository": governance,
        "pull_request": f"{target}/pulls/84",
        "base_commit": f"{target}/commits/{base}",
        "head_commit": f"{target}/commits/{head}",
        "evaluator_commit": f"{governance}/commits/{evaluator}",
        "workflow_run": f"{target}/actions/runs/999",
        "effective_base_rules": f"{target}/rules/branches/main",
    }


def _resource_bodies(
    base: str,
    head: str,
    base_tree: str,
    head_tree: str,
    evaluator: str,
    evaluator_tree: str,
) -> dict[str, object]:
    return {
        "target_repository": _repository(101, "example/target"),
        "evaluator_repository": _repository(202, "markheck-solutions/governance"),
        "pull_request": {
            "number": 84,
            "url": "https://api.github.com/repos/example/target/pulls/84",
            "html_url": "https://github.com/example/target/pull/84",
            "base": {
                "ref": "main",
                "sha": base,
                "repo": {"id": 101, "full_name": "example/target"},
            },
            "head": {
                "ref": "feature",
                "sha": head,
                "repo": {"id": 101, "full_name": "example/target"},
            },
        },
        "base_commit": _commit("example/target", base, base_tree),
        "head_commit": _commit("example/target", head, head_tree),
        "evaluator_commit": _commit(
            "markheck-solutions/governance", evaluator, evaluator_tree
        ),
        "workflow_run": {
            "id": 999,
            "run_attempt": 1,
            "event": "pull_request_target",
            "path": ".github/workflows/supportability-enforcement.yml",
            "head_sha": base,
            "repository": {"id": 101, "full_name": "example/target"},
            "referenced_workflows": [
                {
                    "path": f"markheck-solutions/governance/.github/workflows/supportability-gate.yml@{evaluator}",
                    "sha": evaluator,
                }
            ],
        },
        "effective_base_rules": [],
    }


def _repository(identifier: int, name: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "full_name": name,
        "default_branch": "main",
        "url": f"https://api.github.com/repos/{name}",
        "html_url": f"https://github.com/{name}",
    }


def _commit(repository: str, commit: str, tree: str) -> dict[str, Any]:
    return {
        "url": f"https://api.github.com/repos/{repository}/commits/{commit}",
        "sha": commit,
        "commit": {"tree": {"sha": tree}},
    }


def _pull_ref(
    identifier: int, name: str, ref: str, commit: str, tree: str
) -> dict[str, Any]:
    return {
        "repository_id": identifier,
        "repository_full_name": name,
        "ref": ref,
        "commit_sha": commit,
        "tree_sha": tree,
    }


def _policy_file(path: str, blob: str, content: str) -> dict[str, str]:
    return {"path": path, "git_blob_sha": blob * 40, "content_sha256": content * 64}


def _workflow(
    identifier: int,
    name: str,
    path: str,
    workflow_ref: str,
    commit: str,
    tree: str,
    blob: str,
    content: str,
) -> dict[str, Any]:
    return {
        "repository_id": identifier,
        "repository_full_name": name,
        "path": path,
        "workflow_ref": workflow_ref,
        "commit_sha": commit,
        "tree_sha": tree,
        "git_blob_sha": blob * 40,
        "content_sha256": content * 64,
    }


def _executable(path: str, digest: str, version: str) -> dict[str, str]:
    return {"path": path, "sha256": digest * 64, "version": version}


def _scope_source(receipt: CheckoutReceipt, rule_id: str) -> dict[str, Any]:
    base = receipt.pull_request["base"]
    head = receipt.pull_request["head"]
    if rule_id == "certified-evaluator-tree.v1":
        return _source(
            "EVALUATOR",
            receipt.evaluator["repository_id"],
            receipt.evaluator["repository_full_name"],
            receipt.evaluator["commit_sha"],
            receipt.evaluator["tree_sha"],
        )
    kinds = {
        "pr-base-protected-tests.v1": "TARGET_HEAD_WITH_BASE_TESTS",
        "authenticated-diff.v1": "DIFF",
        "verified-wheel.v1": "INPUT_ARTIFACT",
    }
    return _source(
        kinds.get(rule_id, "TARGET_HEAD"),
        receipt.repository["id"],
        receipt.repository["full_name"],
        head["commit_sha"],
        head["tree_sha"],
        base["commit_sha"] if rule_id in kinds else None,
        base["tree_sha"] if rule_id in kinds else None,
    )


def _source(
    kind: str,
    identifier: int,
    name: str,
    commit: str,
    tree: str,
    base_commit: str | None = None,
    base_tree: str | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "repository_id": identifier,
        "repository_full_name": name,
        "commit_sha": commit,
        "tree_sha": tree,
        "base_commit_sha": base_commit,
        "base_tree_sha": base_tree,
    }


def _scope_path(rule_id: str) -> str:
    if rule_id == "pr-base-protected-tests.v1":
        return "tests/test_example.py"
    if rule_id == "certified-evaluator-tree.v1":
        return "governance_eval/benchmark.py"
    return "governance_eval/example.py"


def cloned_receipt(receipt: CheckoutReceipt, **changes: object) -> CheckoutReceipt:
    payload = deepcopy(receipt.to_json())
    payload.update(changes)
    payload["receipt_id"] = sha256_json(
        {key: value for key, value in payload.items() if key != "receipt_id"}
    )
    return CheckoutReceipt(**payload)
