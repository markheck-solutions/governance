from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def load_target_pack(
    path: Path, root: Path | None = None, require_governance_owned: bool = False
) -> dict[str, Any]:
    governance_root = repo_root(root or Path(__file__).resolve())
    resolved = resolve_pack_path(
        path, governance_root, require_governance_owned=require_governance_owned
    )
    data = json.loads(resolved.read_text(encoding="utf-8"))
    validate_named("target_pack", data, governance_root)
    _validate_repository_identity(data)
    _validate_detector_policies(data)
    _validate_revision_modes(data)
    _validate_behavior_cases(data, governance_root)
    return data


def resolve_pack_path(
    path: Path, root: Path, require_governance_owned: bool = False
) -> Path:
    if not path.is_absolute():
        if any(part == ".." for part in path.parts):
            raise SchemaValidationError(
                f"target pack path traversal is not allowed: {path}"
            )
        resolved = (root / path).resolve(strict=True)
    else:
        resolved = path.resolve(strict=True)
    if require_governance_owned or not path.is_absolute():
        try:
            resolved.relative_to(root.resolve(strict=True))
        except ValueError as exc:
            raise SchemaValidationError(
                f"target pack must stay inside governance repository: {path}"
            ) from exc
    if resolved.is_symlink():
        raise SchemaValidationError(f"target pack symlink is not allowed: {path}")
    return resolved


def _validate_repository_identity(pack: dict[str, Any]) -> None:
    identity = pack.get("repository_identity") or {}
    canonical = identity.get("canonical_url") or pack.get("repository_url")
    repository_url = pack.get("repository_url")
    if not isinstance(canonical, str) or not isinstance(repository_url, str):
        raise SchemaValidationError(
            f"{pack.get('id', '<unknown>')}: repository identity URLs must be strings"
        )
    if _normalize_url(canonical) != _normalize_url(repository_url):
        raise SchemaValidationError(
            f"{pack['id']}: repository_identity.canonical_url does not match repository_url"
        )


def _validate_detector_policies(pack: dict[str, Any]) -> None:
    detectors = set(pack.get("structural_detectors", []))
    policies = pack.get("detector_policies", {})
    missing = sorted(detectors - set(policies))
    if missing:
        raise SchemaValidationError(
            f"{pack['id']}: detector_policies missing {missing}"
        )
    for detector, policy in policies.items():
        for field in ("required", "blocking", "fail_on_unknown"):
            if field not in policy:
                raise SchemaValidationError(
                    f"{pack['id']}: detector_policies.{detector}.{field} required"
                )


def _validate_revision_modes(pack: dict[str, Any]) -> None:
    supported = set(pack.get("revision_modes", []))
    required = {"HISTORICAL_FIXED", "SAFE_FIXED", "CANDIDATE_DYNAMIC"}
    if not required.issubset(supported):
        raise SchemaValidationError(
            f"{pack['id']}: revision_modes must include {sorted(required)}"
        )
    revisions = pack["immutable_revisions"]
    for field in ("base_sha", "head_sha"):
        if not SHA_RE.fullmatch(revisions[field]):
            raise SchemaValidationError(
                f"{pack['id']}: immutable_revisions.{field} must be a full SHA"
            )
    for field in ("merge_sha", "safe_base_sha", "safe_head_sha"):
        value = revisions.get(field)
        if value and not SHA_RE.fullmatch(value):
            raise SchemaValidationError(
                f"{pack['id']}: immutable_revisions.{field} must be a full SHA"
            )


def _validate_behavior_cases(pack: dict[str, Any], root: Path) -> None:
    for case in pack["behavior_cases"]:
        reproducer = root / case["reproducer"]
        if not reproducer.exists():
            raise SchemaValidationError(
                f"{case['id']}: reproducer missing: {case['reproducer']}"
            )
        if not case.get("source_symbols"):
            raise SchemaValidationError(f"{case['id']}: source_symbols required")
        if "expected_source_hashes" not in case:
            raise SchemaValidationError(
                f"{case['id']}: expected_source_hashes required"
            )
        policy = _case_policies(case)
        if "PINNED_EXPECTED" in policy.values() and "expected_base_result" not in case:
            raise SchemaValidationError(
                f"{case['id']}: expected_base_result required for PINNED_EXPECTED"
            )
        if case.get("pull_request") is not None and not case["expected_source_hashes"]:
            raise SchemaValidationError(
                f"{case['id']}: pull-request cases require expected_source_hashes"
            )
        if case.get("pull_request") is not None:
            _validate_historical_hash_expectations(pack, case)


def _case_policies(case: dict[str, Any]) -> dict[str, str]:
    default = case.get("behavior_comparison_policy", "PINNED_EXPECTED")
    if isinstance(case.get("comparison_policies"), dict):
        explicit = dict(case["comparison_policies"])
        return {
            mode: explicit.get(mode, default)
            for mode in ("HISTORICAL_FIXED", "SAFE_FIXED", "CANDIDATE_DYNAMIC")
        }
    return {
        mode: default
        for mode in ("HISTORICAL_FIXED", "SAFE_FIXED", "CANDIDATE_DYNAMIC")
    }


def _validate_historical_hash_expectations(
    pack: dict[str, Any], case: dict[str, Any]
) -> None:
    expected_by_sha = case["expected_source_hashes"]
    revisions = pack["immutable_revisions"]
    required_shas = [revisions["base_sha"], revisions["head_sha"]]
    source_files = set(case["source_files"])
    source_symbols = {
        f"{item['path']}::{item['symbol']}" for item in case["source_symbols"]
    }
    for sha in required_shas:
        expected = expected_by_sha.get(sha)
        if not expected:
            raise SchemaValidationError(
                f"{case['id']}: expected_source_hashes missing {sha}"
            )
        expected_files = expected.get("files", {})
        expected_symbols = expected.get("symbols", {})
        missing_files = sorted(source_files - set(expected_files))
        missing_symbols = sorted(source_symbols - set(expected_symbols))
        if missing_files:
            raise SchemaValidationError(
                f"{case['id']}: expected_source_hashes.{sha}.files missing {missing_files}"
            )
        if missing_symbols:
            raise SchemaValidationError(
                f"{case['id']}: expected_source_hashes.{sha}.symbols missing {missing_symbols}"
            )
        for path, item in expected_files.items():
            if not item.get("git_blob_sha") or not item.get("file_sha256"):
                raise SchemaValidationError(
                    f"{case['id']}: expected file hash incomplete for {sha}:{path}"
                )
        for symbol, item in expected_symbols.items():
            if (
                not item.get("symbol_sha256")
                or item.get("line_start") is None
                or item.get("line_end") is None
            ):
                raise SchemaValidationError(
                    f"{case['id']}: expected symbol hash incomplete for {sha}:{symbol}"
                )


def validate_target_request(
    pack_path: Path,
    repository_url: str,
    base_sha: str,
    head_sha: str,
    merge_sha: str | None,
    revision_mode: str,
    root: Path | None = None,
) -> dict[str, Any]:
    governance_root = repo_root(root or Path(__file__).resolve())
    pack = load_target_pack(
        pack_path, root=governance_root, require_governance_owned=True
    )
    _validate_requested_repository(pack, repository_url, revision_mode)
    _validate_requested_revisions(pack, base_sha, head_sha, merge_sha, revision_mode)
    return pack


def _validate_requested_repository(
    pack: dict[str, Any], repository_url: str, revision_mode: str
) -> None:
    if _normalize_url(repository_url) != _normalize_url(pack["repository_url"]):
        raise ValueError(
            f"target repository mismatch for pack {pack['id']}: {repository_url}"
        )


def _validate_requested_revisions(
    pack: dict[str, Any],
    base_sha: str,
    head_sha: str,
    merge_sha: str | None,
    revision_mode: str,
) -> None:
    if revision_mode not in set(pack.get("revision_modes", [])):
        raise ValueError(
            f"revision mode is not supported by pack {pack['id']}: {revision_mode}"
        )
    _validate_target_sha("base", base_sha)
    _validate_target_sha("head", head_sha)
    if merge_sha:
        _validate_target_sha("merge", merge_sha)
    revisions = pack["immutable_revisions"]
    if revision_mode == "HISTORICAL_FIXED":
        if base_sha != revisions["base_sha"] or head_sha != revisions["head_sha"]:
            raise ValueError(
                f"HISTORICAL_FIXED requires pinned target revisions for pack {pack['id']}"
            )
        expected_merge = revisions.get("merge_sha")
        if expected_merge and merge_sha != expected_merge:
            raise ValueError(
                f"HISTORICAL_FIXED requires pinned merge SHA for pack {pack['id']}: {expected_merge}"
            )
        return
    if revision_mode == "SAFE_FIXED":
        if (
            base_sha != revisions.get("safe_base_sha")
            or head_sha != revisions.get("safe_head_sha")
            or merge_sha
        ):
            raise ValueError(
                f"SAFE_FIXED requires pinned safe base/head and no merge SHA for pack {pack['id']}"
            )
        return
    if revision_mode == "CANDIDATE_DYNAMIC":
        if merge_sha:
            raise ValueError(
                "CANDIDATE_DYNAMIC must evaluate base/head directly without a merge SHA"
            )
        return
    raise ValueError(f"unknown revision mode: {revision_mode}")


def _validate_target_sha(label: str, value: str) -> None:
    if not SHA_RE.fullmatch(value):
        raise ValueError(f"invalid target {label} SHA: {value}")


def infer_revision_mode(
    pack: dict[str, Any], base_sha: str, head_sha: str, merge_sha: str | None
) -> str:
    revisions = pack["immutable_revisions"]
    if base_sha == revisions.get("base_sha") and head_sha == revisions.get("head_sha"):
        return "HISTORICAL_FIXED"
    if (
        base_sha == revisions.get("safe_base_sha")
        and head_sha == revisions.get("safe_head_sha")
        and not merge_sha
    ):
        return "SAFE_FIXED"
    return "CANDIDATE_DYNAMIC"


def target_pack_hash(path: Path) -> str:
    return sha256_file(path.resolve())


def schema_hashes(root: Path) -> dict[str, str]:
    schema_root = root / "schemas" / "v1"
    return {path.name: sha256_file(path) for path in sorted(schema_root.glob("*.json"))}


def dependency_lock_hash(root: Path) -> str:
    candidates = ["uv.lock", "poetry.lock", "requirements.txt", "pyproject.toml"]
    present = [root / name for name in candidates if (root / name).exists()]
    return sha256_json({path.name: sha256_file(path) for path in present})


def _normalize_url(url: str) -> str:
    text = url.strip().rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]
    return text.lower()
