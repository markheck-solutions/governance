from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named


def load_target_pack(path: Path, root: Path | None = None) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    validate_named("target_pack", data, repo_root(root or Path(__file__).resolve()))
    for case in data["behavior_cases"]:
        if not case.get("source_symbols"):
            raise SchemaValidationError(f"{case['id']}: source_symbols required")
        if "expected_source_hashes" not in case:
            raise SchemaValidationError(f"{case['id']}: expected_source_hashes required")
        if case.get("pull_request") is not None and not case["expected_source_hashes"]:
            raise SchemaValidationError(f"{case['id']}: pull-request cases require expected_source_hashes")
        if case.get("pull_request") is not None:
            _validate_historical_hash_expectations(data, case)
    return data


def _validate_historical_hash_expectations(pack: dict[str, Any], case: dict[str, Any]) -> None:
    expected_by_sha = case["expected_source_hashes"]
    revisions = pack["immutable_revisions"]
    required_shas = [revisions["base_sha"], revisions["head_sha"]]
    source_files = set(case["source_files"])
    source_symbols = {f"{item['path']}::{item['symbol']}" for item in case["source_symbols"]}
    for sha in required_shas:
        expected = expected_by_sha.get(sha)
        if not expected:
            raise SchemaValidationError(f"{case['id']}: expected_source_hashes missing {sha}")
        expected_files = expected.get("files", {})
        expected_symbols = expected.get("symbols", {})
        missing_files = sorted(source_files - set(expected_files))
        missing_symbols = sorted(source_symbols - set(expected_symbols))
        if missing_files:
            raise SchemaValidationError(f"{case['id']}: expected_source_hashes.{sha}.files missing {missing_files}")
        if missing_symbols:
            raise SchemaValidationError(f"{case['id']}: expected_source_hashes.{sha}.symbols missing {missing_symbols}")
        for path, item in expected_files.items():
            if not item.get("git_blob_sha") or not item.get("file_sha256"):
                raise SchemaValidationError(f"{case['id']}: expected file hash incomplete for {sha}:{path}")
        for symbol, item in expected_symbols.items():
            if not item.get("symbol_sha256") or item.get("line_start") is None or item.get("line_end") is None:
                raise SchemaValidationError(f"{case['id']}: expected symbol hash incomplete for {sha}:{symbol}")


def target_pack_hash(path: Path) -> str:
    return sha256_file(path)


def schema_hashes(root: Path) -> dict[str, str]:
    schema_root = root / "schemas" / "v1"
    return {path.name: sha256_file(path) for path in sorted(schema_root.glob("*.json"))}


def dependency_lock_hash(root: Path) -> str:
    candidates = ["uv.lock", "poetry.lock", "requirements.txt", "pyproject.toml"]
    present = [root / name for name in candidates if (root / name).exists()]
    return sha256_json({path.name: sha256_file(path) for path in present})
