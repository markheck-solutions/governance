from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_file
from governance_eval.lock import read_target_lock, validate_target_lock
from governance_eval.paths import repo_root
from governance_eval.target_pack import load_target_pack


DEFAULT_REGISTRY_PATH = Path("target_packs/registry.json")


def load_target_registry(path: Path | None = None, root: Path | None = None) -> dict[str, Any]:
    resolved_root = repo_root(root)
    registry_path = resolved_root / (path or DEFAULT_REGISTRY_PATH)
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    errors = validate_target_registry(data, resolved_root)
    if errors:
        raise ValueError("target registry invalid: " + "; ".join(errors))
    return data


def validate_target_registry(registry: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "1.0":
        errors.append("schema_version must be 1.0")
    packs = registry.get("packs")
    if not isinstance(packs, list) or not packs:
        return [*errors, "packs must be a non-empty list"]
    ids: set[str] = set()
    for index, entry in enumerate(packs):
        errors.extend(_registry_entry_errors(entry, index, ids, root))
    return errors


def _registry_entry_errors(entry: Any, index: int, ids: set[str], root: Path) -> list[str]:
    if not isinstance(entry, dict):
        return [f"packs[{index}] must be an object"]
    try:
        pack = load_target_pack(Path(entry["path"]), root=root, require_governance_owned=True)
    except (KeyError, OSError, ValueError) as exc:
        return [f"packs[{index}] invalid: {exc}"]
    errors: list[str] = []
    if pack["id"] in ids:
        errors.append(f"duplicate target pack id: {pack['id']}")
    ids.add(pack["id"])
    if entry.get("lock_path"):
        errors.extend(
            f"packs[{index}]: {error}"
            for error in validate_target_lock(root / entry["lock_path"], root / entry["path"], root=root)
        )
    if not isinstance(entry.get("required_real_evaluation"), bool):
        errors.append(f"packs[{index}].required_real_evaluation must be boolean")
    runs = entry.get("verification_runs")
    if not isinstance(runs, list):
        errors.append(f"packs[{index}].verification_runs must be a list")
    elif entry.get("required_real_evaluation") and not runs:
        errors.append(f"packs[{index}] requires at least one real verification run")
    return errors


def registered_target_locks(registry: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    locks: list[dict[str, Any]] = []
    for entry in registry["packs"]:
        if entry.get("lock_path"):
            locks.append(read_target_lock(root / entry["lock_path"]).to_json())
    return locks


def registry_hash(path: Path | None = None, root: Path | None = None) -> str:
    resolved_root = repo_root(root)
    return sha256_file(resolved_root / (path or DEFAULT_REGISTRY_PATH))
