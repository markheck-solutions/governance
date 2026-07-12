from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from governance_eval.target_pack import load_target_pack


SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class TargetLock:
    target_id: str
    repository_url: str
    generated_at: str
    evidence_source: str
    revisions: dict[str, str]
    metadata: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "repository_url": self.repository_url,
            "generated_at": self.generated_at,
            "evidence_source": self.evidence_source,
            "revisions": dict(self.revisions),
            "metadata": dict(self.metadata),
        }


def write_target_lock(
    path: Path,
    pack_path: Path,
    *,
    evidence_source: str,
    metadata: dict[str, Any] | None = None,
    root: Path | None = None,
) -> TargetLock:
    pack = load_target_pack(pack_path, root=root)
    lock = TargetLock(
        target_id=pack["id"],
        repository_url=pack["repository_url"],
        generated_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        evidence_source=evidence_source,
        revisions={key: value for key, value in pack["immutable_revisions"].items() if value},
        metadata=metadata or {},
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_toml(lock), encoding="utf-8")
    return lock


def read_target_lock(path: Path) -> TargetLock:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return TargetLock(
        target_id=data["target_id"],
        repository_url=data["repository_url"],
        generated_at=data["generated_at"],
        evidence_source=data["evidence_source"],
        revisions=dict(data["revisions"]),
        metadata=dict(data.get("metadata", {})),
    )


def validate_target_lock(path: Path, pack_path: Path, *, root: Path | None = None) -> list[str]:
    if not path.exists():
        return [f"missing lock file: {path}"]
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        lock = read_target_lock(path)
        pack = load_target_pack(pack_path, root=root)
    except (OSError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as exc:
        return [f"malformed lock file: {exc}"]
    problems: list[str] = []
    if raw.get("schema_version") != 1:
        problems.append("schema_version must be 1")
    if lock.target_id != pack["id"]:
        problems.append("target_id does not match target pack")
    if _normalize_url(lock.repository_url) != _normalize_url(pack["repository_url"]):
        problems.append("repository_url does not match target pack")
    if not lock.evidence_source.strip():
        problems.append("evidence_source must be non-empty")
    expected = {key: value for key, value in pack["immutable_revisions"].items() if value}
    if lock.revisions != expected:
        problems.append("revisions do not match target pack immutable revisions")
    for name, value in lock.revisions.items():
        if name.endswith("_sha") and not SHA_RE.fullmatch(value):
            problems.append(f"revisions.{name} is not a full immutable SHA")
    return problems


def _toml(lock: TargetLock) -> str:
    lines = [
        "schema_version = 1",
        f"target_id = {json.dumps(lock.target_id)}",
        f"repository_url = {json.dumps(lock.repository_url)}",
        f"generated_at = {json.dumps(lock.generated_at)}",
        f"evidence_source = {json.dumps(lock.evidence_source)}",
        "",
        "[revisions]",
    ]
    lines.extend(f"{key} = {json.dumps(value)}" for key, value in sorted(lock.revisions.items()))
    if lock.metadata:
        lines.extend(["", "[metadata]"])
        lines.extend(f"{key} = {_toml_scalar(value)}" for key, value in sorted(lock.metadata.items()))
    return "\n".join([*lines, ""])


def _toml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    raise TypeError(f"unsupported lock metadata type: {type(value).__name__}")


def _normalize_url(value: str) -> str:
    normalized = value.strip().rstrip("/").lower()
    return normalized[:-4] if normalized.endswith(".git") else normalized
