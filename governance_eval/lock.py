from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SpaghettiLock:
    repository_url: str
    pull_request: int
    base_sha: str
    head_sha: str
    merge_commit_sha: str
    approved_oracle_sha: str
    observed_main_sha: str
    generated_at: str
    evidence_source: str

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


PINNED_SPAGHETTI_LOCK = SpaghettiLock(
    repository_url="https://github.com/markheck-solutions/Spaghetti.git",
    pull_request=141,
    base_sha="60da7dbe2fad70836f15ed7ec4d7969c6ad436f1",
    head_sha="43f96f395b8a0acb4d323943b6fc68727bf21121",
    merge_commit_sha="dce7cd0397341c87a2c16d5681db586da1c85c75",
    approved_oracle_sha="60da7dbe2fad70836f15ed7ec4d7969c6ad436f1",
    observed_main_sha="9b05ec90140ee65f4c82e8f63cf0c6d50c3a380d",
    generated_at="2026-06-25T19:45:00Z",
    evidence_source="GitHub REST pull #141 and git ls-remote, resolved 2026-06-25",
)


def write_spaghetti_lock(path: Path) -> SpaghettiLock:
    lock = PINNED_SPAGHETTI_LOCK
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_toml(lock), encoding="utf-8")
    return lock


def read_spaghetti_lock(path: Path) -> SpaghettiLock:
    import tomllib

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    pr = data["pull_request_141"]
    return SpaghettiLock(
        repository_url=data["repository_url"],
        pull_request=pr["number"],
        base_sha=pr["base_sha"],
        head_sha=pr["head_sha"],
        merge_commit_sha=pr["merge_commit_sha"],
        approved_oracle_sha=pr["approved_oracle_sha"],
        observed_main_sha=pr["observed_main_sha"],
        generated_at=data["generated_at"],
        evidence_source=data["evidence_source"],
    )


def validate_spaghetti_lock(path: Path) -> list[str]:
    import tomllib

    if not path.exists():
        return [f"missing lock file: {path}"]
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        lock = read_spaghetti_lock(path)
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        return [f"malformed lock file: {exc}"]
    return _lock_problems(raw, lock)


def _lock_problems(raw: dict[str, Any], lock: SpaghettiLock) -> list[str]:
    problems: list[str] = []
    if raw.get("schema_version") != 1:
        problems.append("schema_version must be 1")
    if raw.get("repository_url") != PINNED_SPAGHETTI_LOCK.repository_url:
        problems.append("repository_url does not match targets/spaghetti.toml")
    pr = raw.get("pull_request_141", {})
    if pr.get("historical_case_id") != "SPAGHETTI-PR-141-PARTIAL-METADATA-INTERLEAVING":
        problems.append("historical_case_id mismatch")
    for name, value in lock.to_json().items():
        if name.endswith("_sha") and not _is_full_sha(value):
            problems.append(f"{name} is not a full immutable SHA: {value!r}")
    expected = PINNED_SPAGHETTI_LOCK.to_json()
    for name in (
        "base_sha",
        "head_sha",
        "merge_commit_sha",
        "approved_oracle_sha",
        "observed_main_sha",
    ):
        if lock.to_json()[name] != expected[name]:
            problems.append(f"{name} does not match resolved PR #141 evidence")
    if lock.pull_request != 141:
        problems.append(f"unexpected pull request: {lock.pull_request}")
    if lock.approved_oracle_sha != lock.base_sha:
        problems.append(
            "approved oracle SHA must equal PR base SHA for Phase 1 historical oracle"
        )
    return problems


def _is_full_sha(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdef" for char in value)


def _toml(lock: SpaghettiLock) -> str:
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return "\n".join(
        [
            "schema_version = 1",
            f"generated_at = {now!r}",
            f"evidence_source = {lock.evidence_source!r}",
            f"repository_url = {lock.repository_url!r}",
            "",
            "[pull_request_141]",
            f"number = {lock.pull_request}",
            'html_url = "https://github.com/markheck-solutions/Spaghetti/pull/141"',
            f"base_sha = {lock.base_sha!r}",
            f"head_sha = {lock.head_sha!r}",
            f"merge_commit_sha = {lock.merge_commit_sha!r}",
            f"approved_oracle_sha = {lock.approved_oracle_sha!r}",
            f"observed_main_sha = {lock.observed_main_sha!r}",
            'historical_case_id = "SPAGHETTI-PR-141-PARTIAL-METADATA-INTERLEAVING"',
            'oracle_reason = "TASK.md and targets/spaghetti.toml define approved sequence; PR base SHA pins the pre-change oracle."',
            "",
        ]
    )
