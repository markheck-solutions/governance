from __future__ import annotations

import re


_SPECIAL_PATHS = frozenset(
    {
        ".github/governance/supportability.yml",
        ".github/workflows/supportability-enforcement.yml",
    }
)
_PROTECTED_FILES = frozenset({"pyproject.toml", "requirements-governance.lock"})
_PROTECTED_ROOTS = (
    "governance_eval/",
    "schemas/",
    ".github/actions/",
    ".github/workflows/",
)


def is_protected_judge_path(path: str) -> bool:
    if path in _SPECIAL_PATHS:
        return False
    return path in _PROTECTED_FILES or path.startswith(_PROTECTED_ROOTS)


def canonical_changed_files(paths: list[str]) -> list[str]:
    canonical: set[str] = set()
    for path in paths:
        if not _is_canonical_git_path(path):
            raise ValueError(
                f"changed-file path is not canonical Git-relative: {path!r}"
            )
        canonical.add(path)
    return sorted(canonical)


def _is_canonical_git_path(path: object) -> bool:
    if not isinstance(path, str) or not path:
        return False
    if path.startswith(("/", "./")) or re.match(r"^[A-Za-z]:", path):
        return False
    if any(ord(character) < 32 for character in path) or "\\" in path:
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))
