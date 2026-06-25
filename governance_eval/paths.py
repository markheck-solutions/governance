from __future__ import annotations

from pathlib import Path


def repo_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "TASK.md").exists() and (candidate / "AGENTS.md").exists():
            return candidate
    return current


def case_dir(root: Path) -> Path:
    return root / "cases" / "v1"


def schema_dir(root: Path) -> Path:
    return root / "schemas" / "v1"
