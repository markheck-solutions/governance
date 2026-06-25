from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from governance_eval.paths import case_dir, repo_root
from governance_eval.schemas import validate_named


def load_case(path: Path, root: Path | None = None) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    validate_named("evaluation_case", data, root)
    return data


def load_cases(root: Path | None = None) -> list[dict[str, Any]]:
    resolved_root = repo_root(root)
    paths = sorted(case_dir(resolved_root).glob("*.json"))
    cases = [load_case(path, resolved_root) for path in paths]
    ids = [case["id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("case ids must be unique")
    return cases
