from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from governance_eval.paths import repo_root, schema_dir
from governance_eval.schema_validator import validate


SCHEMA_FILES = {
    "evaluation_case": "evaluation_case.schema.json",
    "detector_evidence": "detector_evidence.schema.json",
    "review_finding": "review_finding.schema.json",
    "benchmark_run_result": "benchmark_run_result.schema.json",
    "final_decision": "final_decision.schema.json",
    "target_pack": "target_pack.schema.json",
    "target_evaluation_result": "target_evaluation_result.schema.json",
}


def load_schema(name: str, root: Path | None = None) -> dict[str, Any]:
    if name not in SCHEMA_FILES:
        raise KeyError(f"unknown schema {name!r}")
    path = schema_dir(repo_root(root)) / SCHEMA_FILES[name]
    return json.loads(path.read_text(encoding="utf-8"))


def validate_named(name: str, instance: Any, root: Path | None = None) -> None:
    validate(instance, load_schema(name, root))
