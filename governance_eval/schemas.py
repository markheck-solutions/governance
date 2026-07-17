from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from governance_eval.paths import repo_root
from governance_eval.schema_validator import validate

SCHEMA_FILES = {
    "evaluation_case": "evaluation_case.schema.json",
    "detector_evidence": "detector_evidence.schema.json",
    "review_finding": "review_finding.schema.json",
    "benchmark_run_result": "benchmark_run_result.schema.json",
    "final_decision": "final_decision.schema.json",
    "target_pack": "target_pack.schema.json",
    "target_evaluation_result": "target_evaluation_result.schema.json",
    "review_quorum": "review_quorum.schema.json",
    "supportability_config": "supportability_config.schema.json",
    "supportability_gate_result": "supportability_gate_result.schema.json",
    "architecture_gate_result": "architecture_gate_result.schema.json",
    "copilot_review_gate_result": "copilot_review_gate_result.schema.json",
    "judge_evidence_bundle": "judge_evidence_bundle.schema.json",
    "judge_evidence_pair": "judge_evidence_pair.schema.json",
    "delivery_receipt": "delivery_receipt.schema.json",
    "bootstrap_audit_receipt": "bootstrap_audit_receipt.schema.json",
    "codex_connector_snapshot": "codex_connector_snapshot.schema.json",
    "codex_connector_evidence_result": "codex_connector_evidence_result.schema.json",
    "codex_connector_snapshot_v2": "codex_connector_snapshot.schema.json",
    "codex_connector_evidence_result_v2": "codex_connector_evidence_result.schema.json",
    "codex_connector_evidence_result_v3": "codex_connector_evidence_result.schema.json",
    "codex_connector_evidence_result_v4": "codex_connector_evidence_result.schema.json",
    "execution_plan": "execution_plan.schema.json",
    "execution_result": "execution_result.schema.json",
    "governance_toolchain_receipt": "governance_toolchain_receipt.schema.json",
    "governance_toolchain_artifact_binding": "governance_toolchain_artifact_binding.schema.json",
}

SCHEMA_VERSIONS = {
    "codex_connector_snapshot_v2": "v2",
    "codex_connector_evidence_result_v2": "v2",
    "codex_connector_evidence_result_v3": "v3",
    "codex_connector_evidence_result_v4": "v4",
}


def load_schema(name: str, root: Path | None = None) -> dict[str, Any]:
    if name not in SCHEMA_FILES:
        raise KeyError(f"unknown schema {name!r}")
    repository_root = repo_root(root)
    version = SCHEMA_VERSIONS.get(name, "v1")
    path = repository_root / "schemas" / version / SCHEMA_FILES[name]
    return json.loads(path.read_text(encoding="utf-8"))


def validate_named(name: str, instance: Any, root: Path | None = None) -> None:
    validate(instance, load_schema(name, root))
