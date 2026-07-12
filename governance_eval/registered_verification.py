from __future__ import annotations

from pathlib import Path
from typing import Any

from governance_eval.target_eval import evaluate_target
from governance_eval.target_pack import load_target_pack
from governance_eval.target_registry import load_target_registry


def run_registered_target_verification(root: Path, artifacts_dir: Path) -> dict[str, Any]:
    registry = load_target_registry(root=root)
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    for entry in registry["packs"]:
        if not entry["required_real_evaluation"]:
            continue
        pack_path = root / entry["path"]
        pack = load_target_pack(pack_path, root=root, require_governance_owned=True)
        for run in entry["verification_runs"]:
            result, error = _run_registered_target(pack_path, pack, run, artifacts_dir)
            results.append(result)
            if error:
                errors.append(error)
    if not results:
        errors.append("no registered required real-target evaluations ran")
    return {"status": "PASS" if not errors else "FAIL", "results": results, "errors": errors}


def _run_registered_target(
    pack_path: Path,
    pack: dict[str, Any],
    run: dict[str, Any],
    artifacts_dir: Path,
) -> tuple[dict[str, Any], str]:
    mode = run["revision_mode"]
    revisions = pack["immutable_revisions"]
    base_sha, head_sha, merge_sha = _revisions_for_mode(revisions, mode)
    try:
        result = evaluate_target(
            pack_path,
            base_sha,
            head_sha,
            artifacts_dir / pack["id"] / mode.lower(),
            merge_sha,
            pack["repository_url"],
            mode,
            None,
            True,
            "NOT_APPLICABLE",
            "NOT_APPLICABLE",
            "SHADOW",
            artifacts_dir / ".target-cache",
        )
    except Exception as exc:
        failed = {"target_pack_id": pack["id"], "revision_mode": mode, "error": str(exc)}
        return failed, f"{pack['id']} {mode}: real-target evaluation failed: {exc}"
    actual = result["real_target_shadow_decision"]
    expected = run["expected_decision"]
    summary = {
        "target_pack_id": pack["id"],
        "revision_mode": mode,
        "expected_decision": expected,
        "actual_decision": actual,
        "artifact_content_hash": result["artifact_content_hash"],
        "deterministic_evidence_hash": result["deterministic_evidence_hash"],
        "target_base_sha": result["target_base_sha"],
        "target_head_sha": result["target_head_sha"],
    }
    error = "" if actual == expected else f"{pack['id']} {mode}: expected {expected}, got {actual}"
    return summary, error


def _revisions_for_mode(revisions: dict[str, str], mode: str) -> tuple[str, str, str | None]:
    if mode == "HISTORICAL_FIXED":
        return revisions["base_sha"], revisions["head_sha"], revisions.get("merge_sha")
    if mode == "SAFE_FIXED":
        return revisions["safe_base_sha"], revisions["safe_head_sha"], None
    raise ValueError(f"registry verification mode must be immutable: {mode}")
