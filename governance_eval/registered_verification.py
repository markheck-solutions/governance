from __future__ import annotations

import json
import subprocess
import tempfile
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
            result, error = _run_registered_target(root, pack_path, pack, run, artifacts_dir)
            results.append(result)
            if error:
                errors.append(error)
    if not results:
        errors.append("no registered required real-target evaluations ran")
    return {"status": "PASS" if not errors else "FAIL", "results": results, "errors": errors}


def _run_registered_target(
    root: Path,
    pack_path: Path,
    pack: dict[str, Any],
    run: dict[str, Any],
    artifacts_dir: Path,
) -> tuple[dict[str, Any], str]:
    mode = run["revision_mode"]
    if mode == "EXACT_PUBLISHED":
        return _run_exact_published(root, pack_path, pack, run, artifacts_dir)
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


def _run_exact_published(
    root: Path,
    pack_path: Path,
    pack: dict[str, Any],
    run: dict[str, Any],
    artifacts_dir: Path,
) -> tuple[dict[str, Any], str]:
    try:
        resolution = resolve_exact_published_head(root, pack["repository_url"])
        resolved_pack = _resolved_pack(root, pack_path, pack, artifacts_dir, resolution["local_head_sha"])
        result = evaluate_target(
            resolved_pack,
            resolution["local_head_sha"],
            resolution["local_head_sha"],
            artifacts_dir / pack["id"] / "exact_published",
            None,
            pack["repository_url"],
            "SAFE_FIXED",
            None,
            True,
            "NOT_APPLICABLE",
            "NOT_APPLICABLE",
            "SHADOW",
            artifacts_dir / ".target-cache",
        )
    except Exception as exc:
        failed = {"target_pack_id": pack["id"], "revision_mode": "EXACT_PUBLISHED", "error": str(exc)}
        return failed, f"{pack['id']} EXACT_PUBLISHED: real-target evaluation failed: {exc}"
    actual = result["real_target_shadow_decision"]
    expected = run["expected_decision"]
    summary = {
        "target_pack_id": pack["id"],
        "revision_mode": "EXACT_PUBLISHED",
        "revision_source": "EVALUATOR_HEAD",
        "expected_decision": expected,
        "actual_decision": actual,
        "artifact_content_hash": result["artifact_content_hash"],
        "deterministic_evidence_hash": result["deterministic_evidence_hash"],
        "target_base_sha": result["target_base_sha"],
        "target_head_sha": result["target_head_sha"],
        "resolution": resolution,
    }
    error = "" if actual == expected else f"{pack['id']} EXACT_PUBLISHED: expected {expected}, got {actual}"
    return summary, error


def resolve_exact_published_head(root: Path, repository_url: str) -> dict[str, Any]:
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise RuntimeError("exact published self-verification requires a clean worktree")
    local_head = _git(root, "rev-parse", "HEAD")
    local_tree = _git(root, "rev-parse", "HEAD^{tree}")
    origin = _git(root, "remote", "get-url", "origin")
    if _normalize_url(origin) != _normalize_url(repository_url):
        raise RuntimeError("self-verification origin does not match target pack canonical repository")
    with tempfile.TemporaryDirectory(prefix="governance-published-head-") as tmp:
        checkout = Path(tmp) / "remote"
        subprocess.run(
            ["git", "clone", "--quiet", "--no-checkout", repository_url, str(checkout)],
            check=True,
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "fetch", "--quiet", "--depth=1", "origin", local_head],
            cwd=checkout,
            check=True,
            text=True,
            capture_output=True,
        )
        remote_head = _git(checkout, "rev-parse", "FETCH_HEAD")
        remote_tree = _git(checkout, "rev-parse", "FETCH_HEAD^{tree}")
    if remote_head != local_head:
        raise RuntimeError("published self-verification commit mismatch")
    if remote_tree != local_tree:
        raise RuntimeError("published self-verification tree mismatch")
    return {
        "revision_source": "EVALUATOR_HEAD",
        "local_head_sha": local_head,
        "local_tree_sha": local_tree,
        "remote_url": repository_url,
        "remote_head_sha": remote_head,
        "remote_tree_sha": remote_tree,
        "worktree_clean": True,
        "published": True,
    }


def _resolved_pack(root: Path, pack_path: Path, pack: dict[str, Any], artifacts_dir: Path, sha: str) -> Path:
    del pack_path
    resolved = json.loads(json.dumps(pack))
    resolved["immutable_revisions"] = {
        "base_sha": sha,
        "head_sha": sha,
        "safe_base_sha": sha,
        "safe_head_sha": sha,
    }
    path = (artifacts_dir / ".resolved-packs" / f"{pack['id']}-{sha}.json").resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError("resolved self pack must stay inside governance repository") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(resolved, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.STDOUT).strip()


def _normalize_url(url: str) -> str:
    normalized = url.strip().rstrip("/").lower()
    return normalized[:-4] if normalized.endswith(".git") else normalized


def _revisions_for_mode(revisions: dict[str, str], mode: str) -> tuple[str, str, str | None]:
    if mode == "HISTORICAL_FIXED":
        return revisions["base_sha"], revisions["head_sha"], revisions.get("merge_sha")
    if mode == "SAFE_FIXED":
        return revisions["safe_base_sha"], revisions["safe_head_sha"], None
    raise ValueError(f"registry verification mode must be immutable: {mode}")
