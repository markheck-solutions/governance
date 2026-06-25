from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_file, sha256_json, sha256_text
from governance_eval.paths import repo_root
from governance_eval.schemas import validate_named
from governance_eval.structural import scan_structural_metrics, structural_delta
from governance_eval.target_pack import dependency_lock_hash, load_target_pack, schema_hashes, target_pack_hash

SHADOW_MERGE = "SHADOW_MERGE"
SHADOW_BLOCK_TECHNICAL = "SHADOW_BLOCK_TECHNICAL"
SHADOW_ASK_BUSINESS = "SHADOW_ASK_BUSINESS"
NON_BLOCKING = "NON_BLOCKING"


def evaluate_target(
    pack_path: Path,
    base_sha: str,
    head_sha: str,
    artifacts_dir: Path | None = None,
    merge_sha: str | None = None,
    repository_url: str | None = None,
) -> dict[str, Any]:
    root = repo_root(Path(__file__).resolve())
    pack = load_target_pack(pack_path, root=root)
    target_repository_url = repository_url or pack["repository_url"]
    _validate_requested_target(pack, target_repository_url, base_sha, head_sha, merge_sha)
    started = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    with tempfile.TemporaryDirectory(prefix="governance-target-") as tmp:
        temp_root = Path(tmp)
        base_dir = _checkout(target_repository_url, base_sha, temp_root / "base")
        head_dir = _checkout(target_repository_url, head_sha, temp_root / "head")
        setup_results = {"base": _run_setup_commands(pack, base_dir), "head": _run_setup_commands(pack, head_dir)}
        changed = _changed_files(base_dir, base_sha, head_sha)
        behavior = [
            _run_behavior_case(root, target_repository_url, case, base_dir, head_dir, base_sha, head_sha, merge_sha)
            for case in pack["behavior_cases"]
        ]
        base_struct = scan_structural_metrics(base_dir, changed)
        head_struct = scan_structural_metrics(head_dir, changed)
        delta = structural_delta(base_struct, head_struct)

    acceptance_errors = _target_acceptance_errors(behavior, delta, set(pack["structural_detectors"]), setup_results)
    decision = SHADOW_BLOCK_TECHNICAL if acceptance_errors else SHADOW_MERGE
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": started,
        "governance_evaluator_git_sha": _git_sha(root),
        "governance_target_pack_hash": target_pack_hash(pack_path),
        "schema_hashes": schema_hashes(root),
        "dependency_lock_hash": dependency_lock_hash(root),
        "target_repository_url": target_repository_url,
        "target_pack_id": pack["id"],
        "target_base_sha": base_sha,
        "target_head_sha": head_sha,
        "target_merge_sha": merge_sha,
        "operating_system": platform.platform(),
        "python_version": platform.python_version(),
        "enforcement_mode": NON_BLOCKING,
        "real_target_shadow_decision": decision,
        "acceptance_errors": acceptance_errors,
        "case_counts": {
            "behavior_case_count": len(behavior),
            "behavior_cases_passed": sum(1 for item in behavior if item["status"] == "PASS"),
            "behavior_cases_failed": sum(1 for item in behavior if item["status"] == "FAIL"),
        },
        "setup_results": setup_results,
        "behavior_results": behavior,
        "structural_metrics_before": base_struct,
        "structural_metrics_after": head_struct,
        "structural_delta": delta,
        "commands": [
            *(item["command"] for side in setup_results.values() for item in side),
            *(cmd for item in behavior for cmd in item["commands"]),
        ],
        "deterministic_evidence_hash": "",
        "artifact_content_hash": "",
    }
    result["deterministic_evidence_hash"] = sha256_json(_stable_target_payload(result))
    result["artifact_content_hash"] = sha256_json({**result, "artifact_content_hash": ""})
    validate_named("target_evaluation_result", result, root)
    if artifacts_dir is not None:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        name = f"target-evaluation-{pack['id']}-{started.replace(':', '').replace('-', '')}.json"
        (artifacts_dir / name).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        (artifacts_dir / "target-evaluation-latest.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        result["artifact_path"] = str(artifacts_dir / name)
    return result


def _validate_requested_target(
    pack: dict[str, Any], repository_url: str, base_sha: str, head_sha: str, merge_sha: str | None
) -> None:
    if repository_url != pack["repository_url"]:
        raise ValueError(f"target repository mismatch for pack {pack['id']}: {repository_url}")
    revisions = pack["immutable_revisions"]
    historical_pair = base_sha == revisions["base_sha"] and head_sha == revisions["head_sha"]
    safe_pair = base_sha == revisions.get("safe_base_sha") and head_sha == revisions.get("safe_head_sha") and not merge_sha
    if not (historical_pair or safe_pair):
        raise ValueError(f"base/head pair is not allowed by target pack {pack['id']}: {base_sha}..{head_sha}")
    if historical_pair and revisions.get("merge_sha") and merge_sha != revisions["merge_sha"]:
        raise ValueError(f"merge_sha is required for historical pair in target pack {pack['id']}: {revisions['merge_sha']}")
    if merge_sha and merge_sha != revisions.get("merge_sha"):
        raise ValueError(f"merge_sha is not allowed by target pack {pack['id']}: {merge_sha}")


def _run_setup_commands(pack: dict[str, Any], target_dir: Path) -> list[dict[str, Any]]:
    results = []
    for command in pack.get("build_setup_commands", []):
        if "<checkout>" in command:
            command = command.replace("<checkout>", str(target_dir))
        try:
            completed = subprocess.run(
                command,
                cwd=target_dir,
                shell=True,
                text=True,
                capture_output=True,
                timeout=180,
            )
            results.append(
                {
                    "command": command,
                    "exit_code": completed.returncode,
                    "stdout_hash": sha256_json(completed.stdout),
                    "stderr_hash": sha256_json(completed.stderr),
                    "timed_out": False,
                }
            )
        except subprocess.TimeoutExpired as exc:
            results.append(
                {
                    "command": command,
                    "exit_code": 124,
                    "stdout_hash": sha256_json(exc.stdout or ""),
                    "stderr_hash": sha256_json(exc.stderr or ""),
                    "timed_out": True,
                }
            )
    return results


def _stable_target_payload(result: dict[str, Any]) -> dict[str, Any]:
    return _normalize_transient_paths(
        {**result, "generated_at": "", "deterministic_evidence_hash": "", "artifact_content_hash": ""}
    )


def _normalize_transient_paths(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize_transient_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_transient_paths(item) for item in value]
    if isinstance(value, str) and " --target " in value and "governance-target-" in value:
        return value.split(" --target ", 1)[0] + " --target <checkout>"
    return value


def _checkout(repo_url: str, sha: str, path: Path) -> Path:
    subprocess.run(["git", "clone", "--quiet", "--no-checkout", repo_url, str(path)], check=True)
    subprocess.run(["git", "checkout", "--quiet", sha], cwd=path, check=True)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
    if actual != sha:
        raise RuntimeError(f"checkout integrity failure: expected {sha}, got {actual}")
    return path


def _changed_files(base_dir: Path, base_sha: str, head_sha: str) -> set[str]:
    try:
        output = subprocess.check_output(["git", "diff", "--name-only", base_sha, head_sha], cwd=base_dir, text=True)
    except subprocess.CalledProcessError:
        return set()
    return {line.strip() for line in output.splitlines() if line.strip()}


def _run_behavior_case(root: Path, target_repository_url: str, case: dict[str, Any], base_dir: Path, head_dir: Path, base_sha: str, head_sha: str, merge_sha: str | None) -> dict[str, Any]:
    base = _execute_case(root, case, base_dir, base_sha)
    head = _execute_case(root, case, head_dir, head_sha)
    expected = case.get("expected_base_result") or base["observed_result"]
    status = "PASS" if base["observed_result"] == expected and head["observed_result"] == expected else "FAIL"
    source_validation = "PASS" if base["source_hash_validation"] == "PASS" and head["source_hash_validation"] == "PASS" else "FAIL"
    return {
        "case_id": case["id"],
        "status": status,
        "provenance_classification": case["provenance_classification"],
        "classification_reason": case.get("classification_reason", ""),
        "target_repository_url": target_repository_url,
        "pull_request": case.get("pull_request"),
        "base_sha": base_sha,
        "head_sha": head_sha,
        "merge_sha": merge_sha,
        "base_execution": base,
        "head_execution": head,
        "expected_result": expected,
        "observed_result": {"base": base["observed_result"], "head": head["observed_result"]},
        "source_files": {"base": base["source_files"], "head": head["source_files"]},
        "source_symbols": {"base": base["source_symbols"], "head": head["source_symbols"]},
        "source_hash_validation": source_validation,
        "reproducer_files": [{"path": case["reproducer"], "sha256": sha256_file(root / case["reproducer"])}],
        "commands": [base["command"], head["command"]],
    }


def _execute_case(root: Path, case: dict[str, Any], target_dir: Path, sha: str) -> dict[str, Any]:
    script = root / case["reproducer"]
    command = [sys.executable, str(script), "--target", str(target_dir)]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(target_dir / "src")
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=target_dir,
            env=env,
            text=True,
            capture_output=True,
            timeout=int(case.get("timeout_seconds", 60)),
        )
        stdout = completed.stdout
        stderr = completed.stderr
        exit_code = completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        exit_code = 124
    try:
        observed = json.loads(stdout) if stdout.strip() else {"stdout": ""}
    except json.JSONDecodeError:
        observed = {"invalid_json_stdout": stdout}
    source_files = _source_file_evidence(target_dir, case.get("source_files", []), sha)
    source_symbols = _source_symbol_evidence(target_dir, case.get("source_symbols", []), sha)
    validation = _source_hash_validation(case, sha, source_files, source_symbols)
    if exit_code != 0:
        validation = "FAIL"
    return {
        "exact_revision_executed": sha,
        "command": " ".join(command),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout_hash": sha256_json(stdout),
        "stderr_hash": sha256_json(stderr),
        "observed_result": observed,
        "source_files": source_files,
        "source_symbols": source_symbols,
        "source_hash_validation": validation,
    }


def _source_hash_validation(
    case: dict[str, Any], sha: str, source_files: list[dict[str, str]], source_symbols: list[dict[str, Any]]
) -> str:
    if any(item["file_sha256"] == "MISSING" for item in source_files):
        return "FAIL"
    if any(item["status"] != "PASS" for item in source_symbols):
        return "FAIL"
    expected = case.get("expected_source_hashes", {}).get(sha)
    if not expected:
        if case.get("pull_request") is not None:
            return "FAIL"
        return "PASS"
    for item in source_files:
        expected_file = expected.get("files", {}).get(item["path"])
        if not expected_file:
            return "FAIL"
        if item["file_sha256"] != expected_file.get("file_sha256"):
            return "FAIL"
        if item["git_blob_sha"] != expected_file.get("git_blob_sha"):
            return "FAIL"
    symbol_lookup = {
        f"{item['path']}::{item['symbol']}": item
        for item in source_symbols
    }
    expected_symbols = expected.get("symbols", {})
    for actual in source_symbols:
        key = f"{actual['path']}::{actual['symbol']}"
        expected_symbol = expected_symbols.get(key)
        if not expected_symbol:
            return "FAIL"
        if actual["symbol_sha256"] != expected_symbol.get("symbol_sha256"):
            return "FAIL"
        if actual["line_start"] != expected_symbol.get("line_start"):
            return "FAIL"
        if actual["line_end"] != expected_symbol.get("line_end"):
            return "FAIL"
    return "PASS"


def _source_file_evidence(target_dir: Path, relative_paths: list[str], sha: str) -> list[dict[str, str]]:
    evidence = []
    for relative in relative_paths:
        path = target_dir / relative
        blob = "MISSING"
        if path.exists():
            try:
                blob = subprocess.check_output(["git", "ls-tree", sha, relative], cwd=target_dir, text=True).split()[2]
            except Exception:
                blob = "UNKNOWN"
        evidence.append(
            {
                "commit": sha,
                "path": relative,
                "git_blob_sha": blob,
                "file_sha256": sha256_file(path) if path.exists() else "MISSING",
            }
        )
    return evidence


def _source_symbol_evidence(target_dir: Path, symbols: list[dict[str, Any]], sha: str) -> list[dict[str, Any]]:
    evidence = []
    for symbol in symbols:
        relative = symbol["path"]
        path = target_dir / relative
        item: dict[str, Any] = {
            "commit": sha,
            "path": relative,
            "symbol": symbol["symbol"],
            "line_start": None,
            "line_end": None,
            "symbol_sha256": "MISSING",
            "status": "FAIL",
        }
        if path.exists():
            source = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            try:
                import ast

                tree = ast.parse("\n".join(source), filename=str(path))
                node = next(
                    (
                        candidate
                        for candidate in ast.walk(tree)
                        if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                        and candidate.name == symbol["symbol"]
                    ),
                    None,
                )
            except SyntaxError:
                node = None
            if node is not None and getattr(node, "lineno", None) and getattr(node, "end_lineno", None):
                line_start = int(node.lineno)
                line_end = int(node.end_lineno)
                text = "\n".join(source[line_start - 1 : line_end])
                item.update(
                    {
                        "line_start": line_start,
                        "line_end": line_end,
                        "symbol_sha256": sha256_text(text),
                        "status": "PASS",
                    }
                )
        evidence.append(item)
    return evidence


def _target_acceptance_errors(
    behavior: list[dict[str, Any]],
    delta: dict[str, Any],
    configured_detectors: set[str],
    setup_results: dict[str, list[dict[str, Any]]],
) -> list[str]:
    errors = []
    for side, results in setup_results.items():
        for result in results:
            if result["exit_code"] != 0:
                errors.append(f"{side} setup failed: {result['command']}")
    for item in behavior:
        if item["provenance_classification"] == "FIXTURE_ONLY":
            errors.append(f"{item['case_id']}: FIXTURE_ONLY provenance not accepted for required behavior")
        if item["source_hash_validation"] != "PASS":
            errors.append(f"{item['case_id']}: source hash validation failed")
        if item["status"] != "PASS":
            errors.append(f"{item['case_id']}: behavior evidence failed")
    blocking_structural_detectors = configured_detectors & {
            "cross_module_private_references",
            "private_helper_reexports",
            "tests_private_production_internals",
            "import_cycles",
            "weak_public_contracts",
            "large_typed_god_modules",
            "gate_scope_or_threshold_weakening",
        }
    for name, metric in delta.items():
        if metric["introduced"] and name in blocking_structural_detectors:
            errors.append(f"{name}: new structural violation(s): {len(metric['introduced'])}")
    return errors


def _git_sha(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:
        return "UNKNOWN"
