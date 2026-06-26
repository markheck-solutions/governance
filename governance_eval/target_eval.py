from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_file, sha256_json, sha256_text
from governance_eval.paths import repo_root
from governance_eval.schemas import validate_named
from governance_eval.structural import scan_structural_metrics, structural_delta
from governance_eval.target_pack import (
    dependency_lock_hash,
    infer_revision_mode,
    load_target_pack,
    schema_hashes,
    target_pack_hash,
    validate_target_request,
)

SHADOW_MERGE = "SHADOW_MERGE"
SHADOW_BLOCK_TECHNICAL = "SHADOW_BLOCK_TECHNICAL"
SHADOW_ASK_BUSINESS = "SHADOW_ASK_BUSINESS"
NON_BLOCKING = "NON_BLOCKING"
GOVERNANCE_REPOSITORY_URL = "https://github.com/markheck-solutions/governance.git"


def evaluate_target(
    pack_path: Path,
    base_sha: str,
    head_sha: str,
    artifacts_dir: Path | None = None,
    merge_sha: str | None = None,
    repository_url: str | None = None,
    revision_mode: str | None = None,
    target_pr_number: int | None = None,
    require_governance_owned_pack: bool = False,
) -> dict[str, Any]:
    root = repo_root(Path(__file__).resolve())
    pack = load_target_pack(pack_path, root=root, require_governance_owned=require_governance_owned_pack)
    mode = revision_mode or infer_revision_mode(pack, base_sha, head_sha, merge_sha)
    target_repository_url = repository_url or pack["repository_url"]
    if require_governance_owned_pack:
        pack = validate_target_request(pack_path, target_repository_url, base_sha, head_sha, merge_sha, mode, root=root)
    else:
        _validate_requested_target(pack, target_repository_url, base_sha, head_sha, merge_sha, mode)
    started = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    validation: dict[str, Any] = {"status": "PASS", "mode": mode}
    with tempfile.TemporaryDirectory(prefix="governance-target-") as tmp:
        temp_root = Path(tmp)
        base_dir = _checkout(target_repository_url, base_sha, temp_root / "base")
        head_dir = _checkout(target_repository_url, head_sha, temp_root / "head")
        validation["base_commit_exists"] = _commit_exists(base_dir, base_sha)
        validation["head_commit_exists"] = _commit_exists(head_dir, head_sha)
        validation["candidate_pull_request_validation"] = _candidate_pull_request_validation(
            target_repository_url,
            base_sha,
            head_sha,
            mode,
            target_pr_number,
        )
        if (
            not validation["base_commit_exists"]
            or not validation["head_commit_exists"]
            or validation["candidate_pull_request_validation"].get("status") == "FAIL"
        ):
            validation["status"] = "FAIL"
        setup_results = {"base": _run_setup_commands(pack, base_dir), "head": _run_setup_commands(pack, head_dir)}
        changed = _changed_files(base_dir, head_dir, base_sha, head_sha)
        behavior = [
            _run_behavior_case(
                root,
                pack,
                target_repository_url,
                case,
                base_dir,
                head_dir,
                base_sha,
                head_sha,
                merge_sha,
                mode,
            )
            for case in pack["behavior_cases"]
            if _case_applies(case, mode)
        ]
        base_struct = scan_structural_metrics(base_dir, changed, pack)
        head_struct = scan_structural_metrics(head_dir, changed, pack)
        delta = structural_delta(base_struct, head_struct, pack)

    structural_measurements = _structural_measurement_summary(delta)
    acceptance_errors, business_ambiguities = _target_acceptance_errors(behavior, delta, pack, setup_results, validation)
    decision = SHADOW_BLOCK_TECHNICAL if acceptance_errors else SHADOW_ASK_BUSINESS if business_ambiguities else SHADOW_MERGE
    result: dict[str, Any] = {
        "schema_version": "1.1",
        "generated_at": started,
        "governance_repository_url": GOVERNANCE_REPOSITORY_URL,
        "governance_evaluator_git_sha": _git_sha(root),
        "governance_target_pack_hash": target_pack_hash(pack_path),
        "schema_hashes": schema_hashes(root),
        "dependency_lock_hash": dependency_lock_hash(root),
        "target_repository_url": target_repository_url,
        "target_pack_id": pack["id"],
        "target_pr_number": target_pr_number,
        "target_base_sha": base_sha,
        "target_head_sha": head_sha,
        "target_merge_sha": merge_sha,
        "revision_mode": mode,
        "revision_validation": validation,
        "operating_system": platform.platform(),
        "runner_os": os.environ.get("RUNNER_OS", platform.system()),
        "python_version": platform.python_version(),
        "enforcement_mode": NON_BLOCKING,
        "real_target_shadow_decision": decision,
        "acceptance_errors": acceptance_errors,
        "business_ambiguities": business_ambiguities,
        "case_counts": {
            "behavior_case_count": len(behavior),
            "behavior_cases_passed": sum(1 for item in behavior if item["status"] == "PASS"),
            "behavior_cases_failed": sum(1 for item in behavior if item["status"] == "FAIL"),
            "behavior_cases_business_ambiguous": sum(1 for item in behavior if item["status"] == "BUSINESS_AMBIGUITY"),
        },
        "setup_results": setup_results,
        "behavior_results": behavior,
        "structural_metrics_before": base_struct,
        "structural_metrics_after": head_struct,
        "structural_delta": delta,
        "structural_measurements": structural_measurements,
        "commands": [
            *(item["command"] for side in setup_results.values() for item in side),
            *(cmd for item in behavior for cmd in item["commands"]),
        ],
        "github_artifact_id": None,
        "github_artifact_digest": None,
        "deterministic_evidence_hash": "",
        "artifact_content_hash": "",
    }
    _validate_expected_artifact_fields(pack, result)
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
    pack: dict[str, Any],
    repository_url: str,
    base_sha: str,
    head_sha: str,
    merge_sha: str | None,
    revision_mode: str,
) -> None:
    from governance_eval.target_pack import _validate_requested_repository, _validate_requested_revisions

    _validate_requested_repository(pack, repository_url, revision_mode)
    _validate_requested_revisions(pack, base_sha, head_sha, merge_sha, revision_mode)


def _run_setup_commands(pack: dict[str, Any], target_dir: Path) -> list[dict[str, Any]]:
    results = []
    for command in pack.get("setup_commands") or pack.get("build_setup_commands", []):
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
        {
            **result,
            "generated_at": "",
            "deterministic_evidence_hash": "",
            "artifact_content_hash": "",
            "github_artifact_id": None,
            "github_artifact_digest": None,
        }
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


def _commit_exists(repo_dir: Path, sha: str) -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo_dir).returncode == 0


def _candidate_pull_request_validation(
    repository_url: str,
    base_sha: str,
    head_sha: str,
    revision_mode: str,
    target_pr_number: int | None,
) -> dict[str, Any]:
    if revision_mode != "CANDIDATE_DYNAMIC":
        return {"status": "NOT_APPLICABLE", "reason": "fixed revision mode"}
    parsed = _parse_github_repository(repository_url)
    if parsed is None:
        return {"status": "SKIPPED", "reason": "non-GitHub repository"}
    if target_pr_number is None:
        return {"status": "FAIL", "reason": "candidate GitHub evaluation requires target PR number"}
    owner, repo = parsed
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{target_pr_number}"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return {"status": "FAIL", "reason": f"GitHub pull request lookup failed: HTTP {exc.code}"}
    except Exception as exc:
        return {"status": "FAIL", "reason": f"GitHub pull request lookup failed: {type(exc).__name__}: {exc}"}
    actual_base = data.get("base", {}).get("sha")
    actual_head = data.get("head", {}).get("sha")
    matches = actual_base == base_sha and actual_head == head_sha
    return {
        "status": "PASS" if matches else "FAIL",
        "pull_request": target_pr_number,
        "expected_base_sha": actual_base,
        "expected_head_sha": actual_head,
        "reason": "" if matches else "target PR base/head does not match supplied revisions",
    }


def _parse_github_repository(repository_url: str) -> tuple[str, str] | None:
    match = re.search(r"github\.com[:/]([^/]+)/([^/.]+)(?:\.git)?/?$", repository_url)
    if not match:
        return None
    return match.group(1), match.group(2)


def _changed_files(base_dir: Path, head_dir: Path, base_sha: str, head_sha: str) -> set[str]:
    try:
        subprocess.run(["git", "fetch", "--quiet", "origin", head_sha], cwd=base_dir, check=False)
        output = subprocess.check_output(["git", "diff", "--name-only", base_sha, head_sha], cwd=base_dir, text=True)
        return {line.strip() for line in output.splitlines() if line.strip()}
    except subprocess.CalledProcessError:
        return _changed_files_by_content(base_dir, head_dir)


def _changed_files_by_content(base_dir: Path, head_dir: Path) -> set[str]:
    base_files = _file_hashes(base_dir)
    head_files = _file_hashes(head_dir)
    return {path for path in set(base_files) | set(head_files) if base_files.get(path) != head_files.get(path)}


def _file_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in root.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        hashes[relative] = sha256_file(path)
    return hashes


def _case_applies(case: dict[str, Any], revision_mode: str) -> bool:
    modes = case.get("revision_modes")
    return not modes or revision_mode in set(modes)


def _run_behavior_case(
    root: Path,
    pack: dict[str, Any],
    target_repository_url: str,
    case: dict[str, Any],
    base_dir: Path,
    head_dir: Path,
    base_sha: str,
    head_sha: str,
    merge_sha: str | None,
    revision_mode: str,
) -> dict[str, Any]:
    policy = _behavior_policy(case, revision_mode)
    base = _execute_case(root, pack, case, base_dir, base_sha, policy)
    head = _execute_case(root, pack, case, head_dir, head_sha, policy)
    expected = case.get("expected_base_result") or base["observed_result"]
    status = _behavior_status(policy, base, head, expected)
    source_validation = "PASS" if base["source_hash_validation"] == "PASS" and head["source_hash_validation"] == "PASS" else "FAIL"
    return {
        "case_id": case["id"],
        "status": status,
        "behavior_comparison_policy": policy,
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


def _behavior_policy(case: dict[str, Any], revision_mode: str) -> str:
    policies = case.get("comparison_policies") or {}
    return policies.get(revision_mode) or case.get("behavior_comparison_policy") or "PINNED_EXPECTED"


def _behavior_status(policy: str, base: dict[str, Any], head: dict[str, Any], expected: dict[str, Any]) -> str:
    if base["exit_code"] != 0 or head["exit_code"] != 0:
        return "FAIL"
    if base["source_hash_validation"] != "PASS" or head["source_hash_validation"] != "PASS":
        return "FAIL"
    if policy == "PINNED_EXPECTED":
        return "PASS" if base["observed_result"] == expected and head["observed_result"] == expected else "FAIL"
    if policy == "PRESERVE_BASE_BEHAVIOR":
        return "PASS" if head["observed_result"] == base["observed_result"] else "FAIL"
    if policy == "BUSINESS_REVIEW_ON_CHANGE":
        return "PASS" if head["observed_result"] == base["observed_result"] else "BUSINESS_AMBIGUITY"
    return "FAIL"


def _execute_case(
    root: Path,
    pack: dict[str, Any],
    case: dict[str, Any],
    target_dir: Path,
    sha: str,
    behavior_policy: str,
) -> dict[str, Any]:
    script = root / case["reproducer"]
    command = [sys.executable, str(script), "--target", str(target_dir)]
    env = dict(os.environ)
    roots = [str(target_dir / item) for item in (pack.get("production_roots") or ["src"])]
    env["PYTHONPATH"] = os.pathsep.join(roots + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
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
    validation = _source_hash_validation(case, sha, source_files, source_symbols, behavior_policy)
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
    case: dict[str, Any],
    sha: str,
    source_files: list[dict[str, str]],
    source_symbols: list[dict[str, Any]],
    behavior_policy: str,
) -> str:
    if any(item["file_sha256"] == "MISSING" for item in source_files):
        return "FAIL"
    if any(item["status"] != "PASS" for item in source_symbols):
        return "FAIL"
    expected = case.get("expected_source_hashes", {}).get(sha)
    if not expected:
        return "FAIL" if behavior_policy == "PINNED_EXPECTED" and case.get("pull_request") is not None else "PASS"
    for item in source_files:
        expected_file = expected.get("files", {}).get(item["path"])
        if not expected_file:
            return "FAIL"
        if item["file_sha256"] != expected_file.get("file_sha256"):
            return "FAIL"
        if item["git_blob_sha"] != expected_file.get("git_blob_sha"):
            return "FAIL"
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
                tree = ast_parse("\n".join(source), path)
                node = next(
                    (
                        candidate
                        for candidate in walk_ast(tree)
                        if candidate.__class__.__name__ in {"FunctionDef", "AsyncFunctionDef", "ClassDef"}
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


def ast_parse(source: str, path: Path) -> Any:
    import ast

    return ast.parse(source, filename=str(path))


def walk_ast(tree: Any) -> Any:
    import ast

    return ast.walk(tree)


def _target_acceptance_errors(
    behavior: list[dict[str, Any]],
    delta: dict[str, Any],
    pack: dict[str, Any],
    setup_results: dict[str, list[dict[str, Any]]],
    revision_validation: dict[str, Any],
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    business: list[str] = []
    if revision_validation.get("status") != "PASS":
        errors.append("revision validation failed")
    if not revision_validation.get("base_commit_exists") or not revision_validation.get("head_commit_exists"):
        errors.append("target commit validation failed")
    pr_validation = revision_validation.get("candidate_pull_request_validation") or {}
    if pr_validation.get("status") == "FAIL":
        errors.append(f"candidate pull request validation failed: {pr_validation.get('reason', '')}")
    for side, results in setup_results.items():
        for result in results:
            if result["exit_code"] != 0:
                errors.append(f"{side} setup failed: {result['command']}")
    for item in behavior:
        if item["provenance_classification"] == "FIXTURE_ONLY":
            errors.append(f"{item['case_id']}: FIXTURE_ONLY provenance not accepted for required behavior")
        if item["source_hash_validation"] != "PASS":
            errors.append(f"{item['case_id']}: source hash validation failed")
        if item["status"] == "BUSINESS_AMBIGUITY":
            business.append(f"{item['case_id']}: deterministic behavior difference requires business review")
        elif item["status"] != "PASS":
            errors.append(f"{item['case_id']}: behavior evidence failed under {item['behavior_comparison_policy']}")
    policies = _detector_policies(pack)
    for name, policy in policies.items():
        metric = delta.get(name)
        if not isinstance(metric, dict):
            if policy["required"] and policy["fail_on_unknown"]:
                errors.append(f"{name}: required detector evidence missing")
            continue
        status = metric.get("status")
        if status in {"UNKNOWN", "UNSUPPORTED"} and policy["required"] and policy["fail_on_unknown"]:
            errors.append(f"{name}: required detector evidence {status}: {metric.get('reason', '')}")
            continue
        if status not in {"MEASURED", "UNKNOWN", "UNSUPPORTED"}:
            if policy["required"] and policy["fail_on_unknown"]:
                errors.append(f"{name}: malformed detector status {status!r}")
            continue
        introduced = metric.get("introduced") or []
        if policy["blocking"] and introduced:
            errors.append(f"{name}: new structural violation(s): {len(introduced)}")
    return errors, business


def _detector_policies(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    policies: dict[str, dict[str, Any]] = {}
    for name in pack.get("structural_detectors", []):
        policy = (pack.get("detector_policies") or {}).get(name, {})
        policies[name] = {
            "required": bool(policy.get("required", False)),
            "blocking": bool(policy.get("blocking", False)),
            "fail_on_unknown": bool(policy.get("fail_on_unknown", False)),
            "thresholds": dict(policy.get("thresholds") or {}),
        }
    return policies


def _structural_measurement_summary(delta: dict[str, Any]) -> dict[str, Any]:
    unknown_required = []
    unknown_advisory = []
    unsupported_required = []
    unsupported_advisory = []
    for name, metric in sorted(delta.items()):
        if not isinstance(metric, dict):
            continue
        status = metric.get("status")
        policy = metric.get("policy") or {}
        item = {
            "detector": name,
            "status": status,
            "blocking": bool(policy.get("required") and policy.get("fail_on_unknown")),
            "reason": metric.get("reason", ""),
        }
        if status == "UNKNOWN":
            (unknown_required if item["blocking"] else unknown_advisory).append(item)
        elif status == "UNSUPPORTED":
            (unsupported_required if item["blocking"] else unsupported_advisory).append(item)
    return {
        "unknown_required": unknown_required,
        "unknown_required_count": len(unknown_required),
        "unknown_advisory": unknown_advisory,
        "unknown_advisory_count": len(unknown_advisory),
        "unsupported_required": unsupported_required,
        "unsupported_required_count": len(unsupported_required),
        "unsupported_advisory": unsupported_advisory,
        "unsupported_advisory_count": len(unsupported_advisory),
    }


def _validate_expected_artifact_fields(pack: dict[str, Any], result: dict[str, Any]) -> None:
    missing = [field for field in pack.get("expected_artifact_fields", []) if field not in result]
    if missing:
        raise ValueError(f"{pack['id']}: expected artifact fields missing: {missing}")


def _git_sha(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:
        return "UNKNOWN"
