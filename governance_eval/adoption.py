from __future__ import annotations

import argparse
import json
import re
import subprocess
import sysconfig
from pathlib import Path
from typing import Any, Mapping, Sequence

from governance_eval.adopter_template import (
    render_candidate_workflow,
    validate_candidate_workflow,
)
from governance_eval.capability_catalog import STANDARD_PROFILE_ADAPTERS
from governance_eval.hashing import sha256_bytes


GOVERNANCE_REPOSITORY = "markheck-solutions/governance"
PROFILE_ID = "python.standard.v1"
REQUIRED_CONTEXT = "Governance / Authoritative Decision"
CONFIG_PATH = ".github/governance/supportability.yml"
STANDARD_PATH = ".github/governance/supportability-standard.md"
WORKFLOW_PATH = ".github/workflows/governance-candidate.yml"
MANIFEST_PATH = ".github/governance/adoption-manifest.json"
ADAPTERS = STANDARD_PROFILE_ADAPTERS
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
_BUNDLE_FILES = (CONFIG_PATH, STANDARD_PATH, WORKFLOW_PATH)


class AdoptionError(ValueError):
    pass


def generate_adoption_bundle(
    *,
    repo_root: Path,
    output_dir: Path,
    github_repository: str,
    repository_id: int,
    governance_sha: str,
    verifier_app_id: int,
    rollback_sha: str,
    source_root: Path | None = None,
) -> dict[str, Any]:
    _validate_bindings(
        github_repository,
        repository_id,
        governance_sha,
        verifier_app_id,
        rollback_sha,
    )
    target = repo_root.resolve(strict=True)
    before = _clean_git_state(target)
    output = _new_external_directory(output_dir, target)
    workflow = render_candidate_workflow(
        _asset("governance-candidate.yml", source_root), governance_sha
    )
    standard = _asset("supportability-standard.md", source_root).read_bytes()
    config = _canonical_json(
        _configuration(governance_sha, verifier_app_id, sha256_bytes(standard))
    )
    payloads = {
        CONFIG_PATH: config,
        STANDARD_PATH: standard,
        WORKFLOW_PATH: workflow,
    }
    _write_payloads(output, payloads)
    manifest = _manifest(
        payloads=payloads,
        repository=github_repository,
        repository_id=repository_id,
        target=before,
        governance_sha=governance_sha,
        verifier_app_id=verifier_app_id,
        rollback_sha=rollback_sha,
    )
    _write(output / MANIFEST_PATH, _canonical_json(manifest))
    if _clean_git_state(target) != before:
        raise AdoptionError("target repository changed during bundle generation")
    return manifest


def prove_adoption_bundle(
    *,
    repo_root: Path,
    bundle_dir: Path,
    artifacts_dir: Path,
    github_repository: str,
) -> dict[str, Any]:
    target = repo_root.resolve(strict=True)
    before = _clean_git_state(target)
    bundle = bundle_dir.resolve(strict=True)
    manifest = _load_json(_safe_file(bundle, MANIFEST_PATH))
    _validate_manifest(manifest, github_repository, before)
    _validate_file_set(bundle, manifest)
    config = _load_json(_safe_file(bundle, CONFIG_PATH))
    _validate_config_against_manifest(config, manifest)
    workflow = _safe_file(bundle, WORKFLOW_PATH).read_text(encoding="utf-8")
    validate_candidate_workflow(workflow, manifest["governance"]["sha"])
    if _clean_git_state(target) != before:
        raise AdoptionError("target repository changed during adoption proof")
    proof = {
        "schema_version": "1.0",
        "status": "PASS",
        "read_only": True,
        "target": manifest["target"],
        "governance": manifest["governance"],
        "verifier": manifest["verifier"],
        "profile": PROFILE_ID,
        "capabilities": [
            {
                "capability": capability,
                "adapter_id": adapter_id,
                "assurance_class": assurance,
                "status": "SUPPORTED",
            }
            for capability, adapter_id, assurance in ADAPTERS
        ],
        "bundle_sha256": manifest["bundle_sha256"],
        "files": manifest["files"],
    }
    output = _new_external_directory(artifacts_dir, target)
    _write(output / "adoption-proof.json", _canonical_json(proof))
    return proof


def _configuration(
    governance_sha: str, verifier_app_id: int, standard_sha256: str
) -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "profile": PROFILE_ID,
        "python_version": "3.12",
        "adapters": [
            {"capability": capability, "adapter_id": adapter_id}
            for capability, adapter_id, _assurance in ADAPTERS
        ],
        "governance": {
            "repository": GOVERNANCE_REPOSITORY,
            "sha": governance_sha,
        },
        "standard": {"source": STANDARD_PATH, "sha256": standard_sha256},
        "verifier": {
            "app_id": verifier_app_id,
            "required_context": REQUIRED_CONTEXT,
        },
    }


def validate_adoption_config(
    value: Mapping[str, Any], *, governance_sha: str, verifier_app_id: int
) -> None:
    standard = value.get("standard")
    candidate_hash = standard.get("sha256") if isinstance(standard, Mapping) else ""
    if not isinstance(candidate_hash, str) or not re.fullmatch(
        r"[0-9a-f]{64}", candidate_hash
    ):
        raise AdoptionError("adoption standard hash is invalid")
    if dict(value) != _configuration(governance_sha, verifier_app_id, candidate_hash):
        raise AdoptionError("adoption configuration differs from fixed Python profile")


def _manifest(
    *,
    payloads: Mapping[str, bytes],
    repository: str,
    repository_id: int,
    target: Mapping[str, str],
    governance_sha: str,
    verifier_app_id: int,
    rollback_sha: str,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "1.0",
        "profile": PROFILE_ID,
        "target": {
            "repository": repository,
            "repository_id": repository_id,
            **target,
        },
        "governance": {
            "repository": GOVERNANCE_REPOSITORY,
            "sha": governance_sha,
            "rollback_sha": rollback_sha,
        },
        "verifier": {
            "app_id": verifier_app_id,
            "required_context": REQUIRED_CONTEXT,
        },
        "files": {
            name: {"bytes": len(payload), "sha256": sha256_bytes(payload)}
            for name, payload in sorted(payloads.items())
        },
    }
    value["bundle_sha256"] = sha256_bytes(_canonical_json(value))
    return value


def _validate_manifest(
    value: Mapping[str, Any], repository: str, target: Mapping[str, str]
) -> None:
    expected_keys = {
        "schema_version",
        "profile",
        "target",
        "governance",
        "verifier",
        "files",
        "bundle_sha256",
    }
    if set(value) != expected_keys:
        raise AdoptionError("adoption manifest fields are invalid")
    unsigned = dict(value)
    digest = unsigned.pop("bundle_sha256", None)
    if digest != sha256_bytes(_canonical_json(unsigned)):
        raise AdoptionError("adoption bundle digest mismatch")
    expected_target: dict[str, Any] = {"repository": repository, **target}
    observed_target = value.get("target")
    if not isinstance(observed_target, Mapping):
        raise AdoptionError("adoption target binding is invalid")
    expected_target["repository_id"] = observed_target.get("repository_id")
    if dict(observed_target) != expected_target:
        raise AdoptionError("adoption target binding is stale")
    if value.get("schema_version") != "1.0" or value.get("profile") != PROFILE_ID:
        raise AdoptionError("adoption manifest profile is invalid")


def _validate_file_set(bundle: Path, manifest: Mapping[str, Any]) -> None:
    files = manifest.get("files")
    if not isinstance(files, Mapping) or set(files) != set(_BUNDLE_FILES):
        raise AdoptionError("adoption manifest file set is invalid")
    actual = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    if actual != {*_BUNDLE_FILES, MANIFEST_PATH}:
        raise AdoptionError("adoption bundle contains missing or unexpected files")
    for name in _BUNDLE_FILES:
        path = _safe_file(bundle, name)
        expected = files[name]
        if not isinstance(expected, Mapping):
            raise AdoptionError("adoption file receipt is invalid")
        payload = path.read_bytes()
        if expected != {"bytes": len(payload), "sha256": sha256_bytes(payload)}:
            raise AdoptionError("adoption bundle file digest mismatch")


def _validate_config_against_manifest(
    config: Mapping[str, Any], manifest: Mapping[str, Any]
) -> None:
    governance = _mapping(manifest.get("governance"), "governance binding")
    verifier = _mapping(manifest.get("verifier"), "verifier binding")
    validate_adoption_config(
        config,
        governance_sha=str(governance.get("sha")),
        verifier_app_id=_positive_integer(verifier.get("app_id"), "verifier App id"),
    )
    standard = _mapping(config.get("standard"), "standard binding")
    expected = manifest["files"][STANDARD_PATH]["sha256"]
    if standard.get("sha256") != expected:
        raise AdoptionError("adoption standard binding differs from bundle")


def _asset(name: str, source_root: Path | None) -> Path:
    if source_root is not None:
        relative = {
            "governance-candidate.yml": Path(
                "templates/standard/.github/workflows/governance-candidate.yml"
            ),
            "supportability-standard.md": Path(
                "docs/reference/supportability-standard.md"
            ),
        }[name]
        candidate = source_root.resolve(strict=True) / relative
    else:
        candidate = (
            Path(sysconfig.get_path("data")) / "share" / "governance-eval" / name
        )
    if not candidate.is_file() or candidate.is_symlink():
        raise AdoptionError(f"adoption asset unavailable: {name}")
    return candidate


def _clean_git_state(root: Path) -> dict[str, str]:
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status:
        raise AdoptionError("target repository must be clean")
    return {
        "head_sha": _git_text(root, "rev-parse", "HEAD"),
        "tree_sha": _git_text(root, "rev-parse", "HEAD^{tree}"),
        "status_sha256": sha256_bytes(status),
    }


def _git(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdoptionError("target Git state is unavailable") from exc
    if completed.returncode != 0:
        raise AdoptionError("target Git state is unavailable")
    return completed.stdout


def _git_text(root: Path, *arguments: str) -> str:
    try:
        value = _git(root, *arguments).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise AdoptionError("target Git identity is invalid") from exc
    if not _SHA_RE.fullmatch(value):
        raise AdoptionError("target Git identity is invalid")
    return value


def _new_external_directory(path: Path, target: Path) -> Path:
    output = path.resolve()
    if output == target or target in output.parents:
        raise AdoptionError("adoption output must be outside target repository")
    if output.exists() and (
        output.is_symlink() or not output.is_dir() or any(output.iterdir())
    ):
        raise AdoptionError("adoption output must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    return output


def _write_payloads(output: Path, payloads: Mapping[str, bytes]) -> None:
    for name, payload in payloads.items():
        _write(output / name, payload)


def _write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _safe_file(root: Path, name: str) -> Path:
    path = (root / name).resolve(strict=True)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise AdoptionError("adoption bundle path escapes bundle") from exc
    if not path.is_file() or path.is_symlink():
        raise AdoptionError("adoption bundle file is invalid")
    return path


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdoptionError("adoption JSON is malformed") from exc
    return dict(_mapping(value, "adoption JSON"))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdoptionError(f"duplicate adoption JSON key: {key}")
        value[key] = item
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AdoptionError(f"{label} must be an object")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise AdoptionError(f"{label} must be positive")
    return value


def _validate_bindings(
    repository: str,
    repository_id: int,
    governance_sha: str,
    verifier_app_id: int,
    rollback_sha: str,
) -> None:
    if not _REPOSITORY_RE.fullmatch(repository):
        raise AdoptionError("GitHub repository must use canonical owner/name")
    _positive_integer(repository_id, "repository id")
    _positive_integer(verifier_app_id, "verifier App id")
    if not _SHA_RE.fullmatch(governance_sha) or not _SHA_RE.fullmatch(rollback_sha):
        raise AdoptionError("Governance pins must be exact lowercase 40-hex")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _bundle_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic adopter bundle"
    )
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--governance-sha", required=True)
    parser.add_argument("--verifier-app-id", required=True, type=int)
    parser.add_argument("--rollback-sha", required=True)
    parser.add_argument("--source-root", type=Path)
    return parser


def _proof_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prove an adopter bundle read-only")
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--github-repository", required=True)
    return parser


def bundle_main(argv: Sequence[str] | None = None) -> int:
    result = generate_adoption_bundle(**vars(_bundle_parser().parse_args(argv)))
    print(json.dumps({"bundle_sha256": result["bundle_sha256"]}, sort_keys=True))
    return 0


def proof_main(argv: Sequence[str] | None = None) -> int:
    result = prove_adoption_bundle(**vars(_proof_parser().parse_args(argv)))
    print(
        json.dumps(
            {"status": result["status"], "bundle_sha256": result["bundle_sha256"]},
            sort_keys=True,
        )
    )
    return 0
