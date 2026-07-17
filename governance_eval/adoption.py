from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_bytes, sha256_file, sha256_json
from governance_eval.schemas import validate_named
from governance_eval.supportability import (
    load_supportability_config,
    validate_supportability_config,
)


ADOPTION_READY = "ADOPTION_READY"
ADOPTION_PROOF_PASS = "ADOPTION_PROOF_PASS"
CALLER_PATH = ".github/workflows/supportability-enforcement.yml"
CONFIG_PATH = ".github/governance/supportability.yml"
STANDARD_PATH = "docs/reference/supportability-standard.md"
PROTECTION_PATH = "docs/governance-protection-setup.md"
MANIFEST_PATH = "governance-adoption-manifest.json"
REQUIRED_CONTEXTS = (
    "Baseline Protected Supportability Gate / Supportability Gate",
    "Candidate Supportability Gate / Supportability Gate",
    "Baseline Protected Delivery Receipt / Delivery Receipt",
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PIN_RE = re.compile(
    r"(?m)(markheck-solutions/governance/\.github/workflows/"
    r"(?:supportability-gate|delivery-receipt)\.yml@)[0-9a-f]{40}"
    r"|(governance-ref:\s*)[0-9a-f]{40}"
)


class AdoptionError(ValueError):
    pass


def generate_adoption_bundle(
    *,
    governance_root: Path,
    repository: str,
    governance_sha: str,
    config_source: Path,
    output_dir: Path,
) -> dict[str, Any]:
    _validate_inputs(governance_root, repository, governance_sha, output_dir)
    config = load_supportability_config(config_source)
    config_errors = validate_supportability_config(config)
    if config_errors:
        raise AdoptionError(
            "supportability config invalid: " + "; ".join(config_errors)
        )

    standard_bytes = _git_bytes(governance_root, governance_sha, STANDARD_PATH)
    _validate_standard(config, standard_bytes)
    source_caller = _git_bytes(governance_root, governance_sha, CALLER_PATH).decode(
        "utf-8"
    )
    caller = _render_caller(source_caller, governance_sha)
    config_bytes = (
        json.dumps(config, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    protection = _protection_document(repository).encode("utf-8")
    files = {
        CONFIG_PATH: config_bytes,
        CALLER_PATH: caller.encode("utf-8"),
        STANDARD_PATH: standard_bytes,
        PROTECTION_PATH: protection,
    }
    manifest = _manifest(repository, governance_sha, files)
    validate_named("adoption_bundle", manifest, root=governance_root)

    temporary = output_dir.with_name(f".{output_dir.name}.building-{os.getpid()}")
    if temporary.exists():
        raise AdoptionError(f"temporary output already exists: {temporary}")
    try:
        for relative, content in files.items():
            path = temporary / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        (temporary / MANIFEST_PATH).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary_result = validate_adoption_bundle(
            governance_root=governance_root, bundle_dir=temporary
        )
        if not temporary_result["valid"]:
            raise AdoptionError(
                "generated bundle failed validation: "
                + "; ".join(temporary_result["errors"])
            )
        os.replace(temporary, output_dir)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    result = validate_adoption_bundle(
        governance_root=governance_root,
        bundle_dir=output_dir,
    )
    if not result["valid"]:
        shutil.rmtree(output_dir)
        raise AdoptionError(
            "generated bundle failed post-write validation: "
            + "; ".join(result["errors"])
        )
    return result


def validate_adoption_bundle(
    *, governance_root: Path, bundle_dir: Path
) -> dict[str, Any]:
    errors: list[str] = []
    if bundle_dir.is_symlink() or _is_junction(bundle_dir):
        return {"valid": False, "errors": ["bundle directory must not be a link"]}
    errors.extend(_bundle_inventory_errors(bundle_dir))
    if any("link" in error or "special" in error for error in errors):
        return {"valid": False, "errors": errors}
    manifest_path = bundle_dir / MANIFEST_PATH
    if not manifest_path.is_file():
        return {"valid": False, "errors": [f"missing {MANIFEST_PATH}"]}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        validate_named("adoption_bundle", manifest, root=governance_root)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "errors": [f"manifest invalid: {exc}"]}

    unhashed = {
        key: value for key, value in manifest.items() if key != "artifact_content_hash"
    }
    if manifest.get("artifact_content_hash") != sha256_json(unhashed):
        errors.append("manifest artifact_content_hash mismatch")
    files = manifest.get("files", {})
    allowed_files = {CONFIG_PATH, CALLER_PATH, STANDARD_PATH, PROTECTION_PATH}
    if set(files) != allowed_files:
        errors.append("manifest file set mismatch")
    for relative in sorted(allowed_files):
        expected = files.get(relative)
        path = bundle_dir / relative
        if not path.is_file():
            errors.append(f"missing generated file: {relative}")
        elif not isinstance(expected, str) or sha256_file(path) != expected:
            errors.append(f"generated file hash mismatch: {relative}")

    config_path = bundle_dir / CONFIG_PATH
    if config_path.is_file():
        try:
            config = load_supportability_config(config_path)
            errors.extend(validate_supportability_config(config))
            _validate_standard(config, (bundle_dir / STANDARD_PATH).read_bytes())
        except (OSError, ValueError) as exc:
            errors.append(f"generated config invalid: {exc}")
        if sha256_file(config_path) != manifest.get("config_sha256"):
            errors.append("config_sha256 mismatch")

    sha = manifest.get("governance_sha", "")
    if manifest.get("caller_pins") != [sha] * 6:
        errors.append("caller_pins must equal the exact Governance SHA six times")
    caller_path = bundle_dir / CALLER_PATH
    if SHA_RE.fullmatch(sha) and caller_path.is_file():
        try:
            expected = _render_caller(
                _git_bytes(governance_root, sha, CALLER_PATH).decode("utf-8"), sha
            )
            actual = caller_path.read_text(encoding="utf-8")
            if actual != expected:
                errors.append("caller differs from exact Governance source")
            if actual.count(sha) != 6:
                errors.append("caller must contain exactly six exact Governance pins")
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(f"caller validation failed: {exc}")
    if manifest.get("required_contexts") != list(REQUIRED_CONTEXTS):
        errors.append("required-context mapping mismatch")
    protection_path = bundle_dir / PROTECTION_PATH
    repository = manifest.get("repository", "")
    if protection_path.is_file() and REPOSITORY_RE.fullmatch(repository):
        if protection_path.read_text(encoding="utf-8") != _protection_document(
            repository
        ):
            errors.append("protection instructions differ from repository binding")
    return {
        "valid": not errors,
        "decision": ADOPTION_READY if not errors else "BLOCK_TECHNICAL",
        "errors": errors,
        "manifest": manifest,
    }


def prove_adoption(
    *, governance_root: Path, governance_sha: str, artifacts_dir: Path
) -> dict[str, Any]:
    if artifacts_dir.exists():
        raise AdoptionError(f"artifacts directory already exists: {artifacts_dir}")
    clean_dir = artifacts_dir / "clean"
    defective_dir = artifacts_dir / "defective"
    clean = generate_adoption_bundle(
        governance_root=governance_root,
        repository="disposable/clean-adoption-canary",
        governance_sha=governance_sha,
        config_source=governance_root / CONFIG_PATH,
        output_dir=clean_dir,
    )
    shutil.copytree(clean_dir, defective_dir)
    caller_path = defective_dir / CALLER_PATH
    caller = caller_path.read_text(encoding="utf-8")
    caller_path.write_text(
        caller.replace(governance_sha, "0" * 40, 1), encoding="utf-8"
    )
    defective = validate_adoption_bundle(
        governance_root=governance_root, bundle_dir=defective_dir
    )
    result: dict[str, Any] = {
        "schema_version": 1,
        "decision": ADOPTION_PROOF_PASS
        if clean["valid"] and not defective["valid"]
        else "BLOCK_TECHNICAL",
        "governance_sha": governance_sha,
        "clean_valid": clean["valid"],
        "clean_manifest_content_hash": clean["manifest"]["artifact_content_hash"],
        "defective_valid": defective["valid"],
        "defective_errors": defective["errors"],
        "defect": "CALLER_PIN_SUBSTITUTION",
    }
    result["artifact_content_hash"] = sha256_json(result)
    validate_named("adoption_proof", result, root=governance_root)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    (artifacts_dir / "adoption-proof.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def _validate_inputs(
    governance_root: Path, repository: str, governance_sha: str, output_dir: Path
) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise AdoptionError("repository must be owner/name")
    if not SHA_RE.fullmatch(governance_sha):
        raise AdoptionError(
            "governance SHA must be exactly 40 lowercase hex characters"
        )
    if output_dir.exists():
        raise AdoptionError(f"output directory already exists: {output_dir}")
    for candidate in output_dir.parents:
        if candidate.exists() and (candidate.is_symlink() or _is_junction(candidate)):
            raise AdoptionError(f"output parent must not be a link: {candidate}")
    containing_root = _containing_git_root(output_dir.parent)
    if containing_root is not None and containing_root != governance_root.resolve():
        raise AdoptionError("output directory must not be inside a target Git worktree")


def _validate_standard(config: dict[str, Any], standard_bytes: bytes) -> None:
    standard = config.get("standard")
    if not isinstance(standard, dict):
        raise AdoptionError("standard must be an object")
    if standard.get("source") != STANDARD_PATH:
        raise AdoptionError(f"standard.source must be {STANDARD_PATH}")
    if standard.get("hash") != sha256_bytes(standard_bytes):
        raise AdoptionError("standard hash does not match exact Governance source")


def _git_bytes(root: Path, sha: str, relative: str) -> bytes:
    if not SHA_RE.fullmatch(sha):
        raise AdoptionError("invalid Governance SHA")
    object_type = subprocess.run(
        ["git", "--no-replace-objects", "cat-file", "-t", sha],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if object_type.returncode != 0 or object_type.stdout.strip() != "commit":
        raise AdoptionError("Governance SHA must identify an exact commit object")
    completed = subprocess.run(
        ["git", "--no-replace-objects", "show", f"{sha}:{relative}"],
        cwd=root,
        check=False,
        capture_output=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise AdoptionError(f"exact Governance source unavailable: {sha}:{relative}")
    return completed.stdout


def _render_caller(source: str, governance_sha: str) -> str:
    replacements = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal replacements
        replacements += 1
        return (match.group(1) or match.group(2)) + governance_sha

    rendered = PIN_RE.sub(replace, source)
    if replacements != 6 or rendered.count(governance_sha) != 6:
        raise AdoptionError("protected caller must expose exactly six Governance pins")
    return rendered


def _protection_document(repository: str) -> str:
    lines = [
        "# Governance branch protection setup",
        "",
        f"Repository: `{repository}`",
        "",
        "Protect `main` with strict required status checks from GitHub Actions:",
        "",
    ]
    lines.extend(f"- `{context}`" for context in REQUIRED_CONTEXTS)
    lines.extend(
        [
            "",
            "Also require pull requests and conversation resolution, enforce rules for admins, ",
            "and disable force pushes and branch deletion.",
            "",
            "Verify after setup:",
            "",
            "```powershell",
            f"gh api repos/{repository}/branches/main/protection",
            "```",
            "",
            "This document does not mutate GitHub settings. Apply protection in a separate, ",
            "owner-approved rollout step, then prove it with clean and defective pull requests.",
        ]
    )
    return "\n".join(lines) + "\n"


def _manifest(
    repository: str, governance_sha: str, files: dict[str, bytes]
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": 1,
        "decision": ADOPTION_READY,
        "repository": repository,
        "governance_sha": governance_sha,
        "config_sha256": sha256_bytes(files[CONFIG_PATH]),
        "caller_pins": [governance_sha] * 6,
        "required_contexts": list(REQUIRED_CONTEXTS),
        "files": {
            path: sha256_bytes(content) for path, content in sorted(files.items())
        },
    }
    result["artifact_content_hash"] = sha256_json(result)
    return result


def _is_junction(path: Path) -> bool:
    checker = getattr(path, "is_junction", None)
    return bool(checker and checker())


def _bundle_inventory_errors(bundle_dir: Path) -> list[str]:
    expected = {CONFIG_PATH, CALLER_PATH, STANDARD_PATH, PROTECTION_PATH, MANIFEST_PATH}
    actual: set[str] = set()
    errors: list[str] = []
    if not bundle_dir.is_dir():
        return ["bundle directory is missing"]
    resolved_root = bundle_dir.resolve()
    for current, directories, filenames in os.walk(bundle_dir, followlinks=False):
        current_path = Path(current)
        for name in directories:
            path = current_path / name
            if path.is_symlink() or _is_junction(path):
                errors.append(
                    f"bundle directory link forbidden: {path.relative_to(bundle_dir).as_posix()}"
                )
        for name in filenames:
            path = current_path / name
            relative = path.relative_to(bundle_dir).as_posix()
            actual.add(relative)
            if path.is_symlink() or _is_junction(path):
                errors.append(f"bundle file link forbidden: {relative}")
            elif not path.is_file():
                errors.append(f"bundle special file forbidden: {relative}")
            elif not path.resolve().is_relative_to(resolved_root):
                errors.append(f"bundle file escapes root: {relative}")
    if actual != expected:
        errors.append("bundle disk file inventory mismatch")
    return errors


def _containing_git_root(path: Path) -> Path | None:
    candidate = path
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    completed = subprocess.run(
        ["git", "-C", str(candidate), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        return None
    return Path(completed.stdout.strip()).resolve()
