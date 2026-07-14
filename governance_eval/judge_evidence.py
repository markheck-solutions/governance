from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from governance_eval.copilot_review_evidence import (
    NATIVE_COPILOT_REVIEWER,
    STRUCTURED_COPILOT_COMMENTER,
)
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named


JudgeRole = Literal["protected_baseline", "candidate"]

DOCUMENT_SCHEMAS = {
    "supportability-gate-result.json": "supportability_gate_result",
    "copilot-review-gate-result.json": "copilot_review_gate_result",
    "architecture-gate-result.json": "architecture_gate_result",
}
ROLE_ARTIFACT_NAMES = {
    "protected_baseline": "baseline-supportability-gate-evidence",
    "candidate": "candidate-supportability-gate-evidence",
}
REQUIRED_COMMAND_GATES = {
    "lint",
    "format_check",
    "typecheck",
    "complexity",
    "architecture",
    "tests",
    "compile_or_build",
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
POSITIVE_ID_RE = re.compile(r"^[1-9][0-9]*$")
REPOSITORY_URL_RE = re.compile(
    r"^https://github\.com/(?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\.git$"
)
PR_URL_RE = re.compile(
    r"^https://github\.com/(?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/(?P<number>[1-9][0-9]*)$"
)
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_ENTRY_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 64
MAX_COMPRESSION_RATIO = 100


@dataclass(frozen=True)
class _ValidatedJudgeEvidence:
    _document_json: str
    archive_path: Path
    archive_digest: str
    artifact_id: int | None

    def to_json(self) -> dict[str, Any]:
        value = json.loads(self._document_json)
        return value if isinstance(value, dict) else {}

    def __getitem__(self, key: str) -> Any:
        return self.to_json()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_json().get(key, default)


def validate_judge_evidence_bundle(
    archive_path: Any,
    *,
    role: JudgeRole,
    repository_url: str,
    repository_id: str,
    head_repository_id: str,
    pr_url: str,
    base_sha: str,
    head_sha: str,
    run_id: str,
    artifact_name: str,
    artifact_id: str,
    artifact_digest: str,
    artifact_metadata: Any,
) -> _ValidatedJudgeEvidence:
    errors: list[str] = []
    metadata: dict[str, Any]
    if isinstance(artifact_metadata, dict):
        metadata = artifact_metadata
    else:
        metadata = {}
        errors.append("artifact metadata must be an object")
    archive, archive_digest, archive_bytes = _archive_identity(archive_path, errors)
    documents = _load_archive_documents(archive_bytes, errors)
    errors.extend(
        _binding_errors(
            role,
            repository_url,
            repository_id,
            head_repository_id,
            pr_url,
            base_sha,
            head_sha,
            run_id,
            artifact_name,
            artifact_id,
            artifact_digest,
            metadata,
            archive_digest,
        )
    )
    gate = documents.get("supportability-gate-result.json", {})
    copilot = documents.get("copilot-review-gate-result.json", {})
    architecture = documents.get("architecture-gate-result.json", {})
    errors.extend(
        _document_identity_errors(
            gate,
            copilot,
            architecture,
            repository_url,
            pr_url,
            base_sha,
            head_sha,
        )
    )
    errors.extend(_gate_errors(gate))
    errors.extend(_copilot_errors(copilot, head_sha))
    errors.extend(_architecture_errors(architecture))
    semantic_evidence, semantic_errors = _semantic_evidence(gate, architecture)
    errors.extend(semantic_errors)
    document = {
        "schema_version": "1.0",
        "role": role,
        "owner_status": "RED" if errors else "GREEN",
        "repository_url": repository_url,
        "repository_id": repository_id,
        "head_repository_id": head_repository_id,
        "pull_request_url": pr_url,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "run_id": run_id,
        "artifact": {
            "name": artifact_name,
            "id": artifact_id,
            "digest": artifact_digest,
            "archive_digest": archive_digest,
            "expired": metadata.get("expired") is not False,
        },
        "document_statuses": {
            "supportability": gate.get("owner_status"),
            "copilot_review": copilot.get("owner_status"),
            "architecture": architecture.get("owner_status"),
        },
        "command_gates": _command_gate_evidence(gate),
        "semantic_evidence": semantic_evidence,
        "errors": errors,
    }
    validate_named("judge_evidence_bundle", document)
    return _ValidatedJudgeEvidence(
        _document_json=json.dumps(document, sort_keys=True, separators=(",", ":")),
        archive_path=archive,
        archive_digest=archive_digest,
        artifact_id=_positive_id(artifact_id),
    )


def validate_judge_evidence_pair(
    baseline: Any,
    candidate: Any,
) -> dict[str, Any]:
    errors: list[str] = []
    baseline_evidence = _validated_evidence(baseline, "protected baseline", errors)
    candidate_evidence = _validated_evidence(candidate, "candidate", errors)
    if baseline_evidence is not None and candidate_evidence is not None:
        errors.extend(_pair_errors(baseline_evidence, candidate_evidence))
    baseline_document = baseline_evidence.to_json() if baseline_evidence else {}
    candidate_document = candidate_evidence.to_json() if candidate_evidence else {}
    document = {
        "schema_version": "1.0",
        "owner_status": "RED" if errors else "GREEN",
        "repository_url": baseline_document.get("repository_url", ""),
        "repository_id": baseline_document.get("repository_id", ""),
        "head_repository_id": baseline_document.get("head_repository_id", ""),
        "pull_request_url": baseline_document.get("pull_request_url", ""),
        "base_sha": baseline_document.get("base_sha", ""),
        "head_sha": baseline_document.get("head_sha", ""),
        "run_id": baseline_document.get("run_id", ""),
        "protected_baseline_evidence": _evidence_summary(baseline_document),
        "candidate_evidence": _evidence_summary(candidate_document),
        "errors": errors,
    }
    validate_named("judge_evidence_pair", document)
    return document


def _validated_evidence(
    value: Any,
    label: str,
    errors: list[str],
) -> _ValidatedJudgeEvidence | None:
    if not isinstance(value, _ValidatedJudgeEvidence):
        errors.append(f"{label} evidence must come from archive validation")
        return None
    errors.extend(_bundle_integrity_errors(label, value.to_json()))
    return value


def _pair_errors(
    baseline: _ValidatedJudgeEvidence,
    candidate: _ValidatedJudgeEvidence,
) -> list[str]:
    errors: list[str] = []
    if baseline.get("role") != "protected_baseline":
        errors.append("protected baseline evidence role is invalid")
    if candidate.get("role") != "candidate":
        errors.append("candidate evidence role is invalid")
    for field in (
        "repository_url",
        "repository_id",
        "head_repository_id",
        "pull_request_url",
        "base_sha",
        "head_sha",
        "run_id",
    ):
        if baseline.get(field) != candidate.get(field):
            errors.append(f"judge evidence {field} bindings must match")
    if baseline.archive_path == candidate.archive_path:
        errors.append("judge evidence archives must be distinct files")
    if baseline.archive_digest == candidate.archive_digest:
        errors.append("judge evidence archive digests must be distinct")
    if baseline.artifact_id == candidate.artifact_id:
        errors.append("judge evidence artifact IDs must be distinct")
    if baseline.get("command_gates") != candidate.get("command_gates"):
        errors.append("baseline and candidate command gate evidence must match")
    if baseline.get("semantic_evidence") != candidate.get("semantic_evidence"):
        errors.append("baseline and candidate semantic evidence must match")
    return errors


def _bundle_integrity_errors(label: str, evidence: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        validate_named("judge_evidence_bundle", evidence)
    except (KeyError, FileNotFoundError, SchemaValidationError) as exc:
        return [f"{label} evidence schema invalid: {exc}"]
    statuses = evidence.get("document_statuses")
    statuses = statuses if isinstance(statuses, dict) else {}
    for name in ("supportability", "copilot_review", "architecture"):
        if statuses.get(name) != "GREEN":
            errors.append(f"{label} document status must be GREEN: {name}")
    if evidence.get("owner_status") != "GREEN" or evidence.get("errors"):
        errors.append(f"{label} evidence must be GREEN with no errors")
    return errors


def _archive_identity(path: Any, errors: list[str]) -> tuple[Path, str, bytes]:
    if not isinstance(path, Path):
        errors.append("artifact archive path must be a Path")
        return Path(), "", b""
    try:
        if path.is_symlink():
            raise OSError("archive must not be a symlink")
        archive = path.resolve(strict=True)
        if not archive.is_file():
            raise OSError("archive must be a regular non-symlink file")
        with archive.open("rb") as stream:
            archive_bytes = stream.read(MAX_ARCHIVE_BYTES + 1)
        if not archive_bytes or len(archive_bytes) > MAX_ARCHIVE_BYTES:
            raise OSError("archive size is outside allowed bounds")
        digest = f"sha256:{hashlib.sha256(archive_bytes).hexdigest()}"
        return archive, digest, archive_bytes
    except (OSError, RuntimeError) as exc:
        errors.append(f"artifact archive invalid: {exc}")
        return Path(), "", b""


def _load_archive_documents(
    archive_bytes: bytes,
    errors: list[str],
) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zipped:
            infos = zipped.infolist()
            errors.extend(_archive_entry_errors(infos))
            if errors:
                return documents
            by_name = {info.filename: info for info in infos if not info.is_dir()}
            for filename, schema_name in DOCUMENT_SCHEMAS.items():
                info = by_name.get(filename)
                if info is None:
                    errors.append(f"{filename} must exist exactly once at archive root")
                    continue
                _load_document(zipped, info, filename, schema_name, documents, errors)
    except (
        OSError,
        RuntimeError,
        NotImplementedError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        errors.append(f"artifact archive load failed: {type(exc).__name__}: {exc}")
    return documents


def _archive_entry_errors(infos: list[zipfile.ZipInfo]) -> list[str]:
    errors: list[str] = []
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        errors.append("artifact archive contains too many entries")
    total_size = 0
    seen: set[str] = set()
    for info in infos:
        path = PurePosixPath(info.filename)
        mode = (info.external_attr >> 16) & 0o170000
        if (
            path.is_absolute()
            or ".." in path.parts
            or len(path.parts) != 1
            or str(path) != info.filename
            or "\\" in info.filename
        ):
            errors.append(
                f"artifact archive entry is not root-contained: {info.filename}"
            )
        if info.is_dir() or mode == stat.S_IFDIR:
            errors.append(f"artifact archive entry must be a file: {info.filename}")
        elif mode not in {0, stat.S_IFREG}:
            errors.append(f"artifact archive entry type is unsafe: {info.filename}")
        if info.filename in seen:
            errors.append(f"artifact archive entry is duplicated: {info.filename}")
        seen.add(info.filename)
        if info.file_size > MAX_ENTRY_BYTES:
            errors.append(f"artifact archive entry is too large: {info.filename}")
        if info.file_size > MAX_COMPRESSION_RATIO * max(info.compress_size, 1):
            errors.append(
                f"artifact archive entry compression ratio is unsafe: {info.filename}"
            )
        total_size += info.file_size
    if total_size > MAX_TOTAL_BYTES:
        errors.append("artifact archive expanded size exceeds limit")
    return errors


def _load_document(
    zipped: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    filename: str,
    schema_name: str,
    documents: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    try:
        with zipped.open(info) as stream:
            raw = stream.read(MAX_ENTRY_BYTES + 1)
        if len(raw) > MAX_ENTRY_BYTES:
            raise ValueError("document exceeds byte limit")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("document must contain a JSON object")
        validate_named(schema_name, payload)
    except (
        OSError,
        RuntimeError,
        NotImplementedError,
        ValueError,
        zipfile.BadZipFile,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        SchemaValidationError,
    ) as exc:
        errors.append(f"{filename} invalid: {type(exc).__name__}: {exc}")
        return
    documents[filename] = payload


def _binding_errors(
    role: str,
    repository_url: str,
    repository_id: str,
    head_repository_id: str,
    pr_url: str,
    base_sha: str,
    head_sha: str,
    run_id: str,
    artifact_name: str,
    artifact_id: str,
    artifact_digest: str,
    artifact_metadata: dict[str, Any],
    archive_digest: str,
) -> list[str]:
    errors = _target_binding_errors(repository_url, pr_url, base_sha, head_sha)
    if _positive_id(repository_id) is None:
        errors.append("repository_id must be canonical positive decimal")
    if _positive_id(head_repository_id) is None:
        errors.append("head_repository_id must be canonical positive decimal")
    if role not in ROLE_ARTIFACT_NAMES:
        errors.append("judge evidence role is unsupported")
    elif artifact_name != ROLE_ARTIFACT_NAMES[role]:
        errors.append(f"{role} artifact name is invalid")
    if _positive_id(run_id) is None:
        errors.append("run_id must be canonical positive decimal")
    if _positive_id(artifact_id) is None:
        errors.append("artifact_id must be canonical positive decimal")
    if not DIGEST_RE.fullmatch(artifact_digest):
        errors.append("artifact_digest must be sha256:<lowercase hex>")
    errors.extend(
        _artifact_metadata_errors(
            artifact_metadata,
            artifact_name,
            artifact_id,
            artifact_digest,
            run_id,
            archive_digest,
            repository_id,
            head_repository_id,
            head_sha,
        )
    )
    return errors


def _target_binding_errors(
    repository_url: str,
    pr_url: str,
    base_sha: str,
    head_sha: str,
) -> list[str]:
    errors: list[str] = []
    repository_match = REPOSITORY_URL_RE.fullmatch(repository_url)
    pr_match = PR_URL_RE.fullmatch(pr_url)
    if repository_match is None:
        errors.append("repository_url must be a canonical GitHub repository URL")
    if pr_match is None:
        errors.append("pr_url must be a canonical GitHub pull request URL")
    if (
        repository_match
        and pr_match
        and repository_match.group("slug") != pr_match.group("slug")
    ):
        errors.append("pr_url repository must match repository_url")
    if not SHA_RE.fullmatch(base_sha):
        errors.append("base_sha must be a full lowercase Git SHA")
    if not SHA_RE.fullmatch(head_sha):
        errors.append("head_sha must be a full lowercase Git SHA")
    return errors


def _artifact_metadata_errors(
    metadata: dict[str, Any],
    name: str,
    artifact_id: str,
    digest: str,
    run_id: str,
    archive_digest: str,
    repository_id: str,
    head_repository_id: str,
    head_sha: str,
) -> list[str]:
    errors: list[str] = []
    workflow_run = metadata.get("workflow_run")
    workflow_run = workflow_run if isinstance(workflow_run, dict) else {}
    expected = {
        "id": artifact_id,
        "name": name,
        "digest": digest,
        "run_id": run_id,
        "archive_digest": digest,
        "head_sha": head_sha,
        "repository_id": repository_id,
        "head_repository_id": head_repository_id,
    }
    actual = {
        "id": str(metadata.get("id") or ""),
        "name": metadata.get("name"),
        "digest": metadata.get("digest"),
        "run_id": str(workflow_run.get("id") or ""),
        "archive_digest": archive_digest,
        "head_sha": workflow_run.get("head_sha"),
        "repository_id": str(workflow_run.get("repository_id") or ""),
        "head_repository_id": str(workflow_run.get("head_repository_id") or ""),
    }
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"artifact {field} does not match trusted binding")
    if metadata.get("expired") is not False:
        errors.append("artifact must be present and unexpired")
    return errors


def _document_identity_errors(
    gate: dict[str, Any],
    copilot: dict[str, Any],
    architecture: dict[str, Any],
    repository_url: str,
    pr_url: str,
    base_sha: str,
    head_sha: str,
) -> list[str]:
    errors: list[str] = []
    for field, expected in {
        "repository_url": repository_url,
        "pull_request_url": pr_url,
        "base_sha": base_sha,
        "head_sha": head_sha,
    }.items():
        if gate.get(field) != expected:
            errors.append(f"supportability {field} does not match expected identity")
    for field, expected in {"base_sha": base_sha, "head_sha": head_sha}.items():
        if architecture.get(field) != expected:
            errors.append(f"architecture {field} does not match expected identity")
    repository_match = REPOSITORY_URL_RE.fullmatch(repository_url)
    pr_match = PR_URL_RE.fullmatch(pr_url)
    expected_repository = repository_match.group("slug") if repository_match else ""
    expected_pr = int(pr_match.group("number")) if pr_match else None
    if copilot.get("repository") != expected_repository:
        errors.append("Copilot repository does not match expected identity")
    if copilot.get("pull_request_number") != expected_pr:
        errors.append("Copilot pull request does not match expected identity")
    if copilot.get("head_sha") != head_sha:
        errors.append("Copilot head_sha does not match expected identity")
    return errors


def _gate_errors(gate: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if gate.get("owner_status") != "GREEN":
        errors.append("supportability gate must be GREEN")
    if gate.get("errors"):
        errors.append("supportability gate errors must be empty")
    by_gate = _commands_by_gate(gate)
    for name, matches in sorted(by_gate.items()):
        if name in REQUIRED_COMMAND_GATES:
            if not all(_passing_command(command) for command in matches):
                errors.append(f"required command gate must pass: {name}")
        elif not _valid_optional_commands(matches):
            errors.append(f"optional command gate evidence is invalid: {name}")
    for required in sorted(REQUIRED_COMMAND_GATES):
        if not by_gate.get(required):
            errors.append(f"required command gate is missing: {required}")
    return errors


def _commands_by_gate(gate: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    raw_commands = gate.get("commands")
    commands: list[Any] = raw_commands if isinstance(raw_commands, list) else []
    by_gate: dict[str, list[dict[str, Any]]] = {}
    for command in commands:
        if isinstance(command, dict):
            by_gate.setdefault(str(command.get("gate") or ""), []).append(command)
    return by_gate


def _command_gate_evidence(gate: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {
        name: [
            {
                "command": str(command.get("command") or ""),
                "status": command.get("status"),
                "exit_code": command.get("exit_code"),
            }
            for command in commands
        ]
        for name, commands in sorted(_commands_by_gate(gate).items())
    }


def _passing_command(command: dict[str, Any]) -> bool:
    return command.get("status") == "PASS" and command.get("exit_code") == 0


def _valid_optional_commands(commands: list[dict[str, Any]]) -> bool:
    if commands and all(_passing_command(command) for command in commands):
        return True
    return (
        len(commands) == 1
        and commands[0].get("status") == "SKIPPED"
        and commands[0].get("exit_code") is None
        and not commands[0].get("command")
    )


def _semantic_evidence(
    gate: dict[str, Any], architecture: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    standard = _standard_evidence(gate.get("standard"), errors)
    changed = _file_list(gate.get("changed_files"), "changed_files", errors)
    high_risk = _file_list(gate.get("high_risk_files"), "high_risk_files", errors)
    architecture_changed = _file_list(
        architecture.get("changed_files"), "architecture.changed_files", errors
    )
    if changed != architecture_changed:
        errors.append(
            "architecture changed_files must match supportability changed_files"
        )
    coverage = _coverage_evidence(gate.get("coverage"), changed, high_risk, errors)
    behavior_fixtures = _behavior_fixture_evidence(
        architecture.get("behavior_fixtures"), errors
    )
    rule_results = _rule_result_evidence(architecture.get("rule_results"), errors)
    return {
        "standard": standard,
        "changed_files": changed,
        "high_risk_files": high_risk,
        "coverage": coverage,
        "architecture_changed_files": architecture_changed,
        "architecture_behavior_fixtures": behavior_fixtures,
        "architecture_rule_results": rule_results,
        "architecture_counts": {
            name: len(architecture.get(name) or [])
            for name in (
                "violations",
                "new_violations",
                "existing_violations",
                "known_debt_applied",
                "expired_known_debt",
            )
        },
    }, errors


def _standard_evidence(value: Any, errors: list[str]) -> dict[str, str]:
    standard = value if isinstance(value, dict) else {}
    result = {
        "name": str(standard.get("name") or ""),
        "source": str(standard.get("source") or ""),
        "hash": str(standard.get("hash") or ""),
    }
    if not result["name"] or not result["source"]:
        errors.append("supportability standard name and source are required")
    if not re.fullmatch(r"[0-9a-f]{64}", result["hash"]):
        errors.append("supportability standard hash must be lowercase SHA-256")
    return result


def _file_list(value: Any, label: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        errors.append(f"{label} must contain file path strings")
        return []
    normalized = sorted(value)
    if len(normalized) != len(set(normalized)):
        errors.append(f"{label} must not contain duplicates")
    return normalized


def _coverage_evidence(
    value: Any,
    changed: list[str],
    high_risk: list[str],
    errors: list[str],
) -> dict[str, Any]:
    coverage = value if isinstance(value, dict) else {}
    changed_coverage = _coverage_map(coverage.get("changed_files"), "changed", errors)
    high_risk_coverage = _coverage_map(
        coverage.get("high_risk_files"), "high-risk", errors
    )
    if sorted(changed_coverage) != changed:
        errors.append("coverage changed_files must exactly match changed_files")
    if sorted(high_risk_coverage) != high_risk:
        errors.append("coverage high_risk_files must exactly match high_risk_files")
    excluded_changed = _file_list(
        coverage.get("excluded_changed_files"), "excluded_changed_files", errors
    )
    excluded_high_risk = _file_list(
        coverage.get("excluded_high_risk_files"), "excluded_high_risk_files", errors
    )
    scope_narrowing = _string_list(
        coverage.get("scope_narrowing_detected"), "scope_narrowing_detected", errors
    )
    threshold_weakening = _string_list(
        coverage.get("threshold_weakening_detected"),
        "threshold_weakening_detected",
        errors,
    )
    if excluded_changed or excluded_high_risk:
        errors.append("coverage exclusions must be empty")
    if scope_narrowing or threshold_weakening:
        errors.append("coverage weakening evidence must be empty")
    return {
        "changed_files": changed_coverage,
        "high_risk_files": high_risk_coverage,
        "excluded_changed_files": excluded_changed,
        "excluded_high_risk_files": excluded_high_risk,
        "scope_narrowing_detected": scope_narrowing,
        "threshold_weakening_detected": threshold_weakening,
    }


def _coverage_map(value: Any, label: str, errors: list[str]) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        errors.append(f"{label} coverage must be an object")
        return {}
    result: dict[str, list[str]] = {}
    for path, gates in value.items():
        if not isinstance(path, str) or not path:
            errors.append(f"{label} coverage path is invalid")
            continue
        normalized = _string_list(gates, f"{label} coverage gates", errors)
        if not normalized:
            errors.append(f"{label} coverage gates must not be empty: {path}")
        result[path] = normalized
    return {path: result[path] for path in sorted(result)}


def _string_list(value: Any, label: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{label} must be a string list")
        return []
    return sorted(value)


def _behavior_fixture_evidence(value: Any, errors: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        errors.append("architecture behavior fixtures must be non-empty")
        return []
    fixtures: list[dict[str, Any]] = []
    for fixture in value:
        if not isinstance(fixture, dict) or fixture.get("status") != "PASS":
            errors.append("architecture behavior fixture must be a PASS object")
            continue
        fixtures.append(_canonical_fixture(fixture))
    names = {str(fixture.get("name") or "") for fixture in fixtures}
    if not any("positive" in name for name in names):
        errors.append("architecture behavior fixtures require a positive control")
    if not any("negative" in name for name in names):
        errors.append("architecture behavior fixtures require a negative control")
    return sorted(fixtures, key=lambda fixture: str(fixture.get("name") or ""))


def _canonical_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(fixture.get("name") or ""),
        "status": fixture.get("status"),
        "expected": sorted(str(item) for item in (fixture.get("expected") or [])),
        "observed": sorted(str(item) for item in (fixture.get("observed") or [])),
    }


def _rule_result_evidence(value: Any, errors: list[str]) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        errors.append("architecture rule_results must be non-empty")
        return {}
    result = {str(name): str(status) for name, status in value.items()}
    if any(status != "PASS" for status in result.values()):
        errors.append("architecture rule_results must all PASS")
    return {name: result[name] for name in sorted(result)}


def _copilot_errors(copilot: dict[str, Any], head_sha: str) -> list[str]:
    errors: list[str] = []
    if copilot.get("owner_status") != "GREEN":
        errors.append("Copilot review gate must be GREEN")
    if copilot.get("errors"):
        errors.append("Copilot review errors must be empty")
    raw_review = copilot.get("review_status")
    review: dict[str, Any] = raw_review if isinstance(raw_review, dict) else {}
    errors.extend(_copilot_review_status_errors(review, head_sha))
    return errors


def _copilot_review_status_errors(review: dict[str, Any], head_sha: str) -> list[str]:
    errors: list[str] = []
    if review.get("latest_head_reviewed") is not True:
        errors.append("Copilot review must cover latest head")
    if review.get("reviewed_commit_sha") != head_sha:
        errors.append("Copilot reviewed commit does not match head")
    if (
        review.get("blocking_thread_count") != 0
        or review.get("blocking_comment_count") != 0
    ):
        errors.append("Copilot review contains blocking evidence")
    if review.get("open_finding_count") not in {0, None}:
        errors.append("Copilot review contains open findings")
    errors.extend(_copilot_verdict_errors(review, head_sha))
    return errors


def _copilot_verdict_errors(review: dict[str, Any], head_sha: str) -> list[str]:
    errors: list[str] = []
    verdict = review.get("verdict")
    if verdict == "native_clean":
        if review.get("reviewer") != NATIVE_COPILOT_REVIEWER:
            errors.append("native Copilot reviewer identity is invalid")
        if review.get("commit_oid") != head_sha:
            errors.append("native Copilot commit identity does not match head")
    elif verdict == "clean":
        if review.get("reviewer") != STRUCTURED_COPILOT_COMMENTER:
            errors.append("structured Copilot reviewer identity is invalid")
        if (
            review.get("structured_evidence_present") is not True
            or review.get("structured_evidence_valid") is not True
        ):
            errors.append("structured Copilot evidence must be present and valid")
    else:
        errors.append("Copilot review verdict must be clean evidence")
    return errors


def _architecture_errors(architecture: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field, value in {
        "owner_status": "GREEN",
        "enforcement_mode": "block_all",
        "gate_implementation": "PASS",
        "repo_architecture_supportability": "PASS",
        "architecture_behavior_proof": "PASS",
    }.items():
        if architecture.get(field) != value:
            errors.append(f"architecture {field} must be {value}")
    for field in (
        "violations",
        "new_violations",
        "existing_violations",
        "known_debt_applied",
        "expired_known_debt",
        "errors",
    ):
        if architecture.get(field):
            errors.append(f"architecture {field} must be empty")
    return errors


def _evidence_summary(evidence: dict[str, Any]) -> dict[str, Any]:
    artifact = evidence.get("artifact")
    return {
        "role": evidence.get("role"),
        "owner_status": evidence.get("owner_status"),
        "artifact": artifact if isinstance(artifact, dict) else {},
        "document_statuses": evidence.get("document_statuses", {}),
        "command_gates": evidence.get("command_gates", {}),
        "semantic_evidence": evidence.get("semantic_evidence", {}),
        "errors": evidence.get("errors", []),
    }


def _positive_id(value: str) -> int | None:
    return int(value) if POSITIVE_ID_RE.fullmatch(value) else None
