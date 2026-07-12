from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from governance_eval.judge_evidence import (
    validate_judge_evidence_bundle,
    validate_judge_evidence_pair,
)
from governance_eval.schemas import validate_named


BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
REPOSITORY_URL = "https://github.com/markheck-solutions/governance.git"
PR_URL = "https://github.com/markheck-solutions/governance/pull/26"


class JudgeEvidenceBundleTests(unittest.TestCase):
    def test_accepts_complete_candidate_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = _create_archive(Path(tmp) / "candidate.zip")
            result = _validate(archive, role="candidate", artifact_id="456")

        self.assertEqual(result["owner_status"], "GREEN", result["errors"])
        self.assertEqual(result["role"], "candidate")
        validate_named("judge_evidence_bundle", result.to_json())

    def test_accepts_distinct_green_judge_archives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = _validate(
                _create_archive(root / "baseline.zip", generated_at="2026-07-12T17:00:00Z"),
                role="protected_baseline",
                artifact_id="456",
            )
            candidate = _validate(
                _create_archive(root / "candidate.zip", generated_at="2026-07-12T17:00:01Z"),
                role="candidate",
                artifact_id="789",
            )

            result = validate_judge_evidence_pair(baseline, candidate)

        self.assertEqual(result["owner_status"], "GREEN", result["errors"])
        validate_named("judge_evidence_pair", result)

    def test_rejects_same_archive_reused_for_both_roles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = _create_archive(Path(tmp) / "shared.zip")
            baseline = _validate(archive, role="protected_baseline", artifact_id="456")
            candidate = _validate(archive, role="candidate", artifact_id="789")

            result = validate_judge_evidence_pair(baseline, candidate)

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("archive" in error for error in result["errors"]))

    def test_rejects_forged_or_nonobject_pair_inputs(self) -> None:
        forged = {
            "schema_version": "1.0",
            "role": "protected_baseline",
            "owner_status": "GREEN",
            "errors": [],
        }
        for baseline, candidate in ((forged, forged), (None, []), ("bad", {})):
            with self.subTest(baseline=baseline, candidate=candidate):
                result = validate_judge_evidence_pair(baseline, candidate)
                self.assertEqual(result["owner_status"], "RED")
                self.assertTrue(any("archive validation" in error for error in result["errors"]))

    def test_candidate_green_cannot_mask_forged_baseline_document_red(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = _validate(
                _create_archive(root / "baseline.zip"),
                role="protected_baseline",
                artifact_id="456",
            )
            candidate = _validate(
                _create_archive(root / "candidate.zip", generated_at="2026-07-12T17:00:01Z"),
                role="candidate",
                artifact_id="789",
            )
            forged_baseline = baseline.to_json()
            forged_baseline["document_statuses"]["supportability"] = "RED"
            forged_baseline["owner_status"] = "GREEN"
            forged_baseline["errors"] = []

            result = validate_judge_evidence_pair(forged_baseline, candidate)

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("archive validation" in error for error in result["errors"]))

    def test_rejects_owner_forged_native_review_identity(self) -> None:
        def mutate(documents: dict[str, dict[str, Any]]) -> None:
            documents["copilot-review-gate-result.json"]["review_status"]["reviewer"] = "markheck-solutions"

        with tempfile.TemporaryDirectory() as tmp:
            archive = _create_archive(Path(tmp) / "forged.zip", mutate=mutate)
            result = _validate(archive, role="candidate", artifact_id="456")

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("reviewer" in error for error in result["errors"]))

    def test_rejects_missing_malformed_and_nested_duplicate_documents(self) -> None:
        mutations = ("missing", "malformed", "nested")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                documents = _documents()
                extras: dict[str, bytes] = {}
                if mutation == "missing":
                    del documents["supportability-gate-result.json"]
                elif mutation == "malformed":
                    extras["supportability-gate-result.json"] = b"{bad"
                    del documents["supportability-gate-result.json"]
                else:
                    extras["nested/supportability-gate-result.json"] = json.dumps(
                        documents["supportability-gate-result.json"]
                    ).encode()
                archive = _create_archive(
                    Path(tmp) / "bad.zip",
                    documents=documents,
                    extras=extras,
                )
                result = _validate(archive, role="candidate", artifact_id="456")

            self.assertEqual(result["owner_status"], "RED")

    def test_rejects_failed_skipped_and_duplicate_dynamic_command_gates(self) -> None:
        cases = (
            ("package_audit", "FAIL", 1, False),
            ("sql_supportability", "SKIPPED", None, False),
            ("package_audit", "PASS", 0, True),
        )
        for gate, status, exit_code, duplicate in cases:
            with self.subTest(gate=gate, status=status, duplicate=duplicate), tempfile.TemporaryDirectory() as tmp:
                def mutate(documents: dict[str, dict[str, Any]]) -> None:
                    command = _command(gate, status=status, exit_code=exit_code)
                    documents["supportability-gate-result.json"]["commands"].append(command)
                    if duplicate:
                        documents["supportability-gate-result.json"]["commands"].append(dict(command))

                archive = _create_archive(Path(tmp) / "commands.zip", mutate=mutate)
                result = _validate(archive, role="candidate", artifact_id="456")

            self.assertEqual(result["owner_status"], "RED")
            self.assertTrue(any("command gate" in error for error in result["errors"]))

    def test_rejects_cross_repository_pr_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = _create_archive(
                Path(tmp) / "identity.zip",
                pr_url="https://github.com/attacker/other/pull/26",
            )
            result = _validate(
                archive,
                role="candidate",
                artifact_id="456",
                pr_url="https://github.com/attacker/other/pull/26",
            )

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("must match" in error for error in result["errors"]))

    def test_rejects_noncanonical_artifact_and_run_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = _create_archive(Path(tmp) / "ids.zip")
            result = _validate(
                archive,
                role="candidate",
                artifact_id="01",
                run_id="00",
            )

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("canonical positive decimal" in error for error in result["errors"]))

    def test_rejects_unbound_artifact_metadata_or_archive_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = _create_archive(Path(tmp) / "binding.zip")
            digest = _digest(archive)
            metadata = _metadata("candidate", "456", "123", digest)
            metadata["workflow_run"]["id"] = 999
            result = _validate(
                archive,
                role="candidate",
                artifact_id="456",
                metadata=metadata,
            )

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("run_id" in error for error in result["errors"]))

    def test_rejects_stale_artifact_workflow_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = _create_archive(Path(tmp) / "stale.zip")
            digest = _digest(archive)
            metadata = _metadata("candidate", "456", "123", digest)
            metadata["workflow_run"]["head_sha"] = "c" * 40

            result = _validate(
                archive,
                role="candidate",
                artifact_id="456",
                metadata=metadata,
            )

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("head_sha" in error for error in result["errors"]))

    def test_pair_rejects_candidate_semantic_omission_extra_and_standard_drift(self) -> None:
        mutations = ("omit", "extra", "standard")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                baseline = _validate(
                    _create_archive(root / "baseline.zip"),
                    role="protected_baseline",
                    artifact_id="456",
                )

                def mutate(documents: dict[str, dict[str, Any]]) -> None:
                    gate = documents["supportability-gate-result.json"]
                    architecture = documents["architecture-gate-result.json"]
                    if mutation == "omit":
                        gate["changed_files"] = []
                        gate["high_risk_files"] = []
                        gate["coverage"]["changed_files"] = {}
                        gate["coverage"]["high_risk_files"] = {}
                        architecture["changed_files"] = []
                    elif mutation == "extra":
                        gate["changed_files"].append("src/extra.py")
                        gate["coverage"]["changed_files"]["src/extra.py"] = ["tests"]
                        architecture["changed_files"].append("src/extra.py")
                    else:
                        gate["standard"]["hash"] = "f" * 64

                candidate = _validate(
                    _create_archive(
                        root / "candidate.zip",
                        generated_at="2026-07-12T17:00:01Z",
                        mutate=mutate,
                    ),
                    role="candidate",
                    artifact_id="789",
                )
                self.assertEqual(candidate["owner_status"], "GREEN", candidate["errors"])

                result = validate_judge_evidence_pair(baseline, candidate)

            self.assertEqual(result["owner_status"], "RED")
            self.assertTrue(any("semantic" in error for error in result["errors"]))

    def test_bundle_rejects_coverage_exclusion_and_architecture_mismatch(self) -> None:
        mutations = ("excluded", "architecture", "fixtures")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                def mutate(documents: dict[str, dict[str, Any]]) -> None:
                    gate = documents["supportability-gate-result.json"]
                    architecture = documents["architecture-gate-result.json"]
                    if mutation == "excluded":
                        gate["coverage"]["excluded_changed_files"] = [
                            "governance_eval/judge_evidence.py"
                        ]
                    elif mutation == "architecture":
                        architecture["changed_files"] = []
                    else:
                        architecture["behavior_fixtures"] = []

                archive = _create_archive(Path(tmp) / "semantic.zip", mutate=mutate)
                result = _validate(archive, role="candidate", artifact_id="456")

            self.assertEqual(result["owner_status"], "RED")

    def test_rejects_nonobject_artifact_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = _create_archive(Path(tmp) / "metadata.zip")
            result = _validate(
                archive,
                role="candidate",
                artifact_id="456",
                metadata="not-an-object",
            )

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("metadata" in error for error in result["errors"]))

    def test_rejects_nonpath_archive_without_crashing(self) -> None:
        result = _validate(
            "not-a-path",  # type: ignore[arg-type]
            role="candidate",
            artifact_id="456",
        )

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("archive path" in error for error in result["errors"]))

    def test_rejects_zip_traversal_symlink_and_oversize_entries(self) -> None:
        cases = ("traversal", "symlink", "oversize")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                archive = Path(tmp) / f"{case}.zip"
                _write_malicious_archive(archive, case)
                result = _validate(archive, role="candidate", artifact_id="456")
                self.assertEqual(result["owner_status"], "RED")

    def test_rejects_unsupported_zip_entry_read_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = _create_archive(Path(tmp) / "unsupported.zip")
            with mock.patch.object(
                zipfile.ZipFile,
                "open",
                side_effect=NotImplementedError("unsupported compression"),
            ):
                result = _validate(archive, role="candidate", artifact_id="456")

        self.assertEqual(result["owner_status"], "RED")
        self.assertTrue(any("unsupported" in error for error in result["errors"]))


def _validate(
    archive: Any,
    *,
    role: str,
    artifact_id: str,
    run_id: str = "123",
    repository_url: str = REPOSITORY_URL,
    pr_url: str = PR_URL,
    metadata: Any = None,
):
    digest = _digest(archive) if isinstance(archive, Path) else f"sha256:{'0' * 64}"
    artifact_name = (
        "baseline-supportability-gate-evidence"
        if role == "protected_baseline"
        else "candidate-supportability-gate-evidence"
    )
    return validate_judge_evidence_bundle(
        archive,
        role=role,  # type: ignore[arg-type]
        repository_url=repository_url,
        repository_id="999",
        head_repository_id="999",
        pr_url=pr_url,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        run_id=run_id,
        artifact_name=artifact_name,
        artifact_id=artifact_id,
        artifact_digest=digest,
        artifact_metadata=(
            metadata
            if metadata is not None
            else _metadata(role, artifact_id, run_id, digest)
        ),
    )


def _metadata(role: str, artifact_id: str, run_id: str, digest: str) -> dict[str, Any]:
    return {
        "id": int(artifact_id),
        "name": (
            "baseline-supportability-gate-evidence"
            if role == "protected_baseline"
            else "candidate-supportability-gate-evidence"
        ),
        "digest": digest,
        "expired": False,
        "workflow_run": {
            "id": int(run_id),
            "head_sha": HEAD_SHA,
            "repository_id": 999,
            "head_repository_id": 999,
        },
    }


def _create_archive(
    path: Path,
    *,
    generated_at: str = "2026-07-12T17:00:00Z",
    pr_url: str = PR_URL,
    mutate: Callable[[dict[str, dict[str, Any]]], None] | None = None,
    documents: dict[str, dict[str, Any]] | None = None,
    extras: dict[str, bytes] | None = None,
) -> Path:
    payloads = documents or _documents(generated_at=generated_at, pr_url=pr_url)
    if mutate:
        mutate(payloads)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, payload in payloads.items():
            _writestr(zipped, name, json.dumps(payload, sort_keys=True).encode())
        for name, payload in (extras or {}).items():
            _writestr(zipped, name, payload)
    return path


def _writestr(zipped: zipfile.ZipFile, name: str, payload: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 7, 12, 17, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    zipped.writestr(info, payload)


def _write_malicious_archive(path: Path, case: str) -> None:
    documents = _documents()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, payload in documents.items():
            _writestr(zipped, name, json.dumps(payload).encode())
        if case == "traversal":
            _writestr(zipped, "../escape.json", b"{}")
        elif case == "symlink":
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zipped.writestr(info, b"supportability-gate-result.json")
        else:
            _writestr(zipped, "oversize.txt", b"x" * (5 * 1024 * 1024 + 1))


def _digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _documents(
    *, generated_at: str = "2026-07-12T17:00:00Z", pr_url: str = PR_URL
) -> dict[str, dict[str, Any]]:
    return {
        "supportability-gate-result.json": _gate_result(generated_at, pr_url),
        "copilot-review-gate-result.json": _copilot_result(generated_at),
        "architecture-gate-result.json": _architecture_result(generated_at),
    }


def _gate_result(generated_at: str, pr_url: str) -> dict[str, Any]:
    gates = (
        "lint",
        "format_check",
        "typecheck",
        "complexity",
        "architecture",
        "tests",
        "compile_or_build",
    )
    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "owner_status": "GREEN",
        "repository_url": REPOSITORY_URL,
        "pull_request_url": pr_url,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "standard": {
            "name": "supportability-standard",
            "source": "docs/reference/supportability-standard.md",
            "hash": "e" * 64,
        },
        "changed_files": ["governance_eval/judge_evidence.py"],
        "high_risk_files": ["governance_eval/supportability.py"],
        "coverage": {
            "changed_files": {
                "governance_eval/judge_evidence.py": list(gates),
            },
            "high_risk_files": {
                "governance_eval/supportability.py": list(gates),
            },
            "excluded_changed_files": [],
            "excluded_high_risk_files": [],
            "scope_narrowing_detected": [],
            "threshold_weakening_detected": [],
        },
        "commands": [
            *[_command(gate) for gate in gates],
            _command("lint", command="run lint second"),
            _command("package_audit", status="SKIPPED", exit_code=None, command=""),
            _command("sql_supportability", status="SKIPPED", exit_code=None, command=""),
        ],
        "errors": [],
    }


def _command(
    gate: str,
    *,
    status: str = "PASS",
    exit_code: int | None = 0,
    command: str | None = None,
) -> dict[str, Any]:
    return {
        "gate": gate,
        "command": f"run {gate}" if command is None else command,
        "status": status,
        "exit_code": exit_code,
        "stdout": "",
        "stderr": "",
    }


def _copilot_result(generated_at: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "owner_status": "GREEN",
        "repository": "markheck-solutions/governance",
        "pull_request_number": 26,
        "head_sha": HEAD_SHA,
        "reviewer_login_patterns": [],
        "review_status": {
            "latest_head_reviewed": True,
            "reviewer": "copilot-pull-request-reviewer",
            "submitted_at": generated_at,
            "commit_oid": HEAD_SHA,
            "structured_evidence_present": False,
            "structured_evidence_valid": False,
            "reviewed_commit_sha": HEAD_SHA,
            "verdict": "native_clean",
            "open_finding_count": 0,
            "blocking_thread_count": 0,
            "blocking_comment_count": 0,
        },
        "review_request": {"prompt": "review exact head"},
        "errors": [],
    }


def _architecture_result(generated_at: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "owner_status": "GREEN",
        "enforcement_mode": "block_all",
        "gate_implementation": "PASS",
        "repo_architecture_supportability": "PASS",
        "architecture_behavior_proof": "PASS",
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "changed_files": ["governance_eval/judge_evidence.py"],
        "violations": [],
        "new_violations": [],
        "existing_violations": [],
        "resolved_violations": [],
        "known_debt_applied": [],
        "expired_known_debt": [],
        "behavior_fixtures": [
            {
                "name": "positive_registered_python_module",
                "status": "PASS",
                "expected": [],
                "observed": [],
            },
            {
                "name": "negative_forbidden_dependency",
                "status": "PASS",
                "expected": ["python_dependency_direction"],
                "observed": ["python_dependency_direction"],
            },
        ],
        "rule_results": {
            "changed_file_architecture_coverage": "PASS",
            "python_dependency_direction": "PASS",
        },
        "errors": [],
    }


if __name__ == "__main__":
    unittest.main()
