from __future__ import annotations

import json
import stat
import unittest
import warnings
import zipfile
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from governance_eval.artifact_verifier import (
    GITHUB_ACTIONS_APP_ID,
    REQUIRED_CONTEXT,
    VerifierContext,
    check_run_request,
    verify_candidate_artifact,
)
from governance_eval.candidate_bundle import (
    CandidateBundleError,
    artifact_name,
    build_candidate_bundle,
    recompute_decision,
)
from governance_eval.hashing import sha256_json
from test_execution_result_v2 import _result


WORKFLOW_PATH = ".github/workflows/governance-candidate.yml"
WORKFLOW_FILE_SHA256 = "5" * 64


def _payloads(
    *, ai_review: dict[str, object] | None = None
) -> tuple[dict[str, bytes], object, object, dict[str, object]]:
    result, plan, receipt = _result()
    payloads = build_candidate_bundle(
        receipt=receipt,
        plan=plan,
        result=result,
        workflow_path=WORKFLOW_PATH,
        workflow_commit_sha=receipt.pull_request["head_sha"],
        workflow_file_sha256=WORKFLOW_FILE_SHA256,
        event_name="pull_request",
        ai_review=ai_review or {"status": "AI_REVIEW_UNAVAILABLE", "findings": []},
    )
    return payloads, plan, receipt, result


def _write_archive(
    root: Path,
    payloads: dict[str, bytes],
    *,
    extra: tuple[str, bytes] | None = None,
    symlink: str | None = None,
    duplicate: str | None = None,
) -> Path:
    archive_path = root / "artifact.zip"
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for name, content in payloads.items():
            archive.writestr(name, content)
        if extra is not None:
            archive.writestr(*extra)
        if symlink is not None:
            info = zipfile.ZipInfo(symlink)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "candidate-bundle.json")
        if duplicate is not None:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(duplicate, payloads[duplicate])
    return archive_path


def _context(archive: Path, receipt: object) -> VerifierContext:
    digest = sha256(archive.read_bytes()).hexdigest()
    return VerifierContext(
        repository_id=receipt.repository["id"],
        repository_full_name=receipt.repository["full_name"],
        pull_request=receipt.pull_request["number"],
        base_sha=receipt.pull_request["base_sha"],
        head_sha=receipt.pull_request["head_sha"],
        head_tree_sha=receipt.pull_request["head_tree_sha"],
        current_head_sha=receipt.pull_request["head_sha"],
        workflow_path=WORKFLOW_PATH,
        workflow_commit_sha=receipt.pull_request["head_sha"],
        workflow_file_sha256=WORKFLOW_FILE_SHA256,
        evaluator_repository_id=receipt.evaluator["repository_id"],
        evaluator_repository_full_name=receipt.evaluator["repository_full_name"],
        evaluator_sha=receipt.evaluator["commit_sha"],
        evaluator_tree_sha=receipt.evaluator["tree_sha"],
        configuration_sha256=receipt.config_sha256,
        standard_sha256=receipt.standard_sha256,
        run_id=receipt.workflow["run_id"],
        run_attempt=receipt.workflow["run_attempt"],
        run_event="pull_request",
        run_status="completed",
        run_conclusion="success",
        run_app_id=GITHUB_ACTIONS_APP_ID,
        artifact_id=777,
        artifact_name=artifact_name(
            receipt.workflow["run_id"], receipt.workflow["run_attempt"]
        ),
        artifact_digest=f"sha256:{digest}",
        artifact_created_at="2026-07-19T12:00:01Z",
        verified_at="2026-07-19T12:00:02Z",
        verifier_app_id=9001,
    )


class CandidateBundleTests(unittest.TestCase):
    def test_ai_unavailable_is_nonblocking(self) -> None:
        payloads, _, _, _ = _payloads()
        manifest = json.loads(payloads["candidate-bundle.json"])

        self.assertEqual(manifest["decision"], {"status": "PASS", "reasons": []})
        self.assertEqual(
            manifest["adapter"]["assurance_class"], "EVALUATOR_AUTHORITATIVE"
        )

    def test_valid_exact_head_p0_p1_p2_finding_blocks(self) -> None:
        for severity in ("P0", "P1", "P2"):
            with self.subTest(severity=severity):
                _, _, receipt, result = _payloads()
                decision = recompute_decision(
                    result,
                    {
                        "status": "AVAILABLE",
                        "findings": [
                            {
                                "severity": severity,
                                "head_sha": receipt.pull_request["head_sha"],
                                "valid": True,
                                "resolved": False,
                            }
                        ],
                    },
                    receipt.pull_request["head_sha"],
                )

                self.assertEqual(decision["status"], "BLOCK_TECHNICAL")

    def test_rejects_non_pull_request_or_non_exact_workflow_identity(self) -> None:
        result, plan, receipt = _result()
        cases = {
            "event": {"event_name": "pull_request_target"},
            "commit": {"workflow_commit_sha": "a" * 40},
            "path": {"workflow_path": ".github/workflows/attacker.yml"},
        }
        defaults = {
            "workflow_path": WORKFLOW_PATH,
            "workflow_commit_sha": receipt.pull_request["head_sha"],
            "workflow_file_sha256": WORKFLOW_FILE_SHA256,
            "event_name": "pull_request",
        }
        for name, mutation in cases.items():
            with self.subTest(name=name), self.assertRaises(CandidateBundleError):
                build_candidate_bundle(
                    receipt=receipt,
                    plan=plan,
                    result=result,
                    ai_review={"status": "AI_REVIEW_UNAVAILABLE", "findings": []},
                    **{**defaults, **mutation},
                )


class ArtifactVerifierTests(unittest.TestCase):
    def test_accepts_exact_current_artifact_and_builds_app_check(self) -> None:
        with TemporaryDirectory() as tmp:
            payloads, _, receipt, _ = _payloads()
            archive = _write_archive(Path(tmp), payloads)

            verified = verify_candidate_artifact(archive, _context(archive, receipt))
            request = check_run_request(verified)

        self.assertEqual(verified["result"], "PASS")
        self.assertEqual(request["name"], REQUIRED_CONTEXT)
        self.assertEqual(request["head_sha"], receipt.pull_request["head_sha"])
        self.assertEqual(request["conclusion"], "success")

    def test_rejects_cross_repo_cross_pr_same_head_and_stale_head_replay(self) -> None:
        mutations = {
            "cross repository": {"repository_id": 999},
            "cross PR": {"pull_request": 82},
            "same head different PR": {"pull_request": 82},
            "stale head": {"current_head_sha": "9" * 40},
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), TemporaryDirectory() as tmp:
                payloads, _, receipt, _ = _payloads()
                archive = _write_archive(Path(tmp), payloads)
                context = replace(_context(archive, receipt), **mutation)

                verified = verify_candidate_artifact(archive, context)

                self.assertEqual(verified["result"], "REJECT")

    def test_rejects_stale_evidence_and_digest_mismatch(self) -> None:
        mutations = {
            "stale": {"verified_at": "2026-07-19T14:00:02Z"},
            "digest": {"artifact_digest": "sha256:" + "0" * 64},
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), TemporaryDirectory() as tmp:
                payloads, _, receipt, _ = _payloads()
                archive = _write_archive(Path(tmp), payloads)
                context = replace(_context(archive, receipt), **mutation)

                verified = verify_candidate_artifact(archive, context)

                self.assertEqual(verified["result"], "REJECT")

    def test_rejects_malformed_json_and_content_digest_mutation(self) -> None:
        for name, content in (
            ("malformed", b"{"),
            ("duplicate-key", b'{"schema_version":"x","schema_version":"y"}'),
        ):
            with self.subTest(name=name), TemporaryDirectory() as tmp:
                payloads, _, receipt, _ = _payloads()
                payloads["candidate-bundle.json"] = content
                archive = _write_archive(Path(tmp), payloads)

                verified = verify_candidate_artifact(
                    archive, _context(archive, receipt)
                )

                self.assertEqual(verified["result"], "REJECT")

        with TemporaryDirectory() as tmp:
            payloads, _, receipt, _ = _payloads()
            result = json.loads(payloads["execution-result.json"])
            result["capability_status"] = "BLOCK_TECHNICAL"
            result["exit_code"] = 1
            result["artifact_id"] = sha256_json({**result, "artifact_id": ""})
            payloads["execution-result.json"] = json.dumps(result).encode()
            archive = _write_archive(Path(tmp), payloads)

            verified = verify_candidate_artifact(archive, _context(archive, receipt))

            self.assertEqual(verified["result"], "REJECT")

    def test_rejects_traversal_link_duplicate_oversize_and_decompression_abuse(
        self,
    ) -> None:
        cases = ("traversal", "link", "duplicate", "oversize", "compression")
        for name in cases:
            with self.subTest(name=name), TemporaryDirectory() as tmp:
                payloads, _, receipt, _ = _payloads()
                arguments: dict[str, object] = {}
                if name == "traversal":
                    arguments["extra"] = ("../escape.json", b"{}")
                elif name == "link":
                    arguments["symlink"] = "link.json"
                elif name == "duplicate":
                    arguments["duplicate"] = "candidate-bundle.json"
                elif name == "oversize":
                    payloads["execution-result.json"] = b"x" * (4 * 1024 * 1024 + 1)
                else:
                    payloads["execution-result.json"] = b"0" * (1024 * 1024)
                archive = _write_archive(Path(tmp), payloads, **arguments)

                verified = verify_candidate_artifact(
                    archive, _context(archive, receipt)
                )

                self.assertEqual(verified["result"], "REJECT")

    def test_rejects_non_actions_producer_and_invalid_verifier_app(self) -> None:
        mutations = (
            {"run_app_id": 1},
            {"run_event": "pull_request_target"},
            {"run_conclusion": "failure"},
            {"verifier_app_id": 0},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), TemporaryDirectory() as tmp:
                payloads, _, receipt, _ = _payloads()
                archive = _write_archive(Path(tmp), payloads)

                verified = verify_candidate_artifact(
                    archive, replace(_context(archive, receipt), **mutation)
                )

                self.assertEqual(verified["result"], "REJECT")

    def test_same_name_candidate_check_cannot_replace_app_bound_receipt(self) -> None:
        with TemporaryDirectory() as tmp:
            payloads, _, receipt, _ = _payloads()
            archive = _write_archive(Path(tmp), payloads)
            verified = verify_candidate_artifact(archive, _context(archive, receipt))

        mutations = (
            {"check": {**verified["check"], "app_id": GITHUB_ACTIONS_APP_ID}},
            {"check": {**verified["check"], "name": "Governance Candidate Evidence"}},
            {"check": {**verified["check"], "head_sha": "9" * 40}},
            {"receipt_sha256": "0" * 64},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check_run_request({**deepcopy(verified), **mutation})


if __name__ == "__main__":
    unittest.main()
