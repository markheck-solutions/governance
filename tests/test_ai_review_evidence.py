from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from governance_eval import supportability as supportability_module
from governance_eval.paths import repo_root
from governance_eval.supportability import (
    STATUS_GREEN,
    STATUS_RED,
    evaluate_copilot_review_gate,
)


class NativeReviewEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_copilot_review_gate_accepts_latest_clean_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[_review(head)]),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertTrue(result["review_status"]["latest_head_reviewed"])

    def test_copilot_review_gate_accepts_native_clean_prose_that_names_severities(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            review = _review(head)
            review["author"] = "copilot-pull-request-reviewer[bot]"
            review["body"] = (
                "No P0, P1, or P2 findings. An earlier check failure was resolved."
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[review]),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])
            self.assertTrue(result["review_status"]["latest_head_reviewed"])
            self.assertEqual(
                result["review_status"]["reviewer"], "copilot-pull-request-reviewer"
            )

    def test_copilot_review_gate_accepts_graphql_native_identity_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            review = _review(head)
            review["author"] = "copilot-pull-request-reviewer"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[review]),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])

    def test_copilot_review_gate_rejects_payload_head_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            payload = _copilot_payload(head, reviews=[_review(head)])
            payload["headRefOid"] = "d" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=payload,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("headRefOid" in error for error in result["errors"]))

    def test_copilot_review_gate_rejects_missing_payload_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            payload = _copilot_payload(head, reviews=[_review(head)])
            del payload["headRefOid"]

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=payload,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("headRefOid" in error for error in result["errors"]))

    def test_copilot_review_gate_rejects_approved_native_review_as_clean_attestation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            review = _review(head)
            review["state"] = "APPROVED"
            review["body"] = "Clean."

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[review]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )

    def test_copilot_review_gate_returns_red_for_malformed_native_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            malformed_reviews = (
                {**_review(head), "state": "UNKNOWN"},
                {**_review(head), "submittedAt": None},
                {**_review(head), "submittedAt": "not-a-date"},
                {**_review(head), "submittedAt": "   "},
                {**_review(head), "submittedAt": "2026-06-25T10:05:00"},
                {**_review(head), "commitOid": head[:10]},
            )
            for review in malformed_reviews:
                with self.subTest(review=review):
                    result = evaluate_copilot_review_gate(
                        repo / ".github/governance/supportability.yml",
                        head,
                        payload=_copilot_payload(head, reviews=[review]),
                    )

                    self.assertEqual(result["owner_status"], STATUS_RED)
                    self.assertTrue(any("native Copilot review" in error for error in result["errors"]))

    def test_copilot_review_gate_accepts_raw_graphql_commit_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            review = _review(head)
            review["commit"] = {"oid": review.pop("commitOid")}

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[review]),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])

    def test_copilot_review_gate_returns_red_for_non_list_evidence_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            for field, malformed in (
                ("reviews", None),
                ("comments", {"not": "a list"}),
                ("reviewThreads", "not-a-list"),
            ):
                with self.subTest(field=field):
                    payload = _copilot_payload(head, reviews=[_review(head)])
                    payload[field] = malformed

                    result = evaluate_copilot_review_gate(
                        repo / ".github/governance/supportability.yml",
                        head,
                        payload=payload,
                    )

                    self.assertEqual(result["owner_status"], STATUS_RED)
                    self.assertTrue(any(field in error for error in result["errors"]))

    def test_copilot_review_gate_returns_red_for_non_object_evidence_item(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            payload = _copilot_payload(head, reviews=[_review(head)])
            payload["comments"] = ["not-an-object"]

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=payload,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("comments" in error for error in result["errors"]))

    def test_copilot_review_gate_returns_red_for_malformed_thread_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            malformed_threads = (
                {
                    "isResolved": "false",
                    "path": "src/app.py",
                    "authors": ["copilot-pull-request-reviewer"],
                },
                {
                    "isResolved": False,
                    "path": "src/app.py",
                    "authors": "copilot-pull-request-reviewer",
                },
                {"isResolved": False, "path": "", "authors": []},
            )
            for thread in malformed_threads:
                with self.subTest(thread=thread):
                    result = evaluate_copilot_review_gate(
                        repo / ".github/governance/supportability.yml",
                        head,
                        payload=_copilot_payload(
                            head,
                            reviews=[_review(head)],
                            review_threads=[thread],
                        ),
                    )

                    self.assertEqual(result["owner_status"], STATUS_RED)
                    self.assertTrue(any("review thread" in error for error in result["errors"]))

    def test_copilot_review_cli_returns_red_for_explicit_null_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            payload_path = repo / "payload.json"
            output_dir = repo / "artifacts"
            payload_path.write_text("null", encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                rc = supportability_module.main(
                    [
                        "copilot-review-gate",
                        "--config",
                        str(repo / ".github/governance/supportability.yml"),
                        "--head-sha",
                        "c" * 40,
                        "--payload",
                        str(payload_path),
                        "--output-dir",
                        str(output_dir),
                    ]
                )

            result = json.loads(
                (output_dir / "copilot-review-gate-result.json").read_text(encoding="utf-8")
            )
            self.assertEqual(rc, 1)
            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("JSON object" in error for error in result["errors"]))

    def test_copilot_review_cli_returns_red_for_invalid_json_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            payload_path = repo / "payload.json"
            output_dir = repo / "artifacts"
            payload_path.write_text("{bad", encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                rc = supportability_module.main(
                    [
                        "copilot-review-gate",
                        "--config",
                        str(repo / ".github/governance/supportability.yml"),
                        "--head-sha",
                        "c" * 40,
                        "--payload",
                        str(payload_path),
                        "--output-dir",
                        str(output_dir),
                    ]
                )

            result = json.loads(
                (output_dir / "copilot-review-gate-result.json").read_text(encoding="utf-8")
            )
            self.assertEqual(rc, 1)
            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("payload load failed" in error for error in result["errors"]))

    def test_copilot_review_cli_returns_red_for_unreadable_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            output_dir = repo / "artifacts"

            with contextlib.redirect_stdout(io.StringIO()):
                rc = supportability_module.main(
                    [
                        "copilot-review-gate",
                        "--config",
                        str(repo / ".github/governance/supportability.yml"),
                        "--head-sha",
                        "c" * 40,
                        "--payload",
                        str(repo / "missing.json"),
                        "--output-dir",
                        str(output_dir),
                    ]
                )

            result = json.loads(
                (output_dir / "copilot-review-gate-result.json").read_text(encoding="utf-8")
            )
            self.assertEqual(rc, 1)
            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("payload load failed" in error for error in result["errors"]))

    def test_copilot_review_gate_rejects_wildcard_identity_spoof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            review = _review(head)
            review["author"] = "evil-copilot-attacker[bot]"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[review]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )

    def test_copilot_review_gate_rejects_stale_native_commit_even_when_body_names_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            review = _review("d" * 40)
            review["author"] = "copilot-pull-request-reviewer"
            review["body"] = f"Reviewed commit {head}. No findings."

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[review]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )

    def test_copilot_review_gate_rejects_codex_advisory_comment_as_copilot_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            payload = _copilot_payload(
                head,
                reviews=[],
                comments=[
                    {
                        "author": "chatgpt-codex-connector",
                        "body": f"Codex Review: no major issues.\n\n**Reviewed commit:** `{head[:10]}`",
                        "createdAt": "2026-06-30T14:35:45Z",
                        "isMinimized": False,
                    }
                ],
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=payload,
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertFalse(result["review_status"]["latest_head_reviewed"])
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )


class StructuredReviewEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_copilot_review_gate_accepts_structured_clean_latest_head_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            payload = _copilot_payload(
                head,
                reviews=[],
                comments=[_structured_review_comment(head)],
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=payload,
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertTrue(result["review_status"]["latest_head_reviewed"])
            self.assertTrue(result["review_status"]["structured_evidence_present"])
            self.assertTrue(result["review_status"]["structured_evidence_valid"])
            self.assertEqual(result["review_status"]["reviewed_commit_sha"], head)
            self.assertEqual(result["review_status"]["verdict"], "clean")
            self.assertEqual(result["review_status"]["open_finding_count"], 0)

    def test_copilot_review_gate_rejects_structured_evidence_from_native_reviewer_role(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            comment = _structured_review_comment(head)
            comment["author"] = "copilot-pull-request-reviewer[bot]"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[comment]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertFalse(result["review_status"]["structured_evidence_present"])

    def test_copilot_review_gate_rejects_minimized_structured_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            comment = _structured_review_comment(head)
            comment["isMinimized"] = True

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[comment]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertFalse(result["review_status"]["structured_evidence_present"])

    def test_copilot_review_gate_keeps_minimized_same_head_blocker_red(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            blocked = _structured_review_comment(
                head,
                verdict="blocked",
                open_findings=[
                    {"severity": "P1", "title": "still broken", "path": "src/app.py"}
                ],
            )
            blocked["isMinimized"] = True

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[_review(head)], comments=[blocked]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("verdict is not clean" in error for error in result["errors"]))

    def test_copilot_review_gate_rejects_non_boolean_minimized_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            blocked = _structured_review_comment(head, verdict="blocked")
            blocked["isMinimized"] = "false"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[_review(head)], comments=[blocked]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("isMinimized" in error for error in result["errors"]))

    def test_copilot_review_gate_rejects_truncated_structured_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            truncated = {
                "author": "copilot-swe-agent",
                "body": f"Reviewed commit {head}.\n<!-- governance-review-evidence:v1\n{{not-json}}",
                "createdAt": "2026-06-30T14:35:45Z",
                "isMinimized": False,
            }

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[_review(head)],
                    comments=[truncated],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("evidence is invalid" in error for error in result["errors"]))

    def test_copilot_review_gate_ignores_truncated_marker_bound_to_stale_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            stale_head = "d" * 40
            truncated = {
                "author": "copilot-swe-agent",
                "body": f"Reviewed commit {stale_head}.\n<!-- governance-review-evidence:v1\n{{not-json}}",
                "createdAt": "2026-06-30T14:30:00Z",
                "isMinimized": False,
            }

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[_review(head)],
                    comments=[truncated],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])

    def test_copilot_review_gate_rejects_ambiguous_bare_structured_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            comment = {
                "author": "copilot-swe-agent",
                "body": "<!-- governance-review-evidence:v1",
                "createdAt": "2026-06-30T14:35:45Z",
                "isMinimized": False,
            }

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[_review(head)], comments=[comment]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(any("evidence is invalid" in error for error in result["errors"]))

    def test_later_exact_head_structured_clean_supersedes_unbound_bare_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            bare = {
                "author": "copilot-swe-agent",
                "body": "<!-- governance-review-evidence:v1",
                "createdAt": "2026-06-30T14:30:00Z",
                "isMinimized": False,
            }
            clean = _structured_review_comment(head)
            clean["createdAt"] = "2026-06-30T14:35:45Z"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[bare, clean]),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])

    def test_copilot_review_gate_rejects_structured_evidence_in_review_channel(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "c" * 40
            review = _review(head)
            review["author"] = "copilot-swe-agent"
            review["body"] = _structured_review_block(head)

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[review]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertFalse(result["review_status"]["structured_evidence_present"])

    def test_copilot_review_gate_rejects_missing_or_stale_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40

            missing = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[]),
            )
            stale = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[_review("e" * 40)]),
            )

            self.assertEqual(missing["owner_status"], STATUS_RED)
            self.assertEqual(stale["owner_status"], STATUS_RED)
            self.assertTrue(
                any("missing or stale" in error for error in stale["errors"])
            )
            expected_prompt = "\n".join(
                [
                    f"@copilot review commit {head}. If clean, end your response with exactly:",
                    "<!-- governance-review-evidence:v1",
                    (
                        f'{{"schema_version":"governance-review-evidence.v1","reviewed_commit_sha":"{head}","verdict":"clean","open_findings":[]}}'
                    ),
                    "-->",
                    'If blocked, use verdict "blocked" and list open_findings with severity, title, and path.',
                ]
            )
            self.assertEqual(missing["review_request"]["prompt"], expected_prompt)

    def test_copilot_review_gate_rejects_stale_review_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[],
                    comments=[
                        {
                            "author": "chatgpt-codex-connector",
                            "body": f"Codex Review: no major issues.\n\n**Reviewed commit:** `{'e' * 10}`",
                            "createdAt": "2026-06-30T14:35:45Z",
                            "isMinimized": False,
                        }
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )

    def test_copilot_review_gate_rejects_stale_structured_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            stale_head = "e" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[],
                    comments=[_structured_review_comment(stale_head)],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(result["review_status"]["structured_evidence_present"])
            self.assertFalse(result["review_status"]["structured_evidence_valid"])
            self.assertEqual(result["review_status"]["reviewed_commit_sha"], stale_head)
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )

    def test_copilot_review_gate_allows_legacy_fallback_when_structured_evidence_is_stale(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            stale_head = "e" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[_review(head)],
                    comments=[_structured_review_comment(stale_head)],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertTrue(result["review_status"]["latest_head_reviewed"])
            self.assertTrue(result["review_status"]["structured_evidence_present"])
            self.assertFalse(result["review_status"]["structured_evidence_valid"])

    def test_copilot_review_gate_ignores_blocked_structured_evidence_for_old_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            stale = _structured_review_comment(
                "e" * 40,
                verdict="blocked",
                open_findings=[
                    {"severity": "P1", "title": "old finding", "path": "src/old.py"}
                ],
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head, reviews=[_review(head)], comments=[stale]
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])

    def test_copilot_review_gate_rejects_invalid_structured_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[],
                    comments=[
                        {
                            "author": "copilot-swe-agent",
                            "body": (
                                f'Reviewed commit {head}.\n<!-- governance-review-evidence:v1\n{{"reviewed_commit_sha":"{head}",not-json}}\n-->'
                            ),
                            "createdAt": "2026-06-30T14:35:45Z",
                            "isMinimized": False,
                        }
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(result["review_status"]["structured_evidence_present"])
            self.assertFalse(result["review_status"]["structured_evidence_valid"])
            self.assertTrue(
                any(
                    "structured Copilot review evidence is invalid" in error
                    for error in result["errors"]
                )
            )

    def test_copilot_review_gate_rejects_malformed_current_head_evidence_from_visible_review_line(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            legacy = _review(head)
            legacy["submittedAt"] = "2026-06-30T14:30:00Z"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[legacy],
                    comments=[
                        {
                            "author": "copilot-swe-agent",
                            "body": f"Reviewed commit `{head}`.\n<!-- governance-review-evidence:v1\n{{not-json}}\n-->",
                            "createdAt": "2026-06-30T14:35:45Z",
                            "isMinimized": False,
                        }
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertFalse(result["review_status"]["structured_evidence_valid"])
            self.assertTrue(
                any(
                    "structured Copilot review evidence is invalid" in error
                    for error in result["errors"]
                )
            )

    def test_copilot_review_gate_does_not_erase_malformed_same_head_evidence_with_later_clean(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            malformed = {
                "author": "copilot-swe-agent",
                "body": f"Reviewed commit `{head}`.\n<!-- governance-review-evidence:v1\n{{not-json}}\n-->",
                "createdAt": "2026-06-30T14:30:00Z",
                "isMinimized": False,
            }
            clean = _structured_review_comment(head)
            clean["createdAt"] = "2026-06-30T14:35:45Z"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[malformed, clean]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(result["review_status"]["latest_head_reviewed"])
            self.assertTrue(result["review_status"]["structured_evidence_valid"])
            self.assertTrue(
                any("evidence is invalid" in error for error in result["errors"])
            )

    def test_copilot_review_gate_ignores_quoted_prompt_evidence_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            comment = _structured_review_comment(head)
            comment["body"] = "\n".join(
                [
                    f"> @copilot review commit {head}. If clean, end your response with exactly:",
                    "> <!-- governance-review-evidence:v1",
                    f'> {{"schema_version":"governance-review-evidence.v1","reviewed_commit_sha":"{head}",',
                    "> ...",
                    "",
                    f"Reviewed commit: `{head}`",
                    "",
                    _structured_review_block(head),
                ]
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[comment]),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertTrue(result["review_status"]["structured_evidence_valid"])

    def test_copilot_review_gate_rejects_fenced_example_evidence_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            comment = _structured_review_comment(head)
            comment["body"] = "\n".join(
                [
                    "Example format only:",
                    "````text",
                    "```notclosing",
                    _structured_review_block(head),
                    "````",
                    "I did not review this commit.",
                ]
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[comment]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertFalse(result["review_status"]["latest_head_reviewed"])
            self.assertFalse(result["review_status"]["structured_evidence_present"])
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )

    def test_copilot_review_gate_rejects_fenced_legacy_clean_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            comment = _structured_review_comment(head)
            comment["body"] = "\n".join(
                [
                    "Example only:",
                    "```text",
                    f"Reviewed commit: {head}",
                    "No issues found.",
                    "```",
                ]
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[comment]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertFalse(result["review_status"]["latest_head_reviewed"])
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )

    def test_copilot_review_gate_allows_legacy_fallback_when_stale_structured_json_is_invalid(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            stale_head = "e" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[_review(head)],
                    comments=[
                        {
                            "author": "copilot-swe-agent",
                            "body": f"Reviewed commit {stale_head}.\n<!-- governance-review-evidence:v1\n{{not-json}}\n-->",
                            "createdAt": "2026-06-30T14:35:45Z",
                            "isMinimized": False,
                        }
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertTrue(result["review_status"]["latest_head_reviewed"])

    def test_copilot_review_gate_allows_legacy_fallback_when_unparseable_structured_json_only_context_mentions_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[_review(head)],
                    comments=[
                        {
                            "author": "copilot-swe-agent",
                            "body": f"Current head under discussion: {head}\n<!-- governance-review-evidence:v1\n{{not-json}}\n-->",
                            "createdAt": "2026-06-30T14:35:45Z",
                            "isMinimized": False,
                        }
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertTrue(result["review_status"]["latest_head_reviewed"])

    def test_copilot_review_gate_allows_legacy_fallback_when_off_head_structured_document_is_invalid(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            stale_head = "e" * 40
            invalid_stale_evidence = {
                "schema_version": "governance-review-evidence.v1",
                "reviewed_commit_sha": stale_head,
                "verdict": "clean",
                "open_findings": "not-a-list",
            }

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[_review(head)],
                    comments=[
                        {
                            "author": "copilot-swe-agent",
                            "body": "\n".join(
                                [
                                    f"Current head under discussion: {head}",
                                    "<!-- governance-review-evidence:v1",
                                    json.dumps(
                                        invalid_stale_evidence, separators=(",", ":")
                                    ),
                                    "-->",
                                ]
                            ),
                            "createdAt": "2026-06-30T14:35:45Z",
                            "isMinimized": False,
                        }
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertTrue(result["review_status"]["latest_head_reviewed"])

    def test_copilot_review_gate_rejects_structured_evidence_from_wrong_author(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            comment = _structured_review_comment(head)
            comment["author"] = "owner"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[comment]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertFalse(result["review_status"]["structured_evidence_present"])
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )

    def test_copilot_review_gate_rejects_blocked_structured_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            findings = [
                {"severity": "P1", "title": "gate missing", "path": "src/app.py"}
            ]

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[],
                    comments=[
                        _structured_review_comment(
                            head, verdict="blocked", open_findings=findings
                        )
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(result["review_status"]["structured_evidence_valid"])
            self.assertEqual(result["review_status"]["verdict"], "blocked")
            self.assertEqual(result["review_status"]["open_finding_count"], 1)
            self.assertTrue(
                any("verdict is not clean" in error for error in result["errors"])
            )

    def test_copilot_review_gate_rejects_ambiguous_structured_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[],
                    comments=[_structured_review_comment(head, verdict="ambiguous")],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(result["review_status"]["structured_evidence_valid"])
            self.assertEqual(result["review_status"]["verdict"], "ambiguous")
            self.assertTrue(
                any("verdict is not clean" in error for error in result["errors"])
            )

    def test_copilot_review_gate_rejects_clean_verdict_with_open_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            findings = [
                {"severity": "P2", "title": "coverage gap", "path": "src/risk.py"}
            ]

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[],
                    comments=[
                        _structured_review_comment(
                            head, verdict="clean", open_findings=findings
                        )
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(result["review_status"]["structured_evidence_valid"])
            self.assertEqual(result["review_status"]["verdict"], "clean")
            self.assertEqual(result["review_status"]["open_finding_count"], 1)
            self.assertTrue(
                any("blocking open finding" in error for error in result["errors"])
            )

    def test_copilot_review_gate_allows_p3_only_structured_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            findings = [
                {"severity": "P3", "title": "naming cleanup", "path": "src/risk.py"}
            ]

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[],
                    comments=[
                        _structured_review_comment(
                            head, verdict="clean", open_findings=findings
                        )
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertTrue(result["review_status"]["structured_evidence_valid"])
            self.assertEqual(result["review_status"]["open_finding_count"], 1)

    def test_copilot_review_gate_rejects_dismissed_structured_review_as_only_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            review = _review(head)
            review["state"] = "DISMISSED"
            review["body"] = _structured_review_block(head)

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[review]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertFalse(result["review_status"]["latest_head_reviewed"])
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )


class ReviewEvidenceOrderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_copilot_review_gate_uses_structured_finding_data_not_visible_severity_words(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            comment = _structured_review_comment(head)
            comment["body"] = f"[P1] gate is bypassed\n\n{comment['body']}"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[comment]),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN, result["errors"])
            self.assertEqual(result["review_status"]["blocking_comment_count"], 0)

    def test_copilot_review_gate_ignores_fenced_severe_examples_with_clean_structured_block(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            comment = _structured_review_comment(head)
            comment["body"] = "\n".join(
                [
                    "Example finding label:",
                    "```text",
                    "[P1] example only",
                    "```",
                    comment["body"],
                ]
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[comment]),
            )

            self.assertEqual(result["owner_status"], STATUS_GREEN)
            self.assertEqual(result["review_status"]["blocking_comment_count"], 0)

    def test_copilot_review_gate_does_not_erase_same_head_blocker_with_later_clean(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40
            blocked = _structured_review_comment(
                head,
                verdict="blocked",
                open_findings=[
                    {"severity": "P1", "title": "fixed later", "path": "src/app.py"}
                ],
            )
            blocked["createdAt"] = "2026-06-30T14:30:00Z"
            blocked["body"] = f"P1: fixed later.\n\n{blocked['body']}"
            clean = _structured_review_comment(head)
            clean["createdAt"] = "2026-06-30T14:35:45Z"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[], comments=[blocked, clean]),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertEqual(result["review_status"]["blocking_comment_count"], 0)
            self.assertTrue(
                any("verdict is not clean" in error for error in result["errors"])
            )

    def test_copilot_review_gate_does_not_promote_codex_severity_prose_to_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "d" * 40

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head,
                    reviews=[],
                    comments=[
                        {
                            "author": "chatgpt-codex-connector",
                            "body": f"P1: still broken.\n\n**Reviewed commit:** `{head[:10]}`",
                            "createdAt": "2026-06-30T14:35:45Z",
                            "isMinimized": False,
                        }
                    ],
                ),
            )

            self.assertEqual(result["owner_status"], STATUS_RED)
            self.assertTrue(
                any("missing or stale" in error for error in result["errors"])
            )

    def test_copilot_review_gate_rejects_unresolved_p1_thread(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "f" * 40
            payload = _copilot_payload(
                head,
                reviews=[_review(head)],
                review_threads=[
                    {
                        "isResolved": False,
                        "path": "src/app.py",
                        "body": "P1: gate can be bypassed",
                        "authors": ["copilot-pull-request-reviewer[bot]"],
                    }
                ],
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=payload,
            )

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertEqual(result["review_status"]["blocking_thread_count"], 1)

    def test_copilot_review_gate_rejects_any_unresolved_native_copilot_thread(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "f" * 40
            payload = _copilot_payload(
                head,
                reviews=[_review(head)],
                review_threads=[
                    {
                        "isResolved": False,
                        "path": "src/app.py",
                        "body": "Please consider handling this edge case.",
                        "authors": ["copilot-pull-request-reviewer"],
                    }
                ],
            )

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=payload,
            )

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertEqual(result["review_status"]["blocking_thread_count"], 1)

    def test_copilot_review_gate_rejects_changes_requested_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "f" * 40
            review = _review(head)
            review["state"] = "CHANGES_REQUESTED"
            review["body"] = _structured_review_block(head)

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(head, reviews=[review]),
            )

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(any("CHANGES_REQUESTED" in error for error in result["errors"]))

    def test_copilot_review_gate_does_not_erase_same_head_changes_requested(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _review_repo(Path(tmp), self.root)
            head = "f" * 40
            change_request = _review(head)
            change_request["state"] = "CHANGES_REQUESTED"
            change_request["submittedAt"] = "2026-06-30T14:30:00Z"
            clean_comment = _structured_review_comment(head)
            clean_comment["createdAt"] = "2026-06-30T14:35:00Z"

            result = evaluate_copilot_review_gate(
                repo / ".github/governance/supportability.yml",
                head,
                payload=_copilot_payload(
                    head, reviews=[change_request], comments=[clean_comment]
                ),
            )

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertTrue(result["review_status"]["latest_head_reviewed"])
        self.assertTrue(any("CHANGES_REQUESTED" in error for error in result["errors"]))


def _review_repo(path: Path, root: Path) -> Path:
    (path / ".github/governance").mkdir(parents=True)
    (path / "docs/reference").mkdir(parents=True)
    shutil.copy2(
        root / ".github/governance/supportability.yml",
        path / ".github/governance/supportability.yml",
    )
    shutil.copy2(
        root / "docs/reference/supportability-standard.md",
        path / "docs/reference/supportability-standard.md",
    )
    return path


def _copilot_payload(
    head_sha: str,
    *,
    reviews: list[dict],
    review_threads: list[dict] | None = None,
    comments: list[dict] | None = None,
) -> dict:
    return {
        "headRefOid": head_sha,
        "reviews": reviews,
        "comments": comments if comments is not None else [],
        "reviewThreads": review_threads if review_threads is not None else [],
    }


def _review(head_sha: str) -> dict:
    return {
        "state": "COMMENTED",
        "submittedAt": "2026-06-25T10:05:00Z",
        "commitOid": head_sha,
        "author": "copilot-pull-request-reviewer[bot]",
        "body": f"Reviewed commit {head_sha[:10]}. Clean.",
    }


def _structured_review_block(
    head_sha: str,
    *,
    verdict: str = "clean",
    open_findings: list[dict] | None = None,
) -> str:
    evidence = {
        "schema_version": "governance-review-evidence.v1",
        "reviewed_commit_sha": head_sha,
        "verdict": verdict,
        "open_findings": open_findings if open_findings is not None else [],
    }
    return "\n".join(
        [
            "<!-- governance-review-evidence:v1",
            json.dumps(evidence, separators=(",", ":")),
            "-->",
        ]
    )


def _structured_review_comment(
    head_sha: str,
    *,
    verdict: str = "clean",
    open_findings: list[dict] | None = None,
) -> dict:
    return {
        "author": "copilot-swe-agent",
        "body": _structured_review_block(
            head_sha, verdict=verdict, open_findings=open_findings
        ),
        "createdAt": "2026-06-30T14:35:45Z",
        "isMinimized": False,
    }
