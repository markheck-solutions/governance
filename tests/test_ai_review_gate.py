from __future__ import annotations

import unittest
from hashlib import sha256
from unittest.mock import patch

from governance_eval.ai_review_gate import evaluate_ai_review_gate
from governance_eval.codex_connector_evidence import (
    TrustedCodexConnectorContext,
    TrustedWorkflowRequestReceipt,
)


HEAD_SHA = "a" * 40


def request_receipt() -> TrustedWorkflowRequestReceipt:
    body = f"@codex review\n\nGovernance review request for exact head `{HEAD_SHA}`."
    endpoint = "repos/owner/repo/issues/1/comments"
    return TrustedWorkflowRequestReceipt(
        workflow_ref=(
            "owner/repo/.github/workflows/"
            "supportability-enforcement.yml@refs/heads/main"
        ),
        workflow_sha="e" * 40,
        event_name="pull_request_target",
        event_action="opened",
        run_id=1,
        run_attempt=1,
        repository_id=1,
        repository_full_name="owner/repo",
        pull_request_number=1,
        head_sha=HEAD_SHA,
        review_window_started_at="2026-07-13T00:00:00Z",
        job_id="request-codex-review",
        request_endpoint=endpoint,
        request_body_sha256="sha256:" + sha256(body.encode("utf-8")).hexdigest(),
        outcome="TRANSPORT_UNAVAILABLE",
        transport_command=[
            "gh",
            "api",
            "--method",
            "POST",
            endpoint,
            "-f",
            f"body={body}",
        ],
        transport_started_at="2026-07-13T00:00:01Z",
        transport_completed_at="2026-07-13T00:00:02Z",
        transport_timeout_seconds=30,
        transport_timed_out=False,
        transport_exit_code=1,
        transport_error_sha256="sha256:" + sha256(b"unavailable").hexdigest(),
        response_validation_error_sha256=None,
        comment_id=None,
        comment_created_at=None,
    )


class AiReviewGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trusted = TrustedCodexConnectorContext(
            snapshot_file_sha256="sha256:" + "1" * 64,
            repository_id=1,
            repository_full_name="owner/repo",
            pull_request_number=1,
            pull_request_node_id="PR_node",
            pull_request_created_at="2026-07-13T00:00:00Z",
            base_sha="0" * 40,
            head_sha=HEAD_SHA,
            governance_evaluator_sha="f" * 40,
            review_window_started_at="2026-07-13T00:00:00Z",
            review_deadline_at="2026-07-13T00:05:00Z",
            resolved_clean_commit_sha=HEAD_SHA,
            workflow_request_receipt=request_receipt(),
        )

    def gate(
        self,
        value: object,
        *,
        replay_valid: bool = True,
        unavailable_after_cutoff: str = "non_blocking",
    ) -> dict:
        side_effect = None if replay_valid else ValueError("source mismatch")
        with patch(
            "governance_eval.ai_review_gate.validate_codex_connector_evidence_result",
            side_effect=side_effect,
        ):
            return evaluate_ai_review_gate(
                HEAD_SHA,
                codex_result=value,
                raw_snapshot_bytes=b"{}",
                trusted_context=self.trusted,
                unavailable_after_cutoff=unavailable_after_cutoff,
            )

    def test_blocking_unavailability_policy_is_invalid(self) -> None:
        result = self.gate(
            {
                "capability_status": "BLOCK_TECHNICAL",
                "review_state": "AI_REVIEW_UNAVAILABLE",
                "reviewed_head_sha": None,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": ["NO_IN_WINDOW_RESPONSE"],
                "result_content_hash": "b" * 64,
            },
            unavailable_after_cutoff="blocking",
        )

        self.assertEqual(result["owner_status"], "RED")
        self.assertEqual(result["evidence_status"], "INVALID_EVIDENCE")
        self.assertEqual(result["unavailable_after_cutoff"], "invalid")
        self.assertEqual(
            result["observations"],
            ["AI review unavailability policy is invalid"],
        )
        self.assertFalse(result["approval_provided"])

    def test_reconciled_unavailable_ai_is_recorded_without_blocking_or_approval(
        self,
    ) -> None:
        result = self.gate(
            {
                "capability_status": "BLOCK_TECHNICAL",
                "review_state": "AI_REVIEW_UNAVAILABLE",
                "reviewed_head_sha": None,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": ["NO_IN_WINDOW_RESPONSE"],
                "result_content_hash": "b" * 64,
            },
        )

        self.assertEqual(result["owner_status"], "GREEN")
        self.assertEqual(result["evidence_status"], "AI_REVIEW_UNAVAILABLE")
        self.assertFalse(result["approval_provided"])
        self.assertFalse(result["blocking_findings_present"])
        self.assertEqual(result["head_sha"], HEAD_SHA)
        self.assertEqual(result["unavailable_after_cutoff"], "non_blocking")

    def test_manual_request_is_unavailable_not_approval(self) -> None:
        result = self.gate(
            {
                "capability_status": "BLOCK_TECHNICAL",
                "review_state": "AI_REVIEW_UNAVAILABLE",
                "reviewed_head_sha": None,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": ["MANUAL_REVIEW_REQUEST_PRESENT"],
                "result_content_hash": "b" * 64,
            },
        )

        self.assertEqual(result["owner_status"], "GREEN")
        self.assertEqual(result["evidence_status"], "AI_REVIEW_UNAVAILABLE")
        self.assertFalse(result["approval_provided"])

    def test_late_automatic_request_is_unavailable_not_blocking(self) -> None:
        result = self.gate(
            {
                "capability_status": "BLOCK_TECHNICAL",
                "review_state": "AI_REVIEW_UNAVAILABLE",
                "reviewed_head_sha": None,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": [
                    "NO_IN_WINDOW_RESPONSE",
                    "WORKFLOW_REQUEST_POSTED_AFTER_DEADLINE",
                ],
                "result_content_hash": "b" * 64,
            },
        )

        self.assertEqual(result["owner_status"], "GREEN")
        self.assertEqual(result["evidence_status"], "AI_REVIEW_UNAVAILABLE")
        self.assertFalse(result["approval_provided"])
        self.assertFalse(result["blocking_findings_present"])

    def test_invalid_automatic_request_response_is_unavailable(self) -> None:
        result = self.gate(
            {
                "capability_status": "BLOCK_TECHNICAL",
                "review_state": "AI_REVIEW_UNAVAILABLE",
                "reviewed_head_sha": None,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": [
                    "NO_IN_WINDOW_RESPONSE",
                    "WORKFLOW_REQUEST_RESPONSE_INVALID",
                ],
                "result_content_hash": "b" * 64,
            },
        )

        self.assertEqual(result["owner_status"], "GREEN")
        self.assertEqual(result["evidence_status"], "AI_REVIEW_UNAVAILABLE")
        self.assertFalse(result["approval_provided"])

    def test_ambiguous_boundary_or_manual_unrecognized_is_unavailable(self) -> None:
        for reasons in (
            ["HEAD_ATTRIBUTION_AMBIGUOUS", "NO_IN_WINDOW_RESPONSE"],
            ["MANUAL_REVIEW_REQUEST_PRESENT", "RESPONSE_BODY_UNRECOGNIZED"],
        ):
            with self.subTest(reasons=reasons):
                result = self.gate(
                    {
                        "capability_status": "BLOCK_TECHNICAL",
                        "review_state": "AI_REVIEW_UNAVAILABLE",
                        "reviewed_head_sha": None,
                        "reconciled_head_sha": HEAD_SHA,
                        "reasons": reasons,
                        "result_content_hash": "b" * 64,
                    },
                )

                self.assertEqual(result["owner_status"], "GREEN")
                self.assertEqual(result["evidence_status"], "AI_REVIEW_UNAVAILABLE")
                self.assertFalse(result["approval_provided"])

    def test_exact_head_codex_blocking_finding_is_red(self) -> None:
        result = self.gate(
            {
                "capability_status": "BLOCK_TECHNICAL",
                "review_state": "BLOCKING_FINDINGS_PRESENT",
                "reviewed_head_sha": HEAD_SHA,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": ["BLOCKING_FINDINGS_PRESENT"],
                "result_content_hash": "b" * 64,
            },
        )

        self.assertEqual(result["owner_status"], "RED")
        self.assertEqual(result["evidence_status"], "BLOCKING_FINDINGS_PRESENT")
        self.assertTrue(result["blocking_findings_present"])
        self.assertFalse(result["approval_provided"])

    def test_clean_exact_head_codex_evidence_is_available_not_approval(self) -> None:
        result = self.gate(
            {
                "capability_status": "PASS",
                "review_state": "CLEAN",
                "reviewed_head_sha": HEAD_SHA,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": [],
                "result_content_hash": "c" * 64,
            }
        )

        self.assertEqual(result["owner_status"], "GREEN")
        self.assertEqual(result["evidence_status"], "CLEAN")
        self.assertFalse(result["approval_provided"])
        self.assertFalse(result["blocking_findings_present"])
        self.assertEqual(result["unavailable_after_cutoff"], "non_blocking")

    def test_invalid_unavailability_policy_is_rejected(self) -> None:
        for policy in ("ignore", [], {}):
            with self.subTest(policy=policy):
                result = self.gate(
                    {
                        "capability_status": "PASS",
                        "review_state": "CLEAN",
                        "reviewed_head_sha": HEAD_SHA,
                        "reconciled_head_sha": HEAD_SHA,
                        "reasons": [],
                        "result_content_hash": "c" * 64,
                    },
                    unavailable_after_cutoff=policy,  # type: ignore[arg-type]
                )

                self.assertEqual(result["owner_status"], "RED")
                self.assertEqual(result["evidence_status"], "INVALID_EVIDENCE")
                self.assertEqual(result["unavailable_after_cutoff"], "invalid")
                self.assertEqual(
                    result["observations"],
                    ["AI review unavailability policy is invalid"],
                )

    def test_missing_or_malformed_ai_evidence_is_red(self) -> None:
        cases = (
            None,
            {
                "capability_status": "PASS",
                "reviewed_head_sha": HEAD_SHA,
                "reasons": "not-a-list",
            },
            {
                "capability_status": "PASS",
                "review_state": "CLEAN",
                "reviewed_head_sha": "d" * 40,
                "reconciled_head_sha": "d" * 40,
                "reasons": [],
                "result_content_hash": "e" * 64,
            },
        )

        for value in cases:
            with self.subTest(value=value):
                result = self.gate(value)
                self.assertEqual(result["owner_status"], "RED")
                self.assertEqual(result["evidence_status"], "INVALID_EVIDENCE")
                self.assertFalse(result["approval_provided"])
                self.assertFalse(result["blocking_findings_present"])

    def test_source_replay_failure_is_red(self) -> None:
        result = self.gate(
            {
                "capability_status": "BLOCK_TECHNICAL",
                "review_state": "AI_REVIEW_UNAVAILABLE",
                "reviewed_head_sha": None,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": ["NO_IN_WINDOW_RESPONSE"],
                "result_content_hash": "b" * 64,
            },
            replay_valid=False,
        )
        self.assertEqual(result["owner_status"], "RED")
        self.assertEqual(result["evidence_status"], "INVALID_EVIDENCE")

    def test_unavailability_cannot_hide_integrity_failure(self) -> None:
        result = self.gate(
            {
                "capability_status": "BLOCK_TECHNICAL",
                "review_state": "AI_REVIEW_UNAVAILABLE",
                "reviewed_head_sha": None,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": [
                    "NO_IN_WINDOW_RESPONSE",
                    "SNAPSHOT_FILE_DIGEST_MISMATCH",
                ],
                "result_content_hash": "b" * 64,
            }
        )
        self.assertEqual(result["owner_status"], "RED")
        self.assertEqual(result["evidence_status"], "INVALID_EVIDENCE")

    def test_unrecognized_response_without_connector_failure_is_invalid(self) -> None:
        result = self.gate(
            {
                "capability_status": "BLOCK_TECHNICAL",
                "review_state": "AI_REVIEW_UNAVAILABLE",
                "reviewed_head_sha": None,
                "reconciled_head_sha": HEAD_SHA,
                "reasons": ["RESPONSE_BODY_UNRECOGNIZED"],
                "result_content_hash": "b" * 64,
            }
        )

        self.assertEqual(result["owner_status"], "RED")
        self.assertEqual(result["evidence_status"], "INVALID_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
