from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from governance_eval.codex_review_gate import run_codex_review_gate


HEAD = "b" * 40
BASE = "a" * 40
GOVERNANCE = "c" * 40


def snapshot(captured_at: str) -> dict:
    return {
        "captured_at": captured_at,
        "repository": {"id": 1, "full_name": "owner/repo"},
        "pull_request": {
            "node_id": "PR_node",
            "created_at": "2026-07-13T00:00:00Z",
        },
    }


class CodexReviewGateTests(unittest.TestCase):
    @patch(
        "governance_eval.codex_review_gate.serialize_codex_connector_snapshot",
        return_value=b"{}",
    )
    @patch(
        "governance_eval.codex_review_gate.serialize_codex_connector_evidence_result",
        return_value=b"{}",
    )
    @patch("governance_eval.codex_review_gate.evaluate_codex_connector_evidence")
    @patch("governance_eval.codex_review_gate.evaluate_ai_review_gate")
    def test_recollects_after_server_deadline_and_writes_all_artifacts(
        self, ai_gate, evaluate, _serialize_result, _serialize_snapshot
    ) -> None:
        evaluate.return_value = {"review_state": "AI_REVIEW_UNAVAILABLE"}
        ai_gate.return_value = {"owner_status": "GREEN"}
        captures = iter(
            [snapshot("2026-07-13T00:04:00Z"), snapshot("2026-07-13T00:05:02Z")]
        )
        sleeps: list[float] = []
        with tempfile.TemporaryDirectory() as directory:
            result = run_codex_review_gate(
                repository="owner/repo",
                pull_request_number=1,
                base_sha=BASE,
                head_sha=HEAD,
                governance_sha=GOVERNANCE,
                review_window_started_at="2026-07-13T00:00:00Z",
                output_dir=Path(directory),
                collector=lambda *_: next(captures),
                sleeper=sleeps.append,
            )
            self.assertEqual(result["owner_status"], "GREEN")
            self.assertEqual(sleeps, [62.0])
            self.assertEqual(
                sorted(path.name for path in Path(directory).iterdir()),
                [
                    "ai-review-gate-result.json",
                    "codex-connector-evidence-result.json",
                    "codex-connector-snapshot.json",
                ],
            )

    def test_final_collection_before_deadline_fails_closed(self) -> None:
        calls = iter(
            [snapshot("2026-07-13T00:04:00Z"), snapshot("2026-07-13T00:04:59Z")]
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "before the review deadline"):
                run_codex_review_gate(
                    repository="owner/repo",
                    pull_request_number=1,
                    base_sha=BASE,
                    head_sha=HEAD,
                    governance_sha=GOVERNANCE,
                    review_window_started_at="2026-07-13T00:00:00Z",
                    output_dir=Path(directory),
                    collector=lambda *_: next(calls),
                    sleeper=lambda _: None,
                )
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
