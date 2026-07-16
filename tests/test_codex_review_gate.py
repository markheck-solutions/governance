from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from governance_eval.codex_review_gate import main, run_codex_review_gate
from governance_eval.paths import repo_root


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


def write_config(directory: Path, policy: str = "non_blocking") -> Path:
    source = (
        repo_root(Path(__file__).resolve()) / ".github/governance/supportability.yml"
    )
    text = source.read_text(encoding="utf-8").replace(
        "unavailable_after_cutoff: non_blocking",
        f"unavailable_after_cutoff: {policy}",
    )
    path = directory / "supportability.yml"
    path.write_text(text, encoding="utf-8")
    return path


def cli_args(output_dir: Path) -> list[str]:
    return [
        "--repo",
        "owner/repo",
        "--pr",
        "1",
        "--base-sha",
        BASE,
        "--head-sha",
        HEAD,
        "--governance-sha",
        GOVERNANCE,
        "--review-window-started-at",
        "2026-07-13T00:00:00Z",
        "--output-dir",
        str(output_dir),
    ]


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
    def test_recollects_and_propagates_each_policy_while_writing_all_artifacts(
        self, ai_gate, evaluate, _serialize_result, _serialize_snapshot
    ) -> None:
        evaluate.return_value = {"review_state": "AI_REVIEW_UNAVAILABLE"}
        ai_gate.return_value = {"owner_status": "GREEN"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for policy in ("non_blocking", "blocking"):
                with self.subTest(policy=policy):
                    policy_root = root / policy
                    policy_root.mkdir()
                    output_dir = policy_root / "artifacts"
                    captures = iter(
                        [
                            snapshot("2026-07-13T00:04:00Z"),
                            snapshot("2026-07-13T00:05:02Z"),
                        ]
                    )
                    sleeps: list[float] = []
                    result = run_codex_review_gate(
                        config_path=write_config(policy_root, policy),
                        repository="owner/repo",
                        pull_request_number=1,
                        base_sha=BASE,
                        head_sha=HEAD,
                        governance_sha=GOVERNANCE,
                        review_window_started_at="2026-07-13T00:00:00Z",
                        output_dir=output_dir,
                        collector=lambda *_: next(captures),
                        sleeper=sleeps.append,
                    )
                    self.assertEqual(result["owner_status"], "GREEN")
                    self.assertEqual(sleeps, [62.0])
                    self.assertEqual(
                        sorted(path.name for path in output_dir.iterdir()),
                        [
                            "ai-review-gate-result.json",
                            "codex-connector-evidence-result.json",
                            "codex-connector-snapshot.json",
                        ],
                    )
                    self.assertEqual(
                        ai_gate.call_args.kwargs["unavailable_after_cutoff"], policy
                    )
                    ai_gate.reset_mock()

    def test_final_collection_before_deadline_fails_closed(self) -> None:
        calls = iter(
            [snapshot("2026-07-13T00:04:00Z"), snapshot("2026-07-13T00:04:59Z")]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "before the review deadline"):
                run_codex_review_gate(
                    config_path=write_config(root),
                    repository="owner/repo",
                    pull_request_number=1,
                    base_sha=BASE,
                    head_sha=HEAD,
                    governance_sha=GOVERNANCE,
                    review_window_started_at="2026-07-13T00:00:00Z",
                    output_dir=root,
                    collector=lambda *_: next(calls),
                    sleeper=lambda _: None,
                )
            self.assertEqual(
                sorted(path.name for path in root.iterdir()), ["supportability.yml"]
            )

    def test_invalid_config_fails_before_collection_sleep_or_artifact_write(
        self,
    ) -> None:
        collector = Mock()
        sleeper = Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = write_config(root)
            config_path.write_text(
                config_path.read_text(encoding="utf-8").replace(
                    "  unresolved_p0_p1_p2_blocks: true",
                    "  unresolved_p0_p1_p2_blocks: true\n  unexpected: true",
                ),
                encoding="utf-8",
            )
            output_dir = root / "artifacts"

            with self.assertRaisesRegex(ValueError, "supportability config invalid"):
                run_codex_review_gate(
                    config_path=config_path,
                    repository="owner/repo",
                    pull_request_number=1,
                    base_sha=BASE,
                    head_sha=HEAD,
                    governance_sha=GOVERNANCE,
                    review_window_started_at="invalid timestamp",
                    output_dir=output_dir,
                    collector=collector,
                    sleeper=sleeper,
                )

            collector.assert_not_called()
            sleeper.assert_not_called()
            self.assertFalse(output_dir.exists())

    @patch(
        "governance_eval.codex_review_gate.run_codex_review_gate",
        return_value={"owner_status": "GREEN"},
    )
    def test_cli_requires_config(self, run_gate: Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(cli_args(Path(directory)))

        self.assertEqual(raised.exception.code, 2)
        run_gate.assert_not_called()

    @patch(
        "governance_eval.codex_review_gate.run_codex_review_gate",
        return_value={"owner_status": "GREEN"},
    )
    def test_cli_passes_config_path_and_returns_gate_status(
        self, run_gate: Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = write_config(root)
            for owner_status, expected_code in (("GREEN", 0), ("RED", 1)):
                with self.subTest(owner_status=owner_status):
                    run_gate.return_value = {"owner_status": owner_status}
                    with contextlib.redirect_stdout(io.StringIO()):
                        code = main(
                            ["--config", str(config_path), *cli_args(root / "out")]
                        )

                    self.assertEqual(code, expected_code)
                    self.assertEqual(
                        run_gate.call_args.kwargs["config_path"], config_path
                    )
                    run_gate.reset_mock()

    def test_cli_unreadable_config_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.yml"
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["--config", str(missing), *cli_args(root / "out")])

        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
