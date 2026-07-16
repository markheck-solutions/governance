from __future__ import annotations

import contextlib
import hashlib
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from governance_eval.codex_review_gate import (
    bind_supportability_config,
    main,
    run_codex_review_gate,
)
from governance_eval.paths import repo_root


HEAD = "b" * 40
BASE = "a" * 40
GOVERNANCE = "c" * 40
CONFIG_SOURCE_PATH = ".github/governance/supportability.yml"


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


def bind_config(
    directory: Path, policy: str = "non_blocking"
) -> tuple[Path, Path, dict[str, str]]:
    source_path = write_config(directory, policy)
    bound_path = directory / "bound-supportability.yml"
    binding = bind_supportability_config(
        source_path=source_path,
        bound_path=bound_path,
        repository="owner/repo",
        target_head_sha=HEAD,
        source_relative_path=CONFIG_SOURCE_PATH,
    )
    return source_path, bound_path, binding


def binding_digest(raw: bytes) -> str:
    record = {
        "binding_version": "1.0",
        "repository": "owner/repo",
        "target_head_sha": HEAD,
        "source_path": CONFIG_SOURCE_PATH,
        "content_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )


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
    def test_binds_validated_config_bytes_to_target_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = write_config(root)
            bound_path = root / "bound" / "supportability.yml"
            source_relative_path = CONFIG_SOURCE_PATH
            binding = bind_supportability_config(
                source_path=source_path,
                bound_path=bound_path,
                repository="owner/repo",
                target_head_sha=HEAD,
                source_relative_path=source_relative_path,
            )

            content_sha256 = (
                "sha256:" + hashlib.sha256(source_path.read_bytes()).hexdigest()
            )
            record = {
                "binding_version": "1.0",
                "repository": "owner/repo",
                "target_head_sha": HEAD,
                "source_path": source_relative_path,
                "content_sha256": content_sha256,
            }
            binding_sha256 = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(record, sort_keys=True, separators=(",", ":")).encode(
                        "utf-8"
                    )
                ).hexdigest()
            )

            self.assertEqual(bound_path.read_bytes(), source_path.read_bytes())
            self.assertEqual(
                binding,
                {
                    **record,
                    "binding_sha256": binding_sha256,
                    "bound_config_path": str(bound_path.resolve()),
                },
            )

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
    def test_recollects_and_propagates_fixed_policy_while_writing_all_artifacts(
        self, ai_gate, evaluate, _serialize_result, _serialize_snapshot
    ) -> None:
        evaluate.return_value = {"review_state": "AI_REVIEW_UNAVAILABLE"}
        ai_gate.return_value = {"owner_status": "GREEN"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "artifacts"
            source_path, bound_path, binding = bind_config(root)
            source_path.write_text(
                source_path.read_text(encoding="utf-8").replace(
                    "unavailable_after_cutoff: non_blocking",
                    "unavailable_after_cutoff: blocking",
                ),
                encoding="utf-8",
            )
            captures = iter(
                [
                    snapshot("2026-07-13T00:04:00Z"),
                    snapshot("2026-07-13T00:05:02Z"),
                ]
            )
            sleeps: list[float] = []
            result = run_codex_review_gate(
                config_path=bound_path,
                config_source_path=CONFIG_SOURCE_PATH,
                config_binding_digest=binding["binding_sha256"],
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
                ai_gate.call_args.kwargs["unavailable_after_cutoff"],
                "non_blocking",
            )
            expected_binding = {
                key: value
                for key, value in binding.items()
                if key != "bound_config_path"
            }
            self.assertEqual(result["supportability_config_binding"], expected_binding)
            artifact = json.loads(
                (output_dir / "ai-review-gate-result.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                artifact["supportability_config_binding"], expected_binding
            )

    def test_final_collection_before_deadline_fails_closed(self) -> None:
        calls = iter(
            [snapshot("2026-07-13T00:04:00Z"), snapshot("2026-07-13T00:04:59Z")]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _source_path, bound_path, binding = bind_config(root)
            with self.assertRaisesRegex(ValueError, "before the review deadline"):
                run_codex_review_gate(
                    config_path=bound_path,
                    config_source_path=CONFIG_SOURCE_PATH,
                    config_binding_digest=binding["binding_sha256"],
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
                sorted(path.name for path in root.iterdir()),
                ["bound-supportability.yml", "supportability.yml"],
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
            expected_digest = binding_digest(config_path.read_bytes())

            with self.assertRaisesRegex(ValueError, "supportability config invalid"):
                run_codex_review_gate(
                    config_path=config_path,
                    config_source_path=CONFIG_SOURCE_PATH,
                    config_binding_digest=expected_digest,
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

    def test_binding_evasions_fail_before_collection_sleep_or_artifacts(
        self,
    ) -> None:
        cases = (
            "policy-mutation",
            "same-policy-byte-change",
            "wrong-head-replay",
            "wrong-repository-replay",
            "wrong-path-replay",
            "wrong-digest",
            "uppercase-digest",
            "deleted-bound-config",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _source_path, bound_path, binding = bind_config(root)
                repository = "owner/repo"
                head_sha = HEAD
                source_relative_path = CONFIG_SOURCE_PATH
                expected_digest = binding["binding_sha256"]
                expected_error = "binding digest"
                if case == "policy-mutation":
                    bound_path.write_text(
                        bound_path.read_text(encoding="utf-8").replace(
                            "unavailable_after_cutoff: non_blocking",
                            "unavailable_after_cutoff: blocking",
                        ),
                        encoding="utf-8",
                    )
                elif case == "same-policy-byte-change":
                    bound_path.write_bytes(bound_path.read_bytes() + b"\n")
                elif case == "wrong-head-replay":
                    head_sha = "d" * 40
                elif case == "wrong-repository-replay":
                    repository = "other/repo"
                elif case == "wrong-path-replay":
                    source_relative_path = "docs/supportability.yml"
                elif case == "wrong-digest":
                    expected_digest = "sha256:" + "0" * 64
                elif case == "uppercase-digest":
                    expected_digest = expected_digest.upper()
                elif case == "deleted-bound-config":
                    bound_path.unlink()
                    expected_error = "bound supportability config is unavailable"

                collector = Mock()
                sleeper = Mock()
                output_dir = root / "artifacts"
                with self.assertRaisesRegex(ValueError, expected_error):
                    run_codex_review_gate(
                        config_path=bound_path,
                        config_source_path=source_relative_path,
                        config_binding_digest=expected_digest,
                        repository=repository,
                        pull_request_number=1,
                        base_sha=BASE,
                        head_sha=head_sha,
                        governance_sha=GOVERNANCE,
                        review_window_started_at="invalid timestamp",
                        output_dir=output_dir,
                        collector=collector,
                        sleeper=sleeper,
                    )

                collector.assert_not_called()
                sleeper.assert_not_called()
                self.assertFalse(output_dir.exists())

    def test_binding_rejects_symlink_and_nonregular_source_or_bound_file(
        self,
    ) -> None:
        symlink_stat = SimpleNamespace(st_mode=stat.S_IFLNK)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = write_config(root)
            with patch.object(type(source_path), "lstat", return_value=symlink_stat):
                with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
                    bind_supportability_config(
                        source_path=source_path,
                        bound_path=root / "source-link-bound.yml",
                        repository="owner/repo",
                        target_head_sha=HEAD,
                        source_relative_path=CONFIG_SOURCE_PATH,
                    )

            source_stat = source_path.lstat()
            bound_path = root / "bound" / "supportability.yml"
            with patch.object(
                type(source_path),
                "lstat",
                side_effect=(source_stat, symlink_stat),
            ):
                with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
                    bind_supportability_config(
                        source_path=source_path,
                        bound_path=bound_path,
                        repository="owner/repo",
                        target_head_sha=HEAD,
                        source_relative_path=CONFIG_SOURCE_PATH,
                    )

            with self.assertRaisesRegex(ValueError, "must be a regular file"):
                bind_supportability_config(
                    source_path=root,
                    bound_path=root / "directory-bound.yml",
                    repository="owner/repo",
                    target_head_sha=HEAD,
                    source_relative_path=CONFIG_SOURCE_PATH,
                )

    def test_binding_rejects_invalid_logical_paths_and_invalid_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = write_config(root)
            invalid_paths = (
                "",
                "/supportability.yml",
                "../supportability.yml",
                ".github\\governance\\supportability.yml",
                ".github//supportability.yml",
                "supportability.json",
                "C:/supportability.yml",
            )
            for index, invalid_path in enumerate(invalid_paths):
                with self.subTest(path=invalid_path):
                    with self.assertRaisesRegex(ValueError, "source path is invalid"):
                        bind_supportability_config(
                            source_path=source_path,
                            bound_path=root / f"invalid-{index}.yml",
                            repository="owner/repo",
                            target_head_sha=HEAD,
                            source_relative_path=invalid_path,
                        )

            source_path = write_config(root, "blocking")
            with self.assertRaisesRegex(ValueError, "must be 'non_blocking'"):
                bind_supportability_config(
                    source_path=source_path,
                    bound_path=root / "blocking-config.yml",
                    repository="owner/repo",
                    target_head_sha=HEAD,
                    source_relative_path=CONFIG_SOURCE_PATH,
                )

            source_path.write_bytes(b"\xff")
            with self.assertRaisesRegex(ValueError, "must be UTF-8"):
                bind_supportability_config(
                    source_path=source_path,
                    bound_path=root / "invalid-config.yml",
                    repository="owner/repo",
                    target_head_sha=HEAD,
                    source_relative_path=CONFIG_SOURCE_PATH,
                )

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
                            [
                                "--config",
                                str(config_path),
                                "--config-source-path",
                                CONFIG_SOURCE_PATH,
                                "--config-binding-digest",
                                "sha256:" + "d" * 64,
                                *cli_args(root / "out"),
                            ]
                        )

                    self.assertEqual(code, expected_code)
                    self.assertEqual(
                        run_gate.call_args.kwargs["config_path"], config_path
                    )
                    self.assertEqual(
                        run_gate.call_args.kwargs["config_source_path"],
                        CONFIG_SOURCE_PATH,
                    )
                    self.assertEqual(
                        run_gate.call_args.kwargs["config_binding_digest"],
                        "sha256:" + "d" * 64,
                    )
                    run_gate.reset_mock()

    def test_cli_unreadable_config_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.yml"
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(
                        [
                            "--config",
                            str(missing),
                            "--config-source-path",
                            CONFIG_SOURCE_PATH,
                            "--config-binding-digest",
                            "sha256:" + "d" * 64,
                            *cli_args(root / "out"),
                        ]
                    )

        self.assertEqual(raised.exception.code, 2)

    @patch(
        "governance_eval.codex_review_gate.run_codex_review_gate",
        return_value={"owner_status": "GREEN"},
    )
    def test_cli_requires_config_binding_inputs(self, run_gate: Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = write_config(root)
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["--config", str(config_path), *cli_args(root / "out")])

        self.assertEqual(raised.exception.code, 2)
        run_gate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
