from __future__ import annotations

import base64
import unittest
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Mapping
from unittest import mock

from governance_eval.artifact_verifier import REQUIRED_CONTEXT, VerifierContext
from governance_eval.verifier_pipeline import (
    CONFIGURATION_PATH,
    STANDARD_PATH,
    WORKFLOW_PATH,
    VerificationTarget,
    VerifierPipelineError,
    verify_and_publish,
)


class _FakeAPI:
    def __init__(self, responses: Mapping[str, Any]):
        self.responses = deepcopy(dict(responses))
        self.posts: list[tuple[str, Mapping[str, Any]]] = []
        self.patches: list[tuple[str, Mapping[str, Any]]] = []
        self.downloads: list[tuple[str, Path, int]] = []

    def get_json(self, path: str) -> Mapping[str, Any]:
        value = self.responses[path]
        if isinstance(value, list):
            if len(value) > 1:
                return deepcopy(value.pop(0))
            return deepcopy(value[0])
        return deepcopy(value)

    def post_json(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.posts.append((path, deepcopy(payload)))
        return {
            "id": 987654,
            "name": payload["name"],
            "head_sha": payload["head_sha"],
            "app": {"id": 7654321},
        }

    def patch_json(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.patches.append((path, deepcopy(payload)))
        return {"id": 987654, **deepcopy(payload), "app": {"id": 7654321}}

    def download(self, path: str, destination: Path, limit: int) -> None:
        self.downloads.append((path, destination, limit))
        destination.write_bytes(b"candidate zip")


class VerifierPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = "markheck-solutions/example"
        self.base = "a" * 40
        self.head = "b" * 40
        self.evaluator = "c" * 40
        self.target = VerificationTarget(
            repository=self.repository,
            pull_request=42,
            run_id=1234,
            run_attempt=2,
            evaluator_sha=self.evaluator,
            verifier_app_id=7654321,
        )
        self.responses = self._responses()

    def test_collects_only_fresh_api_identity_and_posts_exact_head_check(self) -> None:
        api = _FakeAPI(self.responses)
        check_request = {
            "name": REQUIRED_CONTEXT,
            "head_sha": self.head,
            "status": "completed",
            "conclusion": "success",
            "external_id": "d" * 64,
            "output": {"title": "PASS", "summary": "verified"},
        }
        with TemporaryDirectory() as temporary_directory:
            with (
                mock.patch(
                    "governance_eval.verifier_pipeline.verify_candidate_artifact",
                    return_value={"result": "PASS", "errors": []},
                ) as verify,
                mock.patch(
                    "governance_eval.verifier_pipeline.check_run_request",
                    return_value=check_request,
                ),
            ):
                result = verify_and_publish(
                    api=api,
                    target=self.target,
                    output_directory=Path(temporary_directory) / "proof",
                    verified_at="2026-07-23T18:03:00Z",
                )

            archive, context = verify.call_args.args
            self.assertIsInstance(context, VerifierContext)
            self.assertEqual(archive.read_bytes(), b"candidate zip")
            self.assertEqual(context.repository_id, 101)
            self.assertEqual(context.pull_request, 42)
            self.assertEqual(context.base_sha, self.base)
            self.assertEqual(context.head_sha, self.head)
            self.assertEqual(context.head_tree_sha, "d" * 40)
            self.assertEqual(context.evaluator_sha, self.evaluator)
            self.assertEqual(context.evaluator_tree_sha, "e" * 40)
            self.assertEqual(context.run_app_id, 15368)
            self.assertEqual(context.verifier_app_id, 7654321)
            self.assertEqual(
                context.workflow_file_sha256, sha256(b"workflow\n").hexdigest()
            )
            self.assertEqual(
                context.configuration_sha256, sha256(b"config\n").hexdigest()
            )
            self.assertEqual(context.standard_sha256, sha256(b"standard\n").hexdigest())
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(api.posts[0][1]["status"], "in_progress")
            self.assertEqual(api.posts[0][0], f"/repos/{self.repository}/check-runs")
            self.assertEqual(api.patches[0][1]["conclusion"], "success")
            self.assertEqual(
                api.patches[0][0], f"/repos/{self.repository}/check-runs/987654"
            )

    def test_rejects_cross_pr_run_before_reading_candidate_content(self) -> None:
        responses = deepcopy(self.responses)
        responses[f"/repos/{self.repository}/actions/runs/1234"]["pull_requests"][0][
            "number"
        ] = 43
        api = _FakeAPI(responses)

        with TemporaryDirectory() as temporary_directory:
            with mock.patch(
                "governance_eval.verifier_pipeline.verify_candidate_artifact"
            ) as verify:
                result = verify_and_publish(
                    api=api,
                    target=self.target,
                    output_directory=Path(temporary_directory) / "proof",
                    verified_at="2026-07-23T18:03:00Z",
                )

        verify.assert_not_called()
        self.assertEqual(result["result"], "REJECT")
        self.assertEqual(api.patches[0][1]["conclusion"], "failure")
        self.assertIn("pull request mismatch", api.patches[0][1]["output"]["summary"])

    def test_rejects_artifact_from_another_head_or_repository(self) -> None:
        artifact_path = (
            f"/repos/{self.repository}/actions/runs/1234/artifacts?per_page=100"
        )
        for field, value in (("head_sha", "f" * 40), ("repository_id", 999)):
            with self.subTest(field=field):
                responses = deepcopy(self.responses)
                responses[artifact_path]["artifacts"][0]["workflow_run"][field] = value
                api = _FakeAPI(responses)
                with TemporaryDirectory() as temporary_directory:
                    result = verify_and_publish(
                        api=api,
                        target=self.target,
                        output_directory=Path(temporary_directory) / "proof",
                        verified_at="2026-07-23T18:03:00Z",
                    )
                self.assertEqual(result["result"], "REJECT")
                self.assertEqual(api.patches[0][1]["conclusion"], "failure")

    def test_head_change_during_verification_never_posts_old_success(self) -> None:
        responses = deepcopy(self.responses)
        pr_path = f"/repos/{self.repository}/pulls/42"
        changed = deepcopy(responses[pr_path])
        changed["head"]["sha"] = "f" * 40
        responses[pr_path] = [responses[pr_path], changed]
        api = _FakeAPI(responses)
        with TemporaryDirectory() as temporary_directory:
            with (
                mock.patch(
                    "governance_eval.verifier_pipeline.verify_candidate_artifact",
                    return_value={"result": "PASS", "errors": []},
                ),
                mock.patch(
                    "governance_eval.verifier_pipeline.check_run_request",
                    return_value={
                        "name": REQUIRED_CONTEXT,
                        "head_sha": self.head,
                        "status": "completed",
                        "conclusion": "success",
                    },
                ),
            ):
                result = verify_and_publish(
                    api=api,
                    target=self.target,
                    output_directory=Path(temporary_directory) / "proof",
                    verified_at="2026-07-23T18:03:00Z",
                )

        self.assertEqual(result["result"], "REJECT")
        self.assertEqual(api.posts[0][1]["head_sha"], "f" * 40)
        self.assertEqual(api.patches[0][1]["conclusion"], "failure")

    def test_actual_check_app_must_match_the_expected_app_id(self) -> None:
        api = _FakeAPI(self.responses)
        with TemporaryDirectory() as temporary_directory:
            with (
                mock.patch(
                    "governance_eval.verifier_pipeline.verify_candidate_artifact",
                    return_value={"result": "PASS", "errors": []},
                ),
                mock.patch(
                    "governance_eval.verifier_pipeline.check_run_request",
                    return_value={
                        "name": REQUIRED_CONTEXT,
                        "head_sha": self.head,
                        "status": "completed",
                        "conclusion": "success",
                        "external_id": "d" * 64,
                        "output": {"title": "PASS", "summary": "verified"},
                    },
                ),
            ):
                result = verify_and_publish(
                    api=api,
                    target=replace(self.target, verifier_app_id=9999999),
                    output_directory=Path(temporary_directory) / "proof",
                    verified_at="2026-07-23T18:03:00Z",
                )

        self.assertEqual(result["result"], "REJECT")
        self.assertEqual(api.posts[0][1]["status"], "in_progress")
        self.assertEqual(api.patches[0][1]["conclusion"], "failure")
        self.assertIn(
            "App or head identity mismatch", api.patches[0][1]["output"]["summary"]
        )

    def test_rejects_noncanonical_or_mutable_target_identity(self) -> None:
        cases = (
            VerificationTarget(
                "MarkHeck-Solutions/example", 1, 1, 1, self.evaluator, 1
            ),
            VerificationTarget(self.repository, 0, 1, 1, self.evaluator, 1),
            VerificationTarget(self.repository, 1, 1, 1, "main", 1),
            VerificationTarget(self.repository, 1, 1, 1, self.evaluator, 0),
        )
        for target in cases:
            with self.subTest(target=target):
                with TemporaryDirectory() as temporary_directory:
                    with self.assertRaises(VerifierPipelineError):
                        verify_and_publish(
                            api=_FakeAPI(self.responses),
                            target=target,
                            output_directory=Path(temporary_directory) / "proof",
                        )

    def _responses(self) -> dict[str, Any]:
        repository_path = f"/repos/{self.repository}"
        pr = {
            "number": 42,
            "state": "open",
            "base": {
                "sha": self.base,
                "repo": {"id": 101, "full_name": self.repository},
            },
            "head": {"sha": self.head, "repo": {"id": 202}},
        }
        run = {
            "id": 1234,
            "run_attempt": 2,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "success",
            "head_sha": self.head,
            "path": WORKFLOW_PATH,
            "repository": {"id": 101, "full_name": self.repository},
            "app": {"id": 15368},
            "pull_requests": [
                {
                    "number": 42,
                    "base": {"sha": self.base},
                    "head": {"sha": self.head},
                }
            ],
        }
        artifact = {
            "id": 555,
            "name": "governance-candidate-evidence-1234-2",
            "expired": False,
            "size_in_bytes": 1000,
            "digest": "sha256:" + "9" * 64,
            "created_at": "2026-07-23T18:02:00Z",
            "workflow_run": {
                "id": 1234,
                "repository_id": 101,
                "head_sha": self.head,
            },
        }
        responses: dict[str, Any] = {
            repository_path: {"id": 101, "full_name": self.repository},
            f"{repository_path}/pulls/42": pr,
            f"{repository_path}/actions/runs/1234": run,
            f"{repository_path}/actions/runs/1234/artifacts?per_page=100": {
                "total_count": 1,
                "artifacts": [artifact],
            },
            "/repos/markheck-solutions/governance": {
                "id": 1280677092,
                "full_name": "markheck-solutions/governance",
            },
            f"{repository_path}/git/commits/{self.head}": {
                "sha": self.head,
                "tree": {"sha": "d" * 40},
            },
            f"/repos/markheck-solutions/governance/git/commits/{self.evaluator}": {
                "sha": self.evaluator,
                "tree": {"sha": "e" * 40},
            },
        }
        for path, content in (
            (WORKFLOW_PATH, b"workflow\n"),
            (CONFIGURATION_PATH, b"config\n"),
            (STANDARD_PATH, b"standard\n"),
        ):
            responses[f"{repository_path}/contents/{path}?ref={self.head}"] = {
                "type": "file",
                "encoding": "base64",
                "content": base64.b64encode(content).decode(),
            }
        return responses


if __name__ == "__main__":
    unittest.main()
