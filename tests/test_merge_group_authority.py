from __future__ import annotations

import unittest

from governance_eval.merge_group_authority import (
    MergeGroupAuthorityError,
    resolve_merge_group_authority,
    validate_merge_group_artifact,
)


class MergeGroupAuthorityTests(unittest.TestCase):
    def test_resolves_single_constituent_pull_request(self) -> None:
        result = resolve_merge_group_authority(
            {
                "repository": {
                    "id": 1280677092,
                    "full_name": "markheck-solutions/governance",
                },
                "merge_group": {
                    "head_ref": "gh-readonly-queue/main/pr-91-abc",
                    "head_sha": "a" * 40,
                    "base_ref": "main",
                    "base_sha": "b" * 40,
                },
            },
            [
                {
                    "number": 91,
                    "html_url": "https://github.com/markheck-solutions/governance/pull/91",
                    "head": {"sha": "c" * 40},
                    "base": {"ref": "main", "sha": "b" * 40},
                }
            ],
        )

        self.assertEqual(
            result,
            {
                "repository": {
                    "id": 1280677092,
                    "full_name": "markheck-solutions/governance",
                },
                "merge_group": {
                    "ref": "gh-readonly-queue/main/pr-91-abc",
                    "sha": "a" * 40,
                    "base_ref": "main",
                    "base_sha": "b" * 40,
                },
                "pull_request": {
                    "number": 91,
                    "url": "https://github.com/markheck-solutions/governance/pull/91",
                    "head_sha": "c" * 40,
                    "base_sha": "b" * 40,
                    "base_ref": "main",
                },
            },
        )

    def test_rejects_candidate_head_artifact_for_merge_group(self) -> None:
        authority = resolve_merge_group_authority(
            {
                "repository": {
                    "id": 1280677092,
                    "full_name": "markheck-solutions/governance",
                },
                "merge_group": {
                    "head_ref": "gh-readonly-queue/main/pr-91-abc",
                    "head_sha": "a" * 40,
                    "base_ref": "main",
                    "base_sha": "b" * 40,
                },
            },
            [
                {
                    "number": 91,
                    "html_url": "https://github.com/markheck-solutions/governance/pull/91",
                    "head": {"sha": "c" * 40},
                    "base": {"ref": "main", "sha": "b" * 40},
                }
            ],
        )

        with self.assertRaisesRegex(
            MergeGroupAuthorityError,
            "artifact merge-group sha differs from current merge group",
        ):
            validate_merge_group_artifact(
                authority,
                {
                    "repository": authority["repository"],
                    "pull_request": authority["pull_request"],
                    "merge_group": {
                        **authority["merge_group"],
                        "sha": authority["pull_request"]["head_sha"],
                    },
                },
            )
