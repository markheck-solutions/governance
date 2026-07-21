from __future__ import annotations

import copy
import unittest

from governance_eval.merge_group_authority import (
    MergeGroupAuthorityError,
    create_merge_group_receipt,
    enforcement_transition_allowed,
    protected_delivery_conditions,
    resolve_merge_group_authority,
    validate_merge_group_artifact,
    verify_merge_group_receipt,
)


def authority() -> dict:
    return resolve_merge_group_authority(
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


def evidence() -> dict:
    return {
        "event_id": "merge-group:29870000000:1",
        "event_created_at": "2026-07-21T21:00:00Z",
        "verification_time": "2026-07-21T21:01:00Z",
        "evaluator_sha": "d" * 40,
        "caller_workflow_path": ".github/workflows/supportability-enforcement.yml",
        "caller_workflow_sha256": "e" * 64,
        "reusable_workflow_path": ".github/workflows/delivery-receipt.yml",
        "reusable_workflow_sha256": "f" * 64,
        "workflow_run_id": 29870000000,
        "workflow_run_attempt": 1,
        "check_run_id": 88770000000,
        "github_app_id": 15368,
        "config_sha256": "1" * 64,
        "standard_sha256": "2" * 64,
        "transaction_id": "merge-group:29870000000:1:91",
        "artifact_digest": "sha256:" + "3" * 64,
    }


class MergeGroupAuthorityTests(unittest.TestCase):
    def test_protected_activation_and_job_conditions_are_exact(self) -> None:
        transition = (
            "e7dcc678d0391535a5befc148c63f3a41029c6a020645b855514ff408bd85e1d",
            "4fc59fe8d102ced45dc14f49343a22a0130af32ddbb6afec63c9ce09b005adc7",
        )
        self.assertTrue(enforcement_transition_allowed(transition))
        self.assertFalse(enforcement_transition_allowed((transition[0], "0" * 64)))
        conditions = protected_delivery_conditions()
        self.assertIn(
            "${{ needs.resolve-authority.outputs.base-ref == 'main' }}",
            conditions["baseline-supportability"],
        )
        self.assertIn(
            "${{ always() && needs.resolve-authority.outputs.base-ref == 'main' }}",
            conditions["delivery-receipt"],
        )

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

    def test_rejects_missing_or_ambiguous_constituent_pull_request(self) -> None:
        base_event = {
            "repository": authority()["repository"],
            "merge_group": {
                "head_ref": authority()["merge_group"]["ref"],
                "head_sha": authority()["merge_group"]["sha"],
                "base_ref": authority()["merge_group"]["base_ref"],
                "base_sha": authority()["merge_group"]["base_sha"],
            },
        }
        pull = {
            "number": 91,
            "html_url": authority()["pull_request"]["url"],
            "head": {"sha": authority()["pull_request"]["head_sha"]},
            "base": {
                "ref": authority()["pull_request"]["base_ref"],
                "sha": authority()["pull_request"]["base_sha"],
            },
        }
        for name, pulls in (("missing", []), ("ambiguous", [pull, pull])):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    MergeGroupAuthorityError, "exactly one pull request"
                ),
            ):
                resolve_merge_group_authority(base_event, pulls)

    def test_rejects_incomplete_api_response(self) -> None:
        current = authority()
        with self.assertRaisesRegex(MergeGroupAuthorityError, "head sha is invalid"):
            resolve_merge_group_authority(
                {
                    "repository": current["repository"],
                    "merge_group": {
                        "head_ref": current["merge_group"]["ref"],
                        "head_sha": current["merge_group"]["sha"],
                        "base_ref": current["merge_group"]["base_ref"],
                        "base_sha": current["merge_group"]["base_sha"],
                    },
                },
                [
                    {
                        "number": 91,
                        "html_url": current["pull_request"]["url"],
                        "head": {},
                        "base": {
                            "ref": "main",
                            "sha": current["pull_request"]["base_sha"],
                        },
                    }
                ],
            )

    def test_rejects_merge_group_after_base_movement(self) -> None:
        current = authority()
        with self.assertRaisesRegex(
            MergeGroupAuthorityError, "base sha differs from merge group"
        ):
            resolve_merge_group_authority(
                {
                    "repository": current["repository"],
                    "merge_group": {
                        "head_ref": current["merge_group"]["ref"],
                        "head_sha": current["merge_group"]["sha"],
                        "base_ref": "main",
                        "base_sha": "9" * 40,
                    },
                },
                [
                    {
                        "number": current["pull_request"]["number"],
                        "html_url": current["pull_request"]["url"],
                        "head": {"sha": current["pull_request"]["head_sha"]},
                        "base": {
                            "ref": "main",
                            "sha": current["pull_request"]["base_sha"],
                        },
                    }
                ],
            )

    def test_creates_and_verifies_current_authoritative_receipt(self) -> None:
        current = authority()
        current_evidence = evidence()
        receipt = create_merge_group_receipt(current, current_evidence)

        verify_merge_group_receipt(receipt, current, current_evidence)

        self.assertEqual(receipt["base_branch"], "main")
        self.assertEqual(receipt["merge_group"]["sha"], "a" * 40)
        self.assertEqual(receipt["pull_request"]["number"], 91)
        self.assertEqual(receipt["workflow"]["github_app_id"], 15368)

    def test_receipt_generation_and_duplicate_delivery_are_idempotent(self) -> None:
        current = authority()
        current_evidence = evidence()

        first = create_merge_group_receipt(current, current_evidence)
        duplicate = create_merge_group_receipt(current, current_evidence)
        repeated_event = create_merge_group_receipt(current, current_evidence)

        self.assertEqual(first, duplicate)
        self.assertEqual(first, repeated_event)

    def test_rejects_wrong_or_stale_authority_bindings(self) -> None:
        current = authority()
        current_evidence = evidence()
        receipt = create_merge_group_receipt(current, current_evidence)
        mutations = {
            "repository_id": ("repository", "id", 7),
            "repository_name": (
                "repository",
                "full_name",
                "markheck-solutions/other",
            ),
            "pull_request_number": ("pull_request", "number", 92),
            "pull_request_head": ("pull_request", "head_sha", "4" * 40),
            "pull_request_base": ("pull_request", "base_sha", "5" * 40),
            "base_sha": (None, "base_sha", "6" * 40),
            "stale_merge_group": ("merge_group", "sha", "7" * 40),
            "cross_merge_group": (
                "merge_group",
                "ref",
                "gh-readonly-queue/main/pr-91-other",
            ),
            "cross_pr": ("pull_request", "number", 93),
        }
        for name, (parent, key, value) in mutations.items():
            changed = copy.deepcopy(receipt)
            target = changed if parent is None else changed[parent]
            target[key] = value
            with self.subTest(name=name), self.assertRaises(MergeGroupAuthorityError):
                verify_merge_group_receipt(changed, current, current_evidence)

    def test_rejects_wrong_or_old_evidence_bindings(self) -> None:
        current = authority()
        current_evidence = evidence()
        receipt = create_merge_group_receipt(current, current_evidence)
        mutations = {
            "evaluator_sha": (None, "evaluator_sha", "4" * 40),
            "caller_workflow_path": (
                "caller_workflow",
                "path",
                ".github/workflows/other.yml",
            ),
            "caller_workflow_hash": ("caller_workflow", "sha256", "4" * 64),
            "reusable_workflow_path": (
                "reusable_workflow",
                "path",
                ".github/workflows/supportability-gate.yml",
            ),
            "reusable_workflow_hash": (
                "reusable_workflow",
                "sha256",
                "5" * 64,
            ),
            "workflow_run_id": ("workflow", "run_id", 29870000001),
            "workflow_run_attempt": ("workflow", "run_attempt", 2),
            "old_check_run": ("workflow", "check_run_id", 88770000001),
            "github_app": ("workflow", "github_app_id", 1),
            "config_hash": (None, "config_sha256", "6" * 64),
            "standard_hash": (None, "standard_sha256", "7" * 64),
            "transaction": (None, "transaction_id", "other:transaction"),
            "artifact": (None, "artifact_digest", "8" * 64),
            "event_id": ("merge_group", "event_id", "merge-group:other:1"),
            "event_created_at": (
                "merge_group",
                "event_created_at",
                "2026-07-21T20:00:00Z",
            ),
            "verification_time": (
                None,
                "verification_time",
                "2026-07-21T21:02:00Z",
            ),
        }
        for name, (parent, key, value) in mutations.items():
            changed = copy.deepcopy(receipt)
            target = changed if parent is None else changed[parent]
            target[key] = value
            with self.subTest(name=name), self.assertRaises(MergeGroupAuthorityError):
                verify_merge_group_receipt(changed, current, current_evidence)

    def test_rejects_missing_merge_group_and_mutated_receipt_id(self) -> None:
        current = authority()
        current_evidence = evidence()
        receipt = create_merge_group_receipt(current, current_evidence)
        missing = copy.deepcopy(receipt)
        missing.pop("merge_group")
        mutated = copy.deepcopy(receipt)
        mutated["receipt_id"] = "0" * 64

        with self.assertRaises(MergeGroupAuthorityError):
            verify_merge_group_receipt(missing, current, current_evidence)
        with self.assertRaisesRegex(
            MergeGroupAuthorityError, "receipt id does not match content"
        ):
            verify_merge_group_receipt(mutated, current, current_evidence)

    def test_rejects_verification_before_event(self) -> None:
        current_evidence = evidence()
        current_evidence["verification_time"] = "2026-07-21T20:59:59Z"
        with self.assertRaisesRegex(
            MergeGroupAuthorityError, "precedes merge-group event"
        ):
            create_merge_group_receipt(authority(), current_evidence)
