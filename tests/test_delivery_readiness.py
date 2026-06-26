from __future__ import annotations

import json
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from governance_eval import delivery_readiness
from governance_eval.delivery_readiness import evaluate_readiness
from governance_eval.hashing import sha256_json


class DeliveryReadinessTests(unittest.TestCase):
    def test_ready_when_final_review_workflow_and_benchmark_are_valid(self) -> None:
        sha = "a" * 40
        payload = _payload(sha, reviews=[_clean_review(sha)])

        result = evaluate_readiness(payload)

        self.assertTrue(result["ready"])
        self.assertEqual(result["review_gate"], "GITHUB_CODEX_FINAL_REVIEW")
        self.assertEqual(result["github_review_state"], "CLEAN")
        self.assertEqual(result["unresolved_p0_count"], 0)
        self.assertEqual(result["final_review_commit"], sha)

    def test_blocks_stale_review_unresolved_p1_and_failed_workflow(self) -> None:
        sha = "b" * 40
        payload = _payload(
            sha,
            reviews=[_clean_review(sha, submitted_at="2026-06-25T09:59:00Z")],
            unresolved_threads=[{"body": "severity: P1 candidate workflow can be bypassed"}],
            workflow_contexts=[{"name": "tests", "conclusion": "FAILURE"}],
        )

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertEqual(result["github_review_state"], "BLOCKING_FINDINGS_PRESENT")
        self.assertEqual(result["unresolved_p1_count"], 1)
        self.assertEqual(len(result["failed_workflow_contexts"]), 1)
        self.assertIsNone(result["final_review_timestamp"])

    def test_change_request_review_is_not_final_clean_review(self) -> None:
        sha = "c" * 40
        payload = _payload(
            sha,
            reviews=[
                {
                    "state": "CHANGES_REQUESTED",
                    "submittedAt": "2026-06-25T10:05:00Z",
                    "commitOid": sha,
                    "author": "chatgpt-codex-connector",
                    "body": f"Reviewed commit {sha[:10]}. Please fix this.",
                }
            ],
        )

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertEqual(result["github_review_state"], "BLOCKING_FINDINGS_PRESENT")
        self.assertIsNone(result["final_review_timestamp"])

    def test_owner_review_comment_is_not_final_independent_review(self) -> None:
        sha = "d" * 40
        payload = _payload(
            sha,
            reviews=[
                {
                    "state": "COMMENTED",
                    "submittedAt": "2026-06-25T10:05:00Z",
                    "commitOid": sha,
                    "author": "markheck-solutions",
                    "body": f"Reviewed commit {sha[:10]}.",
                }
            ],
        )

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertEqual(result["github_review_state"], "STALE")
        self.assertIsNone(result["final_review_timestamp"])

    def test_unrelated_green_status_is_not_workflow_evidence(self) -> None:
        sha = "f" * 40
        payload = _payload(
            sha,
            reviews=[_clean_review(sha)],
            workflow_contexts=[{"name": "lint", "workflowName": "Validation", "conclusion": "SUCCESS"}],
        )

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(result["missing_workflow_evidence"])

    def test_missing_workflow_evidence_blocks_readiness(self) -> None:
        sha = "e" * 40
        payload = _payload(sha, reviews=[_clean_review(sha)], workflow_contexts=[])

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(result["missing_workflow_evidence"])

    def test_clean_review_followed_by_later_blocking_review_blocks(self) -> None:
        sha = "1" * 40
        payload = _payload(
            sha,
            reviews=[
                _clean_review(sha, submitted_at="2026-06-25T10:05:00Z"),
                _blocking_review(sha, submitted_at="2026-06-25T10:06:00Z", body="severity: P1 benchmark evidence missing"),
            ],
        )

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertEqual(result["github_review_state"], "BLOCKING_FINDINGS_PRESENT")
        self.assertEqual(result["later_blocking_review_count"], 1)

    def test_blocking_review_followed_by_later_clean_review_passes(self) -> None:
        sha = "2" * 40
        payload = _payload(
            sha,
            reviews=[
                _blocking_review(sha, submitted_at="2026-06-25T10:05:00Z", body="severity: P2 older issue"),
                _clean_review(sha, submitted_at="2026-06-25T10:06:00Z"),
            ],
        )

        result = evaluate_readiness(payload)

        self.assertTrue(result["ready"])
        self.assertEqual(result["github_review_state"], "CLEAN")
        self.assertEqual(result["later_blocking_review_count"], 0)

    def test_stale_blocking_review_on_older_head_does_not_block_latest_clean_review(self) -> None:
        sha = "3" * 40
        payload = _payload(
            sha,
            reviews=[
                _blocking_review("9" * 40, submitted_at="2026-06-25T10:06:00Z", body="severity: P1 old head issue"),
                _clean_review(sha, submitted_at="2026-06-25T10:07:00Z"),
            ],
        )

        result = evaluate_readiness(payload)

        self.assertTrue(result["ready"])
        self.assertEqual(result["github_review_state"], "CLEAN")

    def test_dismissed_blocking_review_does_not_override_later_clean_review(self) -> None:
        sha = "4" * 40
        payload = _payload(
            sha,
            reviews=[
                _clean_review(sha, submitted_at="2026-06-25T10:05:00Z"),
                {
                    **_blocking_review(sha, submitted_at="2026-06-25T10:06:00Z", body="severity: P1 dismissed"),
                    "state": "DISMISSED",
                },
            ],
        )

        result = evaluate_readiness(payload)

        self.assertTrue(result["ready"])
        self.assertEqual(result["later_blocking_review_count"], 0)

    def test_review_body_containing_blocking_severity_without_thread_blocks(self) -> None:
        sha = "5" * 40
        payload = _payload(
            sha,
            reviews=[_blocking_review(sha, submitted_at="2026-06-25T10:05:00Z", body="P2: missing benchmark artifact")],
            unresolved_threads=[],
        )

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertEqual(result["github_review_state"], "BLOCKING_FINDINGS_PRESENT")

    def test_green_workflow_but_missing_benchmark_artifact_blocks(self) -> None:
        sha = "6" * 40
        payload = _payload(sha, reviews=[_clean_review(sha)], benchmark_evidence=None)
        payload.pop("benchmarkEvidence")

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertFalse(result["benchmark_evidence_valid"])
        self.assertTrue(any("benchmark evidence missing" in error for error in result["benchmark_evidence_errors"]))

    def test_green_workflow_but_benchmark_fail_blocks(self) -> None:
        sha = "7" * 40
        payload = _payload(sha, reviews=[_clean_review(sha)], benchmark_evidence=_benchmark(phase1_decision="BENCHMARK_FAIL"))

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertEqual(result["benchmark_phase1_decision"], "BENCHMARK_FAIL")

    def test_green_workflow_but_inconsistent_benchmark_metrics_blocks(self) -> None:
        sha = "7a" * 20
        benchmark = _benchmark()
        benchmark["metrics"]["critical_defects_blocked"] = 0
        payload = _payload(sha, reviews=[_clean_review(sha)], benchmark_evidence=benchmark)

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(
            any("critical_defects_blocked must equal" in error for error in result["benchmark_evidence_errors"])
        )

    def test_green_workflow_but_tampered_case_decision_blocks(self) -> None:
        sha = "7b" * 20
        benchmark = _benchmark()
        benchmark["cases"][0]["decision"]["decision"] = "MERGE"
        benchmark["artifact_content_hash"] = sha256_json({**benchmark, "artifact_content_hash": ""})
        payload = _payload(sha, reviews=[_clean_review(sha)], benchmark_evidence=benchmark)

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(any("cases[0].decision expected" in error for error in result["benchmark_evidence_errors"]))

    def test_green_workflow_but_missing_stability_metrics_blocks(self) -> None:
        sha = "7c" * 20
        benchmark = _benchmark()
        benchmark["metrics"].pop("deterministic_flake_rate")
        benchmark["artifact_content_hash"] = sha256_json({**benchmark, "artifact_content_hash": ""})
        payload = _payload(sha, reviews=[_clean_review(sha)], benchmark_evidence=benchmark)

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(any("deterministic_flake_rate missing" in error for error in result["benchmark_evidence_errors"]))

    def test_green_workflow_but_artifact_content_hash_mismatch_blocks(self) -> None:
        sha = "7d" * 20
        benchmark = _benchmark()
        benchmark["artifact_content_hash"] = "1" * 64
        payload = _payload(sha, reviews=[_clean_review(sha)], benchmark_evidence=benchmark)

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(any("artifact_content_hash does not match" in error for error in result["benchmark_evidence_errors"]))

    def test_green_workflow_but_missing_phase1_decision_blocks(self) -> None:
        sha = "8" * 40
        benchmark = _benchmark()
        benchmark.pop("phase1_decision")
        payload = _payload(sha, reviews=[_clean_review(sha)], benchmark_evidence=benchmark)

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(any("phase1_decision expected" in error for error in result["benchmark_evidence_errors"]))

    def test_green_workflow_but_malformed_benchmark_json_blocks(self) -> None:
        sha = "a1" * 20
        payload = _payload(sha, reviews=[_clean_review(sha)], benchmark_evidence={"__load_error": "bad json"})

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(any("malformed JSON" in error for error in result["benchmark_evidence_errors"]))

    def test_github_context_requires_artifact_digest_when_requested(self) -> None:
        sha = "a2" * 20
        payload = _payload(sha, reviews=[_clean_review(sha)])
        payload["requireGithubArtifactDigest"] = True

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(any("artifact digest required" in error for error in result["benchmark_evidence_errors"]))

    def test_valid_benchmark_digest_passes_when_required(self) -> None:
        sha = "a3" * 20
        payload = _payload(sha, reviews=[_clean_review(sha)])
        payload["requireGithubArtifactDigest"] = True
        payload["benchmarkArtifactDigest"] = f"sha256:{'a' * 64}"

        result = evaluate_readiness(payload)

        self.assertTrue(result["ready"])
        self.assertEqual(result["benchmark_artifact_digest"], f"sha256:{'a' * 64}")

    def test_skipped_governance_context_is_missing_workflow_evidence(self) -> None:
        sha = "a4" * 20
        payload = _payload(
            sha,
            reviews=[_clean_review(sha)],
            workflow_contexts=[
                {"name": "Phase 1 shadow run", "workflowName": "Governance Shadow Benchmark", "conclusion": "SKIPPED"}
            ],
        )

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(result["missing_workflow_evidence"])

    def test_fallback_quorum_is_accepted_when_github_review_is_stale_and_clean(self) -> None:
        sha = "b1" * 20
        base = "c1" * 20
        payload = _payload(sha, base_sha=base, reviews=[], fallback_quorum=_quorum(base, sha))

        result = evaluate_readiness(payload)

        self.assertTrue(result["ready"])
        self.assertEqual(result["review_gate"], "FALLBACK_CLEAN_ROOM_QUORUM")
        self.assertEqual(result["github_review_state"], "STALE")
        self.assertTrue(result["fallback_quorum_valid"])

    def test_fallback_quorum_is_rejected_when_reviewer_reports_p1(self) -> None:
        sha = "b2" * 20
        base = "c2" * 20
        quorum = _quorum(base, sha)
        quorum["reviewers"][1]["findings"] = [
            {"id": "finding-1", "severity": "P1", "message": "blocking gap", "has_reproducer": True}
        ]
        payload = _payload(sha, base_sha=base, reviews=[], fallback_quorum=quorum)

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertFalse(result["fallback_quorum_valid"])

    def test_fallback_quorum_is_rejected_without_provenance(self) -> None:
        sha = "b5" * 20
        base = "c5" * 20
        quorum = _quorum(base, sha)
        quorum.pop("provenance")
        payload = _payload(sha, base_sha=base, reviews=[], fallback_quorum=quorum)

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertFalse(result["fallback_quorum_valid"])
        self.assertTrue(any("provenance missing" in error for error in result["fallback_quorum_errors"]))

    def test_fallback_quorum_is_rejected_when_top_level_sha_is_stale(self) -> None:
        sha = "b4" * 20
        base = "c4" * 20
        quorum = _quorum(base, sha)
        quorum["reviewed_head_sha"] = "0" * 40
        payload = _payload(sha, base_sha=base, reviews=[], fallback_quorum=quorum)

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertFalse(result["fallback_quorum_valid"])
        self.assertTrue(any("reviewed_head_sha does not match" in error for error in result["fallback_quorum_errors"]))

    def test_unresolved_github_finding_overrides_clean_fallback_quorum(self) -> None:
        sha = "b3" * 20
        base = "c3" * 20
        payload = _payload(
            sha,
            base_sha=base,
            reviews=[],
            unresolved_threads=[{"body": "severity: P2 unresolved review finding"}],
            fallback_quorum=_quorum(base, sha),
        )

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertIsNone(result["review_gate"])
        self.assertEqual(result["github_review_state"], "BLOCKING_FINDINGS_PRESENT")

    def test_benchmark_schema_invalid_blocks_readiness(self) -> None:
        sha = "b6" * 20
        benchmark = _benchmark()
        benchmark.pop("schema_version")
        benchmark["artifact_content_hash"] = sha256_json({**benchmark, "artifact_content_hash": ""})
        payload = _payload(sha, reviews=[_clean_review(sha)], benchmark_evidence=benchmark)

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertTrue(any("benchmark schema invalid" in error for error in result["benchmark_evidence_errors"]))

    def test_live_thread_loader_paginates_review_threads(self) -> None:
        pages = [
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [
                                    {
                                        "isResolved": True,
                                        "path": "a.py",
                                        "line": 1,
                                        "comments": {"nodes": [{"body": "severity: P1 fixed"}]},
                                    }
                                ],
                                "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                            }
                        }
                    }
                }
            },
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [
                                    {
                                        "isResolved": False,
                                        "path": "b.py",
                                        "line": 2,
                                        "comments": {"nodes": [{"body": "severity: P2 still open"}]},
                                    }
                                ],
                                "pageInfo": {"hasNextPage": False, "endCursor": None},
                            }
                        }
                    }
                }
            },
        ]
        calls: list[list[str]] = []

        def fake_run(args: list[str], **_: object) -> CompletedProcess[str]:
            calls.append(args)
            page = pages.pop(0)
            return CompletedProcess(args, 0, stdout=json.dumps(page), stderr="")

        with patch.object(delivery_readiness.subprocess, "run", side_effect=fake_run):
            threads = delivery_readiness._load_review_threads("owner", "repo", 12)

        self.assertEqual(threads, [{"path": "b.py", "line": 2, "body": "severity: P2 still open"}])
        self.assertEqual(len(calls), 2)
        self.assertTrue(any("cursor=cursor-1" in arg for arg in calls[1]))


def _payload(
    head_sha: str,
    *,
    base_sha: str = "0" * 40,
    reviews: list[dict] | None = None,
    unresolved_threads: list[dict] | None = None,
    workflow_contexts: list[dict] | None = None,
    benchmark_evidence: dict | None = None,
    fallback_quorum: dict | None = None,
) -> dict:
    payload = {
        "state": "OPEN",
        "isDraft": False,
        "mergeStateStatus": "CLEAN",
        "baseRefOid": base_sha,
        "headRefOid": head_sha,
        "latestHeadCommittedAt": "2026-06-25T10:00:00Z",
        "reviews": reviews if reviews is not None else [],
        "unresolvedThreads": unresolved_threads if unresolved_threads is not None else [{"body": "nit: wording"}],
        "workflowContexts": workflow_contexts
        if workflow_contexts is not None
        else [{"name": "Phase 1 shadow run", "workflowName": "Governance Shadow Benchmark", "conclusion": "SUCCESS"}],
        "benchmarkEvidence": benchmark_evidence if benchmark_evidence is not None else _benchmark(),
    }
    if fallback_quorum is not None:
        payload["fallbackQuorum"] = fallback_quorum
    return payload


def _clean_review(head_sha: str, submitted_at: str = "2026-06-25T10:05:00Z") -> dict:
    return {
        "state": "COMMENTED",
        "submittedAt": submitted_at,
        "commitOid": head_sha,
        "author": "chatgpt-codex-connector",
        "body": f"Reviewed commit {head_sha[:10]}. Clean.",
    }


def _blocking_review(head_sha: str, submitted_at: str, body: str) -> dict:
    return {
        "state": "COMMENTED",
        "submittedAt": submitted_at,
        "commitOid": head_sha,
        "author": "chatgpt-codex-connector",
        "body": body,
    }


def _benchmark(phase1_decision: str = "BENCHMARK_PASS") -> dict:
    cases = [
        _benchmark_case("critical", "historical_spaghetti", "REPRODUCED_BAD", True, "BLOCK_TECHNICAL"),
        _benchmark_case("negative", "synthetic_structural", "REPRODUCED_BAD", False, "BLOCK_TECHNICAL"),
        _benchmark_case("safe", "verified_safe", "VERIFIED_SAFE", False, "MERGE"),
    ]
    benchmark = {
        "schema_version": "1.0",
        "run_id": "unit-test-run",
        "generated_at": "2026-06-25T10:00:00Z",
        "duration_seconds": 0.1,
        "repeat_count": 1,
        "phase1_decision": phase1_decision,
        "acceptance_errors": [],
        "artifact_content_hash": "",
        "target_lock": {
            "repository_url": "https://github.com/example/repo.git",
            "pull_request": 1,
            "base_sha": "1" * 40,
            "head_sha": "2" * 40,
            "merge_commit_sha": "3" * 40,
            "approved_oracle_sha": "4" * 40,
            "observed_main_sha": "5" * 40,
            "generated_at": "2026-06-25T10:00:00Z",
            "evidence_source": "unit test",
        },
        "metrics": {
            "case_count": 3,
            "critical_defect_recall": 1.0,
            "critical_defects_blocked": 1,
            "critical_defect_count": 1,
            "negative_control_recall": 1.0,
            "negative_controls_blocked": 1,
            "negative_control_count": 1,
            "false_block_rate": 0.0,
            "false_blocks": 0,
            "repeated_run_decision_stability": 1.0,
            "deterministic_flake_rate": 0.0,
            "execution_duration_seconds": 0.1,
            "verified_safe_count": 1,
        },
        "cases": cases,
    }
    benchmark["artifact_content_hash"] = sha256_json({**benchmark, "artifact_content_hash": ""})
    return benchmark


def _benchmark_case(case_id: str, category: str, label: str, critical: bool, decision: str) -> dict:
    evidence_id = f"{case_id}-evidence"
    return {
        "id": case_id,
        "title": case_id,
        "category": category,
        "label": label,
        "critical": critical,
        "expected_decision": decision,
        "decision": {
            "case_id": case_id,
            "decision": decision,
            "reasons": ["unit test"],
            "evidence_refs": [evidence_id],
            "fail_closed": decision != "MERGE",
        },
        "evidence": [
            {
                "evidence_id": evidence_id,
                "case_id": case_id,
                "detector_id": "unit-test-detector",
                "status": "FAIL" if decision == "BLOCK_TECHNICAL" else "PASS",
                "message": "unit test",
                "observed": {},
                "findings": [],
            }
        ],
    }


def _quorum(base_sha: str, head_sha: str) -> dict:
    return {
        "schema_version": "1.0",
        "review_gate": "FALLBACK_CLEAN_ROOM_QUORUM",
        "github_review_state": "STALE",
        "reviewed_base_sha": base_sha,
        "reviewed_head_sha": head_sha,
        "provenance": {
            "source": "codex_multi_agent_v1_clean_room_review",
            "created_in": "unit test",
            "github_pr": "https://github.com/example/repo/pull/1",
            "reviewed_base_sha": base_sha,
            "reviewed_head_sha": head_sha,
            "reviewer_outputs": [
                {
                    "reviewer_id": "clean-room-reviewer-a",
                    "agent_id": "agent-a",
                    "response_sha256": "a" * 64,
                },
                {
                    "reviewer_id": "clean-room-reviewer-b",
                    "agent_id": "agent-b",
                    "response_sha256": "b" * 64,
                },
            ],
        },
        "reviewers": [
            {
                "reviewer_id": "clean-room-reviewer-a",
                "reviewed_base_sha": base_sha,
                "reviewed_head_sha": head_sha,
                "reviewed_files": ["governance_eval/delivery_readiness.py"],
                "findings": [],
                "commands": ["python -m unittest tests.test_delivery_readiness"],
                "final_verdict": "CLEAN",
            },
            {
                "reviewer_id": "clean-room-reviewer-b",
                "reviewed_base_sha": base_sha,
                "reviewed_head_sha": head_sha,
                "reviewed_files": ["governance_eval/delivery_readiness.py"],
                "findings": [],
                "commands": ["python -m unittest tests.test_delivery_readiness"],
                "final_verdict": "CLEAN",
            },
        ],
    }


if __name__ == "__main__":
    unittest.main()
