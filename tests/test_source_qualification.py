from __future__ import annotations

import copy
import unittest
from typing import Any

from governance_eval.source_qualification import (
    _matching_runs,
    candidate_job_errors,
    candidate_run_errors,
)


REPOSITORY = "markheck-solutions/governance"
HEAD_SHA = "a" * 40
PR_NUMBER = 101
RUN_ID = 7001


def _run() -> dict[str, Any]:
    return {
        "id": RUN_ID,
        "name": "Governance Source Candidate",
        "path": ".github/workflows/source-candidate.yml",
        "event": "pull_request",
        "head_sha": HEAD_SHA,
        "run_attempt": 1,
        "repository": {"full_name": REPOSITORY},
        "pull_requests": [{"number": PR_NUMBER}],
        "status": "completed",
        "conclusion": "success",
    }


def _jobs() -> dict[str, Any]:
    names = (
        "Governance Source Static",
        "Governance Source Tests",
        "Governance Source Build",
        "Governance Source Candidate Result",
    )
    return {
        "total_count": len(names),
        "jobs": [
            {
                "name": name,
                "run_id": RUN_ID,
                "head_sha": HEAD_SHA,
                "workflow_name": "Governance Source Candidate",
                "status": "completed",
                "conclusion": "success",
            }
            for name in names
        ],
    }


class SourceQualificationTests(unittest.TestCase):
    def test_exact_candidate_run_and_jobs_pass(self) -> None:
        self.assertEqual(
            candidate_run_errors(
                _run(),
                repository=REPOSITORY,
                head_sha=HEAD_SHA,
                pr_number=PR_NUMBER,
            ),
            [],
        )
        self.assertEqual(
            candidate_job_errors(_jobs(), run_id=RUN_ID, head_sha=HEAD_SHA), []
        )

    def test_candidate_run_rejects_rerun_or_cross_pr_replay(self) -> None:
        for field, value in (
            ("run_attempt", 2),
            ("run_attempt", True),
            ("pull_requests", [{"number": PR_NUMBER + 1}]),
            ("head_sha", "b" * 40),
            ("path", ".github/workflows/spoof.yml"),
        ):
            with self.subTest(field=field):
                run = _run()
                run[field] = value
                self.assertNotEqual(
                    candidate_run_errors(
                        run,
                        repository=REPOSITORY,
                        head_sha=HEAD_SHA,
                        pr_number=PR_NUMBER,
                    ),
                    [],
                )

    def test_candidate_jobs_reject_failure_or_set_drift(self) -> None:
        failed = _jobs()
        failed["jobs"][0]["conclusion"] = "failure"
        self.assertTrue(
            any(
                "did not complete successfully" in error
                for error in candidate_job_errors(
                    failed, run_id=RUN_ID, head_sha=HEAD_SHA
                )
            )
        )

        missing = _jobs()
        missing["jobs"] = missing["jobs"][:-1]
        missing["total_count"] = 3
        self.assertTrue(
            any(
                "job set is invalid" in error
                for error in candidate_job_errors(
                    missing, run_id=RUN_ID, head_sha=HEAD_SHA
                )
            )
        )

    def test_matching_runs_requires_exact_pr_and_head(self) -> None:
        valid = _run()
        wrong_pr = copy.deepcopy(valid)
        wrong_pr["pull_requests"] = [{"number": PR_NUMBER + 1}]
        wrong_head = copy.deepcopy(valid)
        wrong_head["head_sha"] = "b" * 40
        payload = {"workflow_runs": [wrong_pr, wrong_head, valid]}

        self.assertEqual(
            _matching_runs(payload, head_sha=HEAD_SHA, pr_number=PR_NUMBER), [valid]
        )


if __name__ == "__main__":
    unittest.main()
