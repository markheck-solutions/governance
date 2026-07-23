from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


_API_ROOT = "https://api.github.com"
_WORKFLOW_FILE = "source-candidate.yml"
_WORKFLOW_PATH = ".github/workflows/source-candidate.yml"
_WORKFLOW_NAME = "Governance Source Candidate"
_EXPECTED_JOBS = frozenset(
    {
        "Governance Source Static",
        "Governance Source Tests",
        "Governance Source Build",
        "Governance Source Candidate Result",
    }
)
_POLL_ATTEMPTS = 54
_POLL_SECONDS = 10
_MAX_RESPONSE_BYTES = 1_000_000


def _pull_request_numbers(run: dict[str, Any]) -> set[int]:
    pull_requests = run.get("pull_requests")
    if not isinstance(pull_requests, list):
        return set()
    return {
        item["number"]
        for item in pull_requests
        if isinstance(item, dict)
        and type(item.get("number")) is int
        and item["number"] > 0
    }


def _matching_runs(
    payload: object, *, head_sha: str, pr_number: int
) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(
        payload.get("workflow_runs"), list
    ):
        return []
    return [
        run
        for run in payload["workflow_runs"]
        if isinstance(run, dict)
        and run.get("head_sha") == head_sha
        and run.get("event") == "pull_request"
        and pr_number in _pull_request_numbers(run)
    ]


def candidate_run_errors(
    run: object, *, repository: str, head_sha: str, pr_number: int
) -> list[str]:
    if not isinstance(run, dict):
        return ["candidate workflow run is not an object"]
    expected = {
        "name": _WORKFLOW_NAME,
        "path": _WORKFLOW_PATH,
        "event": "pull_request",
        "head_sha": head_sha,
    }
    errors = [
        f"candidate workflow run {field} is invalid"
        for field, value in expected.items()
        if run.get(field) != value
    ]
    if type(run.get("run_attempt")) is not int or run["run_attempt"] != 1:
        errors.append("candidate workflow run attempt is invalid")
    repository_value = run.get("repository")
    if (
        not isinstance(repository_value, dict)
        or repository_value.get("full_name") != repository
    ):
        errors.append("candidate workflow repository is invalid")
    if _pull_request_numbers(run) != {pr_number}:
        errors.append("candidate workflow pull-request binding is invalid")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        errors.append("candidate workflow did not complete successfully")
    if type(run.get("id")) is not int or run["id"] <= 0:
        errors.append("candidate workflow run ID is invalid")
    return errors


def candidate_job_errors(payload: object, *, run_id: int, head_sha: str) -> list[str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("jobs"), list):
        return ["candidate workflow jobs payload is invalid"]
    jobs = payload["jobs"]
    names = {
        job.get("name") for job in jobs if isinstance(job, dict) and job.get("name")
    }
    errors: list[str] = []
    if payload.get("total_count") != len(_EXPECTED_JOBS) or names != _EXPECTED_JOBS:
        errors.append("candidate workflow job set is invalid")
    for job in jobs:
        if not isinstance(job, dict):
            errors.append("candidate workflow job is not an object")
            continue
        if (
            job.get("run_id") != run_id
            or job.get("head_sha") != head_sha
            or job.get("workflow_name") != _WORKFLOW_NAME
        ):
            errors.append("candidate workflow job identity is invalid")
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            errors.append("candidate workflow job did not complete successfully")
    return errors


def _api_json(url: str, token: str) -> object:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "governance-source-qualification",
        },
    )
    with urlopen(request, timeout=20) as response:  # noqa: S310
        body = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ValueError("GitHub API response exceeds the source limit")
    return json.loads(body)


def _wait_for_candidate_run(
    *, repository: str, head_sha: str, pr_number: int, token: str
) -> dict[str, Any]:
    query = urlencode(
        {"event": "pull_request", "head_sha": head_sha, "per_page": "100"}
    )
    url = f"{_API_ROOT}/repos/{repository}/actions/workflows/{_WORKFLOW_FILE}/runs?{query}"
    for attempt in range(_POLL_ATTEMPTS):
        matches = _matching_runs(
            _api_json(url, token), head_sha=head_sha, pr_number=pr_number
        )
        if len(matches) > 1:
            raise ValueError("multiple candidate workflow runs match the exact PR head")
        if matches and matches[0].get("status") == "completed":
            return matches[0]
        if attempt + 1 < _POLL_ATTEMPTS:
            time.sleep(_POLL_SECONDS)
    raise TimeoutError("candidate workflow did not complete before the source cutoff")


def _validated_environment() -> tuple[str, int, str, str]:
    repository = os.environ.get("SOURCE_REPOSITORY", "")
    pr_text = os.environ.get("SOURCE_PR_NUMBER", "")
    head_sha = os.environ.get("SOURCE_HEAD_SHA", "")
    token = os.environ.get("GH_TOKEN", "")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise ValueError("source repository identity is invalid")
    if re.fullmatch(r"[1-9][0-9]*", pr_text) is None:
        raise ValueError("source pull-request number is invalid")
    if re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        raise ValueError("source head SHA is invalid")
    if not token:
        raise ValueError("source GitHub token is missing")
    return repository, int(pr_text), head_sha, token


def reconcile() -> dict[str, object]:
    repository, pr_number, head_sha, token = _validated_environment()
    run = _wait_for_candidate_run(
        repository=repository,
        head_sha=head_sha,
        pr_number=pr_number,
        token=token,
    )
    errors = candidate_run_errors(
        run, repository=repository, head_sha=head_sha, pr_number=pr_number
    )
    run_id = run.get("id")
    if type(run_id) is int and run_id > 0:
        jobs_url = f"{_API_ROOT}/repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"
        errors.extend(
            candidate_job_errors(
                _api_json(jobs_url, token), run_id=run_id, head_sha=head_sha
            )
        )
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "candidate_run_id": run_id,
        "head_sha": head_sha,
        "pr_number": pr_number,
        "repository": repository,
        "status": "PASS",
    }


def main() -> int:
    try:
        receipt = reconcile()
    except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        print(f"SOURCE_QUALIFICATION_FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
