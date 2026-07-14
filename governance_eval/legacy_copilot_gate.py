from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from governance_eval.copilot_review_evidence import (
    copilot_review_prompt,
    evaluate_review_evidence,
)
from governance_eval.github_review_client import load_copilot_payload


_UNSET = object()


def evaluate_copilot_review_gate(
    config_path: Path,
    head_sha: str,
    *,
    payload: Any = _UNSET,
    payload_errors: list[str] | None = None,
    repo: str = "",
    pr_number: int | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    # Compatibility-only evaluator. Active workflows never call this module.
    from governance_eval import supportability

    config = supportability.load_supportability_config(config_path)
    errors = supportability.validate_supportability_config(config)
    errors.extend(payload_errors or [])
    if payload is _UNSET:
        if not repo or pr_number is None:
            raise supportability.SupportabilityError(
                "repo and pr_number are required when payload is not supplied"
            )
        try:
            payload = load_copilot_payload(repo, pr_number)
        except Exception as exc:
            errors.append(
                f"GitHub review evidence load failed: {type(exc).__name__}: {exc}"
            )
            payload = {"reviews": [], "comments": [], "reviewThreads": []}
    evidence = evaluate_review_evidence(copy.deepcopy(payload), head_sha)
    errors.extend(evidence["errors"])
    result = {
        "schema_version": "1.0",
        "generated_at": supportability._utc_now(),
        "owner_status": supportability.STATUS_RED
        if errors
        else supportability.STATUS_GREEN,
        "repository": repo,
        "pull_request_number": pr_number,
        "head_sha": supportability._schema_safe_sha(head_sha),
        "reviewer_login_patterns": [],
        "review_status": evidence["review_status"],
        "review_request": {"prompt": copilot_review_prompt(head_sha)},
        "errors": errors,
    }
    supportability._validate_if_schema_exists("copilot_review_gate_result", result)
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "copilot-review-gate-result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return result
