from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def generate_bootstrap_audit_receipt(
    record: dict[str, Any],
    *,
    pre_protection: Any,
    post_protection: Any,
    pre_rulesets: Any,
    post_rulesets: Any,
) -> dict[str, Any]:
    candidate = str(record.get("candidate_sha") or "")
    pr_head = str(record.get("pr_head_before_merge") or "")
    errors: list[str] = []
    repository_url = str(record.get("repository_url") or "")
    match = re.fullmatch(
        r"https://github\.com/(?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)",
        repository_url,
    )
    slug = match.group("slug") if match else ""
    safe_slug = slug or "invalid/invalid"
    expected_protection_url = (
        f"https://api.github.com/repos/{slug}/branches/main/protection"
    )
    expected_rulesets_url = f"https://api.github.com/repos/{slug}/rulesets"
    urls_bound = bool(
        slug
        and record.get("protection_url") == expected_protection_url
        and record.get("rulesets_url") == expected_rulesets_url
    )
    if not urls_bound:
        errors.append("repository resource URLs are not bound")
    actor = str(record.get("actor") or "")
    if not actor:
        errors.append("actor is invalid")
    pull_request_number = record.get("pull_request_number")
    if not isinstance(pull_request_number, int) or pull_request_number < 1:
        errors.append("pull_request_number is invalid")
    etags = record.get("resource_etags")
    expected_etag_keys = {
        "pre_protection",
        "post_protection",
        "pre_rulesets",
        "post_rulesets",
    }
    etags_valid = bool(
        isinstance(etags, dict)
        and set(etags) == expected_etag_keys
        and all(
            value is None or isinstance(value, str) and value
            for value in etags.values()
        )
    )
    if not etags_valid:
        errors.append("resource_etags are invalid")
    safe_etags = {
        key: value if isinstance(value, str) and value else None
        for key in expected_etag_keys
        for value in [etags.get(key) if isinstance(etags, dict) else None]
    }
    for field in ("candidate_sha", "pr_head_before_merge", "merge_sha", "rollback_sha"):
        if not _SHA_RE.fullmatch(str(record.get(field) or "")):
            errors.append(f"{field} is invalid")
    events = record.get("mutation_events")
    if not isinstance(events, list) or len(events) != 2:
        errors.append("exactly two protection mutation events are required")
        events = []
    else:
        expected = ("disable_enforce_admins", "restore_enforce_admins")
        for index, (event, action) in enumerate(zip(events, expected, strict=True)):
            if not isinstance(event, dict) or event.get("action") != action:
                errors.append(f"mutation event {index} action is invalid")
                continue
            if not _timestamp_valid(event.get("server_timestamp")):
                errors.append(f"mutation event {index} timestamp is invalid")
            if event.get("resource_url") != expected_protection_url:
                errors.append(f"mutation event {index} resource_url is invalid")
            for key in ("request_sha256", "response_sha256"):
                if not _DIGEST_RE.fullmatch(str(event.get(key) or "")):
                    errors.append(f"mutation event {index} {key} is invalid")
            for payload_key, digest_key in (
                ("request", "request_sha256"),
                ("response", "response_sha256"),
            ):
                if payload_key not in event:
                    errors.append(f"mutation event {index} {payload_key} is missing")
                elif sha256_json(event[payload_key]) != event.get(digest_key):
                    errors.append(f"mutation event {index} {digest_key} mismatch")
            request = (
                event.get("request") if isinstance(event.get("request"), dict) else {}
            )
            response = (
                event.get("response") if isinstance(event.get("response"), dict) else {}
            )
            endpoint = f"{expected_protection_url}/enforce_admins"
            expected_method = "DELETE" if index == 0 else "POST"
            expected_status = 204 if index == 0 else 200
            if (
                request.get("method") != expected_method
                or request.get("url") != endpoint
            ):
                errors.append(f"mutation event {index} request semantics are invalid")
            if response.get("status") != expected_status:
                errors.append(f"mutation event {index} response status is invalid")
            body = response.get("body")
            if index == 0 and body is not None:
                errors.append("disable response body must be null")
            if index == 1 and not (
                isinstance(body, dict)
                and body.get("enabled") is True
                and body.get("url") == endpoint
            ):
                errors.append("restore response body is invalid")
    started = _timestamp(record.get("started_at"), errors, "started_at")
    completed = _timestamp(record.get("completed_at"), errors, "completed_at")
    expires = _timestamp(record.get("expires_at"), errors, "expires_at")
    event_times = [
        datetime.fromisoformat(str(event["server_timestamp"])[:-1] + "+00:00")
        for event in events
        if isinstance(event, dict) and _timestamp_valid(event.get("server_timestamp"))
    ]
    bounded_order = bool(
        started
        and completed
        and expires
        and len(event_times) == 2
        and started <= event_times[0] < event_times[1] <= completed <= expires
        and (expires - started).total_seconds() <= 3600
    )
    checks = {
        "candidate_matches_pr_head": candidate == pr_head,
        "protection_restored": pre_protection == post_protection,
        "rulesets_restored": pre_rulesets == post_rulesets,
        "completed_before_expiry": bounded_order,
        "resource_urls_bound": urls_bound,
        "resource_etags_valid": etags_valid,
    }
    errors.extend(f"{name} is false" for name, passed in checks.items() if not passed)
    receipt = {
        "schema_version": "1.0",
        "decision": "BLOCK_TECHNICAL" if errors else "PASS",
        "repository_url": repository_url
        if match
        else "https://github.com/invalid/invalid",
        "protection_url": record.get("protection_url")
        if isinstance(record.get("protection_url"), str)
        and record.get("protection_url", "").startswith("https://api.github.com/repos/")
        else f"https://api.github.com/repos/{safe_slug}/branches/main/protection",
        "rulesets_url": record.get("rulesets_url")
        if isinstance(record.get("rulesets_url"), str)
        and record.get("rulesets_url", "").startswith("https://api.github.com/repos/")
        else f"https://api.github.com/repos/{safe_slug}/rulesets",
        "actor": actor or "UNKNOWN",
        "started_at": record.get("started_at") if started else "1970-01-01T00:00:00Z",
        "completed_at": record.get("completed_at")
        if completed
        else "1970-01-01T00:00:00Z",
        "expires_at": record.get("expires_at") if expires else "1970-01-01T00:00:00Z",
        "candidate_sha": candidate if _SHA_RE.fullmatch(candidate) else "0" * 40,
        "pull_request_number": pull_request_number
        if isinstance(pull_request_number, int) and pull_request_number > 0
        else 1,
        "pr_head_before_merge": pr_head if _SHA_RE.fullmatch(pr_head) else "0" * 40,
        "merge_sha": record.get("merge_sha")
        if _SHA_RE.fullmatch(str(record.get("merge_sha") or ""))
        else "0" * 40,
        "rollback_sha": record.get("rollback_sha")
        if _SHA_RE.fullmatch(str(record.get("rollback_sha") or ""))
        else "0" * 40,
        "resource_etags": safe_etags,
        "mutation_events": [
            {
                key: str(event.get(key) or "")
                for key in (
                    "action",
                    "server_timestamp",
                    "resource_url",
                    "request_sha256",
                    "response_sha256",
                )
            }
            for event in events
            if isinstance(event, dict)
        ],
        "evidence_digests": {
            "pre_protection_sha256": sha256_json(pre_protection),
            "post_protection_sha256": sha256_json(post_protection),
            "pre_rulesets_sha256": sha256_json(pre_rulesets),
            "post_rulesets_sha256": sha256_json(post_rulesets),
        },
        "checks": checks,
        "errors": sorted(set(errors)),
        "content_hash": "",
    }
    receipt["content_hash"] = sha256_json(receipt)
    validate_named("bootstrap_audit_receipt", receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bootstrap-audit")
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--pre-protection", type=Path, required=True)
    parser.add_argument("--post-protection", type=Path, required=True)
    parser.add_argument("--pre-rulesets", type=Path, required=True)
    parser.add_argument("--post-rulesets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    def load(path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8"))

    try:
        receipt = generate_bootstrap_audit_receipt(
            load(args.record),
            pre_protection=load(args.pre_protection),
            post_protection=load(args.post_protection),
            pre_rulesets=load(args.pre_rulesets),
            post_rulesets=load(args.post_rulesets),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.exit(2, f"bootstrap audit failed: {exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["decision"] == "PASS" else 1


def _timestamp(value: Any, errors: list[str], field: str) -> datetime | None:
    if not _timestamp_valid(value):
        errors.append(f"{field} is invalid")
        return None
    return datetime.fromisoformat(str(value)[:-1] + "+00:00")


def _timestamp_valid(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").tzinfo is not None
    except ValueError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
