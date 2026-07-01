from __future__ import annotations

import json
import re
from typing import Any, Callable


STRUCTURED_REVIEW_MARKER = "governance-review-evidence:v1"
STRUCTURED_REVIEW_SCHEMA_VERSION = "governance-review-evidence.v1"
STRUCTURED_REVIEW_BLOCK_RE = re.compile(
    rf"<!--\s*{re.escape(STRUCTURED_REVIEW_MARKER)}\s*(?P<payload>.*?)\s*-->",
    re.DOTALL,
)
STRUCTURED_REVIEW_VERDICTS = {"clean", "blocked", "ambiguous"}
STRUCTURED_REVIEW_SEVERITIES = {"P0", "P1", "P2", "P3"}
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
AuthorMatcher = Callable[[Any, list[str]], bool]


def structured_review_errors(
    payload: dict[str, Any],
    head_sha: str,
    patterns: list[str],
    author_matches: AuthorMatcher,
) -> list[str]:
    records = _structured_review_records(payload, patterns, author_matches)
    head_records = [record for record in records if _record_applies_to_head(record, head_sha)]
    if not head_records:
        return []
    latest = max(head_records, key=lambda item: item.get("submittedAt") or "")
    if not latest.get("valid"):
        details = "; ".join(latest.get("errors") or ["invalid structured review evidence"])
        return [f"structured Copilot review evidence is invalid: {details}"]
    reviewed_commit_sha = str(latest.get("reviewed_commit_sha") or "")
    verdict = str(latest.get("verdict") or "")
    blocking_open_finding_count = int(latest.get("blocking_open_finding_count") or 0)
    if reviewed_commit_sha != head_sha:
        return [f"structured Copilot review evidence is stale: reviewed {reviewed_commit_sha}"]
    errors: list[str] = []
    if verdict != "clean":
        errors.append(f"structured Copilot review verdict is not clean: {verdict}")
    if blocking_open_finding_count:
        errors.append(f"structured Copilot review has {blocking_open_finding_count} blocking open finding(s)")
    return errors


def latest_clean_structured_review_evidence(
    payload: dict[str, Any],
    head_sha: str,
    patterns: list[str],
    author_matches: AuthorMatcher,
) -> dict[str, Any] | None:
    clean = [
        record
        for record in _structured_review_records(payload, patterns, author_matches)
        if record.get("valid")
        and record.get("reviewed_commit_sha") == head_sha
        and record.get("verdict") == "clean"
        and int(record.get("blocking_open_finding_count") or 0) == 0
    ]
    if not clean:
        return None
    return max(clean, key=lambda item: item.get("submittedAt") or "")


def latest_structured_review_evidence(
    payload: dict[str, Any],
    patterns: list[str],
    author_matches: AuthorMatcher,
) -> dict[str, Any] | None:
    evidence = _structured_review_records(payload, patterns, author_matches)
    if not evidence:
        return None
    return max(evidence, key=lambda item: item.get("submittedAt") or "")


def copilot_review_prompt(head_sha: str) -> str:
    safe_head = head_sha if SHA1_RE.fullmatch(head_sha) else "0" * 40
    return "\n".join(
        [
            f"@copilot review commit {safe_head}. If clean, end your response with exactly:",
            f"<!-- {STRUCTURED_REVIEW_MARKER}",
            (
                '{"schema_version":"governance-review-evidence.v1",'
                f'"reviewed_commit_sha":"{safe_head}",'
                '"verdict":"clean","open_findings":[]}'
            ),
            "-->",
            'If blocked, use verdict "blocked" and list open_findings with severity, title, and path.',
        ]
    )


def has_structured_review_evidence(body: str) -> bool:
    return STRUCTURED_REVIEW_MARKER in _without_markdown_blockquotes(body)


def visible_review_text(body: str) -> str:
    return STRUCTURED_REVIEW_BLOCK_RE.sub("", _without_markdown_blockquotes(body))


def structured_comment_superseded_by_clean_evidence(
    comment: dict[str, Any],
    head_sha: str,
    latest_clean: dict[str, Any] | None,
    patterns: list[str],
    author_matches: AuthorMatcher,
) -> bool:
    if latest_clean is None or not author_matches(comment.get("author"), patterns):
        return False
    clean_submitted_at = str(latest_clean.get("submittedAt") or "")
    comment_submitted_at = str(comment.get("createdAt") or comment.get("submittedAt") or "")
    if not clean_submitted_at or not comment_submitted_at or comment_submitted_at >= clean_submitted_at:
        return False
    records = _structured_review_records_from_body(
        body=str(comment.get("body") or ""),
        source="comment",
        author=str(comment.get("author") or ""),
        submitted_at=comment_submitted_at,
        commit_oid="",
    )
    return any(_record_applies_to_head(record, head_sha) for record in records)


def _record_applies_to_head(record: dict[str, Any], head_sha: str) -> bool:
    if record.get("valid"):
        return record.get("reviewed_commit_sha") == head_sha
    return _invalid_record_applies_to_head(record, head_sha)


def _invalid_record_applies_to_head(record: dict[str, Any], head_sha: str) -> bool:
    reviewed_commit_sha = str(record.get("reviewed_commit_sha") or "")
    if reviewed_commit_sha:
        return reviewed_commit_sha == head_sha
    raw_payload = str(record.get("body") or "")
    if head_sha in raw_payload or head_sha[:10] in raw_payload:
        return True
    visible_body = visible_review_text(str(record.get("context_body") or ""))
    reviewed_commit_re = re.compile(r"\breviewed\s+(?:head\s+)?commit(?:\s+sha)?\b", re.IGNORECASE)
    return bool(reviewed_commit_re.search(visible_body)) and (head_sha in visible_body or head_sha[:10] in visible_body)


def _structured_review_records(
    payload: dict[str, Any],
    patterns: list[str],
    author_matches: AuthorMatcher,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for review in payload.get("reviews", []):
        if author_matches(review.get("author"), patterns) and review.get("state") != "DISMISSED":
            records.extend(
                _structured_review_records_from_body(
                    body=str(review.get("body") or ""),
                    source="review",
                    author=str(review.get("author") or ""),
                    submitted_at=str(review.get("submittedAt") or ""),
                    commit_oid=str(review.get("commitOid") or ""),
                )
            )
    for comment in payload.get("comments", []):
        if author_matches(comment.get("author"), patterns) and not comment.get("isMinimized", False):
            records.extend(
                _structured_review_records_from_body(
                    body=str(comment.get("body") or ""),
                    source="comment",
                    author=str(comment.get("author") or ""),
                    submitted_at=str(comment.get("createdAt") or ""),
                    commit_oid="",
                )
            )
    return records


def _structured_review_records_from_body(
    *,
    body: str,
    source: str,
    author: str,
    submitted_at: str,
    commit_oid: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    body_without_quotes = _without_markdown_blockquotes(body)
    for match in STRUCTURED_REVIEW_BLOCK_RE.finditer(body_without_quotes):
        records.append(
            _structured_review_record(
                raw_payload=match.group("payload").strip(),
                context_body=body_without_quotes,
                source=source,
                author=author,
                submitted_at=submitted_at,
                commit_oid=commit_oid,
            )
        )
    return records


def _without_markdown_blockquotes(body: str) -> str:
    return "\n".join(line for line in body.splitlines() if not line.lstrip().startswith(">"))


def _structured_review_record(
    *,
    raw_payload: str,
    context_body: str,
    source: str,
    author: str,
    submitted_at: str,
    commit_oid: str,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "state": "COMMENTED",
        "source": source,
        "submittedAt": submitted_at,
        "commitOid": commit_oid,
        "author": author,
        "body": raw_payload,
        "context_body": context_body,
        "valid": False,
        "errors": [],
        "reviewed_commit_sha": "",
        "verdict": "",
        "open_finding_count": 0,
        "blocking_open_finding_count": 0,
    }
    try:
        document = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        record["errors"] = [f"invalid JSON at offset {exc.pos}"]
        return record
    if not isinstance(document, dict):
        record["errors"] = ["evidence payload must be a JSON object"]
        return record
    errors = _structured_review_document_errors(document)
    record["errors"] = errors
    record["reviewed_commit_sha"] = str(document.get("reviewed_commit_sha") or "")
    record["verdict"] = str(document.get("verdict") or "")
    open_findings = document.get("open_findings")
    record["open_finding_count"] = len(open_findings) if isinstance(open_findings, list) else 0
    if isinstance(open_findings, list):
        record["blocking_open_finding_count"] = sum(
            1
            for finding in open_findings
            if isinstance(finding, dict) and finding.get("severity") in {"P0", "P1", "P2"}
        )
    record["valid"] = not errors
    return record


def _structured_review_document_errors(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("schema_version") != STRUCTURED_REVIEW_SCHEMA_VERSION:
        errors.append("schema_version must be governance-review-evidence.v1")
    reviewed_commit_sha = document.get("reviewed_commit_sha")
    if not isinstance(reviewed_commit_sha, str) or not SHA1_RE.fullmatch(reviewed_commit_sha):
        errors.append("reviewed_commit_sha must be a 40-character lowercase Git SHA")
    verdict = document.get("verdict")
    if verdict not in STRUCTURED_REVIEW_VERDICTS:
        errors.append("verdict must be clean, blocked, or ambiguous")
    open_findings = document.get("open_findings")
    if not isinstance(open_findings, list):
        errors.append("open_findings must be a list")
    else:
        errors.extend(_structured_review_finding_errors(open_findings))
    return errors


def _structured_review_finding_errors(open_findings: list[Any]) -> list[str]:
    errors: list[str] = []
    for index, finding in enumerate(open_findings):
        if not isinstance(finding, dict):
            errors.append(f"open_findings[{index}] must be an object")
            continue
        if finding.get("severity") not in STRUCTURED_REVIEW_SEVERITIES:
            errors.append(f"open_findings[{index}].severity must be P0, P1, P2, or P3")
        if not isinstance(finding.get("title"), str) or not finding["title"].strip():
            errors.append(f"open_findings[{index}].title must be a non-empty string")
        if not isinstance(finding.get("path"), str) or not finding["path"].strip():
            errors.append(f"open_findings[{index}].path must be a non-empty string")
    return errors
