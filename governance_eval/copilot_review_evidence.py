from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Callable

from governance_eval.ai_review_failures import is_ai_review_service_failure


STRUCTURED_REVIEW_MARKER = "governance-review-evidence:v1"
STRUCTURED_REVIEW_SCHEMA_VERSION = "governance-review-evidence.v1"
STRUCTURED_REVIEW_BLOCK_RE = re.compile(
    rf"<!--\s*{re.escape(STRUCTURED_REVIEW_MARKER)}\s*(?P<payload>.*?)\s*-->",
    re.DOTALL,
)
STRUCTURED_REVIEW_VERDICTS = {"clean", "blocked", "ambiguous"}
STRUCTURED_REVIEW_SEVERITIES = {"P0", "P1", "P2", "P3"}
NATIVE_REVIEW_STATES = {
    "APPROVED",
    "CHANGES_REQUESTED",
    "COMMENTED",
    "DISMISSED",
    "PENDING",
}
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
NATIVE_COPILOT_REVIEWER = "copilot-pull-request-reviewer"
NATIVE_COPILOT_REVIEWER_ALIASES = {
    NATIVE_COPILOT_REVIEWER,
    f"{NATIVE_COPILOT_REVIEWER}[bot]",
}
STRUCTURED_COPILOT_COMMENTER = "copilot-swe-agent"
STRUCTURED_COPILOT_COMMENTER_ALIASES = {
    STRUCTURED_COPILOT_COMMENTER,
    f"{STRUCTURED_COPILOT_COMMENTER}[bot]",
}
MARKDOWN_BLOCKQUOTE_LINE_RE = re.compile(r"(?m)^[ \t]*>.*(?:\n|$)")
MARKDOWN_FENCE_BLOCK_RE = re.compile(
    r"(?ms)^[ \t]*(?P<backtick_fence>`{3,})[^\n]*\n.*?^[ \t]*(?P=backtick_fence)`*[ \t]*(?:\n|$)"
    r"|^[ \t]*(?P<tilde_fence>~{3,})[^\n]*\n.*?^[ \t]*(?P=tilde_fence)~*[ \t]*(?:\n|$)"
)
AuthorMatcher = Callable[[Any, list[str]], bool]


def evaluate_review_evidence(payload: Any, head_sha: str) -> dict[str, Any]:
    source: dict[str, Any] = payload if isinstance(payload, dict) else {}
    errors = (
        [] if isinstance(payload, dict) else ["review payload must be a JSON object"]
    )
    errors.extend(_evidence_shape_errors(source))
    normalized = _normalized_payload(source)
    errors.extend(_head_binding_errors(normalized, head_sha))
    errors.extend(_native_review_service_failure_errors(normalized, head_sha))
    errors.extend(
        structured_review_errors(
            normalized,
            head_sha,
            [],
            structured_comment_author_matches,
        )
    )
    latest = _latest_applicable_clean_evidence(normalized, head_sha)
    if latest is None:
        errors.append("Copilot review is missing or stale for latest head SHA")
    errors.extend(_blocking_review_errors(normalized, head_sha))
    return {
        "errors": errors,
        "review_status": _review_status(normalized, head_sha, latest),
    }


def canonical_ai_author(author: Any) -> Any:
    if not isinstance(author, str):
        return author
    normalized = author.lower()
    if normalized in NATIVE_COPILOT_REVIEWER_ALIASES:
        return NATIVE_COPILOT_REVIEWER
    if normalized in STRUCTURED_COPILOT_COMMENTER_ALIASES:
        return STRUCTURED_COPILOT_COMMENTER
    return author


def native_review_author_matches(author: Any) -> bool:
    return canonical_ai_author(author) == NATIVE_COPILOT_REVIEWER


def structured_comment_author_matches(author: Any, patterns: list[str]) -> bool:
    del patterns
    return canonical_ai_author(author) == STRUCTURED_COPILOT_COMMENTER


def _head_binding_errors(payload: dict[str, Any], head_sha: str) -> list[str]:
    payload_head = payload.get("headRefOid")
    if not isinstance(payload_head, str) or not SHA1_RE.fullmatch(payload_head):
        return ["review payload headRefOid must be a 40-character lowercase Git SHA"]
    if payload_head != head_sha:
        return ["review payload headRefOid does not match requested head SHA"]
    return []


def _evidence_shape_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("reviews", "comments", "reviewThreads"):
        value = payload.get(field)
        if not isinstance(value, list):
            errors.append(f"review payload {field} must be a list")
        elif not all(isinstance(item, dict) for item in value):
            errors.append(f"review payload {field} must contain objects")
    for review in _payload_objects(payload, "reviews"):
        raw_author = review.get("author")
        author = raw_author.get("login") if isinstance(raw_author, dict) else raw_author
        if native_review_author_matches(author):
            errors.extend(_native_review_shape_errors(review))
    for comment in _payload_objects(payload, "comments"):
        author = comment.get("author")
        login = author.get("login") if isinstance(author, dict) else author
        if canonical_ai_author(login) != STRUCTURED_COPILOT_COMMENTER:
            continue
        if not isinstance(comment.get("isMinimized"), bool):
            errors.append("structured Copilot comment isMinimized must be boolean")
        if not isinstance(comment.get("createdAt"), str) or not comment.get(
            "createdAt"
        ):
            errors.append(
                "structured Copilot comment createdAt must be a non-empty string"
            )
        if not isinstance(comment.get("body"), str):
            errors.append("structured Copilot comment body must be a string")
    for thread in _payload_objects(payload, "reviewThreads"):
        errors.extend(_review_thread_shape_errors(thread))
    return errors


def _native_review_shape_errors(review: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if review.get("state") not in NATIVE_REVIEW_STATES:
        errors.append("native Copilot review state is invalid")
    if not _is_github_datetime(review.get("submittedAt")):
        errors.append("native Copilot review submittedAt must be a GitHub UTC DateTime")
    commit_oid = _review_commit_oid(review)
    if not isinstance(commit_oid, str) or not SHA1_RE.fullmatch(commit_oid):
        errors.append(
            "native Copilot review commitOid must be a full lowercase Git SHA"
        )
    if not isinstance(review.get("body"), str):
        errors.append("native Copilot review body must be a string")
    return errors


def _review_thread_shape_errors(thread: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(thread.get("isResolved"), bool):
        errors.append("review thread isResolved must be a boolean")
    path = thread.get("path")
    if not isinstance(path, str) or not path.strip():
        errors.append("review thread path must be a non-empty string")
    authors = thread.get("authors")
    if (
        not isinstance(authors, list)
        or not authors
        or not all(isinstance(author, str) and author.strip() for author in authors)
    ):
        errors.append("review thread authors must contain non-empty strings")
    return errors


def structured_review_errors(
    payload: dict[str, Any],
    head_sha: str,
    patterns: list[str],
    author_matches: AuthorMatcher,
) -> list[str]:
    records = _structured_review_records(
        payload,
        patterns,
        author_matches,
        include_minimized=True,
    )
    head_records = _applicable_structured_records(records, head_sha)
    errors: list[str] = []
    for record in head_records:
        errors.extend(_structured_record_errors(record, head_sha))
    return errors


def _structured_record_errors(record: dict[str, Any], head_sha: str) -> list[str]:
    if not record.get("valid"):
        details = "; ".join(
            record.get("errors") or ["invalid structured review evidence"]
        )
        return [f"structured Copilot review evidence is invalid: {details}"]
    reviewed_commit_sha = str(record.get("reviewed_commit_sha") or "")
    if reviewed_commit_sha != head_sha:
        return [
            f"structured Copilot review evidence is stale: reviewed {reviewed_commit_sha}"
        ]
    errors: list[str] = []
    verdict = str(record.get("verdict") or "")
    if verdict != "clean":
        errors.append(f"structured Copilot review verdict is not clean: {verdict}")
    blocking_count = int(record.get("blocking_open_finding_count") or 0)
    if blocking_count:
        errors.append(
            f"structured Copilot review has {blocking_count} blocking open finding(s)"
        )
    return errors


def _applicable_structured_records(
    records: list[dict[str, Any]],
    head_sha: str,
) -> list[dict[str, Any]]:
    current_valid = [
        record
        for record in records
        if record.get("valid") and record.get("reviewed_commit_sha") == head_sha
    ]
    applicable: list[dict[str, Any]] = []
    for record in records:
        if record.get("unbound_malformed"):
            if not _unbound_record_superseded(record, current_valid):
                applicable.append(record)
        elif _record_applies_to_head(record, head_sha):
            applicable.append(record)
    return applicable


def _unbound_record_superseded(
    record: dict[str, Any],
    current_valid: list[dict[str, Any]],
) -> bool:
    submitted_at = str(record.get("submittedAt") or "")
    return bool(submitted_at) and any(
        str(candidate.get("submittedAt") or "") > submitted_at
        for candidate in current_valid
    )


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
    comment_submitted_at = str(
        comment.get("createdAt") or comment.get("submittedAt") or ""
    )
    if (
        not clean_submitted_at
        or not comment_submitted_at
        or comment_submitted_at >= clean_submitted_at
    ):
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
    reviewed_commit_re = re.compile(
        r"\breviewed\s+(?:head\s+)?commit(?:\s+sha)?\b", re.IGNORECASE
    )
    return bool(reviewed_commit_re.search(visible_body)) and (
        head_sha in visible_body or head_sha[:10] in visible_body
    )


def _structured_review_records(
    payload: dict[str, Any],
    patterns: list[str],
    author_matches: AuthorMatcher,
    *,
    include_minimized: bool = False,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for comment in payload.get("comments", []):
        if author_matches(comment.get("author"), patterns) and (
            include_minimized or not comment.get("isMinimized", False)
        ):
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
    matches = list(STRUCTURED_REVIEW_BLOCK_RE.finditer(body_without_quotes))
    for match in matches:
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
    if body_without_quotes.count(STRUCTURED_REVIEW_MARKER) > len(matches):
        record = _structured_review_record(
            raw_payload="",
            context_body=body_without_quotes,
            source=source,
            author=author,
            submitted_at=submitted_at,
            commit_oid=commit_oid,
        )
        record["errors"] = ["structured evidence marker is truncated or unclosed"]
        record["unbound_malformed"] = not _context_binds_reviewed_commit(
            body_without_quotes
        )
        records.append(record)
    return records


def _without_markdown_blockquotes(body: str) -> str:
    return "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith(">")
    )


def _context_binds_reviewed_commit(body: str) -> bool:
    visible_body = visible_review_text(body)
    reviewed_commit = re.search(
        r"\breviewed\s+(?:head\s+)?commit(?:\s+sha)?\b",
        visible_body,
        re.IGNORECASE,
    )
    commit_sha = re.search(r"\b[0-9a-f]{10,40}\b", visible_body)
    return reviewed_commit is not None and commit_sha is not None


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
    record["open_finding_count"] = (
        len(open_findings) if isinstance(open_findings, list) else 0
    )
    if isinstance(open_findings, list):
        record["blocking_open_finding_count"] = sum(
            1
            for finding in open_findings
            if isinstance(finding, dict)
            and finding.get("severity") in {"P0", "P1", "P2"}
        )
    record["valid"] = not errors
    return record


def _structured_review_document_errors(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("schema_version") != STRUCTURED_REVIEW_SCHEMA_VERSION:
        errors.append("schema_version must be governance-review-evidence.v1")
    reviewed_commit_sha = document.get("reviewed_commit_sha")
    if not isinstance(reviewed_commit_sha, str) or not SHA1_RE.fullmatch(
        reviewed_commit_sha
    ):
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


def _normalized_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        **payload,
        "reviews": [
            _normalized_review(review)
            for review in _payload_objects(payload, "reviews")
        ],
        "comments": [
            _normalized_comment(comment)
            for comment in _payload_objects(payload, "comments")
        ],
        "reviewThreads": [
            _normalized_thread(thread)
            for thread in _payload_objects(payload, "reviewThreads")
        ],
    }


def _payload_objects(payload: dict[str, Any], field: str) -> list[dict[str, Any]]:
    value = payload.get(field)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _normalized_review(review: dict[str, Any]) -> dict[str, Any]:
    raw_author = review.get("author")
    author: dict[str, Any] = raw_author if isinstance(raw_author, dict) else {}
    return {
        "state": review.get("state"),
        "submittedAt": review.get("submittedAt"),
        "commitOid": _review_commit_oid(review),
        "author": canonical_ai_author(author.get("login") or review.get("author")),
        "body": _normalized_body(review.get("body")),
        "failureBody": str(review.get("body") or ""),
    }


def _normalized_comment(comment: dict[str, Any]) -> dict[str, Any]:
    raw_author = comment.get("author")
    author: dict[str, Any] = raw_author if isinstance(raw_author, dict) else {}
    return {
        "author": canonical_ai_author(author.get("login") or comment.get("author")),
        "body": _normalized_body(comment.get("body")),
        "failureBody": str(comment.get("body") or ""),
        "createdAt": comment.get("createdAt"),
        "isMinimized": comment.get("isMinimized"),
    }


def _normalized_thread(thread: dict[str, Any]) -> dict[str, Any]:
    raw_authors = thread.get("authors")
    authors: list[Any] = raw_authors if isinstance(raw_authors, list) else []
    return {
        **thread,
        "authors": [canonical_ai_author(author) for author in authors],
    }


def _normalized_body(body: Any) -> str:
    text = str(body or "")
    return MARKDOWN_FENCE_BLOCK_RE.sub("", MARKDOWN_BLOCKQUOTE_LINE_RE.sub("", text))


def _review_commit_oid(review: dict[str, Any]) -> Any:
    raw_commit = review.get("commit")
    commit: dict[str, Any] = raw_commit if isinstance(raw_commit, dict) else {}
    return review.get("commitOid") or commit.get("oid")


def _is_github_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not GITHUB_DATETIME_RE.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError:
        return False
    return True


def _latest_applicable_clean_evidence(
    payload: dict[str, Any],
    head_sha: str,
) -> dict[str, Any] | None:
    evidence: list[dict[str, Any]] = []
    structured = latest_clean_structured_review_evidence(
        payload,
        head_sha,
        [],
        structured_comment_author_matches,
    )
    if structured is not None:
        evidence.append(structured)
    native = _latest_clean_native_review(payload.get("reviews", []), head_sha)
    if native is not None:
        evidence.append(native)
    return (
        max(evidence, key=lambda item: item.get("submittedAt") or "")
        if evidence
        else None
    )


def _latest_clean_native_review(
    reviews: list[dict[str, Any]],
    head_sha: str,
) -> dict[str, Any] | None:
    clean = [
        review
        for review in reviews
        if native_review_author_matches(review.get("author"))
        and review.get("state") == "COMMENTED"
        and review.get("commitOid") == head_sha
        and _is_github_datetime(review.get("submittedAt"))
        and not _native_review_service_failure(review)
    ]
    return max(clean, key=lambda item: item.get("submittedAt") or "") if clean else None


def _native_review_service_failure_errors(
    payload: dict[str, Any], head_sha: str
) -> list[str]:
    review_failures = [
        review
        for review in payload.get("reviews", [])
        if native_review_author_matches(review.get("author"))
        and (
            review.get("commitOid") == head_sha
            or not isinstance(review.get("commitOid"), str)
            or not SHA1_RE.fullmatch(review["commitOid"])
        )
        and _native_review_service_failure(review)
    ]
    comment_failures = [
        comment
        for comment in payload.get("comments", [])
        if structured_comment_author_matches(comment.get("author"), [])
        and is_ai_review_service_failure(comment.get("failureBody"))
    ]
    return (
        ["AI review service failure is present for latest head SHA"]
        if review_failures or comment_failures
        else []
    )


def _native_review_service_failure(review: dict[str, Any]) -> bool:
    return is_ai_review_service_failure(review.get("failureBody"))


def _blocking_review_errors(
    payload: dict[str, Any],
    head_sha: str,
) -> list[str]:
    errors: list[str] = []
    latest_change_request = _latest_change_request(payload.get("reviews", []), head_sha)
    if latest_change_request is not None:
        errors.append(
            f"AI review CHANGES_REQUESTED remains from {latest_change_request.get('author', '')}"
        )
    for thread in _blocking_threads(payload.get("reviewThreads", [])):
        errors.append(
            f"unresolved Copilot review thread remains: {thread.get('path', '')}"
        )
    return errors


def _latest_change_request(
    reviews: list[dict[str, Any]],
    head_sha: str,
) -> dict[str, Any] | None:
    requests = [
        review
        for review in reviews
        if native_review_author_matches(review.get("author"))
        and review.get("state") == "CHANGES_REQUESTED"
        and review.get("commitOid") == head_sha
    ]
    return (
        max(requests, key=lambda item: item.get("submittedAt") or "")
        if requests
        else None
    )


def _blocking_threads(threads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        thread
        for thread in threads
        if not thread.get("isResolved", False)
        and any(
            native_review_author_matches(author)
            for author in thread.get("authors") or []
        )
    ]


def _review_status(
    payload: dict[str, Any],
    head_sha: str,
    latest: dict[str, Any] | None,
) -> dict[str, Any]:
    structured = latest_structured_review_evidence(
        payload,
        [],
        structured_comment_author_matches,
    )
    reviewed_commit_sha = ""
    verdict = ""
    open_finding_count = 0
    structured_valid = False
    if structured is not None:
        reviewed_commit_sha = str(structured.get("reviewed_commit_sha") or "")
        verdict = str(structured.get("verdict") or "")
        open_finding_count = int(structured.get("open_finding_count") or 0)
        structured_valid = (
            bool(structured.get("valid")) and reviewed_commit_sha == head_sha
        )
    elif latest is not None:
        reviewed_commit_sha = str(latest.get("commitOid") or "")
        verdict = "native_clean"
    return {
        "latest_head_reviewed": latest is not None,
        "reviewer": latest.get("author") if latest else "",
        "submitted_at": latest.get("submittedAt") if latest else "",
        "commit_oid": latest.get("commitOid") if latest else "",
        "structured_evidence_present": structured is not None,
        "structured_evidence_valid": structured_valid,
        "reviewed_commit_sha": reviewed_commit_sha,
        "verdict": verdict,
        "open_finding_count": open_finding_count,
        "blocking_thread_count": len(
            _blocking_threads(payload.get("reviewThreads", []))
        ),
        "blocking_comment_count": 0,
    }
