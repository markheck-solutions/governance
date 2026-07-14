from __future__ import annotations

import re
from typing import Any


_FENCE_LINE_RE = re.compile(r"^\s*(?:`{3,}|~{3,}).*$")
_QUOTE_PREFIX_RE = re.compile(r"^\s*>+\s?")
_LIST_PREFIX_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)")
_WHITESPACE_RE = re.compile(r"\s+")
_SERVICE_FAILURE_PATTERNS = (
    re.compile(
        r"\A(?:(?:github\s+)?(?:copilot|codex)\s+(?:was\s+|is\s+)?|"
        r"(?:i|we)\s+(?:was\s+|were\s+)?|)"
        r"(?:unable|cannot|could[-\s]+not|couldn't)\s+(?:to\s+)?"
        r"(?:review|complete|perform|run)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\A(?:you|the\s+user(?:\s+who\s+requested\s+the\s+review)?|"
        r"your\s+account|this\s+account)\s+(?:currently\s+)?"
        r"(?:has\s+|have\s+)?(?:reached|exceeded|exhausted)\s+"
        r"(?:their\s+|your\s+|the\s+)?(?:codex\s+)?"
        r"(?:quota|usage)(?:\s+limits?)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\A(?:codex\s+)?(?:quota|usage)(?:\s+limits?)?\s+"
        r"(?:has\s+|is\s+|was\s+)?(?:reached|exceeded|exhausted)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\A(?:the\s+)?(?:(?:codex|copilot|ai)\s+)?review\s+"
        r"(?:has\s+|is\s+|was\s+)?(?:failed\b|"
        r"(?:a\s+failure|unavailable|error)(?=[.!?]|\Z)|"
        r"encountered\s+an\s+error\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\A(?:(?:the\s+)?(?:codex|copilot|review)\s+)?service\s+"
        r"(?:is\s+|was\s+)?unavailable\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\A(?:to\s+use\s+codex\s+here,?\s+)?"
        r"(?:create|set\s+up|configure)\s+(?:an?\s+|the\s+)?"
        r"(?:codex\s+)?environment\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\A(?:codex\s+)?environment\s+(?:setup\s+)?"
        r"(?:is\s+|was\s+)?required\b",
        re.IGNORECASE,
    ),
)


def is_ai_review_service_failure(body: Any) -> bool:
    return any(
        pattern.search(segment)
        for segment in _visible_segments(body)
        for pattern in _SERVICE_FAILURE_PATTERNS
    )


def _visible_segments(body: Any) -> list[str]:
    lines: list[str] = []
    for raw_line in str(body or "").splitlines():
        visible_line = _strip_markdown_prefixes(raw_line)
        if _FENCE_LINE_RE.fullmatch(visible_line):
            continue
        normalized = _WHITESPACE_RE.sub(" ", visible_line).strip()
        if normalized:
            lines.append(normalized)
    return lines


def _strip_markdown_prefixes(line: str) -> str:
    current = line
    for _ in range(8):
        updated = _LIST_PREFIX_RE.sub("", _QUOTE_PREFIX_RE.sub("", current))
        if updated == current:
            break
        current = updated
    return current
