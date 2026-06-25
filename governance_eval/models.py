from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    MERGE = "MERGE"
    BLOCK_TECHNICAL = "BLOCK_TECHNICAL"
    ASK_BUSINESS = "ASK_BUSINESS"


class EvidenceStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    MALFORMED = "MALFORMED"
    UNVERIFIABLE = "UNVERIFIABLE"
    BUSINESS_AMBIGUITY = "BUSINESS_AMBIGUITY"


class Label(StrEnum):
    REPRODUCED_BAD = "REPRODUCED_BAD"
    VERIFIED_SAFE = "VERIFIED_SAFE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ReviewFinding:
    id: str
    severity: str
    category: str
    message: str
    evidence_id: str
    status: str = "REPRODUCED"

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "evidence_id": self.evidence_id,
            "status": self.status,
        }


@dataclass(frozen=True)
class DetectorEvidence:
    evidence_id: str
    case_id: str
    detector_id: str
    status: EvidenceStatus
    message: str
    observed: dict[str, Any] = field(default_factory=dict)
    findings: tuple[ReviewFinding, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "detector_id": self.detector_id,
            "status": self.status.value,
            "message": self.message,
            "observed": self.observed,
            "findings": [finding.to_json() for finding in self.findings],
        }


@dataclass(frozen=True)
class FinalDecision:
    case_id: str
    decision: Decision
    reasons: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    fail_closed: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "evidence_refs": list(self.evidence_refs),
            "fail_closed": self.fail_closed,
        }
