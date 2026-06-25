from __future__ import annotations

from governance_eval.models import Decision, DetectorEvidence, EvidenceStatus, FinalDecision

BLOCKING_SEVERITIES = {"P0", "P1", "P2"}


def decide(case: dict, evidence: list[DetectorEvidence]) -> FinalDecision:
    wrong_case_evidence = [item for item in evidence if item.case_id != case["id"]]
    if wrong_case_evidence:
        return FinalDecision(
            case_id=case["id"],
            decision=Decision.BLOCK_TECHNICAL,
            reasons=tuple(
                f"evidence case mismatch: {item.evidence_id} belongs to {item.case_id}"
                for item in wrong_case_evidence
            ),
            evidence_refs=tuple(item.evidence_id for item in evidence),
            fail_closed=True,
        )

    required = set(case["detectors"])
    present = {item.detector_id for item in evidence}
    missing = sorted(required - present)
    required_evidence = case.get("required_evidence", [])
    present_evidence = present | {item.evidence_id for item in evidence}
    unsatisfied_evidence = [label for label in required_evidence if label not in present_evidence]
    if unsatisfied_evidence:
        return FinalDecision(
            case_id=case["id"],
            decision=Decision.BLOCK_TECHNICAL,
            reasons=tuple(f"required evidence not satisfied: {label}" for label in unsatisfied_evidence),
            evidence_refs=tuple(item.evidence_id for item in evidence),
            fail_closed=True,
        )
    if missing:
        return FinalDecision(
            case_id=case["id"],
            decision=Decision.BLOCK_TECHNICAL,
            reasons=tuple(f"missing detector evidence: {detector}" for detector in missing),
            evidence_refs=tuple(item.evidence_id for item in evidence),
            fail_closed=True,
        )

    fail_closed_statuses = {EvidenceStatus.UNKNOWN, EvidenceStatus.MALFORMED, EvidenceStatus.UNVERIFIABLE}
    unresolved = [item for item in evidence if item.status in fail_closed_statuses]
    if unresolved:
        return FinalDecision(
            case_id=case["id"],
            decision=Decision.BLOCK_TECHNICAL,
            reasons=tuple(f"{item.detector_id}: {item.status.value} - {item.message}" for item in unresolved),
            evidence_refs=tuple(item.evidence_id for item in evidence),
            fail_closed=True,
        )

    blocking_findings = [
        finding
        for item in evidence
        for finding in item.findings
        if finding.severity in BLOCKING_SEVERITIES and finding.status != "RESOLVED"
    ]
    if blocking_findings or any(item.status == EvidenceStatus.FAIL for item in evidence):
        reasons = [finding.message for finding in blocking_findings]
        if not reasons:
            reasons = [item.message for item in evidence if item.status == EvidenceStatus.FAIL]
        return FinalDecision(
            case_id=case["id"],
            decision=Decision.BLOCK_TECHNICAL,
            reasons=tuple(reasons),
            evidence_refs=tuple(item.evidence_id for item in evidence),
        )

    if any(item.status == EvidenceStatus.BUSINESS_AMBIGUITY for item in evidence):
        return FinalDecision(
            case_id=case["id"],
            decision=Decision.ASK_BUSINESS,
            reasons=tuple(item.message for item in evidence if item.status == EvidenceStatus.BUSINESS_AMBIGUITY),
            evidence_refs=tuple(item.evidence_id for item in evidence),
        )

    return FinalDecision(
        case_id=case["id"],
        decision=Decision.MERGE,
        reasons=("all required deterministic evidence passed",),
        evidence_refs=tuple(item.evidence_id for item in evidence),
    )
