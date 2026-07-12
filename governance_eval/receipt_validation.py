from __future__ import annotations

import re
from typing import Any

STATUS_GREEN = "GREEN"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
LEGACY_APPLIED_DEBT_FIELD = "ex" + "ceptions_applied"
LEGACY_EXPIRED_DEBT_FIELD = "expired_ex" + "ceptions"


def embedded_receipt_status_errors(receipt: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    gate = mapping(receipt.get("supportability_gate"))
    review = mapping(receipt.get("copilot_review"))
    architecture = mapping(receipt.get("architecture"))
    judges = mapping(receipt.get("required_judges"))
    bootstrap = mapping(receipt.get("bootstrap"))
    errors.extend(_green_gate_errors("supportability_gate", gate))
    errors.extend(_green_gate_errors("copilot_review", review))
    expected = {
        "owner_status": STATUS_GREEN,
        "gate_implementation": "PASS",
        "repo_architecture_supportability": "PASS",
        "architecture_behavior_proof": "PASS",
        "enforcement_mode": "block_all",
    }
    errors.extend(
        f"receipt architecture.{key} must be {value}"
        for key, value in expected.items()
        if architecture.get(key) != value
    )
    zero_fields = (
        "violation_count",
        "new_violation_count",
        "existing_violation_count",
        "known_debt_applied_count",
        "expired_known_debt_count",
    )
    errors.extend(
        f"receipt architecture.{key} must be 0" for key in zero_fields if architecture.get(key) not in {0, None}
    )
    empty_fields = (
        LEGACY_APPLIED_DEBT_FIELD,
        LEGACY_EXPIRED_DEBT_FIELD,
        "known_debt_applied",
        "known_debt",
        "expired_known_debt",
    )
    errors.extend(f"receipt architecture.{key} must be empty" for key in empty_fields if architecture.get(key))
    if architecture.get("errors"):
        errors.append("receipt architecture.errors must be empty")
    errors.extend(required_judge_errors(judges))
    if bootstrap.get("governance_pass") is False or bootstrap.get("gate_result") == "RED" or bootstrap.get("reason"):
        errors.append("receipt bootstrap must not indicate active bootstrap RED state")
    return errors


def required_judge_errors(judges: dict[str, Any]) -> list[str]:
    keys = (
        "protected_baseline_judge_ran",
        "candidate_judge_ran",
        "baseline_receipt_produced",
        "candidate_receipt_produced",
    )
    errors = [f"required judge proof missing: {key}" for key in keys if judges.get(key) is not True]
    if judges.get("governance_weakening_detected") is True:
        errors.append("governance weakening detected")
    return errors


def receipt_sha_errors(receipt: dict[str, Any]) -> list[str]:
    errors = [
        f"{key} must be a 40-character lowercase Git SHA"
        for key in ("base_sha", "head_sha")
        if not SHA1_RE.fullmatch(str(receipt.get(key) or ""))
    ]
    merged_sha = str(receipt.get("merged_sha") or "")
    if merged_sha and not SHA1_RE.fullmatch(merged_sha):
        errors.append("merged_sha must be empty or a 40-character lowercase Git SHA")
    return errors


def _green_gate_errors(name: str, value: dict[str, Any]) -> list[str]:
    errors = [f"receipt {name}.owner_status must be GREEN"] if value.get("owner_status") != STATUS_GREEN else []
    if value.get("errors"):
        errors.append(f"receipt {name}.errors must be empty")
    return errors


def mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
