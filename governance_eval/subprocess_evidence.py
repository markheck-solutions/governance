from __future__ import annotations

import base64
import binascii
import json
import subprocess
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Sequence

from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named

_SCHEMA_ROOT = Path(__file__).resolve().parents[1]


def run_recorded_subprocess(
    command: Sequence[str],
    *,
    repository: str,
    pull_request: int,
    base_sha: str,
    head_sha: str,
    evaluator_sha: str,
    caller_workflow_sha: str,
    output_path: Path,
    timeout_seconds: int,
    output_limit_bytes: int = 65536,
) -> tuple[dict[str, Any], bytes]:
    exact_command = list(command)
    started_at = _utc_timestamp()
    monotonic_start = time.monotonic()
    stdout = b""
    stderr = b""
    termination = "EXITED"
    exit_code: int | None = None
    errors: list[str] = []

    try:
        completed = subprocess.run(
            exact_command,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
        stdout = _as_bytes(completed.stdout)
        stderr = _as_bytes(completed.stderr)
        exit_code = completed.returncode
        if exit_code != 0:
            errors.append(f"subprocess exited with code {exit_code}")
    except subprocess.TimeoutExpired as exc:
        termination = "TIMED_OUT"
        stdout = _as_bytes(exc.stdout)
        stderr = _as_bytes(exc.stderr)
        errors.append(f"subprocess timed out after {timeout_seconds} seconds")
    except OSError as exc:
        termination = "SPAWN_FAILED"
        error_number = exc.errno if isinstance(exc.errno, int) else "NONE"
        stderr = f"{type(exc).__name__}:errno={error_number}".encode("ascii")
        errors.append("subprocess could not be started")

    completed_at = _utc_timestamp()
    duration_seconds = round(max(0.0, time.monotonic() - monotonic_start), 6)
    captured_stdout, remaining = _captured_output(stdout, output_limit_bytes)
    captured_stderr, _ = _captured_output(stderr, remaining)
    decision = (
        "PASS"
        if termination == "EXITED" and exit_code == 0 and not errors
        else "BLOCK_TECHNICAL"
    )
    evidence = {
        "schema_version": "1.0",
        "record_type": "LEGACY_REQUEST_CALLER_SUBPROCESS",
        "artifact_content_hash": "",
        "repository": repository,
        "pull_request": pull_request,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "evaluator_sha": evaluator_sha,
        "caller_workflow_sha": caller_workflow_sha,
        "command": exact_command,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": duration_seconds,
        "timeout_seconds": timeout_seconds,
        "timed_out": termination == "TIMED_OUT",
        "termination": termination,
        "exit_code": exit_code,
        "output_limit_bytes": output_limit_bytes,
        "stdout": captured_stdout,
        "stderr": captured_stderr,
        "decision": decision,
        "errors": errors,
    }
    evidence["artifact_content_hash"] = sha256_json(evidence)
    validate_subprocess_evidence_integrity(evidence)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evidence, stdout


def validate_subprocess_evidence_integrity(evidence: dict[str, Any]) -> None:
    validate_named("subprocess_evidence", evidence, _SCHEMA_ROOT)
    expected_hash = sha256_json({**evidence, "artifact_content_hash": ""})
    if evidence["artifact_content_hash"] != expected_hash:
        raise ValueError("subprocess evidence content hash is invalid")
    _validate_timing(evidence)
    _validate_termination(evidence)
    _validate_outputs(evidence)


def _validate_timing(evidence: dict[str, Any]) -> None:
    started = datetime.fromisoformat(evidence["started_at"].replace("Z", "+00:00"))
    completed = datetime.fromisoformat(evidence["completed_at"].replace("Z", "+00:00"))
    elapsed = (completed - started).total_seconds()
    if elapsed < 0:
        raise ValueError("subprocess evidence timestamps are out of order")
    if abs(elapsed - evidence["duration_seconds"]) > 1:
        raise ValueError("subprocess evidence duration does not match timestamps")


def _validate_termination(evidence: dict[str, Any]) -> None:
    termination = evidence["termination"]
    exit_code = evidence["exit_code"]
    timed_out = evidence["timed_out"]
    consistent = (
        (
            termination == "EXITED"
            and not timed_out
            and isinstance(exit_code, int)
            and not isinstance(exit_code, bool)
        )
        or (termination == "TIMED_OUT" and timed_out and exit_code is None)
        or (termination == "SPAWN_FAILED" and not timed_out and exit_code is None)
    )
    if not consistent:
        raise ValueError("subprocess evidence termination is inconsistent")
    passed = evidence["decision"] == "PASS"
    if passed != (
        termination == "EXITED" and exit_code == 0 and not evidence["errors"]
    ):
        raise ValueError("subprocess evidence decision is inconsistent")
    if not passed and not evidence["errors"]:
        raise ValueError("blocking subprocess evidence must contain an error")


def _validate_outputs(evidence: dict[str, Any]) -> None:
    captured_total = 0
    for stream_name in ("stdout", "stderr"):
        output = evidence[stream_name]
        try:
            captured = base64.b64decode(output["captured_base64"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(
                f"subprocess evidence {stream_name} encoding is invalid"
            ) from exc
        if len(captured) != output["captured_bytes"]:
            raise ValueError(f"subprocess evidence {stream_name} byte count is invalid")
        if sha256(captured).hexdigest() != output["sha256"]:
            raise ValueError(f"subprocess evidence {stream_name} hash is invalid")
        captured_total += len(captured)
    if captured_total > evidence["output_limit_bytes"]:
        raise ValueError("subprocess evidence output exceeds its limit")


def _captured_output(content: bytes, limit: int) -> tuple[dict[str, Any], int]:
    captured = content[:limit]
    return (
        {
            "sha256": sha256(captured).hexdigest(),
            "captured_bytes": len(captured),
            "captured_base64": base64.b64encode(captured).decode("ascii"),
            "truncated": len(content) > len(captured),
        },
        max(0, limit - len(captured)),
    )


def _as_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", errors="replace")


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
