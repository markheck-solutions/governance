from __future__ import annotations

import base64
import binascii
import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Sequence

from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named

_SCHEMA_ROOT = Path(__file__).resolve().parents[1]
_READ_CHUNK_BYTES = 8192
_READER_JOIN_SECONDS = 2
_TERMINATION_WAIT_SECONDS = 5


class _BoundedStreamCapture:
    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._captured = bytearray()
        self._total_bytes = 0
        self._hasher = sha256()
        self._read_failed = False
        self._lock = threading.Lock()

    def drain(self, stream: BinaryIO) -> None:
        try:
            while chunk := stream.read(_READ_CHUNK_BYTES):
                with self._lock:
                    self._total_bytes += len(chunk)
                    self._hasher.update(chunk)
                    remaining = self._limit - len(self._captured)
                    if remaining > 0:
                        self._captured.extend(chunk[:remaining])
        except (OSError, ValueError):
            with self._lock:
                self._read_failed = True
        finally:
            try:
                stream.close()
            except OSError:
                with self._lock:
                    self._read_failed = True

    def snapshot(self) -> tuple[bytes, int, str, bool]:
        with self._lock:
            return (
                bytes(self._captured),
                self._total_bytes,
                self._hasher.hexdigest(),
                self._read_failed,
            )


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
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)
    started_at = _utc_timestamp()
    monotonic_start = time.monotonic()
    termination = "EXITED"
    exit_code: int | None = None
    errors: list[str] = []
    stdout_capture = _BoundedStreamCapture(output_limit_bytes)
    stderr_capture = _BoundedStreamCapture(output_limit_bytes)

    try:
        process = subprocess.Popen(
            exact_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        termination = "SPAWN_FAILED"
        error_number = exc.errno if isinstance(exc.errno, int) else "NONE"
        stderr_capture.drain(
            _BytesReader(f"{type(exc).__name__}:errno={error_number}".encode("ascii"))
        )
        errors.append("subprocess could not be started")
    else:
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("subprocess capture pipes were not created")
        streams = (process.stdout, process.stderr)
        threads = (
            threading.Thread(
                target=stdout_capture.drain,
                args=(process.stdout,),
                daemon=True,
            ),
            threading.Thread(
                target=stderr_capture.drain,
                args=(process.stderr,),
                daemon=True,
            ),
        )
        for thread in threads:
            thread.start()
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            termination = "TIMED_OUT"
            errors.append(f"subprocess timed out after {timeout_seconds} seconds")
            try:
                process.kill()
                process.wait(timeout=_TERMINATION_WAIT_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                errors.append("timed-out subprocess could not be terminated")
        if termination == "EXITED":
            exit_code = process.returncode
            if exit_code != 0:
                errors.append(f"subprocess exited with code {exit_code}")
        if not _finish_reader_threads(threads, streams):
            errors.append("subprocess output capture did not terminate")

    stdout_sample, stdout_total, stdout_hash, stdout_read_failed = (
        stdout_capture.snapshot()
    )
    stderr_sample, stderr_total, stderr_hash, stderr_read_failed = (
        stderr_capture.snapshot()
    )
    if stdout_read_failed or stderr_read_failed:
        errors.append("subprocess output capture failed")
    captured_stdout = stdout_sample[:output_limit_bytes]
    remaining = max(0, output_limit_bytes - len(captured_stdout))
    captured_stderr = stderr_sample[:remaining]
    if stdout_total + stderr_total > output_limit_bytes:
        errors.append(
            f"subprocess output exceeded {output_limit_bytes} byte capture limit"
        )

    completed_at = _utc_timestamp()
    duration_seconds = round(max(0.0, time.monotonic() - monotonic_start), 6)
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
        "stdout": _output_record(
            captured_stdout,
            total_bytes=stdout_total,
            full_sha256=stdout_hash,
        ),
        "stderr": _output_record(
            captured_stderr,
            total_bytes=stderr_total,
            full_sha256=stderr_hash,
        ),
        "decision": decision,
        "errors": errors,
    }
    evidence["artifact_content_hash"] = sha256_json(evidence)
    validate_subprocess_evidence_integrity(evidence)
    output_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evidence, captured_stdout


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
    output_total = 0
    truncated = False
    for stream_name in ("stdout", "stderr"):
        output = evidence[stream_name]
        try:
            captured = base64.b64decode(output["captured_base64"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(
                f"subprocess evidence {stream_name} encoding is invalid"
            ) from exc
        captured_hash = sha256(captured).hexdigest()
        if len(captured) != output["captured_bytes"]:
            raise ValueError(f"subprocess evidence {stream_name} byte count is invalid")
        if captured_hash != output["captured_sha256"]:
            raise ValueError(f"subprocess evidence {stream_name} hash is invalid")
        if output["total_bytes"] < output["captured_bytes"]:
            raise ValueError(f"subprocess evidence {stream_name} total is invalid")
        expected_truncation = output["total_bytes"] > output["captured_bytes"]
        if output["truncated"] != expected_truncation:
            raise ValueError(
                f"subprocess evidence {stream_name} truncation is inconsistent"
            )
        if not expected_truncation and output["full_sha256"] != captured_hash:
            raise ValueError(f"subprocess evidence {stream_name} full hash is invalid")
        captured_total += len(captured)
        output_total += output["total_bytes"]
        truncated = truncated or expected_truncation
    limit = evidence["output_limit_bytes"]
    if captured_total > limit:
        raise ValueError("subprocess evidence output exceeds its capture limit")
    if truncated != (output_total > limit):
        raise ValueError("subprocess evidence combined truncation is inconsistent")
    if output_total > limit and evidence["decision"] == "PASS":
        raise ValueError("truncated subprocess evidence cannot pass")


def _finish_reader_threads(
    threads: tuple[threading.Thread, threading.Thread],
    streams: tuple[BinaryIO, BinaryIO],
) -> bool:
    for thread in threads:
        thread.join(timeout=_READER_JOIN_SECONDS)
    for thread, stream in zip(threads, streams, strict=True):
        if thread.is_alive():
            try:
                stream.close()
            except OSError:
                pass
    for thread in threads:
        if thread.is_alive():
            thread.join(timeout=_READER_JOIN_SECONDS)
    return not any(thread.is_alive() for thread in threads)


def _output_record(
    captured: bytes,
    *,
    total_bytes: int,
    full_sha256: str,
) -> dict[str, Any]:
    return {
        "full_sha256": full_sha256,
        "total_bytes": total_bytes,
        "captured_sha256": sha256(captured).hexdigest(),
        "captured_bytes": len(captured),
        "captured_base64": base64.b64encode(captured).decode("ascii"),
        "truncated": total_bytes > len(captured),
    }


class _BytesReader:
    def __init__(self, content: bytes) -> None:
        self._content = content
        self._read = False

    def read(self, _size: int = -1) -> bytes:
        if self._read:
            return b""
        self._read = True
        return self._content

    def close(self) -> None:
        return None


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
