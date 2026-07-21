from __future__ import annotations

import base64
import configparser
import csv
import io
import json
import shutil
import stat
import subprocess
import sys
import tomllib
import zipfile
from datetime import datetime, timezone
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

from governance_eval.hashing import sha256_bytes, sha256_file

SCHEMA_VERSION = "governance_package_audit.v1"
MAX_MEMBERS = 5_000
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024


class _EntryPointParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def run_package_audit(repo_root: Path, artifacts_dir: Path) -> dict[str, Any]:
    root = repo_root.resolve()
    output = artifacts_dir.resolve()
    errors = _preflight_errors(root, output)
    output.mkdir(parents=True, exist_ok=True)
    wheel_dir = output / "wheel"
    wheel_dir.mkdir(exist_ok=True)
    source_dir = output / "source"
    if not errors:
        source_dir.mkdir()
        shutil.copy2(root / "pyproject.toml", source_dir / "pyproject.toml")
        shutil.copytree(
            root / "governance_eval",
            source_dir / "governance_eval",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    started_at = _utc_now()
    command = [
        sys.executable,
        "-m",
        "pip",
        "wheel",
        "--no-deps",
        "--no-index",
        "--no-build-isolation",
        str(source_dir),
        "-w",
        str(wheel_dir),
    ]
    timed_out = False
    exit_code: int | None = None
    stdout = b""
    stderr = b""
    if not errors:
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                timeout=120,
                check=False,
            )
            exit_code = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = 124
            stdout = _as_bytes(exc.stdout)
            stderr = _as_bytes(exc.stderr)
    if exit_code not in (None, 0):
        errors.append(f"wheel build exited {exit_code}")
    wheels = sorted(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        errors.append(f"expected exactly one wheel, found {len(wheels)}")
    wheel_evidence: dict[str, Any] | None = None
    if len(wheels) == 1:
        wheel_evidence, wheel_errors = audit_wheel(root, wheels[0])
        errors.extend(wheel_errors)
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "PASS" if not errors else "FAIL",
        "repo_root": str(root),
        "build": {
            "command": command,
            "started_at": started_at,
            "completed_at": _utc_now(),
            "timeout_seconds": 120,
            "timed_out": timed_out,
            "exit_code": exit_code,
            "stdout_sha256": sha256_bytes(stdout),
            "stderr_sha256": sha256_bytes(stderr),
        },
        "wheel": wheel_evidence,
        "errors": errors,
    }
    audit_path = output / "package-audit.json"
    audit_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_lines = [f"{sha256_file(audit_path)}  {audit_path.name}"]
    if len(wheels) == 1:
        manifest_lines.append(f"{sha256_file(wheels[0])}  wheel/{wheels[0].name}")
    (output / "checksums.sha256").write_text(
        "\n".join(manifest_lines) + "\n", encoding="ascii"
    )
    return result


def audit_wheel(repo_root: Path, wheel_path: Path) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    expected = _expected_package_files(repo_root)
    project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    with zipfile.ZipFile(wheel_path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        errors.extend(_archive_errors(infos))
        package_names = {name for name in names if name.startswith("governance_eval/")}
        missing = sorted(expected - package_names)
        unexpected = sorted(package_names - expected)
        if missing:
            errors.append("missing package files: " + ", ".join(missing))
        if unexpected:
            errors.append("unexpected package files: " + ", ".join(unexpected))
        metadata_name = _one_suffix(names, ".dist-info/METADATA", errors)
        entry_name = _one_suffix(names, ".dist-info/entry_points.txt", errors)
        record_name = _one_suffix(names, ".dist-info/RECORD", errors)
        if metadata_name:
            dist_info = metadata_name.removesuffix("METADATA")
            allowed = expected | {
                dist_info + name
                for name in (
                    "METADATA",
                    "RECORD",
                    "WHEEL",
                    "entry_points.txt",
                    "top_level.txt",
                )
            }
            outside_allowlist = sorted(set(names) - allowed)
            if outside_allowlist:
                errors.append(
                    "unexpected wheel members: " + ", ".join(outside_allowlist)
                )
        if metadata_name:
            metadata = BytesParser().parsebytes(archive.read(metadata_name))
            expected_name = project["project"]["name"]
            expected_version = project["project"]["version"]
            if metadata.get("Name") != expected_name:
                errors.append("wheel metadata project name mismatch")
            if metadata.get("Version") != expected_version:
                errors.append("wheel metadata version mismatch")
        if entry_name:
            entry_points = archive.read(entry_name).decode("utf-8")
            errors.extend(_entry_point_errors(entry_points, project))
        if record_name:
            errors.extend(_record_errors(archive, record_name, names))
    evidence = {
        "name": wheel_path.name,
        "sha256": sha256_file(wheel_path),
        "member_count": len(names),
        "uncompressed_bytes": sum(item.file_size for item in infos),
        "expected_package_files": sorted(expected),
        "members": sorted(names),
    }
    return evidence, errors


def _preflight_errors(root: Path, output: Path) -> list[str]:
    errors = []
    if not (root / "pyproject.toml").is_file():
        errors.append("pyproject.toml missing")
    if not (root / "governance_eval").is_dir():
        errors.append("governance_eval package missing")
    if output == root or root in output.parents:
        errors.append("artifacts directory must be outside repository")
    if any(output.glob("wheel/*.whl")):
        errors.append("artifacts wheel directory must not contain an existing wheel")
    if (output / "source").exists():
        errors.append("artifacts source directory must not exist")
    return errors


def _expected_package_files(root: Path) -> set[str]:
    package = root / "governance_eval"
    return {
        path.relative_to(root).as_posix()
        for path in package.rglob("*")
        if path.is_file()
        and (path.suffix == ".py" or "schema_data" in path.parts)
        and "__pycache__" not in path.parts
    }


def _archive_errors(infos: list[zipfile.ZipInfo]) -> list[str]:
    errors: list[str] = []
    names = [item.filename for item in infos]
    if len(names) > MAX_MEMBERS:
        errors.append(f"wheel member count exceeds {MAX_MEMBERS}")
    if sum(item.file_size for item in infos) > MAX_UNCOMPRESSED_BYTES:
        errors.append(f"wheel uncompressed size exceeds {MAX_UNCOMPRESSED_BYTES}")
    if len(names) != len(set(names)):
        errors.append("wheel contains duplicate members")
    for item in infos:
        path = PurePosixPath(item.filename)
        if (
            not item.filename
            or "\\" in item.filename
            or path.is_absolute()
            or ".." in path.parts
        ):
            errors.append(f"unsafe wheel member: {item.filename}")
        mode = item.external_attr >> 16
        if stat.S_ISLNK(mode):
            errors.append(f"wheel symlink forbidden: {item.filename}")
    return errors


def _one_suffix(names: list[str], suffix: str, errors: list[str]) -> str | None:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        errors.append(f"expected one {suffix}, found {len(matches)}")
        return None
    return matches[0]


def _entry_point_errors(text: str, project: dict[str, Any]) -> list[str]:
    parser = _EntryPointParser(interpolation=None, strict=True)
    try:
        parser.read_string(text)
    except configparser.Error:
        return ["wheel entry points are malformed"]
    expected = project["project"].get("scripts", {})
    observed = (
        dict(parser.items("console_scripts"))
        if parser.has_section("console_scripts")
        else {}
    )
    if parser.sections() != ["console_scripts"] or observed != expected:
        return ["wheel console entry points mismatch pyproject.toml"]
    return []


def _record_errors(
    archive: zipfile.ZipFile, record_name: str, archive_names: list[str]
) -> list[str]:
    errors: list[str] = []
    rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
    if any(len(row) != 3 for row in rows):
        return ["wheel RECORD row must contain three fields"]
    record_names = [row[0] for row in rows]
    if sorted(record_names) != sorted(archive_names):
        errors.append("wheel RECORD member set mismatch")
    for name, digest, size in rows:
        if name == record_name:
            if digest or size:
                errors.append("wheel RECORD self-entry must omit hash and size")
            continue
        if name not in archive_names:
            continue
        data = archive.read(name)
        encoded = (
            base64.urlsafe_b64encode(bytes.fromhex(sha256_bytes(data)))
            .rstrip(b"=")
            .decode("ascii")
        )
        if digest != f"sha256={encoded}" or size != str(len(data)):
            errors.append(f"wheel RECORD mismatch: {name}")
    return errors


def _as_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
