from __future__ import annotations

import base64
import compileall
import csv
import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from pip._vendor.packaging.markers import default_environment
from pip._vendor.packaging.requirements import InvalidRequirement, Requirement

_MARKER = "GOVERNANCE_PACKAGE_AUDIT_SUMMARY="
_MAX_FILES = 20_000
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024


def main() -> int:
    input_root = Path(sys.argv[1])
    scratch = Path(sys.argv[2])
    wheels = sorted(input_root.glob("*.whl"))
    if len(wheels) != 1 or any(path.is_symlink() for path in input_root.iterdir()):
        raise SystemExit("exactly one regular wheel is required")
    wheel = wheels[0]
    before = _digest(wheel)
    with zipfile.ZipFile(wheel) as archive:
        names = _validate_archive(archive)
        metadata, wheel_metadata, record = _metadata_files(archive, names)
        _validate_wheel_metadata(archive.read(wheel_metadata))
        _validate_record(archive, names, record)
        top_levels = _top_levels(archive, names, metadata)
        package_identity = _validate_dependencies(archive.read(metadata))
    install = scratch / "install"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "--no-input",
            "--no-cache-dir",
            "install",
            "--no-index",
            "--no-deps",
            f"--target={install}",
            str(wheel),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        env={"PATH": "/usr/local/bin", "LC_ALL": "C"},
    )
    if completed.returncode != 0:
        raise SystemExit("isolated wheel installation failed")
    if not compileall.compile_dir(install, quiet=1, force=True):
        raise SystemExit("installed wheel does not compile")
    _validate_install(install, package_identity, top_levels)
    if _digest(wheel) != before:
        raise SystemExit("input wheel changed during audit")
    summary = {
        "wheel": wheel.name,
        "sha256": before,
        "files": len(names),
        "top_levels": top_levels,
    }
    print(_MARKER + json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


def _validate_archive(archive: zipfile.ZipFile) -> list[str]:
    infos = archive.infolist()
    if not infos or len(infos) > _MAX_FILES:
        raise SystemExit("wheel file count is invalid")
    names: list[str] = []
    total = 0
    for info in infos:
        name = _safe_name(info.filename)
        mode = (info.external_attr >> 16) & 0o170000
        if mode not in {0, 0o100000, 0o040000}:
            raise SystemExit("wheel contains a non-regular entry")
        if (
            info.flag_bits & 1
            or info.file_size > _MAX_FILE_BYTES
            or info.compress_size < 0
        ):
            raise SystemExit("wheel entry exceeds size limit")
        if info.file_size > 1024 * max(1, info.compress_size):
            raise SystemExit("wheel entry compression ratio is unsafe")
        if name.endswith((".pth", ".so", ".dll", ".dylib", ".pyd")):
            raise SystemExit("wheel contains unsupported executable content")
        total += info.file_size
        names.append(name)
    if total > _MAX_TOTAL_BYTES or len(names) != len(set(names)):
        raise SystemExit("wheel inventory is invalid")
    if len({name.casefold() for name in names}) != len(names):
        raise SystemExit("wheel paths collide by case")
    return names


def _safe_name(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or any(character in value for character in ("\r", "\n", "\0"))
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part for part in path.parts)
        or path.as_posix() != value.rstrip("/")
    ):
        raise SystemExit("wheel path is unsafe")
    return value.rstrip("/")


def _metadata_files(archive: zipfile.ZipFile, names: list[str]) -> tuple[str, str, str]:
    metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
    wheel = [name for name in names if name.endswith(".dist-info/WHEEL")]
    record = [name for name in names if name.endswith(".dist-info/RECORD")]
    roots = {name.split("/", 1)[0] for name in (*metadata, *wheel, *record)}
    if len(metadata) != 1 or len(wheel) != 1 or len(record) != 1 or len(roots) != 1:
        raise SystemExit("wheel metadata inventory is invalid")
    return metadata[0], wheel[0], record[0]


def _validate_wheel_metadata(raw: bytes) -> None:
    message = BytesParser().parsebytes(raw)
    if message.get("Root-Is-Purelib", "").lower() != "true":
        raise SystemExit("wheel is not pure Python")
    tags = message.get_all("Tag", [])
    if tags != ["py3-none-any"]:
        raise SystemExit("wheel tag is not certified")


def _validate_record(
    archive: zipfile.ZipFile, names: list[str], record_name: str
) -> None:
    try:
        rows = list(csv.reader(archive.read(record_name).decode("utf-8").splitlines()))
    except UnicodeDecodeError as exc:
        raise SystemExit("wheel RECORD is not UTF-8") from exc
    records = {row[0]: row[1:] for row in rows if len(row) == 3}
    if len(records) != len(rows) or set(records) != set(names):
        raise SystemExit("wheel RECORD inventory is invalid")
    for name in names:
        digest, size = records[name]
        if name == record_name:
            if digest or size:
                raise SystemExit("wheel RECORD self-entry is invalid")
            continue
        raw = archive.read(name)
        expected = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=")
        if digest != "sha256=" + expected.decode("ascii") or size != str(len(raw)):
            raise SystemExit("wheel RECORD digest is invalid")


def _top_levels(archive: zipfile.ZipFile, names: list[str], metadata: str) -> list[str]:
    dist_info = metadata.split("/", 1)[0]
    top_level_path = f"{dist_info}/top_level.txt"
    if top_level_path in names:
        values = archive.read(top_level_path).decode("utf-8").splitlines()
    else:
        values = sorted(
            {
                name.split("/", 1)[0]
                for name in names
                if "/" in name and ".dist-info/" not in name
            }
        )
    if not values or any(
        re.fullmatch(r"[A-Za-z_]\w*", value) is None for value in values
    ):
        raise SystemExit("wheel top-level imports are invalid")
    return sorted(set(values))


def _validate_dependencies(raw: bytes) -> tuple[str, str]:
    message = BytesParser().parsebytes(raw)
    name = message.get("Name", "").strip()
    version = message.get("Version", "").strip()
    if not name or not version:
        raise SystemExit("wheel package identity is invalid")
    environment = {str(key): str(value) for key, value in default_environment().items()}
    environment["extra"] = ""
    for requirement in message.get_all("Requires-Dist", []):
        try:
            parsed = Requirement(requirement)
        except InvalidRequirement as exc:
            raise SystemExit("wheel dependency metadata is malformed") from exc
        if parsed.marker is None or parsed.marker.evaluate(environment=environment):
            raise SystemExit("wheel has an unresolved active dependency")
    return name, version


def _validate_install(
    install: Path, package_identity: tuple[str, str], top_levels: list[str]
) -> None:
    distributions = list(importlib.metadata.distributions(path=[str(install)]))
    if len(distributions) != 1:
        raise SystemExit("isolated install distribution inventory is invalid")
    distribution = distributions[0]
    observed = (
        str(distribution.metadata.get("Name", "")).strip(),
        str(distribution.version).strip(),
    )
    if observed != package_identity:
        raise SystemExit("isolated install package identity differs")
    root = install.resolve(strict=True)
    files = list(distribution.files or ())
    if not files:
        raise SystemExit("isolated install file inventory is empty")
    for item in files:
        candidate = install / item
        if candidate.is_symlink():
            raise SystemExit("isolated install contains an unsafe file")
        path = candidate.resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise SystemExit("isolated install contains an unsafe file")
    for name in top_levels:
        module = install / f"{name}.py"
        package = install / name / "__init__.py"
        if not module.is_file() and not package.is_file():
            raise SystemExit("isolated install top-level package is missing")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    os.environ.clear()
    raise SystemExit(main())
