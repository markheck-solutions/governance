from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from governance_eval.docker_process import (
    DockerCommandRecord,
    DockerProcessError,
    DockerProcessResult,
    run_docker_container,
    run_docker_control,
    validate_bind_source,
)
from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.self_update_policy import canonical_changed_files
from governance_eval.toolchain_bootstrap import BootstrapError, validate_lock


PYTHON_IMAGE = (
    "python@sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d"
)
GIT_DEB_URL = (
    "https://deb.debian.org/debian/pool/main/g/git/git_2.39.5-0+deb12u3_amd64.deb"
)
GIT_DEB_VERSION = "1:2.39.5-0+deb12u3"
GIT_DEB_SIZE = 7_264_380
GIT_DEB_SHA256 = "637a85ddd6247fab13bdd0592f2f39aff04ce4dbf0655d3ab553ac359a38ce6f"
GIT_BINARY_SHA256 = "2540879925a6881e3877ff7e3330746ba3027b04edf16a3a12dccd1644c4f32d"
CERTIFIED_TOOLCHAIN_BUNDLE_ID = (
    "e5e7c2334fe38ae759348e64bd1bc609e1772a116f696eb3e973524e32731b03"
)
MANIFEST_NAME = "toolchain-manifest.json"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_FILES = 20_000
_MAX_ENTRIES = 25_000
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_GIT_RUNTIME_PATHS = (
    "git/bin/git",
    "git/bin/git-upload-pack",
    "git/templates/description",
    "git/templates/hooks/applypatch-msg.sample",
    "git/templates/hooks/commit-msg.sample",
    "git/templates/hooks/fsmonitor-watchman.sample",
    "git/templates/hooks/post-update.sample",
    "git/templates/hooks/pre-applypatch.sample",
    "git/templates/hooks/pre-commit.sample",
    "git/templates/hooks/pre-merge-commit.sample",
    "git/templates/hooks/pre-push.sample",
    "git/templates/hooks/pre-rebase.sample",
    "git/templates/hooks/pre-receive.sample",
    "git/templates/hooks/prepare-commit-msg.sample",
    "git/templates/hooks/push-to-checkout.sample",
    "git/templates/hooks/update.sample",
    "git/templates/info/exclude",
)
_PROVISION_SCRIPT = """
import hashlib, pathlib, subprocess, sys, urllib.request
subprocess.run(
    [
        sys.executable,
        '-I',
        '-m',
        'pip',
        'install',
        '--require-hashes',
        '--only-binary=:all:',
        '--no-deps',
        '--no-compile',
        '--no-cache-dir',
        '--disable-pip-version-check',
        '--no-input',
        '--index-url=https://pypi.org/simple',
        '--target=/bundle/python',
        '-r',
        '/inputs/requirements-governance.lock',
    ],
    check=True,
    timeout=100,
)
url, expected_size, expected_hash, destination = sys.argv[1:]
with urllib.request.urlopen(url, timeout=30) as response:
    payload = response.read(16 * 1024 * 1024 + 1)
if len(payload) != int(expected_size):
    raise SystemExit('Git package size mismatch')
if hashlib.sha256(payload).hexdigest() != expected_hash:
    raise SystemExit('Git package digest mismatch')
pathlib.Path(destination).write_bytes(payload)
""".strip()
_EXTRACT_GIT_SCRIPT = """
import pathlib, shutil, subprocess
source = pathlib.Path('/tmp/git-package')
subprocess.run(
    ['/usr/bin/dpkg-deb', '--extract', '/bundle/git-runtime.deb', str(source)],
    check=True,
    timeout=30,
)
destination = pathlib.Path('/bundle/git')
binary = source / 'usr/bin/git'
bin_dir = destination / 'bin'
bin_dir.mkdir(parents=True)
for name in ('git', 'git-upload-pack'):
    target = bin_dir / name
    shutil.copyfile(binary, target)
    target.chmod(0o555)
shutil.copytree(
    source / 'usr/share/git-core/templates',
    destination / 'templates',
    symlinks=False,
)
if any(path.is_symlink() for path in destination.rglob('*')):
    raise SystemExit('normalized Git runtime contains a symbolic link')
""".strip()
_PROBE_SCRIPT = """
import importlib, importlib.metadata, json, pathlib, subprocess, sys
if sys.version_info[:3] != (3, 12, 13):
    raise SystemExit('Python version mismatch')
origins = {}
for name, version in (('ruff', '0.15.21'), ('mypy', '2.2.0')):
    module = importlib.import_module(name)
    origin = pathlib.Path(module.__file__).resolve()
    if not origin.is_relative_to('/bundle/python'):
        raise SystemExit(f'{name} origin mismatch')
    if importlib.metadata.version(name) != version:
        raise SystemExit(f'{name} version mismatch')
    origins[name] = str(origin)
git = subprocess.run(
    ['/bundle/git/bin/git', '--version'],
    check=True,
    capture_output=True,
    text=True,
    timeout=10,
)
if git.stdout.strip() != 'git version 2.39.5':
    raise SystemExit('Git version mismatch')
print(json.dumps({'git': git.stdout.strip(), 'origins': origins}, sort_keys=True))
""".strip()


class ToolchainError(RuntimeError):
    def __init__(
        self, message: str, *, records: tuple[DockerCommandRecord, ...] = ()
    ) -> None:
        super().__init__(message)
        self.records = records


@dataclass(frozen=True)
class ToolchainProvisioningResult:
    manifest: dict[str, Any]
    commands: tuple[DockerCommandRecord, ...]


def provision_docker_toolchain(
    *,
    governance_root: Path,
    output_root: Path,
    docker_path: Path,
    docker_sha256: str,
    docker_host: str,
    protected_roots: tuple[Path, ...],
    image: str = PYTHON_IMAGE,
) -> ToolchainProvisioningResult:
    records: list[DockerCommandRecord] = []
    created_output: Path | None = None
    try:
        governance_root = governance_root.resolve(strict=True)
        output_root = output_root.resolve(strict=False)
        forbidden = (governance_root,) + tuple(
            root.resolve(strict=True) for root in protected_roots
        )
        if output_root.exists() or any(
            _inside(output_root, root) for root in forbidden
        ):
            raise ToolchainError("toolchain output must be a new external directory")
        _validate_new_bind_source(output_root)
        lock_path = governance_root / "requirements-governance.lock"
        _validate_existing_bind_source(lock_path)
        lock_sha256 = validate_lock(lock_path)
        docker = _trusted_docker(docker_path, docker_sha256, docker_host)
        _verify_image(docker, docker_host, image, records)
        output_root.mkdir(parents=False)
        created_output = output_root
        package = output_root / "git-runtime.deb"
        _provision_dependencies(
            docker,
            docker_host,
            image,
            lock_path,
            output_root,
            package,
            records,
        )
        _extract_git(docker, docker_host, image, output_root, package, records)
        package.unlink()
        _probe_toolchain(docker, docker_host, image, output_root, records)
        manifest = create_toolchain_manifest(
            output_root,
            lock_sha256=lock_sha256,
            image=image,
        )
        if manifest["bundle_id"] != CERTIFIED_TOOLCHAIN_BUNDLE_ID:
            raise ToolchainError("provisioned toolchain differs from certified bundle")
        return ToolchainProvisioningResult(manifest, tuple(records))
    except Exception as exc:
        cleanup_error = (
            _cleanup_partial_bundle(created_output) if created_output else ""
        )
        message = str(exc)
        if cleanup_error:
            message = f"{message}; {cleanup_error}"
        if isinstance(exc, (DockerProcessError, ToolchainError)):
            _extend_unique_records(records, exc.records)
        if isinstance(exc, BootstrapError) and not message:
            message = "toolchain lock validation failed"
        raise ToolchainError(message, records=tuple(records)) from exc


def create_toolchain_manifest(
    root: Path, *, lock_sha256: str, image: str
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    _validate_identity(lock_sha256, image)
    manifest_path = root / MANIFEST_NAME
    if manifest_path.exists():
        raise ToolchainError("toolchain manifest already exists")
    directories, files = _bundle_inventory(root)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "bundle_id": "",
        "image": image,
        "lock_sha256": lock_sha256,
        "git_package": {
            "version": GIT_DEB_VERSION,
            "url": GIT_DEB_URL,
            "size": GIT_DEB_SIZE,
            "sha256": GIT_DEB_SHA256,
            "binary_sha256": GIT_BINARY_SHA256,
            "runtime_paths": list(_GIT_RUNTIME_PATHS),
        },
        "directories": directories,
        "files": files,
    }
    payload["bundle_id"] = sha256_json(payload)
    validate_toolchain_manifest(payload)
    manifest_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return payload


def verify_toolchain_bundle(root: Path, expected_bundle_id: str) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not _SHA256_RE.fullmatch(expected_bundle_id):
        raise ToolchainError("expected toolchain bundle id is invalid")
    try:
        manifest_path = root / MANIFEST_NAME
        if _is_link_or_junction(manifest_path) or not manifest_path.is_file():
            raise ToolchainError("toolchain manifest is not a regular file")
        if manifest_path.stat().st_size > _MAX_MANIFEST_BYTES:
            raise ToolchainError("toolchain manifest exceeds size limit")
        raw = manifest_path.read_bytes()
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolchainError("toolchain manifest is unavailable or malformed") from exc
    validate_toolchain_manifest(payload)
    if payload["bundle_id"] != expected_bundle_id:
        raise ToolchainError("toolchain bundle differs from execution plan")
    actual_directories, actual = _bundle_inventory(root)
    expected_directories = payload["directories"]
    expected = payload["files"]
    if actual_directories != expected_directories:
        raise ToolchainError("toolchain directory inventory differs from manifest")
    if [item["path"] for item in actual] != [item["path"] for item in expected]:
        raise ToolchainError("toolchain file inventory differs from manifest")
    if actual != expected:
        raise ToolchainError("toolchain file content differs from manifest")
    return payload


def validate_toolchain_manifest(payload: Any) -> dict[str, Any]:
    _validate_manifest_shape(payload)
    unsigned = {**payload, "bundle_id": ""}
    if payload["bundle_id"] != sha256_json(unsigned):
        raise ToolchainError("toolchain bundle id is invalid")
    return payload


def _bundle_inventory(root: Path) -> tuple[list[str], list[dict[str, Any]]]:
    directories, paths = _bounded_entries(root)
    files: list[dict[str, Any]] = []
    total = 0
    for path in paths:
        if path.is_symlink():
            raise ToolchainError("toolchain bundle contains a symbolic link")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ToolchainError("toolchain bundle contains an unsupported entry")
        relative = path.relative_to(root).as_posix()
        try:
            canonical_changed_files([relative])
        except ValueError as exc:
            raise ToolchainError("toolchain bundle path is unsafe") from exc
        size = path.stat().st_size
        if size > _MAX_FILE_BYTES:
            raise ToolchainError("toolchain bundle file exceeds size limit")
        total += size
        if total > _MAX_TOTAL_BYTES:
            raise ToolchainError("toolchain bundle exceeds materialization limits")
        files.append({"path": relative, "size": size, "sha256": sha256_file(path)})
    if len(files) > _MAX_FILES:
        raise ToolchainError("toolchain bundle exceeds materialization limits")
    relative_directories = [path.relative_to(root).as_posix() for path in directories]
    return relative_directories, files


def _bounded_entries(root: Path) -> tuple[list[Path], list[Path]]:
    pending = [root]
    directories: list[Path] = []
    files: list[Path] = []
    entries = 0
    manifest_path = root / MANIFEST_NAME
    while pending:
        directory = pending.pop()
        try:
            children = list(os.scandir(directory))
        except OSError as exc:
            raise ToolchainError("toolchain bundle cannot be enumerated") from exc
        for entry in children:
            entries += 1
            if entries > _MAX_ENTRIES:
                raise ToolchainError("toolchain bundle exceeds entry limit")
            path = Path(entry.path)
            if _is_link_or_junction(path):
                raise ToolchainError("toolchain bundle contains a link")
            if entry.is_dir(follow_symlinks=False):
                directories.append(path)
                pending.append(path)
            elif entry.is_file(follow_symlinks=False):
                if path != manifest_path:
                    files.append(path)
            else:
                raise ToolchainError("toolchain bundle contains an unsupported entry")
    if len(files) > _MAX_FILES:
        raise ToolchainError("toolchain bundle exceeds file limit")
    return (
        sorted(directories, key=lambda path: path.relative_to(root).as_posix()),
        sorted(files, key=lambda path: path.relative_to(root).as_posix()),
    )


def _validate_manifest_shape(payload: Any) -> None:
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "bundle_id",
        "image",
        "lock_sha256",
        "git_package",
        "directories",
        "files",
    }:
        raise ToolchainError("toolchain manifest shape is invalid")
    _validate_identity(payload.get("lock_sha256"), payload.get("image"))
    if payload.get("schema_version") != "1.0" or not _SHA256_RE.fullmatch(
        str(payload.get("bundle_id", ""))
    ):
        raise ToolchainError("toolchain manifest identity is invalid")
    if payload.get("git_package") != {
        "version": GIT_DEB_VERSION,
        "url": GIT_DEB_URL,
        "size": GIT_DEB_SIZE,
        "sha256": GIT_DEB_SHA256,
        "binary_sha256": GIT_BINARY_SHA256,
        "runtime_paths": list(_GIT_RUNTIME_PATHS),
    } or not isinstance(payload.get("files"), list):
        raise ToolchainError("toolchain manifest provenance is invalid")
    _validate_manifest_directories(payload.get("directories"))
    _validate_manifest_files(payload["files"])
    _validate_inventory_relationships(payload["directories"], payload["files"])


def _validate_manifest_directories(value: object) -> None:
    if not isinstance(value, list) or not all(isinstance(path, str) for path in value):
        raise ToolchainError("toolchain manifest directory inventory is invalid")
    paths = list(value)
    try:
        canonical = canonical_changed_files(paths)
    except ValueError as exc:
        raise ToolchainError("toolchain manifest directory path is unsafe") from exc
    if paths != canonical or len(paths) > _MAX_ENTRIES:
        raise ToolchainError("toolchain manifest directory inventory is invalid")


def _validate_manifest_files(files: list[object]) -> None:
    paths: list[str] = []
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise ToolchainError("toolchain manifest file entry is invalid")
        path = item.get("path")
        size = item.get("size")
        digest = item.get("sha256")
        if (
            not isinstance(path, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
        ):
            raise ToolchainError("toolchain manifest file identity is invalid")
        try:
            canonical_changed_files([path])
        except ValueError as exc:
            raise ToolchainError("toolchain manifest file path is unsafe") from exc
        if (
            size < 0
            or size > _MAX_FILE_BYTES
            or not isinstance(digest, str)
            or not _SHA256_RE.fullmatch(digest)
        ):
            raise ToolchainError("toolchain manifest file bounds are invalid")
        paths.append(path)
        total += size
    if paths != sorted(set(paths)) or len(paths) > _MAX_FILES:
        raise ToolchainError("toolchain manifest file inventory is invalid")
    if total > _MAX_TOTAL_BYTES:
        raise ToolchainError("toolchain manifest exceeds materialization limits")
    _validate_git_file_entries(files)


def _validate_git_file_entries(files: list[object]) -> None:
    entries = {item["path"]: item for item in files if isinstance(item, dict)}
    git_paths = sorted(path for path in entries if path.startswith("git/"))
    if git_paths != list(_GIT_RUNTIME_PATHS):
        raise ToolchainError("normalized Git runtime inventory is invalid")
    for path in ("git/bin/git", "git/bin/git-upload-pack"):
        if entries[path]["sha256"] != GIT_BINARY_SHA256:
            raise ToolchainError("normalized Git binary digest is invalid")


def _validate_inventory_relationships(
    directories: list[str], files: list[object]
) -> None:
    directory_set = set(directories)
    file_paths = {str(item["path"]) for item in files if isinstance(item, dict)}
    if directory_set & file_paths or len(directories) + len(files) > _MAX_ENTRIES:
        raise ToolchainError("toolchain manifest entry relationships are invalid")
    if MANIFEST_NAME in file_paths:
        raise ToolchainError("toolchain manifest cannot inventory itself")
    for path in (*directories, *file_paths):
        parents = PurePosixPath(path).parents
        required = {str(parent) for parent in parents if str(parent) != "."}
        if not required.issubset(directory_set):
            raise ToolchainError("toolchain manifest parent inventory is incomplete")


def _validate_identity(lock_sha256: object, image: object) -> None:
    if not isinstance(lock_sha256, str) or not _SHA256_RE.fullmatch(lock_sha256):
        raise ToolchainError("toolchain lock digest is invalid")
    if image != PYTHON_IMAGE:
        raise ToolchainError("toolchain image is not the certified digest")


def _trusted_docker(path: Path, expected_sha256: str, host: str) -> Path:
    resolved = path.resolve(strict=True)
    if sha256_file(resolved) != expected_sha256:
        raise ToolchainError("Docker CLI digest mismatch")
    if host not in {
        "unix:///var/run/docker.sock",
        "npipe:////./pipe/docker_engine",
    }:
        raise ToolchainError("Docker daemon endpoint is unsupported")
    return resolved


def _verify_image(
    docker: Path,
    host: str,
    image: str,
    records: list[DockerCommandRecord],
) -> None:
    completed = _run_control_checked(
        [
            str(docker),
            f"--host={host}",
            "image",
            "inspect",
            "--format={{json .}}",
            image,
        ],
        docker,
        host,
        30,
        records,
    )
    try:
        metadata = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolchainError("Docker image identity is malformed") from exc
    if (
        not isinstance(metadata, dict)
        or image not in metadata.get("RepoDigests", [])
        or metadata.get("Os") != "linux"
        or metadata.get("Architecture") != "amd64"
    ):
        raise ToolchainError("Docker image digest mismatch")


def _provision_dependencies(
    docker: Path,
    host: str,
    image: str,
    lock: Path,
    output: Path,
    package: Path,
    records: list[DockerCommandRecord],
) -> None:
    container_name = _container_name(output, "provision")
    _run_container_checked(
        _provision_argv(
            docker,
            host,
            image,
            lock,
            output,
            container_name,
        )
        + [
            "/usr/local/bin/python",
            "-I",
            "-c",
            _PROVISION_SCRIPT,
            GIT_DEB_URL,
            str(GIT_DEB_SIZE),
            GIT_DEB_SHA256,
            "/bundle/git-runtime.deb",
        ],
        docker,
        host,
        container_name,
        120,
        records,
        (
            (output, "/bundle", False),
            (lock, "/inputs/requirements-governance.lock", True),
        ),
    )
    if not package.is_file() or sha256_file(package) != GIT_DEB_SHA256:
        raise ToolchainError("downloaded Git package digest mismatch")


def _extract_git(
    docker: Path,
    host: str,
    image: str,
    output: Path,
    _package: Path,
    records: list[DockerCommandRecord],
) -> None:
    container_name = _container_name(output, "extract-git")
    _run_container_checked(
        _bundle_argv(
            docker,
            host,
            image,
            output,
            network="none",
            container_name=container_name,
            read_only_root=True,
        )
        + [
            "/usr/local/bin/python",
            "-I",
            "-c",
            _EXTRACT_GIT_SCRIPT,
        ],
        docker,
        host,
        container_name,
        60,
        records,
        ((output, "/bundle", False),),
    )


def _probe_toolchain(
    docker: Path,
    host: str,
    image: str,
    output: Path,
    records: list[DockerCommandRecord],
) -> None:
    container_name = _container_name(output, "probe")
    _run_container_checked(
        _bundle_argv(
            docker,
            host,
            image,
            output,
            network="none",
            container_name=container_name,
            read_only_root=True,
            bundle_readonly=True,
            user=True,
            environment=(
                "PYTHONPATH=/bundle/python",
                "PYTHONNOUSERSITE=1",
                "PYTHONDONTWRITEBYTECODE=1",
                "GIT_EXEC_PATH=/bundle/git/bin",
                "GIT_TEMPLATE_DIR=/bundle/git/templates",
                "GIT_CONFIG_NOSYSTEM=1",
                "GIT_CONFIG_GLOBAL=/dev/null",
            ),
        )
        + [
            "/usr/local/bin/python",
            "-P",
            "-s",
            "-c",
            _PROBE_SCRIPT,
        ],
        docker,
        host,
        container_name,
        30,
        records,
        ((output, "/bundle", True),),
    )


def _provision_argv(
    docker: Path,
    host: str,
    image: str,
    lock: Path,
    output: Path,
    container_name: str,
) -> list[str]:
    base = _bundle_argv(
        docker,
        host,
        image,
        output,
        network="bridge",
        container_name=container_name,
        read_only_root=True,
    )
    return [
        *base[:-1],
        "--mount",
        f"type=bind,src={lock},dst=/inputs/requirements-governance.lock,readonly",
        base[-1],
    ]


def _bundle_argv(
    docker: Path,
    host: str,
    image: str,
    output: Path,
    *,
    network: str,
    container_name: str,
    read_only_root: bool = False,
    bundle_readonly: bool = False,
    user: bool = False,
    environment: tuple[str, ...] = (),
) -> list[str]:
    argv = [
        str(docker),
        f"--host={host}",
        "run",
        f"--name={container_name}",
        "--pull=never",
        "--init",
        f"--network={network}",
        "--cpus=2.0",
        "--memory=1073741824",
        "--memory-swap=1073741824",
        "--pids-limit=256",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=268435456",
        "--mount",
        f"type=bind,src={output},dst=/bundle{',readonly' if bundle_readonly else ''}",
    ]
    if read_only_root:
        argv.append("--read-only")
    if user:
        argv.append("--user=65532:65532")
    for value in environment:
        argv.append(f"--env={value}")
    return [*argv, image]


def _run_container_checked(
    argv: list[str],
    docker: Path,
    host: str,
    container_name: str,
    timeout: int,
    records: list[DockerCommandRecord],
    expected_mounts: tuple[tuple[Path, str, bool], ...],
) -> DockerProcessResult:
    try:
        completed = run_docker_container(
            argv,
            docker=docker,
            docker_host=host,
            container_name=container_name,
            purpose="trusted-provisioning",
            expected_mounts=expected_mounts,
            scratch_root=expected_mounts[0][0].parent,
            timeout_seconds=timeout,
            output_limit_bytes=262_144,
        )
    except DockerProcessError as exc:
        _extend_unique_records(records, exc.records)
        raise ToolchainError(
            "trusted toolchain provisioning command failed", records=exc.records
        ) from exc
    _extend_unique_records(records, completed.records)
    if (
        completed.termination != "EXITED"
        or completed.exit_code != 0
        or completed.errors
    ):
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        raise ToolchainError(
            f"trusted toolchain provisioning command failed: {detail[:1024]}",
            records=completed.records,
        )
    return completed


def _run_control_checked(
    argv: list[str],
    docker: Path,
    host: str,
    timeout: int,
    records: list[DockerCommandRecord],
) -> DockerProcessResult:
    try:
        completed = run_docker_control(
            argv,
            docker=docker,
            docker_host=host,
            timeout_seconds=timeout,
            output_limit_bytes=65_536,
        )
    except DockerProcessError as exc:
        _extend_unique_records(records, exc.records)
        raise ToolchainError(
            "trusted Docker control command failed", records=exc.records
        ) from exc
    _extend_unique_records(records, completed.records)
    if (
        completed.termination != "EXITED"
        or completed.exit_code != 0
        or completed.errors
    ):
        raise ToolchainError(
            "trusted Docker control command failed", records=completed.records
        )
    return completed


def _container_name(output: Path, operation: str) -> str:
    token = sha256_json({"operation": operation, "output": str(output)})[:16]
    return f"governance-toolchain-{operation}-{token}"


def _extend_unique_records(
    destination: list[DockerCommandRecord],
    source: tuple[DockerCommandRecord, ...],
) -> None:
    for record in source:
        if record not in destination:
            destination.append(record)


def _cleanup_partial_bundle(root: Path) -> str:
    if not root.exists() and not root.is_symlink():
        return ""
    try:
        shutil.rmtree(root, onexc=_clear_readonly)
    except OSError:
        return "partial toolchain bundle cleanup failed"
    return ""


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_new_bind_source(path: Path) -> None:
    if not path.parent.is_dir() or any(
        character in str(path) for character in (",", "\r", "\n", "\0")
    ):
        raise ToolchainError("toolchain output path is unsafe for Docker")


def _validate_existing_bind_source(path: Path) -> None:
    try:
        validate_bind_source(path)
    except (DockerProcessError, OSError) as exc:
        raise ToolchainError("toolchain input path is unsafe for Docker") from exc


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ToolchainError("toolchain manifest contains a duplicate key")
        payload[key] = value
    return payload


def _reject_json_constant(value: str) -> None:
    raise ToolchainError(f"toolchain manifest contains invalid constant: {value}")


def _clear_readonly(function: Any, path: str, _error: Any) -> None:
    os.chmod(path, 0o700)
    function(path)
