from __future__ import annotations

from copy import deepcopy
import os
from pathlib import PurePosixPath
from pathlib import Path
import subprocess
from typing import Any, Mapping

from governance_eval.capability_catalog import CapabilityAdapter
from governance_eval.hashing import sha256_json
from governance_eval.hashing import sha256_file

_FIELDS = {"schema_version", "manifest_id", "rule_id", "source", "entries"}
_SOURCE_FIELDS = {
    "kind",
    "repository_id",
    "repository_full_name",
    "commit_sha",
    "tree_sha",
    "base_commit_sha",
    "base_tree_sha",
}
_ENTRY_FIELDS = {"path", "mode", "blob_sha", "size_bytes"}
_MAX_ENTRIES = 20_000
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 1024 * 1024 * 1024


class ScopeManifestError(ValueError):
    pass


def build_scope_manifest(
    *,
    receipt: Mapping[str, Any],
    adapter: CapabilityAdapter,
    target_root: Path,
    evaluator_root: Path,
) -> dict[str, Any]:
    git = _trusted_git(receipt)
    root, commit, tree = _scope_checkout(
        receipt, adapter.scope_rule_id, target_root, evaluator_root
    )
    _validate_checkout(root, commit, tree, git)
    entries = _scope_entries(root, commit, adapter.scope_rule_id, receipt, git)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "manifest_id": "",
        "rule_id": adapter.scope_rule_id,
        "source": _expected_source(receipt, adapter.scope_rule_id),
        "entries": entries,
    }
    payload["manifest_id"] = sha256_json(
        {key: value for key, value in payload.items() if key != "manifest_id"}
    )
    return validate_scope_manifest(payload, receipt=receipt, adapter=adapter)


def validate_scope_manifest(
    payload: Mapping[str, object],
    *,
    receipt: Mapping[str, Any],
    adapter: CapabilityAdapter,
) -> dict[str, Any]:
    manifest = deepcopy(dict(payload))
    if set(manifest) != _FIELDS or manifest.get("schema_version") != "1.0":
        raise ScopeManifestError("scope manifest shape is invalid")
    if manifest.get("rule_id") != adapter.scope_rule_id:
        raise ScopeManifestError("scope manifest rule differs from adapter")
    source = manifest.get("source")
    entries = manifest.get("entries")
    if not isinstance(source, dict) or set(source) != _SOURCE_FIELDS:
        raise ScopeManifestError("scope manifest source is invalid")
    if not isinstance(entries, list) or len(entries) > _MAX_ENTRIES:
        raise ScopeManifestError("scope manifest entries are invalid")
    _validate_source(source, receipt, adapter.scope_rule_id)
    _validate_entries(entries, adapter.scope_rule_id)
    unsigned = deepcopy(manifest)
    manifest_id = unsigned.pop("manifest_id")
    if manifest_id != sha256_json(unsigned):
        raise ScopeManifestError("scope manifest id is invalid")
    return manifest


def scope_paths(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(f"/workspace/{entry['path']}" for entry in manifest["entries"])


def _validate_source(
    source: Mapping[str, Any],
    receipt: Mapping[str, Any],
    rule_id: str,
) -> None:
    expected = _expected_source(receipt, rule_id)
    if dict(source) != expected:
        raise ScopeManifestError("scope manifest source identity is invalid")


def _expected_source(receipt: Mapping[str, Any], rule_id: str) -> dict[str, Any]:
    repository = receipt["repository"]
    head = receipt["pull_request"]["head"]
    base = receipt["pull_request"]["base"]
    if rule_id == "certified-evaluator-tree.v1":
        evaluator = receipt["evaluator"]
        return _source(
            "EVALUATOR",
            evaluator["repository_id"],
            evaluator["repository_full_name"],
            evaluator["commit_sha"],
            evaluator["tree_sha"],
        )
    if rule_id in {
        "pr-base-protected-tests.v1",
        "authenticated-diff.v1",
        "verified-wheel.v1",
    }:
        kinds = {
            "pr-base-protected-tests.v1": "TARGET_HEAD_WITH_BASE_TESTS",
            "authenticated-diff.v1": "DIFF",
            "verified-wheel.v1": "INPUT_ARTIFACT",
        }
        return _source(
            kinds[rule_id],
            repository["id"],
            repository["full_name"],
            head["commit_sha"],
            head["tree_sha"],
            base["commit_sha"],
            base["tree_sha"],
        )
    return _source(
        "TARGET_HEAD",
        repository["id"],
        repository["full_name"],
        head["commit_sha"],
        head["tree_sha"],
    )


def _source(
    kind: str,
    repository_id: int,
    repository_full_name: str,
    commit_sha: str,
    tree_sha: str,
    base_commit_sha: str | None = None,
    base_tree_sha: str | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "repository_id": repository_id,
        "repository_full_name": repository_full_name,
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
        "base_commit_sha": base_commit_sha,
        "base_tree_sha": base_tree_sha,
    }


def _validate_entries(entries: list[object], rule_id: str) -> None:
    if rule_id == "verified-wheel.v1":
        if entries:
            raise ScopeManifestError("wheel-only scope manifest must be empty")
        return
    if not entries:
        raise ScopeManifestError("scope manifest cannot be empty")
    paths: list[str] = []
    total = 0
    for raw in entries:
        if not isinstance(raw, dict) or set(raw) != _ENTRY_FIELDS:
            raise ScopeManifestError("scope manifest entry shape is invalid")
        path = _canonical_path(raw.get("path"))
        _validate_entry_identity(raw)
        _validate_rule_path(path, rule_id)
        paths.append(path)
        total += int(raw["size_bytes"])
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ScopeManifestError("scope manifest paths are not canonical")
    if len({path.casefold() for path in paths}) != len(paths):
        raise ScopeManifestError("scope manifest paths collide by case")
    if total > _MAX_TOTAL_BYTES:
        raise ScopeManifestError("scope manifest exceeds total size limit")


def _validate_entry_identity(entry: Mapping[str, object]) -> None:
    mode = entry.get("mode")
    blob = entry.get("blob_sha")
    size = entry.get("size_bytes")
    if mode not in {"100644", "100755"}:
        raise ScopeManifestError("scope manifest entry mode is invalid")
    if (
        not isinstance(blob, str)
        or len(blob) != 40
        or any(character not in "0123456789abcdef" for character in blob)
    ):
        raise ScopeManifestError("scope manifest entry blob is invalid")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 <= size <= _MAX_FILE_BYTES
    ):
        raise ScopeManifestError("scope manifest entry size is invalid")


def _validate_rule_path(path: str, rule_id: str) -> None:
    if rule_id in {"tracked-python.v1", "tracked-production-python.v1"}:
        if not path.endswith((".py", ".pyi")):
            raise ScopeManifestError("Python scope contains a non-Python path")
    if rule_id == "tracked-production-python.v1" and path.startswith("tests/"):
        raise ScopeManifestError("production scope contains a test path")
    if rule_id == "pr-base-protected-tests.v1" and not path.startswith("tests/"):
        raise ScopeManifestError("base-test scope contains a non-test path")


def _canonical_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise ScopeManifestError("scope manifest path is invalid")
    if "\\" in value or any(character in value for character in ("\r", "\n", "\0")):
        raise ScopeManifestError("scope manifest path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ScopeManifestError("scope manifest path is invalid")
    if path.as_posix() != value or path.parts[0] == ".git":
        raise ScopeManifestError("scope manifest path is invalid")
    return value


def _trusted_git(receipt: Mapping[str, Any]) -> Path:
    try:
        identity = receipt["runtime"]["git"]
        path = Path(identity["path"]).resolve(strict=True)
        expected = identity["sha256"]
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise ScopeManifestError("trusted Git identity is invalid") from exc
    if not path.is_file() or sha256_file(path) != expected:
        raise ScopeManifestError("trusted Git executable digest mismatch")
    return path


def _scope_checkout(
    receipt: Mapping[str, Any],
    rule_id: str,
    target_root: Path,
    evaluator_root: Path,
) -> tuple[Path, str, str]:
    if rule_id == "certified-evaluator-tree.v1":
        evaluator = receipt["evaluator"]
        return (
            evaluator_root.resolve(strict=True),
            evaluator["commit_sha"],
            evaluator["tree_sha"],
        )
    head = receipt["pull_request"]["head"]
    return target_root.resolve(strict=True), head["commit_sha"], head["tree_sha"]


def _validate_checkout(root: Path, commit: str, tree: str, git: Path) -> None:
    status = _git_bytes(
        git,
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    )
    if status:
        raise ScopeManifestError("scope checkout is dirty")
    if _git_text(git, root, "rev-parse", "HEAD") != commit:
        raise ScopeManifestError("scope checkout commit differs from receipt")
    if _git_text(git, root, "rev-parse", "HEAD^{tree}") != tree:
        raise ScopeManifestError("scope checkout tree differs from receipt")


def _scope_entries(
    root: Path,
    commit: str,
    rule_id: str,
    receipt: Mapping[str, Any],
    git: Path,
) -> list[dict[str, Any]]:
    if rule_id == "verified-wheel.v1":
        return []
    selected_commit = (
        receipt["pull_request"]["base"]["commit_sha"]
        if rule_id == "pr-base-protected-tests.v1"
        else commit
    )
    entries = _tree_entries(root, selected_commit, git)
    return [entry for entry in entries if _path_applies(entry["path"], rule_id)]


def _tree_entries(root: Path, commit: str, git: Path) -> list[dict[str, Any]]:
    raw = _git_bytes(
        git,
        root,
        "ls-tree",
        "-r",
        "-z",
        "--long",
        "--full-tree",
        commit,
    )
    entries = [_tree_entry(item) for item in raw.split(b"\0") if item]
    return sorted(entries, key=lambda item: item["path"])


def _tree_entry(raw: bytes) -> dict[str, Any]:
    try:
        header, encoded_path = raw.split(b"\t", 1)
        mode, object_type, blob, size = header.decode("ascii").split()
        path = encoded_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ScopeManifestError("Git tree entry is malformed") from exc
    if object_type != "blob" or mode not in {"100644", "100755"}:
        raise ScopeManifestError("Git tree contains an unsupported entry")
    canonical = _canonical_path(path)
    try:
        parsed_size = int(size)
    except ValueError as exc:
        raise ScopeManifestError("Git tree entry size is invalid") from exc
    entry = {
        "path": canonical,
        "mode": mode,
        "blob_sha": blob,
        "size_bytes": parsed_size,
    }
    _validate_entry_identity(entry)
    return entry


def _path_applies(path: str, rule_id: str) -> bool:
    if rule_id == "tracked-python.v1":
        return path.endswith((".py", ".pyi"))
    if rule_id == "tracked-production-python.v1":
        return path.endswith((".py", ".pyi")) and not path.startswith(
            ("tests/", "test/")
        )
    if rule_id == "pr-base-protected-tests.v1":
        return path.startswith("tests/") and path.endswith((".py", ".pyi"))
    return True


def _git_text(git: Path, root: Path, *arguments: str) -> str:
    try:
        return _git_bytes(git, root, *arguments).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ScopeManifestError("Git scope evidence is not UTF-8") from exc


def _git_bytes(git: Path, root: Path, *arguments: str) -> bytes:
    command = [
        str(git),
        f"--git-dir={root / '.git'}",
        f"--work-tree={root}",
        *arguments,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=10,
            env=_git_environment(git),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScopeManifestError("Git scope command failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > 64 * 1024 * 1024:
        raise ScopeManifestError("Git scope command failed")
    return completed.stdout


def _git_environment(git: Path) -> dict[str, str]:
    environment = {
        "PATH": str(git.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    system_root = os.environ.get("SystemRoot")
    if system_root:
        environment["SystemRoot"] = system_root
    return environment
