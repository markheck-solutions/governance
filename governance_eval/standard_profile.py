from __future__ import annotations

import argparse
import ast
import base64
import json
import os
import signal
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Sequence

from governance_eval.benchmark import BENCHMARK_PASS, run_benchmark
from governance_eval.capability_catalog import STANDARD_PROFILE_ADAPTERS
from governance_eval.docker_runtime import _BoundedOutput
from governance_eval.hashing import sha256_file
from governance_eval.package_audit import audit_candidate_wheel


PROFILE_MARKER = "__GOVERNANCE_STANDARD_PROFILE_V1__"
OUTPUT_LIMIT = 65536
COMMAND_TIMEOUT = 120
_OUTPUT_DIR = ".governance-output"


def run_standard_profile(
    workspace: Path, benchmark_root: Path, evaluator_sha: str
) -> dict[str, Any]:
    root = workspace.resolve(strict=True)
    benchmark = benchmark_root.resolve(strict=True)
    if root.as_posix() != "/workspace":
        raise ValueError("standard profile workspace is not fixed")
    if benchmark.as_posix() != "/opt/governance-toolchain/benchmark":
        raise ValueError("standard profile benchmark root is not fixed")
    if len(evaluator_sha) != 40 or any(
        character not in "0123456789abcdef" for character in evaluator_sha
    ):
        raise ValueError("standard profile evaluator SHA is invalid")
    initial = _source_snapshot(root)
    python_files = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if _tracked_source(path, root)
    )
    output = root / _OUTPUT_DIR
    output.mkdir()
    build_source = output / "build-source"
    _stage_build_source(root, build_source, initial)
    commands = _fixed_commands(root, build_source, python_files, output)
    results = [_run_capability(root, *item) for item in commands[:4]]
    results.append(_architecture_result(root, python_files))
    results.append(_run_capability(root, *commands[4]))
    results.append(_run_capability(root, *commands[5]))
    results.append(_package_result(root, output, results[-1]))
    results.append(_benchmark_result(benchmark, output, evaluator_sha))
    results.append(_integrity_result(root, initial))
    expected = [item[0] for item in STANDARD_PROFILE_ADAPTERS]
    if [item["capability"] for item in results] != expected:
        raise ValueError("standard profile capability order is invalid")
    status = (
        "PASS"
        if all(item["status"] == "PASS" for item in results)
        else "BLOCK_TECHNICAL"
    )
    _release_workspace_directories(root)
    return {
        "schema_version": "1.0",
        "profile": "python.standard.v1",
        "status": status,
        "capabilities": results,
    }


def _release_workspace_directories(root: Path, owner: int | None = None) -> None:
    if owner is None:
        getuid = getattr(os, "getuid", None)
        if not callable(getuid):
            raise RuntimeError("standard profile requires POSIX ownership")
        owner = int(getuid())
    for current, directories, _files in os.walk(root, topdown=True):
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink() and path.stat().st_uid == owner:
                path.chmod(0o777)


def _fixed_commands(
    root: Path, build_source: Path, python_files: list[str], output: Path
) -> list[tuple[str, str, str, list[str]]]:
    ruff = "/opt/governance-toolchain/ruff"
    python = sys.executable
    return [
        (
            "lint",
            "python.ruff-check.v1",
            "EVALUATOR_AUTHORITATIVE",
            [ruff, "check", "--isolated", "--no-cache", "--no-respect-gitignore", "."],
        ),
        (
            "format",
            "python.ruff-format-check.v1",
            "EVALUATOR_AUTHORITATIVE",
            [
                ruff,
                "format",
                "--check",
                "--isolated",
                "--no-cache",
                "--no-respect-gitignore",
                ".",
            ],
        ),
        (
            "typecheck",
            "python.mypy.v1",
            "EVALUATOR_AUTHORITATIVE",
            [
                python,
                "-P",
                "-s",
                "-m",
                "mypy",
                "--config-file=/dev/null",
                "--strict",
                "--no-incremental",
                "--cache-dir=/dev/null",
                *python_files,
            ],
        ),
        (
            "complexity",
            "python.ruff-c901.v1",
            "EVALUATOR_AUTHORITATIVE",
            [
                ruff,
                "check",
                "--isolated",
                "--no-cache",
                "--no-respect-gitignore",
                "--select",
                "C901",
                "--config",
                "lint.mccabe.max-complexity=10",
                ".",
            ],
        ),
        (
            "tests",
            "python.unittest.v1",
            "COOPERATIVE_DYNAMIC",
            [
                python,
                "-P",
                "-s",
                "-m",
                "governance_eval.unittest_runner",
                "--workspace",
                str(root),
            ],
        ),
        (
            "build",
            "python.wheel-build.v1",
            "CONTAINED_BUILD",
            [
                python,
                "-P",
                "-s",
                "-m",
                "pip",
                "wheel",
                "--disable-pip-version-check",
                "--no-deps",
                "--no-index",
                "--no-build-isolation",
                str(build_source),
                "-w",
                str(output / "wheel"),
            ],
        ),
    ]


def _run_capability(
    root: Path,
    capability: str,
    adapter_id: str,
    assurance_class: str,
    command: list[str],
) -> dict[str, Any]:
    outcome = _bounded_command(command, root)
    status = (
        "PASS"
        if outcome["termination"] == "EXITED" and outcome["exit_code"] == 0
        else "BLOCK_TECHNICAL"
    )
    return {
        "capability": capability,
        "adapter_id": adapter_id,
        "assurance_class": assurance_class,
        "status": status,
        "evidence": outcome,
    }


def _architecture_result(root: Path, python_files: list[str]) -> dict[str, Any]:
    started = _now()
    errors = _import_cycle_errors(root, python_files)
    return {
        "capability": "architecture",
        "adapter_id": "python.architecture.v1",
        "assurance_class": "EVALUATOR_AUTHORITATIVE",
        "status": "PASS" if not errors else "BLOCK_TECHNICAL",
        "evidence": {
            "started_at": started,
            "completed_at": _now(),
            "errors": errors,
            "files_scanned": len(python_files),
        },
    }


def _package_result(
    root: Path, output: Path, build_result: dict[str, Any]
) -> dict[str, Any]:
    started = _now()
    errors: list[str] = []
    wheels = sorted((output / "wheel").glob("*.whl"))
    evidence: dict[str, Any] | None = None
    if build_result["status"] != "PASS" or len(wheels) != 1:
        errors.append("contained build did not produce exactly one wheel")
    else:
        evidence, wheel_errors = audit_candidate_wheel(root, wheels[0])
        errors.extend(wheel_errors)
    return {
        "capability": "package_audit",
        "adapter_id": "python.package-audit.v1",
        "assurance_class": "EVALUATOR_AUTHORITATIVE",
        "status": "PASS" if not errors else "BLOCK_TECHNICAL",
        "evidence": {
            "started_at": started,
            "completed_at": _now(),
            "wheel_sha256": sha256_file(wheels[0]) if len(wheels) == 1 else None,
            "audit": evidence,
            "errors": errors,
        },
    }


def _benchmark_result(
    benchmark_root: Path, output: Path, evaluator_sha: str
) -> dict[str, Any]:
    started = _now()
    errors: list[str] = []
    try:
        result = run_benchmark(
            benchmark_root,
            repeat=1,
            artifacts_dir=output / "phase1",
            evaluator_git_sha=evaluator_sha,
        )
        if result["phase1_decision"] != BENCHMARK_PASS:
            errors.extend(result["acceptance_errors"])
        digest = sha256(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    except (OSError, KeyError, TypeError, ValueError) as exc:
        errors.append(str(exc))
        digest = None
    return {
        "capability": "benchmark",
        "adapter_id": "governance.phase1.v1",
        "assurance_class": "EVALUATOR_AUTHORITATIVE",
        "status": "PASS" if not errors else "BLOCK_TECHNICAL",
        "evidence": {
            "started_at": started,
            "completed_at": _now(),
            "result_sha256": digest,
            "errors": errors,
        },
    }


def _integrity_result(root: Path, initial: dict[str, str]) -> dict[str, Any]:
    started = _now()
    current = _source_snapshot(root)
    changed = sorted(
        path
        for path in set(initial) | set(current)
        if current.get(path) != initial.get(path)
    )
    return {
        "capability": "integrity",
        "adapter_id": "git.diff-integrity.v1",
        "assurance_class": "EVALUATOR_AUTHORITATIVE",
        "status": "PASS" if not changed else "BLOCK_TECHNICAL",
        "evidence": {
            "started_at": started,
            "completed_at": _now(),
            "changed_files": changed,
            "tracked_files": len(initial),
        },
    }


def _bounded_command(command: list[str], cwd: Path) -> dict[str, Any]:
    started = datetime.now(UTC)
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_environment(),
        start_new_session=True,
    )
    output = _BoundedOutput(OUTPUT_LIMIT)
    threads = output.start(process)
    deadline = time.monotonic() + COMMAND_TIMEOUT
    termination = "EXITED"
    while process.poll() is None:
        if output.exceeded.is_set():
            termination = "OUTPUT_LIMIT"
            break
        if time.monotonic() >= deadline:
            termination = "TIMED_OUT"
            break
        time.sleep(0.01)
    if termination != "EXITED":
        kill_group = getattr(os, "killpg", None)
        kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
        if callable(kill_group):
            kill_group(process.pid, kill_signal)
        else:  # pragma: no cover - the profile runtime is Linux
            process.kill()
    exit_code = process.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=5)
    completed = datetime.now(UTC)
    stdout = output.stream("stdout")
    stderr = output.stream("stderr")
    return {
        "argv": command,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "completed_at": completed.isoformat().replace("+00:00", "Z"),
        "timeout_seconds": COMMAND_TIMEOUT,
        "termination": termination,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "summary": _summary(stdout, stderr),
    }


def _environment() -> dict[str, str]:
    return {
        "HOME": "/workspace/.home",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": "/opt/governance-toolchain/site-packages",
        "PYTHONSAFEPATH": "1",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "TMPDIR": "/workspace/.tmp",
    }


def _summary(stdout: dict[str, Any], stderr: dict[str, Any]) -> str:
    raw = base64.b64decode(stdout["captured_base64"]) + base64.b64decode(
        stderr["captured_base64"]
    )
    return raw.decode("utf-8", errors="replace")[-2000:]


def _source_snapshot(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in root.rglob("*"):
        if not _tracked_source(path, root):
            continue
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[name] = "SYMLINK"
        elif path.is_file():
            result[name] = sha256_file(path)
        elif not path.is_dir():
            result[name] = "SPECIAL"
    return result


def _stage_build_source(
    root: Path, destination: Path, snapshot: dict[str, str]
) -> None:
    destination.mkdir()
    for name in sorted(snapshot):
        source = root / name
        if snapshot[name] in {"SYMLINK", "SPECIAL"} or not source.is_file():
            raise ValueError(f"unsupported candidate source entry: {name}")
        target = destination.joinpath(*Path(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _tracked_source(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return relative.parts[0] not in {".home", ".tmp", _OUTPUT_DIR}


def _import_cycle_errors(root: Path, python_files: list[str]) -> list[str]:
    modules = {_module_name(path): path for path in python_files}
    graph: dict[str, set[str]] = {module: set() for module in modules}
    errors: list[str] = []
    for module, path in modules.items():
        try:
            tree = ast.parse((root / path).read_text(encoding="utf-8"), filename=path)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            errors.append(f"{path}: {exc}")
            continue
        for imported in _imports(tree, module):
            if imported in modules and imported != module:
                graph[module].add(imported)
    cycles = _cycles(graph)
    return [*errors, *("import cycle: " + " -> ".join(cycle) for cycle in cycles)]


def _module_name(path: str) -> str:
    value = path.removesuffix(".py").replace("/", ".")
    return value.removesuffix(".__init__")


def _imports(tree: ast.AST, module: str) -> set[str]:
    values: set[str] = set()
    package = module.rsplit(".", 1)[0] if "." in module else ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = package.split(".")
            if node.level:
                prefix = prefix[: max(0, len(prefix) - node.level + 1)]
            base = ".".join((*prefix, node.module or "")).strip(".")
            values.add(base)
            values.update(
                ".".join((base, alias.name)).strip(".") for alias in node.names
            )
    return values


def _cycles(graph: dict[str, set[str]]) -> list[tuple[str, ...]]:
    found: set[tuple[str, ...]] = set()
    for start in sorted(graph):
        _walk_cycles(graph, start, start, [], set(), found)
    return sorted(found)


def _walk_cycles(
    graph: dict[str, set[str]],
    start: str,
    node: str,
    path: list[str],
    active: set[str],
    found: set[tuple[str, ...]],
) -> None:
    if node in active:
        if node == start:
            cycle = tuple(path[path.index(node) :])
            rotations = [cycle[index:] + cycle[:index] for index in range(len(cycle))]
            found.add(min(rotations))
        return
    active.add(node)
    path.append(node)
    for target in sorted(graph.get(node, ())):
        _walk_cycles(graph, start, target, path, active, found)
    path.pop()
    active.remove(node)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the fixed Python Governance profile"
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--benchmark-root", required=True, type=Path)
    parser.add_argument("--evaluator-sha", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result = run_standard_profile(
        arguments.workspace, arguments.benchmark_root, arguments.evaluator_sha
    )
    print(PROFILE_MARKER + json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
