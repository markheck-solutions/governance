from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.execution_plan_v2 import (
    ExecutionPlanV2,
    assess_execution_plan_v2,
)
from governance_eval.hashing import sha256_file, sha256_json

_DOCKER_HOSTS = {
    "unix:///var/run/docker.sock",
    "npipe:////./pipe/docker_engine",
}


class DockerRuntimeError(RuntimeError):
    pass


def docker_run_argv(
    *,
    docker: Path,
    docker_host: str,
    plan: ExecutionPlanV2,
    workspace: Path,
    toolchain_root: Path,
    container_name: str,
) -> list[str]:
    runtime = plan.runtime
    step = plan.step
    return [
        str(docker),
        f"--host={docker_host}",
        "run",
        "--rm",
        f"--name={container_name}",
        "--read-only",
        f"--network={runtime['network']}",
        f"--user={runtime['user']}",
        f"--cap-drop={runtime['cap_drop'][0]}",
        "--security-opt=no-new-privileges:true",
        f"--pids-limit={runtime['pids_limit']}",
        f"--memory={runtime['memory_bytes']}",
        f"--cpus={runtime['cpus']}",
        "--env=HOME=/workspace/.home",
        "--env=TMPDIR=/workspace/.tmp",
        "--env=PYTHONNOUSERSITE=1",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        f"--workdir={step['working_directory']}",
        "--mount",
        f"type=bind,src={workspace},dst=/workspace",
        "--mount",
        f"type=bind,src={toolchain_root},dst=/opt/governance-toolchain,readonly",
        runtime["image"],
        *step["argv"],
    ]


def execute_ruff_docker(
    *,
    plan: ExecutionPlanV2,
    receipt: CheckoutReceipt,
    target_root: Path,
    evaluator_root: Path,
    toolchain_binary: Path,
) -> dict[str, Any]:
    started = datetime.now(UTC)
    command: list[str] = []
    docker: Path | None = None
    docker_host = str(plan.runtime.get("docker_host", "unknown"))
    try:
        _validate_plan_binding(plan, receipt)
        docker = _trusted_docker(
            Path(plan.runtime["docker_path"]),
            plan.runtime["docker_sha256"],
            docker_host,
        )
        git = _trusted_git(receipt)
        _validate_evaluator(evaluator_root, receipt.evaluator, git)
        _verify_image(docker, docker_host, plan.runtime["image"])
        with tempfile.TemporaryDirectory(prefix="governance-runtime-") as temporary:
            runtime_root = Path(temporary)
            workspace = runtime_root / "workspace"
            toolchain_root = runtime_root / "toolchain"
            _seal_toolchain(toolchain_binary, toolchain_root, plan)
            _materialize_tree(target_root, plan.target, workspace, git)
            container_name = f"governance-{plan.plan_id[:12]}-{uuid.uuid4().hex[:8]}"
            command = docker_run_argv(
                docker=docker,
                docker_host=docker_host,
                plan=plan,
                workspace=workspace,
                toolchain_root=toolchain_root,
                container_name=container_name,
            )
            outcome = _run_bounded(
                command,
                docker=docker,
                docker_host=docker_host,
                container_name=container_name,
                timeout_seconds=plan.step["timeout_seconds"],
                output_limit=plan.step["output_limit_bytes"],
            )
        return _result(
            plan,
            receipt,
            docker,
            docker_host,
            command,
            started,
            outcome=outcome,
            errors=[],
        )
    except (DockerRuntimeError, OSError, subprocess.SubprocessError) as exc:
        return _result(
            plan,
            receipt,
            docker,
            docker_host,
            command,
            started,
            outcome=None,
            errors=[str(exc)],
        )


def _validate_plan_binding(plan: ExecutionPlanV2, receipt: CheckoutReceipt) -> None:
    if plan.checkout_receipt_id != receipt.receipt_id:
        raise DockerRuntimeError("execution plan checkout receipt mismatch")
    receipt_payload = receipt.to_json()
    receipt_id = receipt_payload.pop("receipt_id")
    if receipt_id != sha256_json(receipt_payload):
        raise DockerRuntimeError("checkout receipt integrity is invalid")
    plan_payload = plan.to_json()
    plan_id = plan_payload.pop("plan_id")
    if plan_id != sha256_json(plan_payload):
        raise DockerRuntimeError("execution plan integrity is invalid")
    assessment = assess_execution_plan_v2(plan.to_json(), receipt)
    if assessment["capability_status"] != "PASS":
        raise DockerRuntimeError("execution plan differs from evaluator-owned plan")


def _trusted_docker(path: Path, expected_sha256: str, host: str) -> Path:
    path = path.resolve()
    if not path.is_file():
        raise DockerRuntimeError("Docker CLI path is invalid")
    if sha256_file(path) != expected_sha256:
        raise DockerRuntimeError("Docker CLI digest mismatch")
    if host not in _DOCKER_HOSTS:
        raise DockerRuntimeError("Docker daemon endpoint is unsupported")
    return path


def _trusted_git(receipt: CheckoutReceipt) -> Path:
    path = Path(receipt.git_path).resolve()
    if not path.is_file():
        raise DockerRuntimeError("trusted Git executable is unavailable")
    if sha256_file(path) != receipt.git_sha256:
        raise DockerRuntimeError("trusted Git executable digest mismatch")
    return path


def _verify_image(docker: Path, docker_host: str, image: str) -> None:
    completed = _command(
        [
            str(docker),
            f"--host={docker_host}",
            "image",
            "inspect",
            "--format={{json .RepoDigests}}",
            image,
        ],
        timeout=30,
        env=_docker_environment(docker),
    )
    digest = image.split("@", 1)[1]
    if digest not in completed.stdout:
        raise DockerRuntimeError("Docker image digest mismatch")


def _validate_evaluator(root: Path, evaluator: dict[str, Any], git: Path) -> None:
    root = root.resolve()
    if _git(
        root,
        git,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    ):
        raise DockerRuntimeError("evaluator checkout changed after receipt")
    if _git(root, git, "rev-parse", "HEAD") != evaluator["commit_sha"]:
        raise DockerRuntimeError("evaluator commit changed after receipt")
    if _git(root, git, "rev-parse", "HEAD^{tree}") != evaluator["tree_sha"]:
        raise DockerRuntimeError("evaluator tree changed after receipt")


def _seal_toolchain(source: Path, destination: Path, plan: ExecutionPlanV2) -> None:
    source = source.resolve()
    if not source.is_file():
        raise DockerRuntimeError("Ruff toolchain binary is unavailable")
    expected = plan.runtime["toolchain_sha256"]
    if sha256_file(source) != expected:
        raise DockerRuntimeError("Ruff toolchain digest mismatch")
    destination.mkdir()
    sealed = destination / "ruff"
    shutil.copyfile(source, sealed)
    if sha256_file(sealed) != expected:
        raise DockerRuntimeError("sealed Ruff toolchain digest mismatch")
    if os.name != "nt":
        sealed.chmod(0o555)


def _materialize_tree(
    root: Path, target: dict[str, str], workspace: Path, git: Path
) -> None:
    root = root.resolve()
    if _git(
        root,
        git,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    ):
        raise DockerRuntimeError("target checkout changed after receipt")
    if _git(root, git, "rev-parse", "HEAD") != target["commit_sha"]:
        raise DockerRuntimeError("target commit changed after receipt")
    if _git(root, git, "rev-parse", "HEAD^{tree}") != target["tree_sha"]:
        raise DockerRuntimeError("target tree changed after receipt")
    workspace.mkdir()
    archive = workspace.parent / "target.tar"
    _git(
        root,
        git,
        "archive",
        "--format=tar",
        f"--output={archive}",
        target["commit_sha"],
    )
    with tarfile.open(archive, "r") as tar:
        tar.extractall(workspace, filter="data")
    (workspace / ".home").mkdir()
    (workspace / ".tmp").mkdir()
    _make_writable(workspace)


def _make_writable(root: Path) -> None:
    if os.name == "nt":
        return
    for path in (root, *root.rglob("*")):
        path.chmod(0o777 if path.is_dir() else 0o666)


def _run_bounded(
    command: list[str],
    *,
    docker: Path,
    docker_host: str,
    container_name: str,
    timeout_seconds: int,
    output_limit: int,
) -> dict[str, Any]:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_docker_environment(docker),
    )
    output = _BoundedOutput(output_limit)
    threads = output.start(process)
    deadline = time.monotonic() + timeout_seconds
    termination = _wait_reason(process, output, deadline)
    if termination != "EXITED":
        _command(
            [str(docker), f"--host={docker_host}", "kill", container_name],
            timeout=10,
            check=False,
            env=_docker_environment(docker),
        )
    exit_code = process.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=5)
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            pipe.close()
    cleanup = _command(
        [
            str(docker),
            f"--host={docker_host}",
            "container",
            "inspect",
            container_name,
        ],
        timeout=10,
        check=False,
        env=_docker_environment(docker),
    )
    if cleanup.returncode == 0:
        _command(
            [str(docker), f"--host={docker_host}", "rm", "-f", container_name],
            timeout=10,
            check=False,
            env=_docker_environment(docker),
        )
        raise DockerRuntimeError("Docker container cleanup failed")
    return {
        "termination": termination,
        "exit_code": exit_code,
        "stdout": output.stream("stdout"),
        "stderr": output.stream("stderr"),
    }


def _wait_reason(
    process: subprocess.Popen[bytes], output: _BoundedOutput, deadline: float
) -> str:
    while process.poll() is None:
        if output.exceeded.is_set():
            return "OUTPUT_LIMIT"
        if time.monotonic() >= deadline:
            return "TIMED_OUT"
        time.sleep(0.01)
    return "EXITED"


class _BoundedOutput:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.remaining = limit
        self.data = {"stdout": bytearray(), "stderr": bytearray()}
        self.truncated = {"stdout": False, "stderr": False}
        self.lock = threading.Lock()
        self.exceeded = threading.Event()

    def start(self, process: subprocess.Popen[bytes]) -> list[threading.Thread]:
        threads = [
            threading.Thread(target=self._drain, args=(name, pipe), daemon=True)
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr))
            if pipe is not None
        ]
        for thread in threads:
            thread.start()
        return threads

    def _drain(self, name: str, pipe: Any) -> None:
        while chunk := pipe.read(8192):
            with self.lock:
                keep = min(len(chunk), self.remaining)
                self.data[name].extend(chunk[:keep])
                self.remaining -= keep
                self.truncated[name] |= keep != len(chunk)
                if keep != len(chunk):
                    self.exceeded.set()

    def stream(self, name: str) -> dict[str, Any]:
        content = bytes(self.data[name])
        return {
            "captured_base64": base64.b64encode(content).decode("ascii"),
            "captured_bytes": len(content),
            "sha256": sha256(content).hexdigest(),
            "truncated": self.truncated[name],
        }


def _result(
    plan: ExecutionPlanV2,
    receipt: CheckoutReceipt,
    _docker: Path | None,
    docker_host: str,
    command: list[str],
    started: datetime,
    *,
    outcome: dict[str, Any] | None,
    errors: list[str],
) -> dict[str, Any]:
    completed = datetime.now(UTC)
    empty = _empty_stream()
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "artifact_id": "",
        "plan_id": plan.plan_id,
        "checkout_receipt_id": receipt.receipt_id,
        "capability_status": "PASS"
        if outcome and outcome["exit_code"] == 0 and not errors
        else "BLOCK_TECHNICAL",
        "runtime": {
            "image": plan.runtime["image"],
            "policy_id": plan.runtime["policy_id"],
            "docker_path": plan.runtime["docker_path"],
            "docker_sha256": plan.runtime["docker_sha256"],
            "toolchain": "ruff==0.15.21",
            "toolchain_sha256": plan.runtime["toolchain_sha256"],
            "docker_host": docker_host,
        },
        "command": command,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "completed_at": completed.isoformat().replace("+00:00", "Z"),
        "duration_seconds": round((completed - started).total_seconds(), 6),
        "timeout_seconds": plan.step["timeout_seconds"],
        "termination": outcome["termination"] if outcome else "NOT_STARTED",
        "exit_code": outcome["exit_code"] if outcome else None,
        "stdout": outcome["stdout"] if outcome else empty,
        "stderr": outcome["stderr"] if outcome else empty,
        "errors": errors,
    }
    payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
    return payload


def _empty_stream() -> dict[str, Any]:
    return {
        "captured_base64": "",
        "captured_bytes": 0,
        "sha256": sha256(b"").hexdigest(),
        "truncated": False,
    }


def _git(root: Path, executable: Path, *arguments: str) -> str:
    command = [
        str(executable),
        f"--git-dir={root / '.git'}",
        f"--work-tree={root}",
        *arguments,
    ]
    return _command(
        command, timeout=10, env=_git_environment(executable)
    ).stdout.strip()


def _command(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise DockerRuntimeError(
            f"command failed: {command[1] if len(command) > 1 else command[0]}: {detail}"
        )
    return completed


def _git_environment(executable: Path) -> dict[str, str]:
    environment = _base_environment(executable)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _docker_environment(executable: Path) -> dict[str, str]:
    return _base_environment(executable)


def _base_environment(executable: Path) -> dict[str, str]:
    environment = {"PATH": str(executable.parent), "LC_ALL": "C"}
    system_root = os.environ.get("SystemRoot")
    if system_root:
        environment["SystemRoot"] = system_root
    return environment
