from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from governance_eval.docker_process import run_docker_container
from governance_eval.docker_toolchain import PYTHON_IMAGE


@unittest.skipIf(
    os.environ.get("GOVERNANCE_RUN_DOCKER_TESTS") != "1",
    "set GOVERNANCE_RUN_DOCKER_TESTS=1 for live Docker controls",
)
class DockerProcessLiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._scratch = tempfile.TemporaryDirectory()
        self.scratch_root = Path(self._scratch.name)
        self.docker = Path(shutil.which("docker") or "missing-docker").resolve()
        self.host = os.environ.get(
            "GOVERNANCE_TRUSTED_DOCKER_HOST",
            "npipe:////./pipe/docker_engine"
            if os.name == "nt"
            else "unix:///var/run/docker.sock",
        )

    def tearDown(self) -> None:
        self._scratch.cleanup()

    def test_timeout_kills_namespace_and_removes_container(self) -> None:
        result = self._run(
            "timeout",
            "import time; time.sleep(10)",
            timeout=1,
            output_limit=4096,
        )

        self.assertEqual(result.termination, "TIMED_OUT")
        self.assertEqual(result.errors, ())

    def test_output_flood_kills_namespace_and_removes_container(self) -> None:
        result = self._run(
            "output",
            "import sys; sys.stdout.write('x' * 1048576)",
            timeout=10,
            output_limit=1024,
        )

        self.assertEqual(result.termination, "OUTPUT_LIMIT")
        self.assertEqual(len(result.stdout) + len(result.stderr), 1024)
        self.assertEqual(result.errors, ())

    def _run(self, label: str, program: str, *, timeout: int, output_limit: int):
        name = f"governance-process-{label}-{os.getpid()}"
        command = [
            str(self.docker),
            f"--host={self.host}",
            "run",
            f"--name={name}",
            "--pull=never",
            "--init",
            "--read-only",
            "--network=none",
            "--user=65532:65532",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=16",
            "--memory=67108864",
            "--memory-swap=67108864",
            "--cpus=0.5",
            PYTHON_IMAGE,
            "/usr/local/bin/python",
            "-I",
            "-c",
            program,
        ]
        return run_docker_container(
            command,
            docker=self.docker,
            docker_host=self.host,
            container_name=name,
            purpose="gate",
            scratch_root=self.scratch_root,
            timeout_seconds=timeout,
            output_limit_bytes=output_limit,
        )


if __name__ == "__main__":
    unittest.main()
