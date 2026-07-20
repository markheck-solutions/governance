from __future__ import annotations

import io
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import governance_eval.docker_process as docker_process
from governance_eval.docker_process import (
    DockerProcessError,
    DockerProcessResult,
    docker_environment,
    run_docker_container,
    run_docker_control,
)


class DockerProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self._scratch = tempfile.TemporaryDirectory()
        self.scratch_root = Path(self._scratch.name)

    def tearDown(self) -> None:
        self._scratch.cleanup()

    def test_environment_drops_host_docker_injection(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "DOCKER_HOST": "tcp://attacker.invalid:2375",
                "DOCKER_CONTEXT": "attacker",
                "DOCKER_CONFIG": "C:/attacker",
            },
        ):
            environment = docker_environment(Path("C:/trusted/docker.exe"))

        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("DOCKER_CONTEXT", environment)
        self.assertNotIn("DOCKER_CONFIG", environment)

    def test_command_roles_and_attached_cleanup_contract_are_fail_closed(self) -> None:
        docker = Path("docker")
        host = "unix:///var/run/docker.sock"
        with self.assertRaisesRegex(DockerProcessError, "control"):
            run_docker_control(
                [str(docker), f"--host={host}", "run", "image"],
                docker=docker,
                docker_host=host,
                timeout_seconds=1,
                output_limit_bytes=1,
            )

        for forbidden in (
            "--rm",
            "--rm=true",
            "--detach",
            "--detach=true",
            "-d",
            "-d=true",
            "-dit",
            "--privileged",
        ):
            with self.subTest(forbidden=forbidden):
                command = self._command(forbidden)
                with (
                    mock.patch("subprocess.Popen") as popen,
                    self.assertRaises(DockerProcessError),
                ):
                    run_docker_container(
                        command,
                        docker=docker,
                        docker_host=host,
                        container_name="governance-test",
                        purpose="gate",
                        scratch_root=self.scratch_root,
                        timeout_seconds=1,
                        output_limit_bytes=1,
                    )
                popen.assert_not_called()

    def test_control_rejects_arbitrary_mutating_operations(self) -> None:
        docker = Path("docker")
        host = "unix:///var/run/docker.sock"
        for arguments in (("system", "prune"), ("exec", "container", "sh")):
            with (
                self.subTest(arguments=arguments),
                mock.patch("subprocess.Popen") as popen,
                self.assertRaisesRegex(DockerProcessError, "allowlisted"),
            ):
                run_docker_control(
                    [str(docker), f"--host={host}", *arguments],
                    docker=docker,
                    docker_host=host,
                    timeout_seconds=1,
                    output_limit_bytes=1,
                )
            popen.assert_not_called()

    def test_gate_mounts_are_limited_to_exact_owned_destinations(self) -> None:
        docker = Path("docker")
        host = "unix:///var/run/docker.sock"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp).resolve()
            forbidden = (
                f"type=bind,src={source},dst=/host",
                f"type=bind,src={source},dst=/opt/governance-toolchain",
                f"type=bind,src={source},dst=/workspace,readonly",
            )
            for mount in forbidden:
                with (
                    self.subTest(mount=mount),
                    mock.patch("subprocess.Popen") as popen,
                    self.assertRaisesRegex(DockerProcessError, "mount"),
                ):
                    run_docker_container(
                        self._command("--mount", mount),
                        docker=docker,
                        docker_host=host,
                        container_name="governance-test",
                        purpose="gate",
                        scratch_root=self.scratch_root,
                        timeout_seconds=1,
                        output_limit_bytes=1,
                    )
                popen.assert_not_called()

    def test_timeout_requests_namespace_stop_and_local_cli_termination(self) -> None:
        process = mock.Mock()
        process.stdout = io.BytesIO(b"")
        process.stderr = io.BytesIO(b"")
        process.poll.return_value = None
        process.wait.return_value = -9
        stop = mock.Mock()
        with (
            mock.patch("subprocess.Popen", return_value=process),
            mock.patch(
                "governance_eval.docker_process._wait_reason",
                return_value="TIMED_OUT",
            ),
        ):
            result = docker_process._run_process(
                ["docker", "run"],
                docker=Path("docker"),
                timeout_seconds=1,
                output_limit_bytes=1024,
                stop=stop,
            )

        stop.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(result.termination, "TIMED_OUT")
        self.assertEqual(result.exit_code, -9)

    def test_fast_exit_output_flood_is_promoted_after_drain(self) -> None:
        process = mock.Mock()
        process.stdout = io.BytesIO(b"x" * 2048)
        process.stderr = io.BytesIO(b"")
        process.wait.return_value = 0
        with (
            mock.patch("subprocess.Popen", return_value=process),
            mock.patch(
                "governance_eval.docker_process._wait_reason",
                return_value="EXITED",
            ),
        ):
            result = docker_process._run_process(
                ["docker", "run"],
                docker=Path("docker"),
                timeout_seconds=1,
                output_limit_bytes=1024,
            )

        self.assertEqual(result.termination, "OUTPUT_LIMIT")
        self.assertEqual(len(result.stdout), 1024)
        self.assertTrue(result.stdout_truncated)
        self.assertFalse(result.stderr_truncated)

    def test_cleanup_error_cannot_be_erased_by_final_absence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cidfile = Path(tmp) / "container.cid"
            cidfile.write_text("a" * 64, encoding="ascii")
            failed_remove = self._result(termination="TIMED_OUT", exit_code=None)
            absent = self._result(stdout=b"")
            with mock.patch(
                "governance_eval.docker_process._control",
                side_effect=(failed_remove, absent),
            ):
                errors = docker_process._remove_and_verify(
                    Path("docker"),
                    "unix:///var/run/docker.sock",
                    "governance-test",
                    cidfile,
                )

        self.assertEqual(errors, ["Docker forced container removal failed"])

    def test_name_race_without_owned_cid_never_kills_or_removes_by_name(self) -> None:
        docker = Path("docker")
        host = "unix:///var/run/docker.sock"
        seen_command: list[str] = []

        def exited(command: list[str], **_kwargs: object) -> DockerProcessResult:
            seen_command.extend(command)
            return self._result(exit_code=125)

        with (
            mock.patch(
                "governance_eval.docker_process._require_container_absent"
            ) as absent,
            mock.patch(
                "governance_eval.docker_process._run_process", side_effect=exited
            ),
            mock.patch(
                "governance_eval.docker_process._read_container_id",
                return_value=None,
            ),
            mock.patch("governance_eval.docker_process._control") as control,
            self.assertRaisesRegex(DockerProcessError, "creation"),
        ):
            run_docker_container(
                self._command(),
                docker=docker,
                docker_host=host,
                container_name="governance-test",
                purpose="gate",
                scratch_root=self.scratch_root,
                timeout_seconds=1,
                output_limit_bytes=1024,
            )

        self.assertEqual(absent.call_count, 2)
        cid_arguments = [
            value for value in seen_command if value.startswith("--cidfile=")
        ]
        self.assertEqual(len(cid_arguments), 1)
        self.assertIn(".docker-control-governance-test", cid_arguments[0])
        control.assert_not_called()

    def test_capture_start_failure_still_stops_and_cleans(self) -> None:
        created = self._result(stdout=("a" * 64).encode("ascii"))
        failed = DockerProcessError("Docker process supervision failed")
        with (
            mock.patch(
                "governance_eval.docker_process._run_process",
                side_effect=(created, failed),
            ),
            mock.patch("governance_eval.docker_process._require_container_absent"),
            mock.patch(
                "governance_eval.docker_process._created_container_id",
                return_value="a" * 64,
            ),
            mock.patch(
                "governance_eval.docker_process._remove_and_verify",
                return_value=[],
            ) as cleanup,
            self.assertRaisesRegex(DockerProcessError, "supervision"),
        ):
            run_docker_container(
                self._command(),
                docker=Path("docker"),
                docker_host="unix:///var/run/docker.sock",
                container_name="governance-test",
                purpose="gate",
                scratch_root=self.scratch_root,
                timeout_seconds=1,
                output_limit_bytes=1024,
            )

        cleanup.assert_called_once()

    def test_pipe_close_failure_is_evidence_and_cleanup_still_runs(self) -> None:
        created = self._result(stdout=("a" * 64).encode("ascii"))
        started = self._result()
        started = DockerProcessResult(
            **{
                **started.__dict__,
                "errors": ("Docker CLI output pipe close failed",),
            }
        )
        with (
            mock.patch(
                "governance_eval.docker_process._run_process",
                side_effect=(created, started),
            ),
            mock.patch("governance_eval.docker_process._require_container_absent"),
            mock.patch(
                "governance_eval.docker_process._created_container_id",
                return_value="a" * 64,
            ),
            mock.patch(
                "governance_eval.docker_process._remove_and_verify",
                return_value=[],
            ) as cleanup,
        ):
            result = run_docker_container(
                self._command(),
                docker=Path("docker"),
                docker_host="unix:///var/run/docker.sock",
                container_name="governance-test",
                purpose="gate",
                scratch_root=self.scratch_root,
                timeout_seconds=1,
                output_limit_bytes=1024,
            )

        cleanup.assert_called_once()
        self.assertIn("Docker CLI output pipe close failed", result.errors)

    @staticmethod
    def _command(*extra: str) -> list[str]:
        return [
            "docker",
            "--host=unix:///var/run/docker.sock",
            "run",
            "--name=governance-test",
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
            *extra,
            "python@sha256:" + "a" * 64,
            "/usr/local/bin/python",
        ]

    @staticmethod
    def _result(
        *,
        termination: str = "EXITED",
        exit_code: int | None = 0,
        stdout: bytes = b"",
    ) -> DockerProcessResult:
        now = datetime.now(UTC)
        return DockerProcessResult(
            command=("docker",),
            termination=termination,
            exit_code=exit_code,
            stdout=stdout,
            stderr=b"",
            started_at=now,
            completed_at=now,
            errors=(),
        )


if __name__ == "__main__":
    unittest.main()
