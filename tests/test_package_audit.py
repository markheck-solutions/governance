from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from governance_eval.docker_runtime import DockerRuntimeError
from governance_eval.package_audit import (
    _copy_build_input,
    _contained_build_argv,
    audit_wheel,
    run_package_audit,
)

LIVE_DOCKER = os.environ.get("GOVERNANCE_LIVE_DOCKER") == "1"


class PackageAuditTests(unittest.TestCase):
    def test_rejected_repo_local_artifact_path_creates_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            output = root / "artifacts" / "package-audit"
            with mock.patch(
                "governance_eval.package_audit._run_contained_build"
            ) as builder:
                result = run_package_audit(root, output)
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(output.exists())
            builder.assert_not_called()

    def test_rejects_symlinked_source_root_before_recursing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            (outside / "secret.py").write_text("secret = True\n", encoding="utf-8")
            linked = root / "linked"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            workspace = root / "workspace"
            workspace.mkdir()
            with self.assertRaisesRegex(
                DockerRuntimeError, "candidate source symlink forbidden: linked"
            ):
                _copy_build_input(root, workspace, linked)
            self.assertFalse((workspace / "linked" / "secret.py").exists())

    def test_accepts_complete_wheel_and_rejects_missing_package_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            complete = self._write_wheel(root / "complete.whl", include_schema=True)
            evidence, errors = audit_wheel(root, complete)
            self.assertEqual(errors, [])
            self.assertEqual(evidence["member_count"], 6)

            incomplete = self._write_wheel(
                root / "incomplete.whl", include_schema=False
            )
            _, errors = audit_wheel(root, incomplete)
            self.assertIn(
                "missing package files: governance_eval/schema_data/v1/example.json",
                errors,
            )

    def test_rejects_record_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            wheel = self._write_wheel(root / "mutated.whl", bad_record=True)
            _, errors = audit_wheel(root, wheel)
            self.assertIn("wheel RECORD mismatch: governance_eval/__init__.py", errors)

    def test_rejects_recorded_member_outside_exact_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            wheel = self._write_wheel(root / "extra.whl", extra_member="evil.pth")
            _, errors = audit_wheel(root, wheel)
            self.assertIn("unexpected wheel members: evil.pth", errors)

    def test_rejects_expected_entry_point_text_in_wrong_section(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            wheel = self._write_wheel(root / "entry.whl", bad_entry_point=True)
            _, errors = audit_wheel(root, wheel)
            self.assertIn("wheel console entry points mismatch pyproject.toml", errors)

    def test_rejects_oversized_individual_member_before_any_read(self) -> None:
        self._assert_initial_rejection(
            "MAX_MEMBER_UNCOMPRESSED_BYTES",
            1,
            "wheel member size exceeds 1",
        )

    def test_rejects_excessive_aggregate_size_before_any_read(self) -> None:
        self._assert_initial_rejection(
            "MAX_UNCOMPRESSED_BYTES",
            4,
            "wheel uncompressed size exceeds 4",
        )

    def test_rejects_excessive_compression_ratio_before_any_read(self) -> None:
        self._assert_initial_rejection(
            "MAX_COMPRESSION_RATIO",
            1,
            "wheel compression ratio exceeds 1",
        )

    def test_rejects_excessive_member_count_before_any_read(self) -> None:
        self._assert_initial_rejection(
            "MAX_MEMBERS",
            5,
            "wheel member count exceeds 5",
        )

    def test_record_reference_to_oversized_member_stops_before_record_read(
        self,
    ) -> None:
        self._assert_initial_rejection(
            "MAX_MEMBER_UNCOMPRESSED_BYTES",
            1,
            "governance_eval/schema_data/v1/example.json",
        )

    def test_truncated_member_is_deterministic_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            wheel = self._write_wheel(root / "truncated.whl")
            with zipfile.ZipFile(wheel) as archive:
                info = archive.getinfo(
                    "governance_eval-0.1.0.dist-info/entry_points.txt"
                )
                offset = info.header_offset + 30 + len(info.filename.encode())
                offset += len(info.extra)
            content = bytearray(wheel.read_bytes())
            content[offset] ^= 0xFF
            wheel.write_bytes(content)
            _, errors = audit_wheel(root, wheel)
            self.assertEqual(errors, ["wheel archive malformed: ValueError"])

    def test_malformed_archive_is_deterministic_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            wheel = root / "malformed.whl"
            wheel.write_bytes(b"not-a-zip")
            _, errors = audit_wheel(root, wheel)
            self.assertEqual(errors, ["wheel archive malformed: BadZipFile"])

    def test_trusted_verifier_never_invokes_candidate_builder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            wheel = self._write_wheel(root / "complete.whl")
            with mock.patch(
                "governance_eval.package_audit._run_contained_build"
            ) as builder:
                _, errors = audit_wheel(root, wheel)
            self.assertEqual(errors, [])
            builder.assert_not_called()

    def test_contained_command_has_fixed_security_and_resource_limits(self) -> None:
        command = _contained_build_argv(
            Path("docker"),
            "unix:///var/run/docker.sock",
            Path("/tmp/workspace"),
            Path("/tmp/toolchain"),
            "contained-build",
            120,
        )
        for expected in (
            "--read-only",
            "--network=none",
            "--user=65532:65532",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=128",
            "--memory=536870912",
            "--cpus=1.0",
            "--ulimit=cpu=120:120",
            "--tmpfs=/workspace:rw,nosuid,nodev,size=67108864,mode=1777",
        ):
            self.assertIn(expected, command)
        self.assertFalse(any("TOKEN" in argument for argument in command))
        mounts = [item for item in command if item.startswith("type=bind")]
        self.assertEqual(len(mounts), 2)
        self.assertTrue(mounts[0].endswith(",readonly"))
        self.assertTrue(mounts[1].endswith(",readonly"))

    @unittest.skipIf(not LIVE_DOCKER, "live Docker package boundary not selected")
    def test_contained_normal_package_builds_and_audits(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory:
            with tempfile.TemporaryDirectory() as artifact_directory:
                root = Path(source_directory)
                self._write_source(root, build_system=True)
                result = run_package_audit(root, Path(artifact_directory))
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["build"]["termination"], "EXITED")

    @unittest.skipIf(not LIVE_DOCKER, "live Docker package boundary not selected")
    def test_malicious_backend_cannot_write_outside_disposable_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory:
            with tempfile.TemporaryDirectory() as artifact_directory:
                root = Path(source_directory)
                self._write_backend_project(
                    root,
                    """from pathlib import Path
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    Path('/governance-host-escape').write_text('escaped')
""",
                )
                original = (root / "backend.py").read_bytes()
                result = run_package_audit(root, Path(artifact_directory))
                self.assertEqual(result["status"], "FAIL")
                self.assertNotEqual(result["build"]["exit_code"], 0)
                self.assertEqual((root / "backend.py").read_bytes(), original)
                self.assertFalse(Path("/governance-host-escape").exists())

    @unittest.skipIf(not LIVE_DOCKER, "live Docker package boundary not selected")
    def test_failed_build_never_passes(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory:
            with tempfile.TemporaryDirectory() as artifact_directory:
                root = Path(source_directory)
                self._write_backend_project(
                    root,
                    """def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    raise RuntimeError('expected build failure')
""",
                )
                result = run_package_audit(root, Path(artifact_directory))
                self.assertEqual(result["status"], "FAIL")
                self.assertIn(
                    "contained wheel build exited", "\n".join(result["errors"])
                )

    @unittest.skipIf(not LIVE_DOCKER, "live Docker package boundary not selected")
    def test_timed_out_build_never_passes(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory:
            with tempfile.TemporaryDirectory() as artifact_directory:
                root = Path(source_directory)
                self._write_backend_project(
                    root,
                    """import time
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    time.sleep(10)
""",
                )
                result = run_package_audit(
                    root, Path(artifact_directory), build_timeout_seconds=1
                )
                self.assertEqual(result["status"], "FAIL")
                self.assertTrue(result["build"]["timed_out"])
                self.assertIn("contained wheel build timed out", result["errors"])

    def _assert_initial_rejection(
        self, constant: str, value: int, expected_error: str
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            wheel = self._write_wheel(root / "hostile.whl", extra_member="extra.txt")
            with mock.patch(f"governance_eval.package_audit.{constant}", value):
                with mock.patch.object(
                    zipfile.ZipFile,
                    "open",
                    side_effect=AssertionError("member content was read"),
                ) as opened:
                    _, errors = audit_wheel(root, wheel)
            self.assertTrue(any(expected_error in error for error in errors), errors)
            opened.assert_not_called()

    @staticmethod
    def _write_source(root: Path, *, build_system: bool = False) -> None:
        package = root / "governance_eval"
        schema = package / "schema_data" / "v1"
        schema.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (schema / "example.json").write_text("{}\n", encoding="utf-8")
        build = (
            '\n[build-system]\nrequires = ["setuptools"]\n'
            'build-backend = "setuptools.build_meta"\n'
            if build_system
            else ""
        )
        (root / "pyproject.toml").write_text(
            """[project]
name = "governance-eval"
version = "0.1.0"
[project.scripts]
governance-eval = "governance_eval.cli:main"
[tool.setuptools.packages.find]
include = ["governance_eval*"]
[tool.setuptools.package-data]
governance_eval = ["schema_data/v1/*.json"]
"""
            + build,
            encoding="utf-8",
        )

    @staticmethod
    def _write_backend_project(root: Path, backend: str) -> None:
        package = root / "governance_eval"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        (root / "backend.py").write_text(backend, encoding="utf-8")
        (root / "pyproject.toml").write_text(
            """[project]
name = "governance-eval"
version = "0.1.0"
[project.scripts]
governance-eval = "governance_eval.cli:main"
[build-system]
requires = []
build-backend = "backend"
backend-path = ["."]
""",
            encoding="utf-8",
        )

    @staticmethod
    def _write_wheel(
        path: Path,
        *,
        include_schema: bool = True,
        bad_record: bool = False,
        extra_member: str | None = None,
        bad_entry_point: bool = False,
    ) -> Path:
        members = {
            "governance_eval/__init__.py": b"",
            "governance_eval-0.1.0.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: governance-eval\nVersion: 0.1.0\n"
            ),
            "governance_eval-0.1.0.dist-info/entry_points.txt": (
                b"[console_scripts]\ngovernance-eval = governance_eval.cli:main\n"
            ),
            "governance_eval-0.1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
        }
        if include_schema:
            members["governance_eval/schema_data/v1/example.json"] = b"{}\n"
        if extra_member:
            members[extra_member] = b"A" * 1024
        if bad_entry_point:
            members["governance_eval-0.1.0.dist-info/entry_points.txt"] = (
                b"[console_scripts]\ngovernance-eval = attacker:main\n"
                b"[notes]\ntext = governance-eval = governance_eval.cli:main\n"
            )
        record_name = "governance_eval-0.1.0.dist-info/RECORD"
        rows = []
        for name, data in members.items():
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(
                b"="
            )
            if bad_record and name == "governance_eval/__init__.py":
                digest = b"wrong"
            rows.append([name, "sha256=" + digest.decode("ascii"), str(len(data))])
        rows.append([record_name, "", ""])
        stream = io.StringIO(newline="")
        csv.writer(stream, lineterminator="\n").writerows(rows)
        members[record_name] = stream.getvalue().encode("utf-8")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return path


if __name__ == "__main__":
    unittest.main()
