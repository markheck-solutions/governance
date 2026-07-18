from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from governance_eval import trusted_command


class TrustedCommandModulePathTests(unittest.TestCase):
    def test_protected_python_module_uses_safe_path(self) -> None:
        bound = trusted_command.bind_current_python("python -m ruff check .")

        self.assertIn(" -P -m ruff check .", bound)

    def test_target_controlled_module_does_not_shadow_protected_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "pip.py").write_text(
                "raise SystemExit('CANDIDATE_PIP_EXECUTED')\n", encoding="utf-8"
            )

            completed = trusted_command.run_bound_shell_command(
                "python -m pip --version", target
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("pip", completed.stdout)
        self.assertNotIn("CANDIDATE_PIP_EXECUTED", completed.stderr)

    def test_unprotected_test_runner_keeps_target_import_path(self) -> None:
        bound = trusted_command.bind_current_python("python -m unittest discover")

        self.assertNotIn(" -P -m unittest", bound)
        self.assertIn(" -m unittest discover", bound)

    def test_env_expanded_non_python_executable_passes_through(self) -> None:
        command = "$GOVERNANCE_TOOLCHAIN_BIN_PATH/printf ok"

        with mock.patch.object(trusted_command.os, "name", "posix"):
            bound = trusted_command.bind_current_python(command)

        self.assertEqual(bound, command)

    def test_windows_trusted_python_path_quotes_shell_metacharacters(self) -> None:
        trusted_python = r"C:\trusted&runtime\python.exe"

        with (
            mock.patch.object(trusted_command.os, "name", "nt"),
            mock.patch.object(trusted_command.sys, "executable", trusted_python),
        ):
            bound = trusted_command.bind_current_python("python -m ruff check .")

        self.assertEqual(bound, f'"{trusted_python}" -P -m ruff check .')

    def test_safe_path_prevents_candidate_module_shadowing_directly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "pip.py").write_text(
                "print('CANDIDATE_PIP_EXECUTED')\n", encoding="utf-8"
            )
            completed = subprocess.run(
                [sys.executable, "-P", "-m", "pip", "--version"],
                cwd=target,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=60,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("CANDIDATE_PIP_EXECUTED", completed.stdout)

    def test_trusted_governance_module_ignores_target_shadow_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            shadow = target / "governance_eval"
            shadow.mkdir()
            (shadow / "__main__.py").write_text(
                "raise SystemExit('CANDIDATE_GOVERNANCE_EXECUTED')\n",
                encoding="utf-8",
            )

            completed = trusted_command.run_bound_shell_command(
                "python -m governance_eval --help", target
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("usage: governance-eval", completed.stdout)
        self.assertNotIn("CANDIDATE_GOVERNANCE_EXECUTED", completed.stderr)


if __name__ == "__main__":
    unittest.main()
