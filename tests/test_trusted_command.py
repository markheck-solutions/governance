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

    def test_python_launcher_casing_still_binds_to_trusted_interpreter(self) -> None:
        trusted_python = "/opt/governance-python/bin/python"

        with (
            mock.patch.object(trusted_command.os, "name", "posix"),
            mock.patch.object(trusted_command.sys, "executable", trusted_python),
        ):
            bound = trusted_command.bind_current_python("Python -m ruff check .")

        self.assertEqual(bound, f"{trusted_python} -P -m ruff check .")

    def test_protected_module_casing_still_uses_safe_path(self) -> None:
        bound = trusted_command.bind_current_python("python -m Ruff check .")

        self.assertIn(" -P -m Ruff check .", bound)

    def test_path_qualified_python_launcher_binds_to_trusted_interpreter(self) -> None:
        trusted_python = "/opt/governance-python/bin/python"

        with (
            mock.patch.object(trusted_command.os, "name", "posix"),
            mock.patch.object(trusted_command.sys, "executable", trusted_python),
        ):
            bound = trusted_command.bind_current_python(
                "/usr/bin/python -m ruff check ."
            )

        self.assertEqual(bound, f"{trusted_python} -P -m ruff check .")

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

    def test_unittest_runner_uses_safe_wrapper(self) -> None:
        bound = trusted_command.bind_current_python("python -m unittest discover")

        self.assertNotIn(" -m unittest", bound)
        self.assertIn(" -P -c ", bound)
        self.assertIn(" discover", bound)

    def test_inline_python_uses_safe_path(self) -> None:
        bound = trusted_command.bind_current_python('python -c "import subprocess"')

        self.assertIn(' -P -c "import subprocess"', bound)

    def test_python_shell_chains_are_rejected(self) -> None:
        commands = (
            "python -c 'print(1)' && PATH=. python -c 'print(2)'",
            "python -m ruff check . || true",
            "python -m ruff check .; python -m unittest",
            "python -m ruff check . | tee output.txt",
            'python -c "$(printf print\\(0\\); printf >&2 SUBSTITUTION_RAN)"',
            'python -c "`printf print\\(0\\)`"',
        )
        with mock.patch.object(trusted_command.os, "name", "posix"):
            for command in commands:
                with self.subTest(command=command):
                    with self.assertRaisesRegex(
                        trusted_command.TrustedCommandError, "shell chains"
                    ):
                        trusted_command.bind_current_python(command)

    def test_windows_single_quotes_do_not_hide_shell_chains(self) -> None:
        with mock.patch.object(trusted_command.os, "name", "nt"):
            with self.assertRaisesRegex(
                trusted_command.TrustedCommandError, "shell chains"
            ):
                trusted_command.bind_current_python(
                    "python -c 'raise SystemExit(9)& echo BYPASS'"
                )

    def test_env_expanded_non_python_executable_passes_through(self) -> None:
        command = "$GOVERNANCE_TOOLCHAIN_BIN_PATH/printf ok"

        with mock.patch.object(trusted_command.os, "name", "posix"):
            bound = trusted_command.bind_current_python(command)

        self.assertEqual(bound, command)

    def test_command_substitution_executable_is_rejected(self) -> None:
        with mock.patch.object(trusted_command.os, "name", "posix"):
            with self.assertRaisesRegex(
                trusted_command.TrustedCommandError, "dynamic shell executable"
            ):
                trusted_command.bind_current_python("$(printf python) -m ruff check .")

    def test_env_wrapped_python_launchers_are_rejected(self) -> None:
        for command in (
            "/usr/bin/env python -m ruff check .",
            "/usr/bin/env /usr/bin/python -m ruff check .",
            "/usr/bin/env -S 'python -m ruff check .'",
            "VAR=x python -m ruff check .",
            "PYTHONPATH=. /usr/bin/python -m ruff check .",
            "VAR= python -m ruff check .",
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    trusted_command.TrustedCommandError, "wrapped Python"
                ):
                    trusted_command.bind_current_python(command)

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

    def test_compileall_shadow_cannot_bypass_current_self_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "compileall.py").write_text(
                "print('CANDIDATE_COMPILEALL_EXECUTED')\n", encoding="utf-8"
            )
            (target / "app.py").write_text("value = 1\n", encoding="utf-8")

            completed = trusted_command.run_bound_shell_command(
                "python -m compileall -q .", target
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("CANDIDATE_COMPILEALL_EXECUTED", completed.stdout)

    def test_inline_python_shadow_cannot_bypass_current_self_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "subprocess.py").write_text(
                "print('CANDIDATE_SUBPROCESS_EXECUTED')\n", encoding="utf-8"
            )

            completed = trusted_command.run_bound_shell_command(
                'python -c "import subprocess; print(subprocess.__name__)"',
                target,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("subprocess", completed.stdout)
        self.assertNotIn("CANDIDATE_SUBPROCESS_EXECUTED", completed.stdout)

    def test_unittest_shadow_cannot_bypass_current_self_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            tests = target / "tests"
            tests.mkdir()
            (target / "unittest.py").write_text(
                "raise SystemExit('CANDIDATE_UNITTEST_EXECUTED')\n",
                encoding="utf-8",
            )
            (tests / "test_sample.py").write_text(
                "import unittest\n\n"
                "class SampleTest(unittest.TestCase):\n"
                "    def test_sample(self):\n"
                "        self.assertTrue(True)\n",
                encoding="utf-8",
            )

            completed = trusted_command.run_bound_shell_command(
                "python -m unittest discover -s tests -p test_*.py",
                target,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Ran 1 test", completed.stderr)
        self.assertNotIn("CANDIDATE_UNITTEST_EXECUTED", completed.stderr)

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
