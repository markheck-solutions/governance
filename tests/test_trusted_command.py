from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
