from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest import mock

from governance_eval import supportability


class SelfUpdateBoundaryTests(unittest.TestCase):
    def test_noncanonical_caller_path_fails_closed(self) -> None:
        errors: list[str] = []

        changed = supportability._changed_files_or_empty(
            Path("."),
            "a" * 40,
            "b" * 40,
            ["governance_eval/../README.md"],
            errors,
        )

        self.assertEqual(changed, [])
        self.assertEqual(
            errors,
            [
                "changed-file path is not canonical Git-relative: "
                "'governance_eval/../README.md'"
            ],
        )

    def test_changed_file_discovery_uses_unambiguous_git_paths(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"schemas/v99/future.json\0governance_eval/future.py\0",
            stderr=b"",
        )
        with mock.patch(
            "governance_eval.supportability.subprocess.run", return_value=completed
        ) as run:
            changed = supportability._git_changed_files(Path("."), "a" * 40, "b" * 40)

        self.assertEqual(
            changed,
            ["governance_eval/future.py", "schemas/v99/future.json"],
        )
        self.assertEqual(
            run.call_args.args[0],
            [
                "git",
                "diff",
                "--no-renames",
                "--name-only",
                "-z",
                "a" * 40,
                "b" * 40,
                "--",
            ],
        )
        self.assertFalse(run.call_args.kwargs["text"])


if __name__ == "__main__":
    unittest.main()
