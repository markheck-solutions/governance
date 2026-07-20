from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from governance_eval.capability_catalog import capability_adapters
from governance_eval.hashing import sha256_file
from governance_eval.scope_manifest import ScopeManifestError, build_scope_manifest
from receipt_fixture import strict_receipt


class ScopeManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.git = Path(shutil.which("git") or "missing-git").resolve()
        _git(self.root, "init", "-q")
        _git(self.root, "config", "user.email", "governance@example.invalid")
        _git(self.root, "config", "user.name", "Governance Test")
        (self.root / "governance_eval").mkdir()
        (self.root / "governance_eval/app.py").write_text("VALUE = 1\n")
        (self.root / "tests").mkdir()
        (self.root / "tests/test_app.py").write_text("def test_app():\n    pass\n")
        (self.root / ".venv").mkdir()
        (self.root / ".venv/hidden.py").write_text("HIDDEN = True\n")
        self.base = _commit(self.root, "base")
        self.base_tree = _git(self.root, "rev-parse", "HEAD^{tree}")
        (self.root / "governance_eval/app.py").write_text("VALUE = 2\n")
        (self.root / "tests/test_app.py").unlink()
        (self.root / "candidate.py").write_text("CANDIDATE = True\n")
        self.head = _commit(self.root, "head")
        self.head_tree = _git(self.root, "rev-parse", "HEAD^{tree}")
        self.receipt = strict_receipt().to_json()
        self.receipt["runtime"]["git"] = {
            "path": str(self.git),
            "sha256": sha256_file(self.git),
            "version": _git(self.root, "--version"),
        }
        self.receipt["pull_request"]["base"].update(
            {"commit_sha": self.base, "tree_sha": self.base_tree}
        )
        self.receipt["pull_request"]["head"].update(
            {"commit_sha": self.head, "tree_sha": self.head_tree}
        )
        self.receipt["evaluator"].update(
            {"commit_sha": self.head, "tree_sha": self.head_tree}
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_tracked_python_ignores_candidate_discovery_controls(self) -> None:
        adapter = capability_adapters()[0]
        manifest = build_scope_manifest(
            receipt=self.receipt,
            adapter=adapter,
            target_root=self.root,
            evaluator_root=self.root,
        )

        self.assertEqual(
            [entry["path"] for entry in manifest["entries"]],
            [".venv/hidden.py", "candidate.py", "governance_eval/app.py"],
        )

    def test_test_scope_uses_base_tests_not_candidate_tests(self) -> None:
        adapter = capability_adapters()[5]
        manifest = build_scope_manifest(
            receipt=self.receipt,
            adapter=adapter,
            target_root=self.root,
            evaluator_root=self.root,
        )

        self.assertEqual(
            [entry["path"] for entry in manifest["entries"]],
            ["tests/test_app.py"],
        )
        self.assertEqual(manifest["source"]["commit_sha"], self.head)
        self.assertEqual(manifest["source"]["base_commit_sha"], self.base)

    def test_dirty_or_mismatched_checkout_blocks(self) -> None:
        adapter = capability_adapters()[0]
        (self.root / "untracked.txt").write_text("dirty")
        with self.assertRaisesRegex(ScopeManifestError, "dirty"):
            build_scope_manifest(
                receipt=self.receipt,
                adapter=adapter,
                target_root=self.root,
                evaluator_root=self.root,
            )
        (self.root / "untracked.txt").unlink()
        self.receipt["pull_request"]["head"]["tree_sha"] = "0" * 40
        with self.assertRaisesRegex(ScopeManifestError, "tree"):
            build_scope_manifest(
                receipt=self.receipt,
                adapter=adapter,
                target_root=self.root,
                evaluator_root=self.root,
            )


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        [str(shutil.which("git") or "git"), *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "--all")
    _git(root, "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD")


if __name__ == "__main__":
    unittest.main()
