from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from governance_eval.registered_verification import resolve_exact_published_head


class ExactPublishedVerificationTests(unittest.TestCase):
    def test_clean_published_head_binds_matching_commit_and_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source, remote = _published_repository(Path(tmp))
            result = resolve_exact_published_head(source, str(remote))

        self.assertTrue(result["worktree_clean"])
        self.assertTrue(result["published"])
        self.assertEqual(result["local_head_sha"], result["remote_head_sha"])
        self.assertEqual(result["local_tree_sha"], result["remote_tree_sha"])

    def test_dirty_tracked_or_untracked_worktree_blocks(self) -> None:
        for untracked in (False, True):
            with self.subTest(untracked=untracked), tempfile.TemporaryDirectory() as tmp:
                source, remote = _published_repository(Path(tmp))
                path = source / ("extra.txt" if untracked else "value.txt")
                path.write_text("dirty\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "clean worktree"):
                    resolve_exact_published_head(source, str(remote))

    def test_unpublished_head_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source, remote = _published_repository(Path(tmp))
            (source / "value.txt").write_text("unpublished\n", encoding="utf-8")
            _git(source, "add", "value.txt")
            _git(source, "commit", "-q", "-m", "unpublished")
            with self.assertRaises(subprocess.CalledProcessError):
                resolve_exact_published_head(source, str(remote))

    def test_origin_mismatch_blocks_before_remote_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source, _ = _published_repository(Path(tmp))
            with self.assertRaisesRegex(RuntimeError, "origin does not match"):
                resolve_exact_published_head(source, "https://example.invalid/other.git")


def _published_repository(root: Path) -> tuple[Path, Path]:
    remote = root / "remote.git"
    source = root / "source"
    _git(root, "init", "-q", "--bare", str(remote))
    _git(root, "init", "-q", str(source))
    _git(source, "config", "user.email", "test@example.invalid")
    _git(source, "config", "user.name", "Test")
    (source / "value.txt").write_text("published\n", encoding="utf-8")
    _git(source, "add", "value.txt")
    _git(source, "commit", "-q", "-m", "published")
    _git(source, "remote", "add", "origin", str(remote))
    _git(source, "push", "-q", "-u", "origin", "HEAD:main")
    return source, remote


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.STDOUT).strip()


if __name__ == "__main__":
    unittest.main()
