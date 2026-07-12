from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from governance_eval.target_eval import _checkout


class TargetCacheTests(unittest.TestCase):
    def test_verified_mirror_supports_exact_offline_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=source, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=source, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=source, check=True)
            (source / "value.txt").write_text("bound\n", encoding="utf-8")
            subprocess.run(["git", "add", "value.txt"], cwd=source, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=source, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
            cache = root / "cache"
            _checkout(str(source), sha, root / "online", cache, offline=False)
            checkout = _checkout(str(source), sha, root / "offline", cache, offline=True)
            self.assertEqual((checkout / "value.txt").read_text(encoding="utf-8"), "bound\n")

    def test_offline_without_verified_cache_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "offline target cache missing"):
                _checkout(
                    "https://example.invalid/missing.git", "a" * 40, Path(tmp) / "checkout", Path(tmp) / "cache", True
                )


if __name__ == "__main__":
    unittest.main()
