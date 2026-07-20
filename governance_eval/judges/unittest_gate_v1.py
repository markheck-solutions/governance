from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_MARKER = "GOVERNANCE_UNITTEST_SUMMARY="


def main() -> int:
    manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise SystemExit("authenticated test scope is empty")
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if len(paths) != len(entries) or any(
        not isinstance(path, str) or not path.startswith("tests/") for path in paths
    ):
        raise SystemExit("authenticated test scope is malformed")
    sys.path.insert(0, "/workspace")
    suite = unittest.defaultTestLoader.discover(
        "/workspace/tests", pattern="test_*.py", top_level_dir="/workspace"
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }
    print(_MARKER + json.dumps(summary, sort_keys=True, separators=(",", ":")))
    passed = (
        result.wasSuccessful()
        and result.testsRun > 0
        and len(result.skipped) < result.testsRun
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
