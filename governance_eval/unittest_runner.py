from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path
from typing import Sequence


MARKER = "__GOVERNANCE_UNITTEST_V1__"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the fixed unittest adapter")
    parser.add_argument("--workspace", required=True, type=Path)
    arguments = parser.parse_args(argv)
    workspace = arguments.workspace.resolve(strict=True)
    if workspace.as_posix() != "/workspace":
        raise SystemExit("unittest workspace is not fixed")
    suite = unittest.defaultTestLoader.discover(
        str(workspace / "tests"), pattern="test_*.py", top_level_dir=str(workspace)
    )
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    payload = {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "successful": result.wasSuccessful(),
    }
    print(MARKER + json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if _accepted(payload) else 1


def _accepted(payload: dict[str, int | bool]) -> bool:
    tests_run = payload["tests_run"]
    skipped = payload["skipped"]
    return bool(
        payload["successful"]
        and isinstance(tests_run, int)
        and isinstance(skipped, int)
        and tests_run > 0
        and skipped < tests_run
    )


if __name__ == "__main__":
    raise SystemExit(main())
