from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    target = Path(args.target)
    sys.path.insert(0, str(target / "src"))
    api = importlib.import_module("demo.api")
    print(json.dumps({"value": api.classify("sample")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
