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
    target = Path(args.target).resolve()
    sys.path.insert(0, str(target))
    decision = importlib.import_module("governance_eval.decision")
    result = decision.decide({"id": "SELF", "detectors": [], "required_evidence": []}, [])
    print(json.dumps({"decision": result.decision.value, "fail_closed": result.fail_closed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
