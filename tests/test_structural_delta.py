from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from governance_eval.structural import scan_structural_metrics, structural_delta


class StructuralDeltaTests(unittest.TestCase):
    def test_delta_splits_existing_introduced_removed_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base"
            head = root / "head"
            _write(base / "src/pkg/a.py", "from pkg._private import _old\n\n\ndef stable():\n    return _old()\n")
            _write(base / "src/pkg/_private.py", "def _old():\n    return 1\n")
            _write(head / "src/pkg/a.py", "from pkg._private import _old\nfrom pkg._private import _new\n\n\ndef stable():\n    return _old()\n")
            _write(head / "src/pkg/_private.py", "def _old():\n    return 1\n\n\ndef _new():\n    return 2\n")

            delta = structural_delta(scan_structural_metrics(base), scan_structural_metrics(head))

        private = delta["cross_module_private_references"]
        self.assertEqual(private["status"], "MEASURED")
        self.assertTrue(private["existing"])
        self.assertTrue(private["introduced"])
        self.assertEqual(delta["publicized_private_helper_renames"]["status"], "UNKNOWN")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
