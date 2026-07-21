from __future__ import annotations

import base64
import csv
import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from governance_eval.package_audit import audit_wheel


class PackageAuditTests(unittest.TestCase):
    def test_accepts_complete_wheel_and_rejects_missing_package_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            complete = self._write_wheel(root / "complete.whl", include_schema=True)
            evidence, errors = audit_wheel(root, complete)
            self.assertEqual(errors, [])
            self.assertEqual(evidence["member_count"], 6)

            incomplete = self._write_wheel(
                root / "incomplete.whl", include_schema=False
            )
            _, errors = audit_wheel(root, incomplete)
            self.assertIn(
                "missing package files: governance_eval/schema_data/v1/example.json",
                errors,
            )

    def test_rejects_record_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_source(root)
            wheel = self._write_wheel(root / "mutated.whl", bad_record=True)
            _, errors = audit_wheel(root, wheel)
            self.assertIn("wheel RECORD mismatch: governance_eval/__init__.py", errors)

    @staticmethod
    def _write_source(root: Path) -> None:
        package = root / "governance_eval"
        schema = package / "schema_data" / "v1"
        schema.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (schema / "example.json").write_text("{}\n", encoding="utf-8")
        (root / "pyproject.toml").write_text(
            """[project]
name = "governance-eval"
version = "0.1.0"
""",
            encoding="utf-8",
        )

    @staticmethod
    def _write_wheel(
        path: Path, *, include_schema: bool = True, bad_record: bool = False
    ) -> Path:
        members = {
            "governance_eval/__init__.py": b"",
            "governance_eval-0.1.0.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: governance-eval\nVersion: 0.1.0\n"
            ),
            "governance_eval-0.1.0.dist-info/entry_points.txt": (
                b"[console_scripts]\ngovernance-eval = governance_eval.cli:main\n"
            ),
            "governance_eval-0.1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
        }
        if include_schema:
            members["governance_eval/schema_data/v1/example.json"] = b"{}\n"
        record_name = "governance_eval-0.1.0.dist-info/RECORD"
        rows = []
        for name, data in members.items():
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(
                b"="
            )
            if bad_record and name == "governance_eval/__init__.py":
                digest = b"wrong"
            rows.append([name, "sha256=" + digest.decode("ascii"), str(len(data))])
        rows.append([record_name, "", ""])
        stream = io.StringIO(newline="")
        csv.writer(stream, lineterminator="\n").writerows(rows)
        members[record_name] = stream.getvalue().encode("utf-8")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return path


if __name__ == "__main__":
    unittest.main()
