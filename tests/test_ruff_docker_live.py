from __future__ import annotations

import base64
import os
import subprocess
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.docker_runtime import execute_ruff_docker
from governance_eval.execution_plan_v2 import compile_execution_plan_v2
from governance_eval.execution_result_v2 import validate_execution_result_v2
from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.schemas import validate_named


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _receipt(root: Path) -> CheckoutReceipt:
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    git_path = Path(shutil.which("git") or "missing-git").resolve()
    docker_path = Path(os.environ["GOVERNANCE_TRUSTED_DOCKER_PATH"]).resolve()
    receipt = CheckoutReceipt(
        schema_version="1.0",
        receipt_id="",
        repository={"id": 1, "full_name": "markheck-solutions/governance"},
        pull_request={
            "number": 1,
            "url": "https://github.com/markheck-solutions/governance/pull/1",
            "base_sha": commit,
            "head_sha": commit,
            "base_tree_sha": tree,
            "head_tree_sha": tree,
        },
        evaluator={"commit_sha": commit, "tree_sha": tree},
        workflow={
            "workflow_ref": "markheck-solutions/governance/.github/workflows/governance.yml@refs/heads/main",
            "run_id": 1,
            "run_attempt": 1,
            "server_url": "https://github.com",
            "api_url": "https://api.github.com",
            "observed_at": "2026-07-19T12:00:00Z",
        },
        git_path=str(git_path),
        git_sha256=sha256_file(git_path),
        docker={
            "path": str(docker_path),
            "sha256": os.environ["GOVERNANCE_TRUSTED_DOCKER_SHA256"],
            "host": os.environ["GOVERNANCE_TRUSTED_DOCKER_HOST"],
        },
        config_sha256="1" * 64,
        standard_sha256="2" * 64,
    )
    payload = receipt.to_json()
    payload.pop("receipt_id")
    return CheckoutReceipt(**{**receipt.__dict__, "receipt_id": sha256_json(payload)})


@unittest.skipIf(os.environ.get("GOVERNANCE_LIVE_DOCKER") != "1", "live Docker control")
class RuffDockerLiveTests(unittest.TestCase):
    def test_clean_passes_and_defective_blocks_without_target_mutation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            _git(root, "init", "-q")
            _git(root, "config", "user.email", "governance@example.invalid")
            _git(root, "config", "user.name", "Governance Test")
            source = root / "example.py"
            source.write_text("answer = 42\n", encoding="utf-8")
            _git(root, "add", source.name)
            _git(root, "commit", "-qm", "clean")
            clean_bytes = source.read_bytes()

            clean = self._execute(root)

            self.assertEqual(clean["capability_status"], "PASS")
            self.assertEqual(source.read_bytes(), clean_bytes)
            source.write_text("import os\nanswer = 42\n", encoding="utf-8")
            _git(root, "commit", "-qam", "defective")
            defective_bytes = source.read_bytes()

            defective = self._execute(root)

            self.assertEqual(defective["capability_status"], "BLOCK_TECHNICAL")
            self.assertEqual(defective["exit_code"], 1)
            self.assertIn(
                "F401",
                base64.b64decode(defective["stdout"]["captured_base64"]).decode(),
            )
            self.assertEqual(source.read_bytes(), defective_bytes)

            for index in range(800):
                (root / f"flood_{index:04d}.py").write_text(
                    "import definitely_unused_module\n", encoding="utf-8"
                )
            _git(root, "add", ".")
            _git(root, "commit", "-qm", "output flood")

            flooded = self._execute(root)

            self.assertEqual(flooded["capability_status"], "BLOCK_TECHNICAL")
            self.assertEqual(flooded["termination"], "OUTPUT_LIMIT")
            captured = (
                flooded["stdout"]["captured_bytes"]
                + flooded["stderr"]["captured_bytes"]
            )
            self.assertLessEqual(captured, 65536)

    def _execute(self, root: Path) -> dict[str, object]:
        receipt = _receipt(root)
        plan = compile_execution_plan_v2(
            receipt, capability="lint", adapter_id="python.ruff-check.v1"
        )
        toolchain_binary = Path(os.environ["GOVERNANCE_RUFF_LINUX_BINARY"]).resolve()
        result = execute_ruff_docker(
            plan=plan,
            receipt=receipt,
            target_root=root,
            evaluator_root=root,
            toolchain_binary=toolchain_binary,
        )
        validate_named("execution_result_v2", result)
        self.assertEqual(
            validate_execution_result_v2(result, plan, receipt)["integrity_status"],
            "INTEGRITY_VALID",
        )
        return result


if __name__ == "__main__":
    unittest.main()
