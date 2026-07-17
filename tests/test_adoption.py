from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from governance_eval.adoption import (
    ADOPTION_PROOF_PASS,
    CALLER_PATH,
    CONFIG_PATH,
    MANIFEST_PATH,
    REQUIRED_CONTEXTS,
    AdoptionError,
    generate_adoption_bundle,
    prove_adoption,
    validate_adoption_bundle,
)
from governance_eval.hashing import sha256_json
from governance_eval.supportability import load_supportability_config
from governance_eval.cli import main as cli_main


class AdoptionBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            text=True,
            capture_output=True,
            timeout=10,
        ).stdout.strip()

    def test_clean_bundle_is_deterministic_and_exactly_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            first = parent / "first"
            second = parent / "second"
            first_result = self._generate(first)
            second_result = self._generate(second)

            self.assertTrue(first_result["valid"])
            self.assertEqual(first_result["manifest"], second_result["manifest"])
            for relative in (*first_result["manifest"]["files"], MANIFEST_PATH):
                self.assertEqual(
                    (first / relative).read_bytes(), (second / relative).read_bytes()
                )
            caller = (first / CALLER_PATH).read_text(encoding="utf-8")
            self.assertEqual(caller.count(self.sha), 6)
            self.assertEqual(
                first_result["manifest"]["required_contexts"], list(REQUIRED_CONTEXTS)
            )
            self.assertEqual(
                first_result["manifest"]["config_sha256"],
                first_result["manifest"]["files"][CONFIG_PATH],
            )

    def test_bundle_generation_does_not_modify_named_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "target"
            target.mkdir()
            marker = target / "owner-file.txt"
            marker.write_text("unchanged\n", encoding="utf-8")
            before = marker.read_bytes()

            self._generate(parent / "bundle")

            self.assertEqual(marker.read_bytes(), before)
            self.assertEqual([path.name for path in target.iterdir()], [marker.name])

    def test_caller_pin_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            self._generate(bundle)
            caller_path = bundle / CALLER_PATH
            caller = caller_path.read_text(encoding="utf-8")
            caller_path.write_text(
                caller.replace(self.sha, "0" * 40, 1), encoding="utf-8"
            )

            result = validate_adoption_bundle(
                governance_root=self.root, bundle_dir=bundle
            )

            self.assertFalse(result["valid"])
            self.assertIn(
                f"generated file hash mismatch: {CALLER_PATH}", result["errors"]
            )
            self.assertIn(
                "caller differs from exact Governance source", result["errors"]
            )

    def test_config_and_required_context_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            config_bundle = parent / "config"
            self._generate(config_bundle)
            with (config_bundle / CONFIG_PATH).open("a", encoding="utf-8") as handle:
                handle.write("\n")
            config_result = validate_adoption_bundle(
                governance_root=self.root, bundle_dir=config_bundle
            )
            self.assertFalse(config_result["valid"])
            self.assertIn("config_sha256 mismatch", config_result["errors"])

            context_bundle = parent / "context"
            self._generate(context_bundle)
            manifest_path = context_bundle / MANIFEST_PATH
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["required_contexts"][0] = "spoofed context"
            unhashed = {
                key: value
                for key, value in manifest.items()
                if key != "artifact_content_hash"
            }
            manifest["artifact_content_hash"] = sha256_json(unhashed)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            context_result = validate_adoption_bundle(
                governance_root=self.root, bundle_dir=context_bundle
            )
            self.assertFalse(context_result["valid"])
            self.assertIn("required-context mapping mismatch", context_result["errors"])

    def test_invalid_inputs_fail_before_output(self) -> None:
        invalid_shas = ("abc", "A" * 40, "f" * 39, "refs/heads/main")
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            for index, invalid in enumerate(invalid_shas):
                output = parent / f"invalid-{index}"
                with self.assertRaisesRegex(AdoptionError, "40 lowercase hex"):
                    generate_adoption_bundle(
                        governance_root=self.root,
                        repository="owner/repo",
                        governance_sha=invalid,
                        config_source=self.root / CONFIG_PATH,
                        output_dir=output,
                    )
                self.assertFalse(output.exists())
            with self.assertRaisesRegex(AdoptionError, "owner/name"):
                generate_adoption_bundle(
                    governance_root=self.root,
                    repository="not-a-slug",
                    governance_sha=self.sha,
                    config_source=self.root / CONFIG_PATH,
                    output_dir=parent / "invalid-repository",
                )

    def test_existing_output_and_unsupported_config_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            existing = parent / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(AdoptionError, "already exists"):
                self._generate(existing)

            config = json.loads(
                json.dumps(load_supportability_config(self.root / CONFIG_PATH))
            )
            config["ai_review"]["adapter"] = "unsupported_adapter"
            invalid_config = parent / "invalid.json"
            invalid_config.write_text(json.dumps(config), encoding="utf-8")
            output = parent / "invalid-config-output"
            with self.assertRaisesRegex(AdoptionError, "config invalid"):
                generate_adoption_bundle(
                    governance_root=self.root,
                    repository="owner/repo",
                    governance_sha=self.sha,
                    config_source=invalid_config,
                    output_dir=output,
                )
            self.assertFalse(output.exists())

    def test_caller_condition_mutation_fails_even_with_updated_file_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            self._generate(bundle)
            caller_path = bundle / CALLER_PATH
            caller_path.write_text(
                caller_path.read_text(encoding="utf-8").replace(
                    "github.event.pull_request.base.ref == 'main'",
                    "github.event.pull_request.base.ref != 'main'",
                    1,
                ),
                encoding="utf-8",
            )
            manifest_path = bundle / MANIFEST_PATH
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            from governance_eval.hashing import sha256_file

            manifest["files"][CALLER_PATH] = sha256_file(caller_path)
            unhashed = {
                key: value
                for key, value in manifest.items()
                if key != "artifact_content_hash"
            }
            manifest["artifact_content_hash"] = sha256_json(unhashed)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            result = validate_adoption_bundle(
                governance_root=self.root, bundle_dir=bundle
            )

            self.assertFalse(result["valid"])
            self.assertIn(
                "caller differs from exact Governance source", result["errors"]
            )

    def test_disposable_clean_and_defective_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = Path(tmp) / "adoption-proof"
            result = prove_adoption(
                governance_root=self.root,
                governance_sha=self.sha,
                artifacts_dir=artifacts,
            )
            self.assertEqual(result["decision"], ADOPTION_PROOF_PASS)
            self.assertTrue(result["clean_valid"])
            self.assertFalse(result["defective_valid"])
            self.assertTrue((artifacts / "adoption-proof.json").is_file())

    def test_manifest_paths_and_recorded_pins_are_semantically_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            pins_bundle = parent / "pins"
            self._generate(pins_bundle)
            manifest_path = pins_bundle / MANIFEST_PATH
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["caller_pins"][0] = "0" * 40
            self._rehash_manifest(manifest)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            pins_result = validate_adoption_bundle(
                governance_root=self.root, bundle_dir=pins_bundle
            )
            self.assertFalse(pins_result["valid"])
            self.assertIn(
                "caller_pins must equal the exact Governance SHA six times",
                pins_result["errors"],
            )

            path_bundle = parent / "paths"
            self._generate(path_bundle)
            path_manifest = path_bundle / MANIFEST_PATH
            manifest = json.loads(path_manifest.read_text(encoding="utf-8"))
            manifest["files"]["../../outside.txt"] = "0" * 64
            self._rehash_manifest(manifest)
            path_manifest.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            path_result = validate_adoption_bundle(
                governance_root=self.root, bundle_dir=path_bundle
            )
            self.assertFalse(path_result["valid"])
            self.assertIn("manifest invalid", path_result["errors"][0])

    def test_validate_adoption_cli_returns_pass_and_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            self._generate(bundle)
            args = [
                "validate-adoption",
                "--root",
                str(self.root),
                "--bundle-dir",
                str(bundle),
            ]
            self.assertEqual(cli_main(args), 0)
            (bundle / CALLER_PATH).write_text("tampered\n", encoding="utf-8")
            self.assertEqual(cli_main(args), 1)

    def _generate(self, output: Path) -> dict:
        return generate_adoption_bundle(
            governance_root=self.root,
            repository="owner/repo",
            governance_sha=self.sha,
            config_source=self.root / CONFIG_PATH,
            output_dir=output,
        )

    @staticmethod
    def _rehash_manifest(manifest: dict) -> None:
        unhashed = {
            key: value
            for key, value in manifest.items()
            if key != "artifact_content_hash"
        }
        manifest["artifact_content_hash"] = sha256_json(unhashed)


if __name__ == "__main__":
    unittest.main()
