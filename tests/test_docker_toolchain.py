import hashlib
import json
import shutil
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from governance_eval.docker_toolchain import (
    CERTIFIED_TOOLCHAIN_BUNDLE_ID,
    GIT_BINARY_SHA256,
    GIT_DEB_SIZE,
    GIT_DEB_SHA256,
    GIT_DEB_URL,
    GIT_DEB_VERSION,
    PYTHON_IMAGE,
    ToolchainError,
    create_toolchain_manifest,
    validate_toolchain_manifest,
    verify_toolchain_bundle,
    provision_docker_toolchain,
)
from governance_eval.hashing import sha256_json


class DockerToolchainTests(unittest.TestCase):
    def test_git_runtime_package_is_exactly_pinned(self) -> None:
        self.assertEqual(
            GIT_DEB_URL,
            "https://deb.debian.org/debian/pool/main/g/git/"
            "git_2.39.5-0+deb12u3_amd64.deb",
        )
        self.assertEqual(
            GIT_DEB_SHA256,
            "637a85ddd6247fab13bdd0592f2f39aff04ce4dbf0655d3ab553ac359a38ce6f",
        )
        self.assertEqual(GIT_DEB_VERSION, "1:2.39.5-0+deb12u3")
        self.assertEqual(GIT_DEB_SIZE, 7_264_380)
        self.assertEqual(
            GIT_BINARY_SHA256,
            "2540879925a6881e3877ff7e3330746ba3027b04edf16a3a12dccd1644c4f32d",
        )
        self.assertEqual(
            CERTIFIED_TOOLCHAIN_BUNDLE_ID,
            "e5e7c2334fe38ae759348e64bd1bc609e1772a116f696eb3e973524e32731b03",
        )

    def test_manifest_binds_every_regular_file_and_rejects_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "python/ruff").parent.mkdir()
            (root / "python/ruff").write_bytes(b"ruff")
            git = self._write_fake_git(root)
            with self._fake_git_identity():
                manifest = create_toolchain_manifest(
                    root,
                    lock_sha256="a" * 64,
                    image=PYTHON_IMAGE,
                )
                self.assertEqual(
                    [item["path"] for item in manifest["files"]],
                    ["git/bin/git", "git/bin/git-upload-pack", "python/ruff"],
                )
                self.assertEqual(
                    verify_toolchain_bundle(root, manifest["bundle_id"]), manifest
                )
                git.write_bytes(b"mutated")
                with self.assertRaisesRegex(ToolchainError, "content differs"):
                    verify_toolchain_bundle(root, manifest["bundle_id"])

    def test_manifest_rejects_extra_file_and_self_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "python").mkdir()
            (root / "python/tool").write_bytes(b"tool")
            self._write_fake_git(root)
            with self._fake_git_identity():
                manifest = create_toolchain_manifest(
                    root,
                    lock_sha256="a" * 64,
                    image=PYTHON_IMAGE,
                )
                (root / "extra").write_bytes(b"extra")
                with self.assertRaisesRegex(ToolchainError, "file inventory differs"):
                    verify_toolchain_bundle(root, manifest["bundle_id"])

                (root / "extra").unlink()
                (root / "empty-directory").mkdir()
                with self.assertRaisesRegex(
                    ToolchainError, "directory inventory differs"
                ):
                    verify_toolchain_bundle(root, manifest["bundle_id"])
                (root / "empty-directory").rmdir()
                path = root / "toolchain-manifest.json"
                payload = json.loads(path.read_text(encoding="utf-8"))
                payload["lock_sha256"] = "c" * 64
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(ToolchainError, "bundle id is invalid"):
                    verify_toolchain_bundle(root, manifest["bundle_id"])

    def test_manifest_rejects_invalid_identity_and_impossible_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tool").write_bytes(b"x")
            with self.assertRaisesRegex(ToolchainError, "lock digest"):
                create_toolchain_manifest(
                    root,
                    lock_sha256="bad",
                    image="python@sha256:" + "b" * 64,
                )

            root.joinpath("tool").unlink()
            (root / "python").mkdir()
            (root / "python/tool").write_bytes(b"tool")
            self._write_fake_git(root)
            with self._fake_git_identity():
                valid = create_toolchain_manifest(
                    root,
                    lock_sha256="a" * 64,
                    image=PYTHON_IMAGE,
                )
                impossible = deepcopy(valid)
                impossible["directories"].append("python/tool")
                impossible["directories"].sort()
                impossible["bundle_id"] = ""
                impossible["bundle_id"] = sha256_json(impossible)
                with self.assertRaisesRegex(ToolchainError, "relationships"):
                    validate_toolchain_manifest(impossible)

    def test_manifest_parser_rejects_duplicate_keys_constants_and_oversize(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "toolchain-manifest.json"
            manifest.write_text('{"schema_version":"1.0","schema_version":"1.0"}')
            with self.assertRaisesRegex(ToolchainError, "duplicate key"):
                verify_toolchain_bundle(root, "a" * 64)

            manifest.write_text('{"value":NaN}')
            with self.assertRaisesRegex(ToolchainError, "invalid constant"):
                verify_toolchain_bundle(root, "a" * 64)

            manifest.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(ToolchainError, "size limit"):
                verify_toolchain_bundle(root, "a" * 64)

    def test_nested_manifest_name_is_bound_and_links_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "python/toolchain-manifest.json"
            nested.parent.mkdir()
            nested.write_bytes(b"nested")
            self._write_fake_git(root)
            with self._fake_git_identity():
                manifest = create_toolchain_manifest(
                    root,
                    lock_sha256="a" * 64,
                    image=PYTHON_IMAGE,
                )
                self.assertIn(
                    "python/toolchain-manifest.json",
                    [item["path"] for item in manifest["files"]],
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_bytes(b"target")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symbolic links unavailable on this host")
            with self.assertRaisesRegex(ToolchainError, "link"):
                create_toolchain_manifest(
                    root,
                    lock_sha256="a" * 64,
                    image=PYTHON_IMAGE,
                )

    def test_mount_csv_injection_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            governance_root = Path(tmp) / "governance"
            governance_root.mkdir()
            crafted = Path(f"{governance_root},readonly=false")
            with patch(
                "governance_eval.docker_toolchain._trusted_docker"
            ) as trusted_docker:
                with self.assertRaisesRegex(ToolchainError, "unsafe for Docker"):
                    provision_docker_toolchain(
                        governance_root=governance_root,
                        output_root=crafted,
                        docker_path=Path("docker"),
                        docker_sha256="a" * 64,
                        docker_host="unix:///var/run/docker.sock",
                        protected_roots=(),
                    )

            trusted_docker.assert_not_called()

    def test_preflight_failures_are_toolchain_errors_without_partial_output(
        self,
    ) -> None:
        cases = ("missing-lock", "malformed-lock", "missing-docker", "bad-parent")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                governance = root / "governance"
                governance.mkdir()
                if case == "malformed-lock":
                    (governance / "requirements-governance.lock").write_text(
                        "not-a-hash-locked-requirement\n", encoding="utf-8"
                    )
                elif case in {"missing-docker", "bad-parent"}:
                    shutil.copyfile(
                        Path(__file__).resolve().parents[1]
                        / "requirements-governance.lock",
                        governance / "requirements-governance.lock",
                    )
                output = (
                    root / "missing-parent" / "bundle"
                    if case == "bad-parent"
                    else root / "bundle"
                )
                with self.assertRaises(ToolchainError):
                    provision_docker_toolchain(
                        governance_root=governance,
                        output_root=output,
                        docker_path=root / "missing-docker",
                        docker_sha256="a" * 64,
                        docker_host="unix:///var/run/docker.sock",
                        protected_roots=(),
                    )
                self.assertFalse(output.exists())

    @staticmethod
    def _write_fake_git(root: Path) -> Path:
        binary = root / "git/bin/git"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"git")
        (binary.parent / "git-upload-pack").write_bytes(b"git")
        return binary

    @staticmethod
    def _fake_git_identity():
        digest = hashlib.sha256(b"git").hexdigest()
        return patch.multiple(
            "governance_eval.docker_toolchain",
            GIT_BINARY_SHA256=digest,
            _GIT_RUNTIME_PATHS=("git/bin/git", "git/bin/git-upload-pack"),
        )


if __name__ == "__main__":
    unittest.main()
