from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlparse

from governance_eval.github_app_manifest import (
    APP_CLIENT_ID_VARIABLE,
    APP_ID_VARIABLE,
    APP_INSTALLATIONS,
    APP_PERMISSIONS,
    APP_PRIVATE_KEY_SECRET,
    APP_SLUG_VARIABLE,
    GitHubAppManifestError,
    github_app_manifest,
    registration_url,
    validate_github_app_manifest,
    write_registration_files,
)


class GitHubAppManifestTests(unittest.TestCase):
    def test_committed_manifest_is_exact_minimum_profile(self) -> None:
        root = Path(__file__).resolve().parents[1]
        committed = json.loads(
            (root / "templates/verifier/github-app-manifest.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(committed, github_app_manifest())
        validate_github_app_manifest(committed)
        self.assertEqual(
            committed["default_permissions"],
            {
                "actions": "read",
                "checks": "write",
                "contents": "read",
                "metadata": "read",
                "pull_requests": "read",
            },
        )
        self.assertFalse(committed["hook_attributes"]["active"])
        self.assertEqual(committed["callback_urls"], [])
        self.assertEqual(committed["default_events"], [])

    def test_registration_url_prefills_the_same_profile(self) -> None:
        parsed = urlparse(registration_url())
        query = {key: value[-1] for key, value in parse_qs(parsed.query).items()}

        self.assertEqual(parsed.path, "/settings/apps/new")
        self.assertEqual({key: query[key] for key in APP_PERMISSIONS}, APP_PERMISSIONS)
        self.assertEqual(query["public"], "false")
        self.assertEqual(query["webhook_active"], "false")
        self.assertEqual(
            query["webhook_url"],
            "https://github.com/markheck-solutions/governance-verifier",
        )
        self.assertNotIn("callback_urls[]", query)
        self.assertNotIn("events[]", query)

    def test_rejects_any_permission_expansion(self) -> None:
        for permission, level in (
            ("administration", "write"),
            ("contents", "write"),
            ("checks", "read"),
        ):
            with self.subTest(permission=permission):
                manifest = deepcopy(github_app_manifest())
                manifest["default_permissions"][permission] = level
                with self.assertRaises(GitHubAppManifestError):
                    validate_github_app_manifest(manifest)

    def test_writes_manifest_and_registration_url_to_empty_directory(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "registration"
            write_registration_files(output)

            self.assertEqual(
                json.loads((output / "github-app-manifest.json").read_text()),
                github_app_manifest(),
            )
            self.assertEqual(
                (output / "github-app-registration-url.txt").read_text().strip(),
                registration_url(),
            )

    def test_operational_names_are_exact(self) -> None:
        self.assertEqual(APP_PRIVATE_KEY_SECRET, "GOVERNANCE_VERIFIER_APP_PRIVATE_KEY")
        self.assertEqual(APP_CLIENT_ID_VARIABLE, "GOVERNANCE_VERIFIER_CLIENT_ID")
        self.assertEqual(APP_ID_VARIABLE, "GOVERNANCE_VERIFIER_APP_ID")
        self.assertEqual(APP_SLUG_VARIABLE, "GOVERNANCE_VERIFIER_APP_SLUG")
        self.assertEqual(
            APP_INSTALLATIONS,
            (
                "markheck-solutions/governance",
                "markheck-solutions/governance-verifier",
                "markheck-solutions/governance-runtime-disposable-20260721",
            ),
        )


if __name__ == "__main__":
    unittest.main()
