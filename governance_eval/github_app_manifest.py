from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlencode


APP_NAME = "MarkHeck Governance Verifier"
APP_SLUG = "markheck-governance-verifier"
APP_HOMEPAGE = "https://github.com/markheck-solutions/governance-verifier"
APP_DESCRIPTION = (
    "Verifies exact Governance evidence and writes the authoritative PR check."
)
APP_PRIVATE_KEY_SECRET = "GOVERNANCE_VERIFIER_APP_PRIVATE_KEY"
APP_CLIENT_ID_VARIABLE = "GOVERNANCE_VERIFIER_CLIENT_ID"
APP_ID_VARIABLE = "GOVERNANCE_VERIFIER_APP_ID"
APP_SLUG_VARIABLE = "GOVERNANCE_VERIFIER_APP_SLUG"
APP_INSTALLATIONS = (
    "markheck-solutions/governance",
    "markheck-solutions/governance-verifier",
    "markheck-solutions/governance-runtime-disposable-20260721",
)
APP_PERMISSIONS = {
    "actions": "read",
    "checks": "write",
    "contents": "read",
    "metadata": "read",
    "pull_requests": "read",
}
_FORBIDDEN_PERMISSIONS = frozenset(
    {
        "administration",
        "deployments",
        "members",
        "packages",
        "secrets",
        "workflows",
    }
)


class GitHubAppManifestError(ValueError):
    pass


def github_app_manifest() -> dict[str, Any]:
    manifest = {
        "name": APP_NAME,
        "url": APP_HOMEPAGE,
        "description": APP_DESCRIPTION,
        "public": False,
        "hook_attributes": {"url": APP_HOMEPAGE, "active": False},
        "callback_urls": [],
        "default_events": [],
        "default_permissions": dict(APP_PERMISSIONS),
        "request_oauth_on_install": False,
        "setup_on_update": False,
    }
    validate_github_app_manifest(manifest)
    return manifest


def registration_url() -> str:
    parameters: list[tuple[str, str]] = [
        ("name", APP_NAME),
        ("description", APP_DESCRIPTION),
        ("url", APP_HOMEPAGE),
        ("public", "false"),
        ("webhook_active", "false"),
        ("webhook_url", APP_HOMEPAGE),
        ("request_oauth_on_install", "false"),
        ("setup_on_update", "false"),
        *sorted(APP_PERMISSIONS.items()),
    ]
    return f"https://github.com/settings/apps/new?{urlencode(parameters)}"


def validate_github_app_manifest(manifest: Mapping[str, Any]) -> None:
    expected = {
        "name": APP_NAME,
        "url": APP_HOMEPAGE,
        "description": APP_DESCRIPTION,
        "public": False,
        "hook_attributes": {"url": APP_HOMEPAGE, "active": False},
        "callback_urls": [],
        "default_events": [],
        "default_permissions": APP_PERMISSIONS,
        "request_oauth_on_install": False,
        "setup_on_update": False,
    }
    if dict(manifest) != expected:
        raise GitHubAppManifestError("GitHub App manifest differs from minimum profile")
    permissions = manifest["default_permissions"]
    if (
        not isinstance(permissions, Mapping)
        or set(permissions) & _FORBIDDEN_PERMISSIONS
    ):
        raise GitHubAppManifestError("GitHub App manifest grants forbidden permission")
    if permissions.get("contents") != "read" or permissions.get("checks") != "write":
        raise GitHubAppManifestError("GitHub App content/check authority is invalid")


def write_registration_files(output_directory: Path) -> None:
    if output_directory.exists() and (
        output_directory.is_symlink() or any(output_directory.iterdir())
    ):
        raise GitHubAppManifestError("registration output must be new or empty")
    output_directory.mkdir(parents=True, exist_ok=True)
    manifest_bytes = (
        json.dumps(github_app_manifest(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    (output_directory / "github-app-manifest.json").write_bytes(manifest_bytes)
    (output_directory / "github-app-registration-url.txt").write_text(
        registration_url() + "\n", encoding="utf-8"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate the minimum Governance verifier GitHub App registration"
    )
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    write_registration_files(arguments.output_directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
