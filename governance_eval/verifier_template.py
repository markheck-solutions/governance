from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Sequence

from governance_eval.github_app_manifest import (
    APP_CLIENT_ID_VARIABLE,
    APP_ID_VARIABLE,
    APP_PRIVATE_KEY_SECRET,
)


GOVERNANCE_SHA_PLACEHOLDER = "__GOVERNANCE_SHA__"
CREATE_APP_TOKEN_SHA = "bcd2ba49218906704ab6c1aa796996da409d3eb1"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class VerifierTemplateError(ValueError):
    pass


def render_verifier_workflow(template: Path, governance_sha: str) -> bytes:
    if not _SHA_RE.fullmatch(governance_sha):
        raise VerifierTemplateError("Governance SHA must be exact lowercase 40-hex")
    try:
        if template.is_symlink():
            raise VerifierTemplateError("verifier workflow template cannot be a link")
        workflow = template.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise VerifierTemplateError(
            "verifier workflow template is unavailable"
        ) from exc
    _validate_common(workflow)
    if workflow.count(GOVERNANCE_SHA_PLACEHOLDER) != 2:
        raise VerifierTemplateError(
            "verifier template must contain two SHA placeholders"
        )
    rendered = workflow.replace(GOVERNANCE_SHA_PLACEHOLDER, governance_sha)
    validate_verifier_workflow(rendered, governance_sha)
    return rendered.encode("utf-8")


def validate_verifier_workflow(workflow: str, governance_sha: str) -> None:
    if not _SHA_RE.fullmatch(governance_sha):
        raise VerifierTemplateError("Governance SHA must be exact lowercase 40-hex")
    _validate_common(workflow)
    if GOVERNANCE_SHA_PLACEHOLDER in workflow or workflow.count(governance_sha) != 2:
        raise VerifierTemplateError(
            "verifier workflow does not bind one exact Governance SHA"
        )


def write_verifier_workflow(
    template: Path, destination: Path, governance_sha: str
) -> None:
    rendered = render_verifier_workflow(template, governance_sha)
    if destination.exists() and destination.is_symlink():
        raise VerifierTemplateError("verifier workflow destination cannot be a link")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(rendered)


def _validate_common(workflow: str) -> None:
    forbidden = (
        "pull_request_target",
        "\n  pull_request:\n",
        "\n  schedule:\n",
        "administration: read",
        "administration: write",
        "contents: write",
        "deployments:",
        "members:",
        "packages:",
        "secrets: inherit",
        "workflows: write",
    )
    if any(value in workflow for value in forbidden):
        raise VerifierTemplateError("verifier workflow contains forbidden authority")
    required = (
        "on:\n  workflow_dispatch:\n",
        "permissions:\n  contents: read\n",
        f"actions/create-github-app-token@{CREATE_APP_TOKEN_SHA}",
        f"vars.{APP_CLIENT_ID_VARIABLE}",
        f"vars.{APP_ID_VARIABLE}",
        f"secrets.{APP_PRIVATE_KEY_SECRET}",
        "permission-actions: read",
        "permission-checks: write",
        "permission-contents: read",
        "permission-metadata: read",
        "permission-pull-requests: read",
        "governance_eval.verifier_pipeline",
        "Verify fresh evidence and publish exact-head App check",
    )
    if any(value not in workflow for value in required):
        raise VerifierTemplateError("verifier workflow contract is incomplete")
    if workflow.count("persist-credentials: false") != 1:
        raise VerifierTemplateError("verifier checkout credentials are unsafe")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render the external verifier workflow"
    )
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--governance-sha", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    write_verifier_workflow(
        arguments.template, arguments.destination, arguments.governance_sha
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
