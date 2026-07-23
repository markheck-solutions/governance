from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Sequence


GOVERNANCE_SHA_PLACEHOLDER = "__GOVERNANCE_SHA__"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_ACTION_PINS = {
    "actions/checkout": "df4cb1c069e1874edd31b4311f1884172cec0e10",
    "actions/setup-python": "ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/upload-artifact": "b7c566a772e6b6bfb58ed0dc250532a479d7789f",
}


class AdopterTemplateError(ValueError):
    pass


def render_candidate_workflow(template: Path, governance_sha: str) -> bytes:
    if not _SHA_RE.fullmatch(governance_sha):
        raise AdopterTemplateError("Governance SHA must be exact lowercase 40-hex")
    try:
        if template.is_symlink():
            raise AdopterTemplateError("candidate workflow template cannot be a link")
        source = template.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AdopterTemplateError(
            "candidate workflow template is unavailable"
        ) from exc
    _validate_template(source)
    rendered = source.replace(GOVERNANCE_SHA_PLACEHOLDER, governance_sha)
    validate_candidate_workflow(rendered, governance_sha)
    return rendered.encode("utf-8")


def write_candidate_workflow(
    template: Path, destination: Path, governance_sha: str
) -> None:
    rendered = render_candidate_workflow(template, governance_sha)
    if destination.exists() and destination.is_symlink():
        raise AdopterTemplateError("candidate workflow destination cannot be a link")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(rendered)


def validate_candidate_workflow(workflow: str, governance_sha: str) -> None:
    if not _SHA_RE.fullmatch(governance_sha):
        raise AdopterTemplateError("Governance SHA must be exact lowercase 40-hex")
    _validate_common_contract(workflow)
    if GOVERNANCE_SHA_PLACEHOLDER in workflow:
        raise AdopterTemplateError(
            "candidate workflow still contains a SHA placeholder"
        )
    required = (
        f"          ref: {governance_sha}",
        f'            --evaluator-sha "{governance_sha}"',
    )
    if any(workflow.count(value) != 1 for value in required):
        raise AdopterTemplateError(
            "candidate workflow does not bind one exact Governance SHA"
        )


def _validate_template(workflow: str) -> None:
    _validate_common_contract(workflow)
    if workflow.count(GOVERNANCE_SHA_PLACEHOLDER) != 2:
        raise AdopterTemplateError(
            "candidate template must contain exactly two SHA placeholders"
        )


def _validate_common_contract(workflow: str) -> None:
    forbidden = (
        "pull_request_target",
        "workflow_run:",
        "checks: write",
        "statuses: write",
        "secrets.",
        "GOVERNANCE_VERIFIER_APP_PRIVATE_KEY",
        "check-runs",
        "docker.sock",
    )
    if any(value in workflow for value in forbidden):
        raise AdopterTemplateError("candidate workflow contains forbidden authority")
    if "on:\n  pull_request:\n" not in workflow:
        raise AdopterTemplateError("candidate workflow must use pull_request")
    if "permissions:\n  contents: read\n" not in workflow:
        raise AdopterTemplateError("candidate workflow permissions are not read-only")
    if workflow.count("permissions:") != 1:
        raise AdopterTemplateError("candidate workflow has ambiguous permissions")
    if '          GH_TOKEN: ""\n          GITHUB_TOKEN: ""' not in workflow:
        raise AdopterTemplateError("candidate execution tokens are not cleared")
    if workflow.count("persist-credentials: false") != 2:
        raise AdopterTemplateError("candidate checkouts must discard credentials")
    for action, commit_sha in _ACTION_PINS.items():
        expected = f"uses: {action}@{commit_sha}"
        if workflow.count(expected) != 1 + (action == "actions/checkout"):
            raise AdopterTemplateError(f"{action} is not exactly pinned")
    required = (
        'python-version: "3.12.13"',
        "--require-hashes",
        "--only-binary=:all:",
        "git -C .governance/evaluator archive --format=tar HEAD",
        "governance_eval.candidate_pipeline",
        '--toolchain-root "$runtime"',
        '--workflow-path ".github/workflows/governance-candidate.yml"',
        "Upload untrusted candidate evidence",
    )
    if any(value not in workflow for value in required):
        raise AdopterTemplateError("candidate workflow contract is incomplete")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render an exact-SHA adopter workflow")
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--governance-sha", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    write_candidate_workflow(
        arguments.template, arguments.destination, arguments.governance_sha
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
