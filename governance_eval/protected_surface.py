from __future__ import annotations


PROTECTED_AUTHORITY_PREFIXES = (
    "governance_eval/",
    "schemas/",
    ".github/actions/",
    ".github/workflows/",
    ".github/governance/",
)
PROTECTED_AUTHORITY_FILES = frozenset(
    {
        "AGENTS.md",
        "TASK.md",
        "pyproject.toml",
        "requirements-governance.lock",
    }
)
PROTECTED_CHECKER_PREFIXES = ("governance_eval/", "schemas/")


def protected_authority_paths(changed: list[str]) -> list[str]:
    normalized = {path.replace("\\", "/").removeprefix("./") for path in changed}
    return sorted(
        path
        for path in normalized
        if path in PROTECTED_AUTHORITY_FILES
        or any(path.startswith(prefix) for prefix in PROTECTED_AUTHORITY_PREFIXES)
    )


def protected_checker_paths(changed: list[str]) -> list[str]:
    return [
        path
        for path in protected_authority_paths(changed)
        if any(path.startswith(prefix) for prefix in PROTECTED_CHECKER_PREFIXES)
    ]
