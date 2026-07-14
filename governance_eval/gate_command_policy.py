from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Any


REQUIRED_COMMAND_GATES = (
    "lint",
    "format_check",
    "typecheck",
    "complexity",
    "architecture",
    "tests",
    "compile_or_build",
)
OPTIONAL_COMMAND_GATES = ("package_audit",)
ALL_COMMAND_GATES = (
    REQUIRED_COMMAND_GATES + OPTIONAL_COMMAND_GATES + ("sql_supportability",)
)
PRODUCTION_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".sql",
    ".ps1",
    ".sh",
    ".go",
    ".rs",
    ".java",
    ".cs",
}
NON_BLOCKING_MARKERS = (
    "|| true",
    "|| :",
    "continue-on-error",
    "--exit-zero",
    "exit 0",
)
SCOPE_NARROWING_MARKERS = (
    "--changed",
    "--staged",
    "--since",
    "--only",
    "--grep",
    "--filter",
    "--include",
    "--exclude",
    "--ignore-pattern",
    "--ignore-path",
)
THRESHOLD_WEAKENING_MARKERS = (
    "--extend-ignore",
    "--ignore",
    "--disable",
    "--max-warnings=-1",
    "--pass-with-no-tests",
)
RUNNER = r"(?:(?:uv|poetry|pipenv)\s+run\s+)?"
JS_RUNNER = r"(?:npx\s+|pnpm\s+(?:exec\s+)?|yarn\s+)?"
REQUIRED_SEMANTICS = {
    "lint": (
        RUNNER + r"(?:python\s+-m\s+)?ruff\s+check\b",
        RUNNER + JS_RUNNER + r"(?:eslint|biome\s+check)\b",
        r"(?:golangci-lint|cargo\s+clippy|dotnet\s+format)\b",
        r"(?:mvn|gradle)\b.*\bcheckstyle\b",
    ),
    "format_check": (
        RUNNER + r"(?:python\s+-m\s+)?(?:ruff\s+format|black)\s+--check\b",
        RUNNER + JS_RUNNER + r"(?:prettier\s+--check|biome\s+format)\b",
        r"(?:cargo\s+fmt|gofmt|dotnet\s+format\s+--verify-no-changes)\b",
    ),
    "typecheck": (
        RUNNER + r"(?:python\s+-m\s+)?(?:mypy|pyright)\b",
        RUNNER + JS_RUNNER + r"tsc\s+--noemit\b",
        r"(?:cargo\s+check|go\s+vet|dotnet\s+build)\b",
        r"(?:mvn|gradle)\b.*\bcompile\b",
    ),
    "complexity": (
        RUNNER
        + r"(?:python\s+-m\s+)?ruff\s+check\b.*(?:--select(?:=|\s+)C901|--extend-select(?:=|\s+)C901)",
        RUNNER + r"(?:python\s+-m\s+)?xenon\b.*--max-absolute(?:=|\s+)[AB]\b",
        r"golangci-lint\s+run\b",
        RUNNER + JS_RUNNER + r"eslint\b.*\bcomplexity\b",
        RUNNER + r"python\s+(?:-m\s+)?\S*(?:complexity|cyclomatic|mccabe)\S*",
        r"(?:pwsh|powershell|bash|sh|node)\s+\S*(?:complexity|cyclomatic|mccabe)\S*",
        r"(?:npm|pnpm|yarn)\s+(?:run\s+)?\S*(?:complexity|cyclomatic|mccabe)\S*",
    ),
    "architecture": (RUNNER + r"python\s+-m\s+governance_eval\s+architecture-gate\b",),
    "tests": (
        RUNNER + r"python\s+-m\s+(?:pytest|unittest)\b",
        RUNNER + r"pytest\b",
        r"(?:npm|pnpm|yarn)\s+(?:run\s+)?test\b",
        JS_RUNNER + r"(?:vitest|jest)\b",
        r"(?:go|cargo|dotnet|mvn|gradle)\s+test\b",
    ),
    "compile_or_build": (
        RUNNER + r"python\s+-m\s+build\b",
        r"(?:npm|pnpm|yarn)\s+(?:run\s+)?build\b",
        r"(?:go|cargo|dotnet)\s+build\b",
        r"mvn\b.*\bpackage\b",
        r"gradle\b.*\bbuild\b",
    ),
}
PACKAGE_AUDIT_MARKERS = (
    RUNNER + r"(?:python\s+-m\s+)?pip\s+check\b",
    r"(?:npm|pnpm|yarn|cargo)\s+audit\b",
    r"(?:govulncheck|osv-scanner)\b",
    r"dotnet\s+list\b.*\bpackage\b",
)
SQL_CAPABILITY_MARKERS = (
    RUNNER + r"(?:python\s+-m\s+)?(?:sqlfluff|sqlglot|sqlfmt|sqlcheck)\b",
    r"(?:psql|sqlite3|mysql|sqlcmd|flyway|liquibase|dbt|alembic|prisma)\b",
    RUNNER + r"python\s+-m\s+governance_eval\s+sql-gate\b",
    RUNNER + r"python\s+(?:-m\s+)?\S*(?:sql|database|migration|schema)\S*",
    r"(?:pwsh|powershell|bash|sh|node)\s+\S*(?:sql|database|migration|schema)\S*",
    RUNNER + r"(?:python\s+-m\s+)?pytest\b.*(?:sql|database|migration|schema)",
    r"(?:npm|pnpm|yarn)\s+(?:run\s+)?\S*(?:sql|database|migration|schema)\S*",
)


def required_gate_transition_errors(
    base_gates: Any, gates: dict[str, Any], *, scope_roots: tuple[str, ...] = ()
) -> list[str]:
    gate_commands = [
        (gate, command)
        for gate in ALL_COMMAND_GATES
        for command in command_list(gates.get(gate))
    ]
    commands = [command for _, command in gate_commands]
    errors = duplicate_gate_command_errors(commands)
    errors.extend(_required_capability_errors(base_gates, gates))
    errors.extend(
        _changed_capability_errors(
            "package_audit", base_gates, gates, PACKAGE_AUDIT_MARKERS
        )
    )
    errors.extend(
        _changed_capability_errors(
            "sql_supportability", base_gates, gates, SQL_CAPABILITY_MARKERS
        )
    )
    errors.extend(gate_command_safety_errors(gate_commands, scope_roots))
    return errors


def _required_capability_errors(base_gates: Any, gates: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for gate, markers in REQUIRED_SEMANTICS.items():
        errors.extend(_changed_capability_errors(gate, base_gates, gates, markers))
    return errors


def _changed_capability_errors(
    gate: str,
    base_gates: Any,
    gates: dict[str, Any],
    markers: tuple[str, ...],
) -> list[str]:
    commands = command_list(gates.get(gate))
    base_commands = (
        command_list(base_gates.get(gate)) if isinstance(base_gates, dict) else []
    )
    if commands == base_commands or not commands:
        return []
    if any(command_invokes_capability(command, markers) for command in commands):
        return []
    return [f"required_gates.{gate} lacks required capability semantics"]


def duplicate_gate_command_errors(commands: list[str]) -> list[str]:
    identities = [normalized_command_identity(command) for command in commands]
    duplicates = sorted(
        {identity for identity in identities if identities.count(identity) > 1}
    )
    return [
        "required gate command duplicated across capabilities: " + " ".join(identity)
        for identity in duplicates
    ]


def normalized_command_identity(command: str) -> tuple[str, ...]:
    return tuple(token.casefold() for token in split_command(command))


def gate_command_safety_errors(
    gate_commands: list[tuple[str, str]], scope_roots: tuple[str, ...]
) -> list[str]:
    errors: list[str] = []
    for gate, command in gate_commands:
        errors.extend(_single_transition_command_errors(gate, command, scope_roots))
    return errors


def _single_transition_command_errors(
    gate: str, command: str, scope_roots: tuple[str, ...]
) -> list[str]:
    lowered = command.lower()
    tokens = {token.lower() for token in split_command(command)}
    errors: list[str] = []
    if any(
        marker in command for marker in (";", "|", ">", "<", "&", "`", "$(", "\n", "\r")
    ):
        errors.append(f"required gate command contains shell control syntax: {command}")
    if tokens & {
        "--help",
        "-h",
        "--version",
        "--collect-only",
        "--list",
        "--list-tests",
        "--dry-run",
        "--no-run",
    }:
        errors.append(f"required gate command uses non-execution mode: {command}")
    if any(marker in lowered for marker in NON_BLOCKING_MARKERS):
        errors.append(f"required gate command is non-blocking: {command}")
    if any(marker in lowered for marker in SCOPE_NARROWING_MARKERS):
        errors.append(f"required gate command narrows scope: {command}")
    if gate in {
        "lint",
        "format_check",
        "typecheck",
        "complexity",
    } and positional_scope_narrowing(command, scope_roots):
        errors.append(
            f"required gate command uses positional scope narrowing: {command}"
        )
    if weakens_threshold(lowered):
        errors.append(f"required gate command weakens thresholds: {command}")
    return errors


def positional_scope_narrowing(command: str, scope_roots: tuple[str, ...] = ()) -> bool:
    tokens = split_command(command)
    entrypoints = command_entrypoint_indexes(tokens)
    scopes = [
        normalize_scope(token)
        for index, token in enumerate(tokens)
        if index not in entrypoints and looks_like_scope_token(token, scope_roots)
    ]
    return bool(scopes) and "." not in scopes


def command_entrypoint_indexes(tokens: list[str]) -> set[int]:
    interpreters = {"python", "python3", "node", "pwsh", "powershell", "bash", "sh"}
    for index, token in enumerate(tokens):
        if token.casefold() not in interpreters:
            continue
        module_offset = 2 if tokens[index + 1 : index + 2] == ["-m"] else 1
        entrypoint_index = index + module_offset
        return {entrypoint_index} if entrypoint_index < len(tokens) else set()
    return set()


def command_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value] if isinstance(value, list) else []


def command_invokes_capability(command: str, patterns: tuple[str, ...]) -> bool:
    normalized = command.strip()
    return any(
        re.match(pattern, normalized, flags=re.IGNORECASE) for pattern in patterns
    )


def weakens_threshold(lowered: str) -> bool:
    if any(marker in lowered for marker in THRESHOLD_WEAKENING_MARKERS):
        return True
    match = re.search(r"max[-_]complexity[=\s]+([0-9]+)", lowered)
    return bool(match and int(match.group(1)) > 10)


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return command.split()


def looks_like_scope_token(token: str, scope_roots: tuple[str, ...] = ()) -> bool:
    clean = token.strip("'\"")
    if clean in {".", "./"}:
        return True
    if clean.startswith("-") or "=" in clean or "*" in clean:
        return False
    if "/" in clean or "\\" in clean:
        return True
    normalized = normalize_scope(clean).casefold()
    normalized_roots = {normalize_scope(root).casefold() for root in scope_roots}
    if normalized in normalized_roots:
        return True
    return Path(clean).suffix in PRODUCTION_SUFFIXES or clean in {"src", "app", "lib"}


def normalize_scope(token: str) -> str:
    clean = token.strip("'\"").replace("\\", "/").rstrip("/")
    if clean in {"", ".", "./", "...", "./..."}:
        return "."
    return clean[2:] if clean.startswith("./") else clean
