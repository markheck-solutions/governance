from __future__ import annotations

import re
import sys
from collections import deque
from hashlib import sha256
from pathlib import Path


STANDARD_EVENT_NAMES = frozenset({"pull_request_target"})

_PERMISSION_RANK = {"none": 0, "read": 1, "write": 2}
_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_REMOTE_CALL = re.compile(
    r"^    uses:\s+markheck-solutions/governance/\.github/workflows/"
    r"(?P<path>[A-Za-z0-9_.-]+\.ya?ml)@(?P<ref>\S+)\s*$"
)
_LOCAL_CALL = re.compile(
    r"^    uses:\s+\./\.github/workflows/"
    r"(?P<path>[A-Za-z0-9_.-]+\.ya?ml)\s*$"
)
_SOURCE_WORKFLOW_SHA256 = (
    "f14453327e5a77f3c2433498487f3a19efa124273a265101b0ed50c99e0c8c9a"
)
_SOURCE_CANDIDATE_WORKFLOW_SHA256 = (
    "729a13276949ce97b108c9638a4bacecf441b42e1a1e623bf7846486ed50bff8"
)
_STANDARD_VALIDATION_SHA256 = (
    "dfcea58955a4a12c8992a9655f7e9d9fb0ce1486daf6e89bde57507bd9515fe4"
)
_READ_PERMISSION_KEYS = frozenset({"actions", "checks", "contents", "pull-requests"})
_TRUSTED_SOURCE_AUTHORITY_PATHS = (
    ".github/workflows/source-candidate.yml",
    ".github/workflows/source-qualification.yml",
    "governance_eval/source_qualification.py",
    "governance_eval/workflow_contract.py",
    "pyproject.toml",
    "requirements-governance.lock",
)
_LITERAL_JOB_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,119}")
_USES_KEY = re.compile(r"(?<![A-Za-z0-9_-])['\"]?uses['\"]?\s*:")
_USES_LINE = re.compile(r"\s*(?:-\s+)?uses:\s+(\S+)\s*")
_LOCAL_USE = re.compile(
    r"\./\.github/actions/"
    r"(?!\.{1,2}(?:/|$))[A-Za-z0-9_.-]+"
    r"(?:/(?!\.{1,2}(?:/|$))[A-Za-z0-9_.-]+)*"
)
_REMOTE_USE = re.compile(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}"
)
_DOCKER_USE = re.compile(r"docker://[^@\s]+@sha256:[0-9a-f]{64}")
_BLOCK_SCALAR = re.compile(
    r"\s*(?:-\s+)?[A-Za-z0-9_-]+:\s*[>|](?:[1-9][+-]?|[+-][1-9]?)?(?:\s+#.*)?"
)
_QUOTED_YAML_KEY = re.compile(r"(?:^\s*(?:-\s*)?|\{\s*|,\s*)['\"][^'\"]*['\"]\s*:")
_QUOTED_YAML_START = re.compile(r"^\s*(?:-\s*)?['\"]|\{\s*['\"]")
_EXPLICIT_YAML_KEY = re.compile(r"^\s*(?:-\s*)?\?")
_TAGGED_YAML_KEY = re.compile(r"(?:^\s*(?:-\s*)?|\{\s*|,\s*)(?:!!|!<)")
_YAML_ANCHOR_OR_ALIAS = re.compile(r"(?:^|[\s:\[,{])(?:&(?!&)|\*(?!\*))[^\s\[\]{},]+")


def _job_blocks(workflow: str) -> dict[str, list[str]]:
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    in_jobs = False
    for line in workflow.splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if not in_jobs:
            continue
        job = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
        if job is not None:
            current = job.group(1)
            blocks[current] = [line]
            continue
        if current is not None:
            if line and not line.startswith(" ") and not line.lstrip().startswith("#"):
                break
            blocks[current].append(line)
    return blocks


def _inline_permission_mapping(inline: str) -> dict[str, str]:
    if inline == "{}":
        return {}
    if not (inline.startswith("{") and inline.endswith("}")):
        return {}
    parsed: dict[str, str] = {}
    for item in inline[1:-1].split(","):
        match = re.fullmatch(r"\s*([a-z-]+):\s*(none|read|write)\s*", item)
        if match is None:
            return {}
        permission = match.group(1)
        if permission in parsed:
            return {}
        parsed[permission] = match.group(2)
    return parsed


def _block_permission_mapping(
    lines: list[str], start: int, indent: int
) -> dict[str, str]:
    mapping: dict[str, str] = {}
    entry = re.compile(rf"^\s{{{indent + 2}}}([a-z-]+):\s*(none|read|write)\s*$")
    for line in lines[start + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = entry.fullmatch(line)
        if match is not None:
            permission = match.group(1)
            if permission in mapping:
                return {}
            mapping[permission] = match.group(2)
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break
    return mapping


def _permission_mapping(lines: list[str], indent: int) -> dict[str, str] | None:
    marker = re.compile(rf"^\s{{{indent}}}permissions:\s*(.*?)\s*$")
    matches = [
        (index, match.group(1))
        for index, line in enumerate(lines)
        if (match := marker.fullmatch(line)) is not None
    ]
    if not matches:
        return None
    if len(matches) != 1:
        return {}
    start, inline = matches[0]
    if inline:
        return _inline_permission_mapping(inline)
    return _block_permission_mapping(lines, start, indent)


def _inline_permission_syntax_is_valid(inline: str) -> bool:
    if inline == "{}":
        return True
    if not (inline.startswith("{") and inline.endswith("}")):
        return False
    seen: set[str] = set()
    for item in inline[1:-1].split(","):
        match = re.fullmatch(r"\s*([a-z-]+):\s*(none|read|write)\s*", item)
        if match is None or match.group(1) in seen:
            return False
        seen.add(match.group(1))
    return True


def _block_permission_syntax_is_valid(
    lines: list[str], start: int, indent: int
) -> bool:
    entry = re.compile(rf"^\s{{{indent + 2}}}([a-z-]+):\s*(none|read|write)\s*$")
    found_entry = False
    seen: set[str] = set()
    for line in lines[start + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break
        match = entry.fullmatch(line)
        if match is None or match.group(1) in seen:
            return False
        seen.add(match.group(1))
        found_entry = True
    return found_entry


def _permission_syntax_errors(lines: list[str], indent: int, label: str) -> list[str]:
    marker = re.compile(rf"^\s{{{indent}}}permissions:\s*(.*?)\s*$")
    matches = [
        (index, match.group(1))
        for index, line in enumerate(lines)
        if (match := marker.fullmatch(line)) is not None
    ]
    if not matches:
        return []
    if len(matches) != 1:
        return [f"permission declaration is duplicated: {label}"]
    start, inline = matches[0]
    valid = (
        _inline_permission_syntax_is_valid(inline)
        if inline
        else _block_permission_syntax_is_valid(lines, start, indent)
    )
    return [] if valid else [f"permission declaration is malformed: {label}"]


def _permission_authority_errors(
    mapping: dict[str, str] | None, workflow: str, scope: str
) -> list[str]:
    errors: list[str] = []
    for permission, level in sorted((mapping or {}).items()):
        safe_read = permission in _READ_PERMISSION_KEYS and level in {"none", "read"}
        safe_issue_write = (
            workflow == "supportability-enforcement.yml"
            and scope == "request-codex-review"
            and permission == "issues"
            and level == "write"
        )
        if not safe_read and not safe_issue_write:
            errors.append(
                "workflow permission exceeds the source authority ceiling: "
                f"{workflow}:{scope} {permission}: {level}"
            )
    return errors


def permission_scope_errors(repository: Path) -> list[str]:
    errors: list[str] = []
    workflow_root = repository / ".github" / "workflows"
    for path in sorted(workflow_root.glob("*.y*ml")):
        workflow = path.read_text(encoding="utf-8")
        header = workflow.split("\njobs:", 1)[0].splitlines()
        errors.extend(_permission_syntax_errors(header, 0, f"{path.name}:workflow"))
        workflow_permissions = _permission_mapping(header, 0)
        if workflow_permissions is None:
            errors.append(
                f"workflow permission declaration is missing: {path.name}:workflow"
            )
        errors.extend(
            _permission_authority_errors(workflow_permissions, path.name, "workflow")
        )
        for job_name, block in _job_blocks(workflow).items():
            errors.extend(
                _permission_syntax_errors(block, 4, f"{path.name}:{job_name}")
            )
            errors.extend(
                _permission_authority_errors(
                    _permission_mapping(block, 4), path.name, job_name
                )
            )
    return errors


def trusted_source_authority_errors(repository: Path) -> list[str]:
    trusted_root = Path(__file__).resolve().parents[1]
    candidate_root = repository.absolute()
    if candidate_root == trusted_root:
        return []
    errors: list[str] = []
    for relative_path in _TRUSTED_SOURCE_AUTHORITY_PATHS:
        trusted = trusted_root / relative_path
        candidate = candidate_root / relative_path
        authority_parts = relative_path.split("/")
        trusted_parts = [
            trusted_root.joinpath(*authority_parts[:index])
            for index in range(1, len(authority_parts) + 1)
        ]
        candidate_parts = [
            candidate_root.joinpath(*authority_parts[:index])
            for index in range(1, len(authority_parts) + 1)
        ]
        if any(path.is_symlink() for path in (*trusted_parts, *candidate_parts)):
            errors.append(
                f"trusted source authority path contains a symlink: {relative_path}"
            )
        elif not trusted.is_file() or not candidate.is_file():
            errors.append(f"trusted source authority file is missing: {relative_path}")
        elif candidate.read_bytes() != trusted.read_bytes():
            errors.append(f"trusted source authority file changed: {relative_path}")
    return errors


def _top_level_permissions(workflow: str) -> dict[str, str]:
    header = workflow.split("\njobs:", 1)[0]
    return _permission_mapping(header.splitlines(), 0) or {}


def _required_permissions(workflow: str) -> dict[str, str]:
    required = dict(_top_level_permissions(workflow))
    for block in _job_blocks(workflow).values():
        for permission, level in (_permission_mapping(block, 4) or {}).items():
            if _PERMISSION_RANK[level] > _PERMISSION_RANK.get(
                required.get(permission, "none"), 0
            ):
                required[permission] = level
    return required


def _call_sites(
    workflow: str,
) -> tuple[list[tuple[str, str, str | None, dict[str, str]]], list[str]]:
    top_permissions = _top_level_permissions(workflow)
    calls: list[tuple[str, str, str | None, dict[str, str]]] = []
    malformed: list[str] = []
    for job_name, block in _job_blocks(workflow).items():
        effective = _permission_mapping(block, 4)
        effective_permissions = top_permissions if effective is None else effective
        call_lines = [
            line
            for line in block
            if re.match(r"^    uses:\s+.*\.github/workflows/", line)
        ]
        for line in call_lines:
            remote = _REMOTE_CALL.fullmatch(line)
            local = _LOCAL_CALL.fullmatch(line)
            if remote is not None:
                calls.append(
                    (
                        job_name,
                        remote.group("path"),
                        remote.group("ref"),
                        effective_permissions,
                    )
                )
            elif local is not None:
                calls.append(
                    (job_name, local.group("path"), None, effective_permissions)
                )
            else:
                malformed.append(f"{job_name}: {line.strip()}")
    return calls, malformed


def reusable_permission_closure_errors(
    repository: Path,
    entry_workflow: str | None = None,
) -> list[str]:
    workflow_root = repository / ".github" / "workflows"
    initial = (
        [entry_workflow]
        if entry_workflow is not None
        else sorted(
            path.name
            for pattern in ("*.yml", "*.yaml")
            for path in workflow_root.glob(pattern)
        )
    )
    pending = deque(initial)
    visited: set[str] = set()
    errors: list[str] = []
    while pending:
        caller_name = pending.popleft()
        if caller_name in visited:
            continue
        visited.add(caller_name)
        caller_path = workflow_root / caller_name
        if not caller_path.is_file():
            errors.append(f"workflow is missing: {caller_name}")
            continue
        caller_text = caller_path.read_text(encoding="utf-8")
        calls, malformed = _call_sites(caller_text)
        errors.extend(
            f"reusable workflow call is malformed: {caller_name} {item}"
            for item in malformed
        )
        for job_name, callee_name, reference, caller_permissions in calls:
            if reference is None or _FULL_SHA.fullmatch(reference) is None:
                shown = "local candidate workflow" if reference is None else reference
                errors.append(
                    "reusable workflow call is not immutable: "
                    f"{caller_name}:{job_name} -> {callee_name}@{shown}"
                )
            callee_path = workflow_root / callee_name
            if not callee_path.is_file():
                errors.append(
                    f"called workflow is missing: {caller_name} -> {callee_name}"
                )
                continue
            for permission, callee_level in sorted(
                _required_permissions(callee_path.read_text(encoding="utf-8")).items()
            ):
                caller_level = caller_permissions.get(permission, "none")
                if _PERMISSION_RANK[caller_level] < _PERMISSION_RANK[callee_level]:
                    errors.append(
                        "reusable permission ceiling is too low: "
                        f"{caller_name}:{job_name} -> {callee_name} requires "
                        f"{permission}: {callee_level}; caller has {caller_level}"
                    )
            pending.append(callee_name)
    return errors


def _event_names(workflow: str) -> set[str]:
    lines = workflow.splitlines()
    start = next((index for index, line in enumerate(lines) if line == "on:"), None)
    if start is None:
        return set()
    events: set[str] = set()
    for line in lines[start + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            break
        match = re.match(r"^  ([A-Za-z0-9_-]+):(?:\s.*)?$", line)
        if match is not None:
            events.add(match.group(1))
    return events


def _event_block(workflow: str, event_name: str) -> list[str]:
    lines = workflow.splitlines()
    marker = f"  {event_name}:"
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        return []
    start = starts[0]
    block = [marker]
    for line in lines[start + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith("    "):
            break
        block.append(line)
    return block


def _named_step_block(workflow: str, step_name: str) -> list[str]:
    marker = f"      - name: {step_name}"
    lines = workflow.splitlines()
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        return []
    start = starts[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("      - name:")
        ),
        len(lines),
    )
    return lines[start:end]


def _step_run_value(block: list[str]) -> str | None:
    for index, line in enumerate(block):
        match = re.fullmatch(r"        run:\s*(.*?)\s*", line)
        if match is None:
            continue
        value = match.group(1)
        if value not in {"|", ">", "|-", ">-"}:
            return value
        body = [
            candidate[10:] if candidate.startswith(" " * 10) else candidate
            for candidate in block[index + 1 :]
        ]
        return "\n".join(body).rstrip()
    return None


def _has_code_line(source: str, expression: str) -> bool:
    return re.search(rf"(?m)^\s*{re.escape(expression)}\s*$", source) is not None


def standard_event_contract_errors(repository: Path) -> list[str]:
    workflow_root = repository / ".github" / "workflows"
    caller = (workflow_root / "supportability-enforcement.yml").read_text(
        encoding="utf-8"
    )
    gate = (workflow_root / "supportability-gate.yml").read_text(encoding="utf-8")
    evidence = (repository / "governance_eval/codex_connector_evidence.py").read_text(
        encoding="utf-8"
    )
    bootstrap = (repository / "governance_eval/toolchain_bootstrap.py").read_text(
        encoding="utf-8"
    )
    errors: list[str] = []
    events = _event_names(caller)
    if events != set(STANDARD_EVENT_NAMES):
        errors.append(
            "standard caller events are invalid: " + ", ".join(sorted(events))
        )
    expected_event_block = [
        "  pull_request_target:",
        "    branches:",
        "      - main",
        "    types:",
        "      - opened",
        "      - reopened",
        "      - synchronize",
        "      - ready_for_review",
    ]
    if _event_block(caller, "pull_request_target") != expected_event_block:
        errors.append("standard caller pull-request action scope is invalid")
    validation_block = _named_step_block(gate, "Validate workflow inputs")
    validation = _step_run_value(validation_block) or ""
    if sha256(validation.encode()).hexdigest() != _STANDARD_VALIDATION_SHA256:
        errors.append(
            "reusable gate input validation differs from the trusted contract"
        )
    guard = 'if os.environ["REQUEST_EVENT_NAME"] != "pull_request_target":'
    if not _has_code_line(validation, guard):
        errors.append("reusable gate does not enforce the standard event")
    if re.search(r"(?m)^\s*[^#\n]*\bmerge_group\b", validation):
        errors.append("reusable gate still accepts the optional merge-group event")
    evidence_guard = 'if receipt.event_name != "pull_request_target":'
    if not _has_code_line(evidence, evidence_guard):
        errors.append("evidence validator does not enforce the standard event")
    bootstrap_guard = 'if context["event_name"] != "pull_request_target":'
    if not _has_code_line(bootstrap, bootstrap_guard):
        errors.append("toolchain receipt does not enforce the standard event")
    return errors


def _source_header_errors(workflow: str) -> list[str]:
    errors: list[str] = []
    top_name = [
        match.group(1)
        for line in workflow.splitlines()
        if (match := re.fullmatch(r"name:\s*(.*?)\s*", line)) is not None
    ]
    if top_name != ["Governance Source Qualification"]:
        errors.append("source qualification workflow name is not stable")
    if _event_names(workflow) != {"pull_request_target"}:
        errors.append("source qualification trigger is not base-controlled")
    expected_trigger = [
        "  pull_request_target:",
        "    branches:",
        "      - main",
        "    types:",
        "      - opened",
        "      - synchronize",
    ]
    if _event_block(workflow, "pull_request_target") != expected_trigger:
        errors.append("source qualification pull_request_target scope is not exact")
    if _top_level_permissions(workflow) != {"actions": "read", "contents": "read"}:
        errors.append("source qualification permissions are not exact")
    return errors


def _literal_job_name(block: list[str]) -> str | None:
    declarations = [
        match.group(1)
        for line in block
        if not line.lstrip().startswith("#")
        and (match := re.fullmatch(r"    name:\s*(.*?)\s*", line)) is not None
    ]
    if len(declarations) != 1 or _LITERAL_JOB_NAME.fullmatch(declarations[0]) is None:
        return None
    return declarations[0]


def _job_name_contract_errors(repository: Path) -> list[str]:
    errors: list[str] = []
    workflow_root = repository / ".github" / "workflows"
    for path in sorted(workflow_root.glob("*.y*ml")):
        for job_name, block in _job_blocks(path.read_text(encoding="utf-8")).items():
            declarations = [line for line in block if re.match(r"^    name:", line)]
            if declarations and _literal_job_name(block) is None:
                errors.append(
                    f"workflow job name is not a safe literal: {path.name}:{job_name}"
                )
    return errors


def _action_reference_is_immutable(reference: str) -> bool:
    return any(
        pattern.fullmatch(reference) is not None
        for pattern in (_LOCAL_USE, _REMOTE_USE, _DOCKER_USE)
    )


def _local_action_path_errors(
    repository: Path, reference: str, label: str
) -> list[str]:
    action_path = repository
    for part in reference.removeprefix("./").split("/"):
        action_path /= part
        if action_path.is_symlink():
            return [f"local action path contains a symlink: {label} {reference}"]
    if not action_path.is_dir():
        return [f"local action directory is missing: {label} {reference}"]
    manifests = [
        action_path / name
        for name in ("action.yml", "action.yaml")
        if (action_path / name).exists()
    ]
    if len(manifests) != 1 or not manifests[0].is_file():
        return [f"local action manifest is not unique: {label} {reference}"]
    if manifests[0].is_symlink():
        return [f"local action manifest is a symlink: {label} {reference}"]
    return []


def _active_yaml_lines(source: str) -> list[tuple[int, str]]:
    active: list[tuple[int, str]] = []
    block_indent: int | None = None
    for line_number, line in enumerate(source.splitlines(), start=1):
        indent = len(line) - len(line.lstrip())
        if block_indent is not None:
            if not line.strip() or indent > block_indent:
                continue
            block_indent = None
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        active.append((line_number, line))
        if _BLOCK_SCALAR.fullmatch(line) is not None:
            block_indent = indent
    return active


def _action_authority_paths(repository: Path) -> list[Path]:
    workflow_root = repository / ".github" / "workflows"
    action_root = repository / ".github" / "actions"
    paths = list(workflow_root.glob("*.y*ml"))
    for pattern in ("action.yml", "action.yaml"):
        paths.extend(action_root.glob(f"**/{pattern}"))
    return sorted(paths)


def _yaml_key_syntax_is_canonical(line: str) -> bool:
    return not any(
        pattern.search(line) is not None
        for pattern in (
            _QUOTED_YAML_KEY,
            _QUOTED_YAML_START,
            _EXPLICIT_YAML_KEY,
            _TAGGED_YAML_KEY,
            _YAML_ANCHOR_OR_ALIAS,
        )
    )


def _action_pin_errors(repository: Path) -> list[str]:
    errors: list[str] = []
    for path in _action_authority_paths(repository):
        label = path.relative_to(repository).as_posix()
        for line_number, line in _active_yaml_lines(path.read_text(encoding="utf-8")):
            if not _yaml_key_syntax_is_canonical(line):
                errors.append(
                    f"workflow YAML key syntax is not canonical: {label}:{line_number}"
                )
                continue
            if _USES_KEY.search(line) is None:
                continue
            declaration = _USES_LINE.fullmatch(line)
            if declaration is None:
                errors.append(
                    f"workflow action use is not canonical: {label}:{line_number}"
                )
                continue
            reference = declaration.group(1)
            if _LOCAL_USE.fullmatch(reference) is not None:
                errors.extend(
                    _local_action_path_errors(
                        repository, reference, f"{label}:{line_number}"
                    )
                )
            elif not _action_reference_is_immutable(reference):
                errors.append(
                    f"workflow action use is not immutable: {label}:{line_number}"
                )
    return errors


def _top_level_syntax_errors(path: Path, lines: list[str]) -> list[str]:
    top_key = re.compile(r"(?:name|on|permissions|jobs):(?:\s.*)?")
    for line in lines:
        if line.strip() and not line.lstrip().startswith("#"):
            if not line.startswith(" ") and top_key.fullmatch(line) is None:
                return [f"workflow top-level syntax is not canonical: {path.name}"]
    return []


def _jobs_block_syntax_errors(
    path: Path, lines: list[str], jobs_index: int
) -> list[str]:
    errors: list[str] = []
    job_key = re.compile(r"  [A-Za-z0-9_-]+:")
    field_key = re.compile(r"    [A-Za-z0-9_-]+:(?:\s.*)?")
    for line in lines[jobs_index + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 2 and job_key.fullmatch(line) is None:
            errors.append(f"workflow job declaration is not canonical: {path.name}")
        elif indent == 4 and field_key.fullmatch(line) is None:
            errors.append(f"workflow job field is not canonical: {path.name}")
        elif indent < 2:
            errors.append(f"workflow jobs block is not final: {path.name}")
    return errors


def _job_field_indentation_errors(
    path: Path, job_blocks: dict[str, list[str]]
) -> list[str]:
    errors: list[str] = []
    for job_name, block in job_blocks.items():
        fields = [
            line
            for line in block[1:]
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if not fields or len(fields[0]) - len(fields[0].lstrip()) != 4:
            errors.append(
                f"workflow job field indentation is invalid: {path.name}:{job_name}"
            )
    return errors


def _workflow_job_syntax_errors(path: Path, workflow: str) -> list[str]:
    lines = workflow.splitlines()
    jobs_lines = [index for index, line in enumerate(lines) if line == "jobs:"]
    if len(jobs_lines) != 1:
        return [f"workflow jobs declaration is not canonical: {path.name}"]
    errors = _top_level_syntax_errors(path, lines)
    job_blocks = _job_blocks(workflow)
    if not job_blocks:
        errors.append(f"workflow has no canonical job declarations: {path.name}")
    errors.extend(_jobs_block_syntax_errors(path, lines, jobs_lines[0]))
    errors.extend(_job_field_indentation_errors(path, job_blocks))
    return errors


def _all_workflow_job_syntax_errors(repository: Path) -> list[str]:
    workflow_root = repository / ".github" / "workflows"
    errors: list[str] = []
    for path in sorted(workflow_root.glob("*.y*ml")):
        errors.extend(
            _workflow_job_syntax_errors(path, path.read_text(encoding="utf-8"))
        )
    return errors


def _required_context_producers(repository: Path) -> list[tuple[str, str]]:
    producers: list[tuple[str, str]] = []
    workflow_root = repository / ".github" / "workflows"
    for path in sorted(workflow_root.glob("*.y*ml")):
        for job_name, block in _job_blocks(path.read_text(encoding="utf-8")).items():
            if _literal_job_name(block) == "Governance Source Qualification":
                producers.append((path.name, job_name))
    return producers


def source_workflow_contract_errors(repository: Path) -> list[str]:
    workflow_root = repository / ".github" / "workflows"
    path = workflow_root / "source-qualification.yml"
    candidate_path = workflow_root / "source-candidate.yml"
    if not path.is_file() or not candidate_path.is_file():
        return ["source qualification workflow is missing"]
    workflow = path.read_text(encoding="utf-8")
    candidate_workflow = candidate_path.read_text(encoding="utf-8")
    errors = _source_header_errors(workflow)
    errors.extend(_all_workflow_job_syntax_errors(repository))
    errors.extend(_job_name_contract_errors(repository))
    errors.extend(_action_pin_errors(repository))
    if sha256(workflow.encode()).hexdigest() != _SOURCE_WORKFLOW_SHA256:
        errors.append("source qualification workflow differs from the exact allowlist")
    if (
        sha256(candidate_workflow.encode()).hexdigest()
        != _SOURCE_CANDIDATE_WORKFLOW_SHA256
    ):
        errors.append("source candidate workflow differs from the exact allowlist")
    if set(_job_blocks(workflow)) != {"source-qualification"}:
        errors.append("source qualification workflow has unexpected jobs")
    expected_producer = [("source-qualification.yml", "source-qualification")]
    if _required_context_producers(repository) != expected_producer:
        errors.append("source qualification required-context producer is not unique")
    return errors


def validate(repository: Path) -> list[str]:
    errors = trusted_source_authority_errors(repository)
    errors.extend(reusable_permission_closure_errors(repository))
    errors.extend(permission_scope_errors(repository))
    errors.extend(standard_event_contract_errors(repository))
    errors.extend(source_workflow_contract_errors(repository))
    return errors


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd().resolve()
    errors = validate(root)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print("SOURCE_WORKFLOW_CONTRACT_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
