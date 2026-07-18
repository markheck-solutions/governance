from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path


class TrustedCommandError(ValueError):
    pass


PROTECTED_PYTHON_MODULES = frozenset(
    {"build", "compileall", "mypy", "pip", "pyright", "ruff"}
)


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return command.split()


def bind_current_python(command: str) -> str:
    leading, word_end, executable = _leading_static_shell_word(command)
    trusted_names = {"python", "python.exe"}
    if executable.casefold() not in trusted_names:
        return command
    if not sys.executable:
        raise TrustedCommandError("trusted Python interpreter path is unavailable")
    if os.name == "nt":
        executable = _quote_windows_shell_token(sys.executable)
    else:
        executable = shlex.quote(sys.executable)
    return leading + executable + _safe_python_module_path(command[word_end:])


def run_bound_shell_command(
    command: str, cwd: Path
) -> subprocess.CompletedProcess[str]:
    try:
        bound_command = bind_current_python(command)
    except TrustedCommandError as exc:
        return subprocess.CompletedProcess(
            args=command,
            returncode=2,
            stdout="",
            stderr=f"trusted command rejected: {exc}",
        )
    env = (
        _trusted_governance_env()
        if _uses_trusted_governance_module(bound_command)
        else None
    )
    return subprocess.run(
        bound_command,
        cwd=cwd,
        env=env,
        shell=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=1200,
    )


def _safe_python_module_path(rest: str) -> str:
    match = re.match(r"(\s+)(-m\s+)([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\b", rest)
    if not match or not _is_protected_python_module(match.group(3)):
        return rest
    return f"{match.group(1)}-P {rest[match.start(2) :]}"


def _is_protected_python_module(module: str) -> bool:
    normalized = module.casefold()
    return normalized in PROTECTED_PYTHON_MODULES or normalized.startswith(
        "governance_eval"
    )


def _quote_windows_shell_token(token: str) -> str:
    quoted = subprocess.list2cmdline([token])
    if quoted == token and re.search(r'[&()<>^|%!" ]', token):
        return '"' + token.replace('"', r"\"") + '"'
    return quoted


def _dynamic_executable_token_is_not_trusted(executable: str, rest: str) -> bool:
    lowered = executable.casefold()
    tail = rest.lstrip().casefold()
    return "python" in lowered or tail.startswith(("-m ", "-c "))


def _uses_trusted_governance_module(command: str) -> bool:
    return bool(re.search(r"(?:^|\s)-P\s+-m\s+governance_eval\b", command))


def _trusted_governance_env() -> dict[str, str]:
    env = os.environ.copy()
    root = str(Path(__file__).resolve().parents[1])
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = root if not current else root + os.pathsep + current
    return env


def _leading_static_shell_word(command: str) -> tuple[str, int, str]:
    index = 0
    while index < len(command) and command[index] in " \t":
        index += 1
    leading = command[:index]
    word: list[str] = []
    quote = ""
    dynamic_seen = False
    dynamic = "$`" + ("%!" if os.name == "nt" else "")
    controls = "&|;<>()"
    while index < len(command):
        char = command[index]
        if not quote and (char in " \t" or char in controls):
            break
        if char in "'\"":
            if not quote:
                quote = char
                index += 1
                continue
            if quote == char:
                quote = ""
                index += 1
                continue
        if char in dynamic and quote != "'":
            if char == "`":
                raise TrustedCommandError(
                    "dynamic shell executable token is not trusted"
                )
            dynamic_seen = True
        posix_escape = (
            os.name != "nt"
            and char == "\\"
            and (
                not quote
                or (
                    quote == '"'
                    and index + 1 < len(command)
                    and command[index + 1] in '$`"\\\n'
                )
            )
        )
        escape = posix_escape or (os.name == "nt" and char == "^" and not quote)
        if escape:
            index += 1
            if index >= len(command):
                raise TrustedCommandError("shell executable token ends with an escape")
            char = command[index]
        word.append(char)
        index += 1
    if quote:
        raise TrustedCommandError("shell executable token has an unclosed quote")
    executable = "".join(word)
    if dynamic_seen and _dynamic_executable_token_is_not_trusted(
        executable, command[index:]
    ):
        raise TrustedCommandError("dynamic shell executable token is not trusted")
    return leading, index, executable
