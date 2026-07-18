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
    {
        "black",
        "build",
        "compileall",
        "mypy",
        "pip",
        "pyright",
        "pytest",
        "radon",
        "ruff",
        "unittest",
    }
)
UNITTEST_SAFE_PATH_WRAPPER = (
    "import pathlib, sys, unittest; "
    "sys.path.insert(0, str(pathlib.Path.cwd())); "
    "unittest.main(module=None)"
)


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return command.split()


def bind_current_python(command: str) -> str:
    leading, word_end, executable = _leading_static_shell_word(command)
    if _wraps_python_launcher(executable, command[word_end:]):
        raise TrustedCommandError("wrapped Python executable token is not trusted")
    if not _is_python_launcher_token(executable):
        return command
    if not sys.executable:
        raise TrustedCommandError("trusted Python interpreter path is unavailable")
    if _contains_shell_control_operator(command[word_end:]):
        raise TrustedCommandError("Python command shell chains are not trusted")
    if os.name == "nt":
        executable = _quote_windows_shell_token(sys.executable)
    else:
        executable = shlex.quote(sys.executable)
    return leading + executable + _safe_python_path(command[word_end:])


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


def _safe_python_path(rest: str) -> str:
    inline = re.match(r"(\s+)(-c\b)", rest)
    if inline:
        return f"{inline.group(1)}-P {rest[inline.start(2) :]}"
    match = re.match(r"(\s+)(-m\s+)([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\b", rest)
    if not match:
        return rest
    module = match.group(3)
    if module.casefold() == "unittest":
        wrapper = _quote_shell_token(UNITTEST_SAFE_PATH_WRAPPER)
        return f"{match.group(1)}-P -c {wrapper}{rest[match.end(3) :]}"
    if not _is_protected_python_module(module):
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


def _quote_shell_token(token: str) -> str:
    return _quote_windows_shell_token(token) if os.name == "nt" else shlex.quote(token)


def _contains_shell_control_operator(text: str) -> bool:
    quote = ""
    quote_chars = _shell_quote_chars()
    index = 0
    while index < len(text):
        char = text[index]
        posix_escape = (
            os.name != "nt"
            and char == "\\"
            and (
                not quote
                or (
                    quote == '"'
                    and index + 1 < len(text)
                    and text[index + 1] in '$`"\\\n'
                )
            )
        )
        escape = posix_escape or (os.name == "nt" and char == "^" and not quote)
        if escape:
            index += 2
            continue
        if os.name != "nt" and quote != "'" and text[index : index + 2] == "$(":
            return True
        if os.name != "nt" and quote != "'" and char == "`":
            return True
        if char in quote_chars:
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
        elif not quote and char in "\r\n;&|":
            return True
        index += 1
    return False


def _shell_quote_chars() -> str:
    return '"' if os.name == "nt" else "'\""


def _dynamic_executable_token_is_not_trusted(executable: str, rest: str) -> bool:
    lowered = executable.casefold()
    tail = rest.lstrip().casefold()
    return "python" in lowered or tail.startswith(("-m ", "-c "))


def _wraps_python_launcher(executable: str, rest: str) -> bool:
    if _is_env_launcher(executable):
        return _tail_contains_python_launcher(rest)
    if _is_shell_assignment(executable):
        return _tail_contains_python_launcher(rest)
    return False


def _is_env_launcher(executable: str) -> bool:
    basename = executable.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    return basename in {"env", "env.exe"}


def _is_shell_assignment(token: str) -> bool:
    name, separator, value = token.partition("=")
    del value
    return bool(separator and name and not name[0].isdigit())


def _tail_contains_python_launcher(rest: str) -> bool:
    return any(_token_starts_python_launcher(token) for token in split_command(rest))


def _token_starts_python_launcher(token: str) -> bool:
    stripped = token.strip("'\"")
    first = stripped.split(maxsplit=1)[0] if stripped else ""
    return _is_python_launcher_token(first)


def _is_python_launcher_token(token: str) -> bool:
    normalized = token.strip("'\"").replace("\\", "/").rsplit("/", 1)[-1].casefold()
    return normalized in {"python", "python.exe"}


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
    quote_chars = _shell_quote_chars()
    while index < len(command):
        char = command[index]
        if not quote and (char in " \t" or char in controls):
            break
        if char in quote_chars:
            if not quote:
                quote = char
                index += 1
                continue
            if quote == char:
                quote = ""
                index += 1
                continue
        if char == "$" and quote != "'" and command[index : index + 2] == "$(":
            raise TrustedCommandError("dynamic shell executable token is not trusted")
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
