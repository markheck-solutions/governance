from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path


class TrustedCommandError(ValueError):
    pass


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return command.split()


def bind_current_python(command: str) -> str:
    leading, word_end, executable = _leading_static_shell_word(command)
    trusted_names = {"python", "python.exe"}
    comparison = executable.casefold() if os.name == "nt" else executable
    if comparison not in trusted_names:
        return command
    if not sys.executable:
        raise TrustedCommandError("trusted Python interpreter path is unavailable")
    if os.name == "nt":
        executable = subprocess.list2cmdline([sys.executable])
    else:
        executable = shlex.quote(sys.executable)
    return leading + executable + command[word_end:]


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
    return subprocess.run(
        bound_command,
        cwd=cwd,
        shell=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=1200,
    )


def _leading_static_shell_word(command: str) -> tuple[str, int, str]:
    index = 0
    while index < len(command) and command[index] in " \t":
        index += 1
    leading = command[:index]
    word: list[str] = []
    quote = ""
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
            raise TrustedCommandError("dynamic shell executable token is not trusted")
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
    return leading, index, "".join(word)
