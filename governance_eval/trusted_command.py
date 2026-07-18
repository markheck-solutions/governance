from __future__ import annotations

import os
import shlex
import subprocess
import sys


class TrustedCommandError(ValueError):
    pass


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return command.split()


def bind_current_python(command: str) -> str:
    if command != "python" and not command.startswith("python "):
        return command
    if not sys.executable:
        raise TrustedCommandError("trusted Python interpreter path is unavailable")
    if os.name == "nt":
        executable = subprocess.list2cmdline([sys.executable])
    else:
        executable = shlex.quote(sys.executable)
    return executable + command[len("python") :]
