from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path, *, max_bytes: int | None = None) -> str:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("hash input is not a regular file")
    if max_bytes is not None and before.st_size > max_bytes:
        raise ValueError("hash input exceeds size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            raise ValueError("hash input identity changed")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError("hash input exceeds size limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if total != before.st_size or not _same_snapshot(opened, after):
        raise ValueError("hash input changed while reading")
    return digest.hexdigest()


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _same_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return _same_file(left, right) and (
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (right.st_size, right.st_mtime_ns, right.st_ctime_ns)


def sha256_json(data: Any) -> str:
    return sha256_text(json.dumps(data, sort_keys=True, separators=(",", ":")))


def git_sha(root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip()
    except Exception:
        return "UNKNOWN"
