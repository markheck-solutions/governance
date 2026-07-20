from __future__ import annotations

import json
import re
from typing import Any


class SupportabilityError(ValueError):
    pass


def parse_supportability_config_bytes(
    raw: bytes, *, suffix: str = ""
) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupportabilityError("supportability config must be UTF-8") from exc
    return parse_supportability_config_text(text, suffix)


def parse_supportability_config_text(text: str, suffix: str = "") -> dict[str, Any]:
    stripped = text.lstrip()
    if suffix == ".json" or stripped.startswith("{"):
        parsed = _parse_json(text)
    else:
        parsed = _parse_simple_yaml(text)
    if not isinstance(parsed, dict):
        raise SupportabilityError("supportability config must be an object")
    return parsed


def _parse_json(text: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_config_object,
            parse_constant=_reject_config_constant,
        )
    except (json.JSONDecodeError, SupportabilityError) as exc:
        raise SupportabilityError(f"supportability config JSON invalid: {exc}") from exc


def _unique_config_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SupportabilityError(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def _reject_config_constant(value: str) -> Any:
    raise SupportabilityError(f"unsupported JSON constant: {value}")


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    lines = _yaml_lines(text)
    if not lines:
        return {}
    result, index = _parse_yaml_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise SupportabilityError("unsupported YAML structure")
    if not isinstance(result, dict):
        raise SupportabilityError("supportability YAML root must be a mapping")
    return result


def _yaml_lines(text: str) -> list[tuple[int, str]]:
    lines = []
    for raw in text.splitlines():
        stripped = _strip_yaml_comment(raw).rstrip()
        if not stripped.strip() or stripped.lstrip().startswith("---"):
            continue
        lines.append((len(stripped) - len(stripped.lstrip(" ")), stripped.lstrip(" ")))
    return lines


def _strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        if char == '"' and not in_single:
            in_double = not in_double
        if char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def _parse_yaml_block(
    lines: list[tuple[int, str]], index: int, indent: int
) -> tuple[Any, int]:
    if lines[index][1].startswith("- "):
        return _parse_yaml_list(lines, index, indent)
    return _parse_yaml_mapping(lines, index, indent)


def _parse_yaml_mapping(
    lines: list[tuple[int, str]], index: int, indent: int
) -> tuple[dict[str, Any], int]:
    data: dict[str, Any] = {}
    while (
        index < len(lines)
        and lines[index][0] == indent
        and not lines[index][1].startswith("- ")
    ):
        key, value = _split_yaml_key_value(lines[index][1])
        if key in data:
            raise SupportabilityError(f"duplicate YAML key: {key!r}")
        if value == "":
            if index + 1 >= len(lines) or lines[index + 1][0] <= indent:
                raise SupportabilityError(f"YAML key {key!r} is missing a nested block")
            child, index = _parse_yaml_block(lines, index + 1, lines[index + 1][0])
            data[key] = child
        else:
            data[key] = _parse_yaml_scalar(value)
            index += 1
    return data, index


def _parse_yaml_list(
    lines: list[tuple[int, str]], index: int, indent: int
) -> tuple[list[Any], int]:
    items: list[Any] = []
    while (
        index < len(lines)
        and lines[index][0] == indent
        and lines[index][1].startswith("- ")
    ):
        value = lines[index][1][2:].strip()
        if value == "":
            if index + 1 >= len(lines) or lines[index + 1][0] <= indent:
                raise SupportabilityError("YAML list item is missing a nested block")
            child, index = _parse_yaml_block(lines, index + 1, lines[index + 1][0])
            items.append(child)
        elif _looks_like_yaml_mapping_item(value):
            item, index = _parse_yaml_mapping_item(lines, index, indent, value)
            items.append(item)
        else:
            items.append(_parse_yaml_scalar(value))
            index += 1
    return items, index


def _parse_yaml_mapping_item(
    lines: list[tuple[int, str]], index: int, indent: int, value: str
) -> tuple[dict[str, Any], int]:
    key, scalar = _split_yaml_key_value(value)
    item = {key: _parse_yaml_scalar(scalar)}
    index += 1
    if index < len(lines) and lines[index][0] > indent:
        child, index = _parse_yaml_mapping(lines, index, lines[index][0])
        duplicates = sorted(set(item) & set(child))
        if duplicates:
            raise SupportabilityError(f"duplicate YAML key: {duplicates[0]!r}")
        item.update(child)
    return item, index


def _looks_like_yaml_mapping_item(value: str) -> bool:
    return ":" in value and not value.startswith(("'", '"'))


def _split_yaml_key_value(text: str) -> tuple[str, str]:
    if ":" not in text:
        raise SupportabilityError(f"unsupported YAML line: {text}")
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def _parse_yaml_scalar(value: str) -> Any:
    if value in {"true", "false"}:
        return value == "true"
    if value in {"null", "~"}:
        return None
    if value == "[]":
        return []
    if value.startswith("[") or value.startswith("{"):
        raise SupportabilityError(f"unsupported YAML flow scalar: {value}")
    if value.startswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise SupportabilityError(f"unsupported YAML scalar: {value}") from exc
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    if re.fullmatch(r"-?[0-9]+", value):
        return int(value)
    return value
