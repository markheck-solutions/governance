from __future__ import annotations

import re
from typing import Any


class SchemaValidationError(ValueError):
    pass


def validate(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    schema_type = schema.get("type")
    if schema_type is not None and not _matches_type(instance, schema_type):
        raise SchemaValidationError(f"{path}: expected {schema_type}, got {type(instance).__name__}")

    _validate_enum(instance, schema, path)
    if isinstance(instance, dict):
        _validate_object(instance, schema, path)
    elif isinstance(instance, list):
        _validate_array(instance, schema, path)
    elif isinstance(instance, str):
        _validate_string(instance, schema, path)
    elif isinstance(instance, (int, float)) and not isinstance(instance, bool):
        _validate_number(instance, schema, path)


def _validate_enum(instance: Any, schema: dict[str, Any], path: str) -> None:
    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(f"{path}: {instance!r} not in enum {schema['enum']!r}")


def _validate_object(instance: dict[str, Any], schema: dict[str, Any], path: str) -> None:
    missing = [key for key in schema.get("required", []) if key not in instance]
    if missing:
        raise SchemaValidationError(f"{path}: missing required key {missing[0]!r}")
    minimum = schema.get("minProperties")
    if minimum is not None and len(instance) < minimum:
        raise SchemaValidationError(f"{path}: expected at least {minimum} properties")
    properties = schema.get("properties", {})
    for key, value in instance.items():
        if key in properties:
            validate(value, properties[key], f"{path}.{key}")
        elif schema.get("additionalProperties") is False:
            raise SchemaValidationError(f"{path}: unexpected key {key!r}")


def _validate_array(instance: list[Any], schema: dict[str, Any], path: str) -> None:
    minimum = schema.get("minItems")
    if minimum is not None and len(instance) < minimum:
        raise SchemaValidationError(f"{path}: expected at least {minimum} items")
    if "items" in schema:
        for index, item in enumerate(instance):
            validate(item, schema["items"], f"{path}[{index}]")


def _validate_string(instance: str, schema: dict[str, Any], path: str) -> None:
    for keyword, compare, message in (
        ("minLength", lambda actual, limit: actual < limit, "length below"),
        ("maxLength", lambda actual, limit: actual > limit, "length above"),
    ):
        limit = schema.get(keyword)
        if limit is not None and compare(len(instance), limit):
            raise SchemaValidationError(f"{path}: {message} {limit}")
    pattern = schema.get("pattern")
    if pattern is not None and not _compile_pattern(pattern, path).search(instance):
        raise SchemaValidationError(f"{path}: does not match pattern {pattern!r}")


def _compile_pattern(pattern: str, path: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except (re.error, TypeError) as exc:
        raise SchemaValidationError(f"{path}: invalid pattern {pattern!r}: {exc}") from exc


def _validate_number(instance: int | float, schema: dict[str, Any], path: str) -> None:
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if minimum is not None and instance < minimum:
        raise SchemaValidationError(f"{path}: value below {minimum}")
    if maximum is not None and instance > maximum:
        raise SchemaValidationError(f"{path}: value above {maximum}")


def _matches_type(instance: Any, schema_type: str | list[str]) -> bool:
    if isinstance(schema_type, list):
        return any(_matches_type(instance, item) for item in schema_type)
    if schema_type == "object":
        return isinstance(instance, dict)
    if schema_type == "array":
        return isinstance(instance, list)
    if schema_type == "string":
        return isinstance(instance, str)
    if schema_type == "boolean":
        return isinstance(instance, bool)
    if schema_type == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if schema_type == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if schema_type == "null":
        return instance is None
    raise SchemaValidationError(f"$schema: unsupported type {schema_type!r}")
