from __future__ import annotations

import re
from typing import Any


class SchemaValidationError(ValueError):
    pass


def validate(
    instance: Any,
    schema: dict[str, Any],
    path: str = "$",
    _root: dict[str, Any] | None = None,
) -> None:
    root = schema if _root is None else _root
    if _validate_reference(instance, schema, path, root):
        return
    schema_type = schema.get("type")
    if schema_type is not None and not _matches_type(instance, schema_type):
        raise SchemaValidationError(
            f"{path}: expected {schema_type}, got {type(instance).__name__}"
        )

    _validate_combinators(instance, schema, path, root)
    if isinstance(instance, dict):
        _validate_object(instance, schema, path, root)
    if isinstance(instance, list):
        _validate_array(instance, schema, path, root)
    if isinstance(instance, str):
        _validate_string(instance, schema, path)
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        _validate_number(instance, schema, path)


def _validate_reference(
    instance: Any, schema: dict[str, Any], path: str, root: dict[str, Any]
) -> bool:
    reference = schema.get("$ref")
    if reference is None:
        return False
    validate(instance, _resolve_local_reference(root, reference), path, root)
    return len(schema) == 1


def _validate_combinators(
    instance: Any, schema: dict[str, Any], path: str, root: dict[str, Any]
) -> None:
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(
            f"{path}: {instance!r} not in enum {schema['enum']!r}"
        )
    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(f"{path}: expected constant {schema['const']!r}")
    if "oneOf" not in schema:
        return
    matches = sum(
        _schema_matches(instance, option, path, root) for option in schema["oneOf"]
    )
    if matches != 1:
        raise SchemaValidationError(
            f"{path}: expected exactly one matching schema, got {matches}"
        )


def _schema_matches(
    instance: Any, option: dict[str, Any], path: str, root: dict[str, Any]
) -> bool:
    try:
        validate(instance, option, path, root)
    except SchemaValidationError:
        return False
    return True


def _validate_object(
    instance: dict[str, Any], schema: dict[str, Any], path: str, root: dict[str, Any]
) -> None:
    for key in schema.get("required", []):
        if key not in instance:
            raise SchemaValidationError(f"{path}: missing required key {key!r}")
    minimum = schema.get("minProperties")
    if minimum is not None and len(instance) < minimum:
        raise SchemaValidationError(f"{path}: expected at least {minimum} properties")
    properties = schema.get("properties", {})
    for key, value in instance.items():
        if key in properties:
            validate(value, properties[key], f"{path}.{key}", root)
        elif schema.get("additionalProperties") is False:
            raise SchemaValidationError(f"{path}: unexpected key {key!r}")


def _validate_array(
    instance: list[Any], schema: dict[str, Any], path: str, root: dict[str, Any]
) -> None:
    minimum = schema.get("minItems")
    maximum = schema.get("maxItems")
    if minimum is not None and len(instance) < minimum:
        raise SchemaValidationError(f"{path}: expected at least {minimum} items")
    if maximum is not None and len(instance) > maximum:
        raise SchemaValidationError(f"{path}: expected at most {maximum} items")
    for index, item in enumerate(instance if "items" in schema else []):
        validate(item, schema["items"], f"{path}[{index}]", root)
    prefix_items = schema.get("prefixItems")
    if isinstance(prefix_items, list):
        for index, item_schema in enumerate(prefix_items[: len(instance)]):
            validate(instance[index], item_schema, f"{path}[{index}]", root)


def _validate_string(instance: str, schema: dict[str, Any], path: str) -> None:
    minimum = schema.get("minLength")
    maximum = schema.get("maxLength")
    if minimum is not None and len(instance) < minimum:
        raise SchemaValidationError(f"{path}: length below {minimum}")
    if maximum is not None and len(instance) > maximum:
        raise SchemaValidationError(f"{path}: length above {maximum}")
    pattern = schema.get("pattern")
    if pattern is None:
        return
    try:
        compiled = re.compile(pattern)
    except (re.error, TypeError) as exc:
        raise SchemaValidationError(
            f"{path}: invalid pattern {pattern!r}: {exc}"
        ) from exc
    if not compiled.search(instance):
        raise SchemaValidationError(f"{path}: does not match pattern {pattern!r}")


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


def _resolve_local_reference(root: dict[str, Any], reference: Any) -> dict[str, Any]:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise SchemaValidationError(f"$schema: unsupported reference {reference!r}")
    current: Any = root
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise SchemaValidationError(f"$schema: unresolved reference {reference!r}")
        current = current[part]
    if not isinstance(current, dict):
        raise SchemaValidationError(f"$schema: reference is not a schema {reference!r}")
    return current
