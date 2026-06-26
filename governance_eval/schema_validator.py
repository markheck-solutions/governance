from __future__ import annotations

from typing import Any


class SchemaValidationError(ValueError):
    pass


def validate(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    schema_type = schema.get("type")
    if schema_type is not None and not _matches_type(instance, schema_type):
        raise SchemaValidationError(f"{path}: expected {schema_type}, got {type(instance).__name__}")

    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(f"{path}: {instance!r} not in enum {schema['enum']!r}")

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                raise SchemaValidationError(f"{path}: missing required key {key!r}")
        min_properties = schema.get("minProperties")
        if min_properties is not None and len(instance) < min_properties:
            raise SchemaValidationError(f"{path}: expected at least {min_properties} properties")

        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                validate(value, properties[key], f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                raise SchemaValidationError(f"{path}: unexpected key {key!r}")

    if isinstance(instance, list) and "items" in schema:
        for index, item in enumerate(instance):
            validate(item, schema["items"], f"{path}[{index}]")

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        if min_length is not None and len(instance) < min_length:
            raise SchemaValidationError(f"{path}: length below {min_length}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            raise SchemaValidationError(f"{path}: value below {minimum}")
        maximum = schema.get("maximum")
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
