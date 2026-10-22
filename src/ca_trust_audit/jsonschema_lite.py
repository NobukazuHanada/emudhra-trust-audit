"""A deliberately small JSON Schema subset validator.

The data files under ``data/`` carry JSON Schema documents so a contributor can
see what a record must contain. Validating them must not require a third-party
package, so the keywords actually used by those schemas - and only those - are
implemented here: ``type``, ``enum``, ``pattern``, ``required``, ``properties``,
``items``, ``minItems``.

Unsupported keywords are ignored rather than silently treated as satisfied by
the caller: :func:`validate` returns the list of errors it *can* prove.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "null": type(None),
}


def _type_matches(value: Any, expected: str) -> bool:
    python_type = _TYPES.get(expected)
    if python_type is None:
        return True
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return isinstance(value, python_type)


def validate(instance: Any, schema: Dict[str, Any], path: str = "$") -> List[str]:
    """Return a list of human-readable validation errors (empty when valid)."""
    errors: List[str] = []

    expected_type = schema.get("type")
    if expected_type is not None:
        options = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_type_matches(instance, option) for option in options):
            errors.append("%s: expected type %s, got %s" % (path, options, type(instance).__name__))
            return errors

    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: %r is not one of %r" % (path, instance, schema["enum"]))

    if (
        "pattern" in schema
        and isinstance(instance, str)
        and not re.search(schema["pattern"], instance)
    ):
        errors.append("%s: %r does not match /%s/" % (path, instance, schema["pattern"]))

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append("%s: missing required property %r" % (path, key))
        for key, subschema in schema.get("properties", {}).items():
            if key in instance:
                errors.extend(validate(instance[key], subschema, "%s.%s" % (path, key)))

    if isinstance(instance, list):
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append("%s: expected at least %d items, got %d" % (path, minimum, len(instance)))
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                errors.extend(validate(item, item_schema, "%s[%d]" % (path, index)))

    return errors
