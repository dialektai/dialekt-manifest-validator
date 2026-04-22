from .validator import ManifestValidator
from .errors import ValidationResult, Issue, Severity, ErrorCode
from .schema import AgentManifest
from pathlib import Path
from typing import Union


def validate(
    source: Union[str, Path],
    *,
    strict: bool = False,
    schema_only: bool = False,
) -> ValidationResult:
    """Validate a manifest from a file path, YAML string, or Path object."""
    v = ManifestValidator(strict=strict, schema_only=schema_only)
    p = Path(source)
    if p.exists():
        return v.validate_file(p)
    return v.validate_string(str(source))


def export_json_schema() -> dict:
    """Return JSON Schema dict generated from Pydantic models."""
    return AgentManifest.model_json_schema()


__all__ = [
    "validate",
    "export_json_schema",
    "ManifestValidator",
    "ValidationResult",
    "Issue",
    "Severity",
    "ErrorCode",
    "AgentManifest",
]
