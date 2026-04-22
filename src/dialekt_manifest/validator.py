from __future__ import annotations
import re
from pathlib import Path
from typing import Optional, Union

import yaml
from pydantic import ValidationError

from .errors import ErrorCode, Issue, Severity, ValidationResult
from .schema import AgentManifest, SUPPORTED_SPEC_VERSIONS, AUTONOMY_LEVELS
from .security import scan_content
from .entropy import scan_entropy
from .paths import check_path_safety


VARIABLE_RE = re.compile(r'(?<!\\)\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}')
ESCAPED_VAR_RE = re.compile(r'\\\{\{')


class ManifestValidator:
    def __init__(self, strict: bool = False, schema_only: bool = False):
        self.strict = strict       # warnings become errors
        self.schema_only = schema_only  # skip semantic and security

    def validate_file(self, path: Union[str, Path]) -> ValidationResult:
        path = Path(path)
        raw = path.read_text(encoding="utf-8")
        return self.validate_string(raw, source=str(path))

    def validate_string(self, content: str, source: str = "<string>") -> ValidationResult:
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            result = ValidationResult(valid=False)
            result.add_error(ErrorCode.SCHEMA_FORMAT, f"YAML parse error: {e}")
            return result

        if not isinstance(data, dict):
            result = ValidationResult(valid=False)
            result.add_error(ErrorCode.SCHEMA_TYPE, "Manifest must be a YAML mapping (dict)")
            return result

        return self.validate_dict(data, raw_content=content)

    def validate_dict(self, data: dict, raw_content: str = "") -> ValidationResult:
        result = ValidationResult(valid=True)

        # 1. Security scan on raw content (before parsing)
        if not self.schema_only and raw_content:
            for issue in scan_content(raw_content):
                result.issues.append(issue)
                if issue.is_error():
                    result.valid = False

        # 2. Entropy scan
        if not self.schema_only and raw_content:
            for issue in scan_entropy(raw_content):
                result.issues.append(issue)

        # 3. Pydantic structural validation
        manifest: Optional[AgentManifest] = None
        try:
            manifest = AgentManifest.model_validate(data)
            result.manifest = manifest
        except ValidationError as e:
            for err in e.errors():
                path_str = ".".join(str(p) for p in err["loc"])
                msg = err["msg"]
                code = _pydantic_error_to_code(err["type"])
                result.add_error(code, f"{path_str}: {msg}", path=path_str)
            return result  # can't do semantic checks without a parsed manifest

        # 4. Spec version check
        if manifest.spec_version not in SUPPORTED_SPEC_VERSIONS:
            result.add_error(
                ErrorCode.SEMANTIC_SPEC_VERSION,
                f"spec_version {manifest.spec_version!r} is not supported. Supported: {sorted(SUPPORTED_SPEC_VERSIONS)}",
                path="spec_version",
                suggestion=f"Use one of: {sorted(SUPPORTED_SPEC_VERSIONS)}",
            )

        if self.schema_only:
            return result

        # 5. Semantic checks
        _check_autonomy_order(manifest, result)
        _check_variables(manifest, result)
        _check_environments(manifest, result)
        _check_capabilities_consistency(manifest, result)
        _check_trigger_input_consistency(manifest, result)
        _check_output_streaming(manifest, result)
        _check_output_path(manifest, result)
        _check_cron_frequency(manifest, result)

        # 6. Apply strict mode: promote warnings to errors
        if self.strict:
            for issue in result.issues:
                if issue.is_warning():
                    issue.severity = Severity.ERROR
                    result.valid = False

        return result


def _pydantic_error_to_code(pydantic_type: str) -> ErrorCode:
    mapping = {
        "missing": ErrorCode.SCHEMA_REQUIRED,
        "string_type": ErrorCode.SCHEMA_TYPE,
        "int_type": ErrorCode.SCHEMA_TYPE,
        "float_type": ErrorCode.SCHEMA_TYPE,
        "bool_type": ErrorCode.SCHEMA_TYPE,
        "literal_error": ErrorCode.SCHEMA_ENUM,
        "value_error": ErrorCode.SCHEMA_FORMAT,
        "string_too_short": ErrorCode.SCHEMA_LENGTH,
        "string_too_long": ErrorCode.SCHEMA_LENGTH,
        "greater_than": ErrorCode.SCHEMA_RANGE,
        "greater_than_equal": ErrorCode.SCHEMA_RANGE,
        "less_than_equal": ErrorCode.SCHEMA_RANGE,
        "union_tag_invalid": ErrorCode.SCHEMA_ENUM,
        "extra_forbidden": ErrorCode.SCHEMA_EXTRA_FIELD,
    }
    return mapping.get(pydantic_type, ErrorCode.SCHEMA_FORMAT)


def _check_autonomy_order(manifest: AgentManifest, result: ValidationResult) -> None:
    rec_idx = AUTONOMY_LEVELS.index(manifest.autonomy.recommended)
    max_idx = AUTONOMY_LEVELS.index(manifest.autonomy.max_allowed)
    if max_idx < rec_idx:
        result.add_error(
            ErrorCode.SEMANTIC_AUTONOMY_ORDER,
            f"autonomy.max_allowed ({manifest.autonomy.max_allowed!r}) must be >= "
            f"autonomy.recommended ({manifest.autonomy.recommended!r}) in ordering: {AUTONOMY_LEVELS}",
            path="autonomy",
            suggestion=f"Set max_allowed to '{manifest.autonomy.recommended}' or higher.",
        )


def _check_variables(manifest: AgentManifest, result: ValidationResult) -> None:
    declared = set(manifest.variables.keys()) if manifest.variables else set()

    # Remove escaped references before scanning
    clean_prompt = ESCAPED_VAR_RE.sub("", manifest.system_prompt)
    used = set(VARIABLE_RE.findall(clean_prompt))

    for var in used - declared:
        result.add_error(
            ErrorCode.SEMANTIC_VARIABLE_UNDEFINED,
            f"system_prompt references '{{{{{var}}}}}' but it is not declared in `variables`",
            path="system_prompt",
            suggestion=f"Add `{var}` to the `variables` section.",
        )

    for var in declared - used:
        result.add_warning(
            ErrorCode.SEMANTIC_VARIABLE_UNUSED,
            f"Variable `{var}` declared in `variables` but never used in system_prompt",
            path=f"variables.{var}",
            suggestion="Remove unused variables or add {{" + var + "}} to system_prompt.",
        )


def _check_environments(manifest: AgentManifest, result: ValidationResult) -> None:
    if not manifest.environments or not manifest.variables:
        return

    required_vars = {k for k, v in manifest.variables.items() if v.required}

    for env_name, env_vals in manifest.environments.items():
        missing = required_vars - set(env_vals.keys())
        for var in missing:
            result.add_error(
                ErrorCode.SEMANTIC_ENV_MISSING_VAR,
                f"Environment `{env_name}` is missing required variable `{var}`",
                path=f"environments.{env_name}",
                suggestion=f"Add `{var}: <value>` to environment `{env_name}`.",
            )

        declared_vars = set(manifest.variables.keys())
        extra = set(env_vals.keys()) - declared_vars
        for var in extra:
            result.add_warning(
                ErrorCode.SEMANTIC_ENV_EXTRA_VAR,
                f"Environment `{env_name}` defines undeclared variable `{var}`",
                path=f"environments.{env_name}.{var}",
                suggestion=f"Remove `{var}` or declare it in `variables`.",
            )


def _check_capabilities_consistency(manifest: AgentManifest, result: ValidationResult) -> None:
    groups = set(manifest.capabilities.groups)

    # filesystem destination requires filesystem_write capability
    if (hasattr(manifest.output.destination, "type") and
            manifest.output.destination.type == "filesystem" and
            "filesystem_write" not in groups):
        result.add_error(
            ErrorCode.SEMANTIC_CAPABILITY_MISSING,
            "output.destination.type='filesystem' requires 'filesystem_write' in capabilities.groups",
            path="capabilities.groups",
            suggestion="Add 'filesystem_write' to capabilities.groups.",
        )


def _check_trigger_input_consistency(manifest: AgentManifest, result: ValidationResult) -> None:
    if (manifest.trigger.type == "scheduled" and
            manifest.input.type != "no-input"):
        result.add_warning(
            ErrorCode.SEMANTIC_SCHEDULED_INPUT,
            "Scheduled agents typically use input.type='no-input'",
            path="input.type",
            suggestion="Set input.type to 'no-input' for scheduled agents.",
        )


def _check_output_streaming(manifest: AgentManifest, result: ValidationResult) -> None:
    if manifest.output.format == "image" and manifest.output.streaming:
        result.add_warning(
            ErrorCode.SEMANTIC_STREAMING_IMAGE,
            "output.streaming=true has no effect for image output format",
            path="output.streaming",
            suggestion="Set output.streaming=false for image output.",
        )


def _check_output_path(manifest: AgentManifest, result: ValidationResult) -> None:
    dest = manifest.output.destination
    if hasattr(dest, "path") and dest.path:
        for issue in check_path_safety(dest.path):
            result.issues.append(issue)
            if issue.is_error():
                result.valid = False


def _check_cron_frequency(manifest: AgentManifest, result: ValidationResult) -> None:
    if manifest.trigger.type != "scheduled":
        return
    try:
        from croniter import croniter
        from datetime import datetime
        c = croniter(manifest.trigger.schedule, datetime.now())
        next1 = c.get_next(float)
        next2 = c.get_next(float)
        interval_minutes = (next2 - next1) / 60
        if interval_minutes < 5:
            result.add_warning(
                ErrorCode.SEMANTIC_CRON_TOO_FREQUENT,
                f"Schedule runs more than once every 5 minutes (interval: {interval_minutes:.1f}min)",
                path="trigger.schedule",
                suggestion="Consider a less frequent schedule. Very frequent agent runs consume significant resources.",
            )
    except Exception:
        pass  # croniter already validated by Pydantic
