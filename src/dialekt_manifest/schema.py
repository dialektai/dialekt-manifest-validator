from __future__ import annotations
import re
import uuid
from typing import Annotated, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import semver


SUPPORTED_SPEC_VERSIONS = {"1.0.0", "1.0.1"}

CAPABILITY_GROUPS = {
    "filesystem_read", "filesystem_write", "database_read",
    "database_write", "shell_execute", "network", "browser", "screen_capture"
}

AUTONOMY_LEVELS = [
    "review-only", "ask-before-write", "autonomous", "sandbox-only",
    # "manual": every action requires user confirmation. Semantically
    # distinct from "review-only" (shows reply, no mutation) and
    # "ask-before-write" (confirm writes, free reads) — "manual" asks
    # before every read too. Added 2026-04-23 to match Builder Wizard UI.
    "manual",
]

CONNECTION_TYPES = {"postgres", "mysql", "clickhouse", "mcp-server", "http-api"}
CONNECTION_ROLES = {"readonly", "readwrite", "admin"}
DATABASE_CATEGORIES = {"analytics", "transactional", "warehouse", "reporting", "operational"}
FIELD_TYPES = {"text", "textarea", "number", "dropdown", "checkbox", "multi-select", "date", "file", "url"}
OUTPUT_FORMATS = {"markdown", "table", "image", "file", "json"}
DESTINATION_TYPES = {"notification", "filesystem", "webhook", "email_or_telegram"}
LANGUAGE_OPTIONS = {"ru", "en", "kk", "multi"}
VARIABLE_TYPES = {"string", "number", "boolean", "list"}
MISSED_RUN_POLICIES = {"run_on_startup", "skip"}


class UIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    primary_action_label: Optional[str] = Field(None, max_length=30)


class Author(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    email: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', v):
            raise ValueError(f"Invalid email: {v}")
        return v


class Metadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(max_length=500)
    version: str
    author: Author
    created_at: str
    updated_at: str
    tags: Optional[list[str]] = None
    icon: Optional[str] = Field(None, max_length=10)
    language: Optional[str] = None
    ui: Optional[UIConfig] = None

    @field_validator("id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        try:
            parsed = uuid.UUID(v)
        except ValueError:
            raise ValueError(f"Invalid UUID format: {v!r}")
        if parsed.version != 4:
            raise ValueError(
                f"metadata.id must be UUID v4 (got version {parsed.version}). "
                f"Generate one with: python3 -c \"import uuid; print(uuid.uuid4())\""
            )
        return v

    @field_validator("version")
    @classmethod
    def validate_semver_version(cls, v: str) -> str:
        try:
            semver.Version.parse(v)
        except ValueError:
            raise ValueError(f"Not a valid semver: {v}")
        return v

    @field_validator("created_at", "updated_at")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        # Must be ISO 8601 with timezone
        if not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([+-]\d{2}:\d{2}|Z)$', v):
            raise ValueError(f"Must be ISO 8601 with timezone offset: {v}")
        return v

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in LANGUAGE_OPTIONS:
            raise ValueError(f"language must be one of {LANGUAGE_OPTIONS}")
        return v


class ModelRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid")
    min_ram_gb: int = Field(ge=0)
    min_vram_gb: int = Field(ge=0)
    recommended_ram_gb: int = Field(ge=0)


class ModelParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    temperature: float = Field(ge=0.0, le=2.0)
    top_p: float = Field(ge=0.0, le=1.0)
    max_tokens: int = Field(gt=0)


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preferred: str = Field(min_length=1)
    acceptable: Optional[list[str]] = None
    min_context_window: int = Field(gt=0)
    requirements: ModelRequirements
    parameters: ModelParameters


class Capabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")
    groups: list[str]
    exceptions: list[str] = Field(default_factory=list)

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, v: list[str]) -> list[str]:
        invalid = set(v) - CAPABILITY_GROUPS
        if invalid:
            raise ValueError(f"Unknown capability groups: {invalid}. Valid: {CAPABILITY_GROUPS}")
        return v


class Connection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    role: str
    purpose: str = Field(min_length=1)
    database_category: Optional[str] = None
    required_permissions: Optional[list[str]] = None
    server: Optional[str] = None

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in CONNECTION_TYPES:
            raise ValueError(f"Connection type must be one of {CONNECTION_TYPES}")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in CONNECTION_ROLES:
            raise ValueError(f"Connection role must be one of {CONNECTION_ROLES}")
        return v

    @field_validator("database_category")
    @classmethod
    def validate_db_category(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in DATABASE_CATEGORIES:
            raise ValueError(f"database_category must be one of {DATABASE_CATEGORIES}")
        return v


class Connections(BaseModel):
    model_config = ConfigDict(extra="forbid")
    required: list[Connection] = Field(default_factory=list)


class Autonomy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recommended: str
    max_allowed: str

    @field_validator("recommended", "max_allowed")
    @classmethod
    def validate_level(cls, v: str) -> str:
        if v not in AUTONOMY_LEVELS:
            raise ValueError(f"Autonomy level must be one of {AUTONOMY_LEVELS}")
        return v


# Input field types (discriminated union via type field)
class BaseFormField(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    label: str = Field(min_length=1)
    required: bool = False


class TextField(BaseFormField):
    type: Literal["text"]
    max_length: Optional[int] = None
    default: Optional[str] = None


class TextareaField(BaseFormField):
    type: Literal["textarea"]
    max_length: Optional[int] = None
    default: Optional[str] = None


class NumberField(BaseFormField):
    type: Literal["number"]
    min: Optional[float] = None
    max: Optional[float] = None
    default: Optional[float] = None


class DropdownField(BaseFormField):
    type: Literal["dropdown"]
    options: list[str]
    default: Optional[str] = None


class CheckboxField(BaseFormField):
    type: Literal["checkbox"]
    default: Optional[bool] = None


class MultiSelectField(BaseFormField):
    type: Literal["multi-select"]
    options: list[str]
    default: Optional[list[str]] = None


class DateField(BaseFormField):
    type: Literal["date"]
    default: Optional[str] = None


class FileField(BaseFormField):
    type: Literal["file"]
    accept: Optional[list[str]] = None
    max_size_mb: Optional[float] = None


class UrlField(BaseFormField):
    type: Literal["url"]
    default: Optional[str] = None


FormField = Annotated[
    Union[TextField, TextareaField, NumberField, DropdownField,
          CheckboxField, MultiSelectField, DateField, FileField, UrlField],
    Field(discriminator="type")
]


class ChatInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["chat"]
    placeholder: Optional[str] = None


class FormInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["form"]
    fields: list[FormField]


class NoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["no-input"]


Input = Annotated[
    Union[ChatInput, FormInput, NoInput],
    Field(discriminator="type")
]


class NotificationDestination(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["notification"]


class FilesystemDestination(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["filesystem"]
    path: str
    overwrite: bool = False


class WebhookDestination(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["webhook"]


class EmailOrTelegramDestination(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["email_or_telegram"]


Destination = Annotated[
    Union[NotificationDestination, FilesystemDestination,
          WebhookDestination, EmailOrTelegramDestination],
    Field(discriminator="type")
]


class Output(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: str
    streaming: bool = True
    destination: Destination

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        if v not in OUTPUT_FORMATS:
            raise ValueError(f"output.format must be one of {OUTPUT_FORMATS}")
        return v


class InteractiveTrigger(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["interactive"]


class ScheduledTrigger(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["scheduled"]
    schedule: str
    timezone: str
    missed_run_policy: str = "run_on_startup"

    @field_validator("schedule")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        try:
            from croniter import croniter
            if not croniter.is_valid(v):
                raise ValueError(f"Invalid cron expression: {v!r}")
        except ImportError:
            pass
        return v

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, v: str) -> str:
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(v)
        except Exception:
            raise ValueError(f"Invalid IANA timezone: {v!r}")
        return v

    @field_validator("missed_run_policy")
    @classmethod
    def validate_policy(cls, v: str) -> str:
        if v not in MISSED_RUN_POLICIES:
            raise ValueError(f"missed_run_policy must be one of {MISSED_RUN_POLICIES}")
        return v


Trigger = Annotated[
    Union[InteractiveTrigger, ScheduledTrigger],
    Field(discriminator="type")
]


class Variable(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    required: bool = True
    description: str = ""

    @field_validator("type")
    @classmethod
    def validate_var_type(cls, v: str) -> str:
        if v not in VARIABLE_TYPES:
            raise ValueError(f"variable type must be one of {VARIABLE_TYPES}")
        return v


class SecretRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    description: str
    required: bool = True


class AgentManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spec_version: str
    minimum_dialekt_version: str
    metadata: Metadata
    model: ModelConfig
    system_prompt: str = Field(min_length=1)
    capabilities: Capabilities
    autonomy: Autonomy
    input: Input
    output: Output
    trigger: Trigger
    connections: Optional[Connections] = None
    variables: Optional[dict[str, Variable]] = None
    environments: Optional[dict[str, dict[str, object]]] = None
    secrets_required: Optional[list[SecretRequirement]] = None

    @field_validator("spec_version")
    @classmethod
    def validate_spec_version(cls, v: str) -> str:
        try:
            semver.Version.parse(v)
        except ValueError:
            raise ValueError(f"spec_version must be semver: {v}")
        return v

    @field_validator("minimum_dialekt_version")
    @classmethod
    def validate_min_version(cls, v: str) -> str:
        try:
            semver.Version.parse(v)
        except ValueError:
            raise ValueError(f"minimum_dialekt_version must be semver: {v}")
        return v
