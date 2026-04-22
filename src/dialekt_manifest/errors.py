from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


class ErrorCode(str, Enum):
    # Schema errors
    SCHEMA_REQUIRED = "schema.required"
    SCHEMA_TYPE = "schema.type"
    SCHEMA_ENUM = "schema.enum"
    SCHEMA_FORMAT = "schema.format"
    SCHEMA_LENGTH = "schema.length"
    SCHEMA_RANGE = "schema.range"
    SCHEMA_EXTRA_FIELD = "schema.extra_field"
    SCHEMA_UUID = "schema.uuid"
    SCHEMA_SEMVER = "schema.semver"
    SCHEMA_TIMESTAMP = "schema.timestamp"
    SCHEMA_EMAIL = "schema.email"
    SCHEMA_CRON = "schema.cron"
    SCHEMA_TIMEZONE = "schema.timezone"
    # Semantic errors
    SEMANTIC_VARIABLE_UNDEFINED = "semantic.variable_undefined"
    SEMANTIC_VARIABLE_UNUSED = "semantic.variable_unused"
    SEMANTIC_ENV_MISSING_VAR = "semantic.env_missing_var"
    SEMANTIC_ENV_EXTRA_VAR = "semantic.env_extra_var"
    SEMANTIC_ENV_TYPE_MISMATCH = "semantic.env_type_mismatch"
    SEMANTIC_AUTONOMY_ORDER = "semantic.autonomy_order"
    SEMANTIC_STREAMING_IMAGE = "semantic.streaming_image"
    SEMANTIC_CAPABILITY_MISSING = "semantic.capability_missing"
    SEMANTIC_SCHEDULED_INPUT = "semantic.scheduled_input"
    SEMANTIC_CRON_TOO_FREQUENT = "semantic.cron_too_frequent"
    SEMANTIC_SPEC_VERSION = "semantic.spec_version"
    SEMANTIC_FORM_NO_FIELDS = "semantic.form_no_fields"
    SEMANTIC_DROPDOWN_NO_OPTIONS = "semantic.dropdown_no_options"
    # Security errors
    SECURITY_PASSWORD = "security.password"
    SECURITY_OPENAI_KEY = "security.openai_key"
    SECURITY_ANTHROPIC_KEY = "security.anthropic_key"
    SECURITY_GITHUB_TOKEN = "security.github_token"
    SECURITY_TELEGRAM_TOKEN = "security.telegram_token"
    SECURITY_SLACK_TOKEN = "security.slack_token"
    SECURITY_AWS_KEY = "security.aws_key"
    SECURITY_PRIVATE_KEY = "security.private_key"
    SECURITY_JWT = "security.jwt"
    SECURITY_DB_CREDENTIALS = "security.db_credentials"
    SECURITY_HIGH_ENTROPY = "security.high_entropy"
    SECURITY_INTERNAL_URL = "security.internal_url"
    SECURITY_EMAIL_IN_PROMPT = "security.email_in_prompt"
    # Path errors
    PATH_SYSTEM_DIR = "path.system_dir"
    PATH_TRAVERSAL = "path.traversal"


@dataclass
class Issue:
    severity: Severity
    code: ErrorCode
    message: str
    path: str = ""
    line: Optional[int] = None
    column: Optional[int] = None
    suggestion: str = ""

    def is_error(self) -> bool:
        return self.severity == Severity.ERROR

    def is_warning(self) -> bool:
        return self.severity == Severity.WARNING


@dataclass
class ValidationResult:
    valid: bool
    issues: list[Issue] = field(default_factory=list)
    manifest: object = None  # AgentManifest | None

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == Severity.WARNING]

    def add_error(self, code: ErrorCode, message: str, path: str = "",
                  line: Optional[int] = None, suggestion: str = "") -> None:
        self.issues.append(Issue(Severity.ERROR, code, message, path, line, suggestion=suggestion))
        self.valid = False

    def add_warning(self, code: ErrorCode, message: str, path: str = "",
                    line: Optional[int] = None, suggestion: str = "") -> None:
        self.issues.append(Issue(Severity.WARNING, code, message, path, line, suggestion=suggestion))
