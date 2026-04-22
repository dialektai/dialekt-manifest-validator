import re
from .errors import ErrorCode, Issue, Severity

# Each pattern: (ErrorCode, regex_pattern, category_label, suggestion)
HARD_BAN_PATTERNS = [
    (
        ErrorCode.SECURITY_PASSWORD,
        r'(?i)(password|passwd|pwd|pass)\s*[:=]\s*["\']?(?!.*\{\{)[^\s"\'#]{4,}',
        "Password value detected",
        "Remove credentials from manifest. Use `secrets_required` to declare that a password is needed.",
    ),
    (
        ErrorCode.SECURITY_OPENAI_KEY,
        r'sk-proj-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20,}',
        "OpenAI API key detected",
        "Remove this key. Declare it in `secrets_required` and store in OS keychain.",
    ),
    (
        ErrorCode.SECURITY_ANTHROPIC_KEY,
        r'sk-ant-[A-Za-z0-9_-]{40,}',
        "Anthropic API key detected",
        "Remove this key. Declare it in `secrets_required` and store in OS keychain.",
    ),
    (
        ErrorCode.SECURITY_GITHUB_TOKEN,
        r'gh[pors]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}',
        "GitHub token detected",
        "Remove this token. Declare it in `secrets_required` and store in OS keychain.",
    ),
    (
        ErrorCode.SECURITY_TELEGRAM_TOKEN,
        r'\b\d{9,10}:[A-Za-z0-9_-]{35}\b',
        "Telegram bot token detected",
        "Remove this token. Declare it in `secrets_required` and store in OS keychain.",
    ),
    (
        ErrorCode.SECURITY_SLACK_TOKEN,
        r'xox[baprs]-[A-Za-z0-9-]{10,}',
        "Slack token detected",
        "Remove this token. Declare it in `secrets_required` and store in OS keychain.",
    ),
    (
        ErrorCode.SECURITY_AWS_KEY,
        r'\bAKIA[0-9A-Z]{16}\b',
        "AWS Access Key detected",
        "Remove this key. Declare it in `secrets_required` and store in OS keychain.",
    ),
    (
        ErrorCode.SECURITY_PRIVATE_KEY,
        r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----',
        "Private key detected",
        "Never embed private keys in manifests. Store in OS keychain.",
    ),
    (
        ErrorCode.SECURITY_JWT,
        r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        "JWT token detected",
        "Remove this token. Declare it in `secrets_required` and store in OS keychain.",
    ),
    (
        ErrorCode.SECURITY_DB_CREDENTIALS,
        r'(?:postgresql|postgres|mysql|mongodb|redis)://[^/:@\s]+:[^@\s]+@',
        "Database connection string with credentials detected",
        "Remove credentials from connection string. Use `connections` section to declare DB needs; credentials go in OS keychain.",
    ),
]

SOFT_WARNING_PATTERNS = [
    (
        ErrorCode.SECURITY_INTERNAL_URL,
        r'https?://[^/\s]*\.(?:internal|local|lan|corp|intranet)\b|https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)',
        "Possible internal/private URL",
        "Verify this URL is intentional. Internal URLs may leak network topology.",
    ),
    (
        ErrorCode.SECURITY_EMAIL_IN_PROMPT,
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "Email address detected",
        "If this is PII, consider removing it from the manifest.",
    ),
]


def scan_content(raw_yaml: str) -> list[Issue]:
    """Scan raw YAML text for security issues. Returns list of Issues."""
    issues: list[Issue] = []
    lines = raw_yaml.splitlines()

    for line_no, line in enumerate(lines, start=1):
        # Hard ban patterns
        for code, pattern, label, suggestion in HARD_BAN_PATTERNS:
            for m in re.finditer(pattern, line):
                # Redact matched value in message
                snippet = m.group(0)[:20] + "..." if len(m.group(0)) > 20 else m.group(0)
                issues.append(Issue(
                    severity=Severity.ERROR,
                    code=code,
                    message=f"{label} at line {line_no}: {snippet!r}",
                    line=line_no,
                    column=m.start() + 1,
                    suggestion=suggestion,
                ))

        # Soft warnings
        for code, pattern, label, suggestion in SOFT_WARNING_PATTERNS:
            for m in re.finditer(pattern, line):
                # Skip email in metadata.author context (lines containing "email:")
                if code == ErrorCode.SECURITY_EMAIL_IN_PROMPT:
                    if "email:" in line or "author:" in line:
                        continue
                issues.append(Issue(
                    severity=Severity.WARNING,
                    code=code,
                    message=f"{label} at line {line_no}",
                    line=line_no,
                    column=m.start() + 1,
                    suggestion=suggestion,
                ))

    return issues
