import math
import re
from .errors import ErrorCode, Issue, Severity

ENTROPY_THRESHOLD = 4.5
MIN_LENGTH = 30

# Patterns that are high-entropy but NOT secrets
WHITELIST_PATTERNS = [
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',  # UUID
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO timestamp
    r'^https?://',  # URLs
    r'^[./~{]',  # Paths
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_whitelisted(s: str) -> bool:
    return any(re.match(pat, s, re.IGNORECASE) for pat in WHITELIST_PATTERNS)


def is_ascii_token(s: str) -> bool:
    """Return True if every character is ASCII printable (no spaces, no control chars)."""
    return bool(s) and all(0x21 <= ord(c) <= 0x7E for c in s)


def scan_entropy(raw_yaml: str) -> list[Issue]:
    """Scan YAML content for high-entropy ASCII tokens that may be secrets.

    Scans token-by-token so that an API key embedded inside a Russian sentence
    (e.g. "Используй ключ sk-proj-aBc123..." ) is still caught — the Cyrillic
    words are skipped individually, but the ASCII token is checked.
    """
    issues: list[Issue] = []
    lines = raw_yaml.splitlines()

    for line_no, line in enumerate(lines, start=1):
        flagged = False
        for token in line.split():
            # Only check pure-ASCII tokens — Cyrillic/CJK/etc. naturally score high
            if not is_ascii_token(token) or len(token) < MIN_LENGTH:
                continue
            if is_whitelisted(token):
                continue
            entropy = shannon_entropy(token)
            if entropy >= ENTROPY_THRESHOLD:
                issues.append(Issue(
                    severity=Severity.WARNING,
                    code=ErrorCode.SECURITY_HIGH_ENTROPY,
                    message=f"High-entropy string detected at line {line_no} (entropy={entropy:.2f}): {token[:20]}...",
                    line=line_no,
                    suggestion=(
                        "If this is a secret, move it to `secrets_required` and store in OS keychain. "
                        "If it's a legitimate value, this warning can be ignored."
                    ),
                ))
                flagged = True
                break  # one warning per line is enough

    return issues
