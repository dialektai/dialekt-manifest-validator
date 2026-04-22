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


def is_ascii_printable(s: str) -> bool:
    """Return True if string contains only ASCII printable characters (no spaces)."""
    return all(0x21 <= ord(c) <= 0x7E for c in s)


def scan_entropy(raw_yaml: str) -> list[Issue]:
    issues: list[Issue] = []
    lines = raw_yaml.splitlines()

    for line_no, line in enumerate(lines, start=1):
        # Extract string values from YAML lines (after : or as standalone)
        for m in re.finditer(r'["\']([^"\']{30,})["\']|:\s*([^\s#][^\n#]{29,})', line):
            candidate = (m.group(1) or m.group(2) or "").strip()
            if len(candidate) < MIN_LENGTH:
                continue
            # Only check entropy on ASCII strings — secrets/tokens are always ASCII.
            # Non-ASCII (Cyrillic, CJK, etc.) text has naturally high character entropy
            # that is not indicative of secrets.
            if not is_ascii_printable(candidate):
                continue
            if is_whitelisted(candidate):
                continue
            entropy = shannon_entropy(candidate)
            if entropy >= ENTROPY_THRESHOLD:
                issues.append(Issue(
                    severity=Severity.WARNING,
                    code=ErrorCode.SECURITY_HIGH_ENTROPY,
                    message=f"High-entropy string detected at line {line_no} (entropy={entropy:.2f})",
                    line=line_no,
                    suggestion="If this is a secret, move it to `secrets_required` and store in OS keychain. If not, this warning can be ignored.",
                ))
                break  # one warning per line

    return issues
