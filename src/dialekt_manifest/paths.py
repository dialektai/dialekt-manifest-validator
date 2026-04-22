import re
from .errors import ErrorCode, Issue, Severity

SYSTEM_DIRS_UNIX = [
    "/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc",
    "/lib", "/lib64", "/opt/homebrew", "/System", "/private",
    "/.ssh", "/.gnupg", "/Library/Keychains",
]

SYSTEM_DIRS_WINDOWS = [
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    "C:\\ProgramData", "C:\\System32",
]

PATH_VARS = {"{user_home}", "{workspace}", "{date}", "{datetime}", "{agent_id}"}


def check_path_safety(path: str) -> list[Issue]:
    issues: list[Issue] = []

    # Check for path traversal
    if ".." in path:
        issues.append(Issue(
            severity=Severity.ERROR,
            code=ErrorCode.PATH_TRAVERSAL,
            message=f"Path contains '..' traversal: {path!r}",
            suggestion="Use absolute paths without '..' components.",
        ))
        return issues

    # Substitute path vars with safe placeholders for analysis
    normalized = path
    for var in PATH_VARS:
        normalized = normalized.replace(var, "/home/user")

    # Expand ~ shorthand
    normalized = normalized.replace("~", "/home/user")

    # Check against system directories
    check_path = normalized.lower().replace("\\", "/")
    for sys_dir in SYSTEM_DIRS_UNIX:
        if check_path.startswith(sys_dir.lower() + "/") or check_path == sys_dir.lower():
            issues.append(Issue(
                severity=Severity.ERROR,
                code=ErrorCode.PATH_SYSTEM_DIR,
                message=f"Output path resolves to system directory: {path!r}",
                suggestion=f"Use a user-writable path like '{{user_home}}/reports/' instead of system directories like '{sys_dir}'.",
            ))
            return issues

    # Check well-known sensitive user directories
    sensitive_home = ["/.ssh", "/.gnupg", "/Library/Keychains", "/.config"]
    for sensitive in sensitive_home:
        if sensitive.lower() in check_path:
            issues.append(Issue(
                severity=Severity.ERROR,
                code=ErrorCode.PATH_SYSTEM_DIR,
                message=f"Output path targets sensitive directory: {path!r}",
                suggestion="Choose a safer output directory like '{user_home}/reports/'.",
            ))
            return issues

    return issues
