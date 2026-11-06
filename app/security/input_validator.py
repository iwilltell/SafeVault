
import re
from pathlib import PurePath

ALLOWED_EXTENSIONS = {
    ".txt", ".pdf", ".png", ".jpg", ".jpeg",
    ".csv", ".docx", ".xlsx"
}

MAX_FILENAME_LENGTH = 255
MAX_INPUT_LENGTH = 1000


def validate_text_input(value: str) -> bool:
    """Validate basic user-provided text."""
    if not isinstance(value, str):
        return False

    if not value or len(value) > MAX_INPUT_LENGTH:
        return False

    if "\x00" in value:
        return False

    return True


def validate_filename(filename: str) -> bool:
    """Reject unsafe filenames and unsupported extensions."""
    if not isinstance(filename, str):
        return False

    if not filename or len(filename) > MAX_FILENAME_LENGTH:
        return False

    if "\x00" in filename:
        return False

    # Reject path traversal and directory separators.
    if "/" in filename or "\\" in filename:
        return False

    if filename in {".", ".."}:
        return False

    if ".." in filename:
        return False

    extension = PurePath(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return False

    return True


def detect_suspicious_input(value: str) -> list[str]:
    """Identify common suspicious input patterns."""
    if not isinstance(value, str):
        return ["invalid_input_type"]

    threats = []

    patterns = {
        "sql_injection": r"(\bUNION\s+SELECT\b|\bOR\s+1\s*=\s*1\b|--\s*$)",
        "script_injection": r"<\s*script\b|javascript\s*:",
        "path_traversal": r"\.\.[/\\]",
        "command_injection": r";\s*(whoami|dir|ls|rm|del|powershell)\b",
    }

    for threat_name, pattern in patterns.items():
        if re.search(pattern, value, re.IGNORECASE):
            threats.append(threat_name)

    return threats
