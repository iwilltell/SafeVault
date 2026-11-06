
from pathlib import PurePath

from app.security.input_validator import ALLOWED_EXTENSIONS


# Standard harmless antivirus test signature.
# This is a test pattern, not actual malware.
EICAR_TEST_SIGNATURE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".msi",
    ".ps1", ".vbs", ".scr", ".sh"
}


def scan_file_content(filename: str, content: bytes) -> list[str]:
    """
    Perform basic educational threat checks.

    Returns a list of detected threat names.
    Does not execute or modify the supplied file.
    """
    threats = []

    if not isinstance(filename, str) or not filename:
        return ["invalid_filename"]

    if not isinstance(content, bytes):
        return ["invalid_file_content"]

    path = PurePath(filename)
    extension = path.suffix.lower()

    # Check whether the file type is allowed.
    if extension not in ALLOWED_EXTENSIONS:
        threats.append("unsupported_file_type")

    # Detect executable or script file extensions.
    if extension in SUSPICIOUS_EXTENSIONS:
        threats.append("suspicious_file_extension")

    # Detect misleading double extensions, such as report.pdf.exe.
    parts = filename.lower().split(".")

    if len(parts) >= 3:
        previous_extension = "." + parts[-2]

        if (
            previous_extension in ALLOWED_EXTENSIONS
            and extension in SUSPICIOUS_EXTENSIONS
        ):
            threats.append("double_extension")

    # Detect the harmless EICAR antivirus test signature.
    if EICAR_TEST_SIGNATURE in content:
        threats.append("eicar_test_signature")

    # Detect common executable file headers.
    executable_signatures = {
        "windows_executable": b"MZ",
        "linux_elf_executable": b"\x7fELF",
    }

    for threat_name, signature in executable_signatures.items():
        if content.startswith(signature):
            threats.append(threat_name)

    return threats


def is_file_safe(filename: str, content: bytes) -> bool:
    """Return True only when no supported threat pattern is detected."""
    return len(scan_file_content(filename, content)) == 0
