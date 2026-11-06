
from app.services.audit_logger import record_event


def log_security_event(
    user_id: int | None,
    threat_name: str,
    filename: str,
) -> bool:
    """
    Record a detected security threat using SafeVault's central audit logger.

    Does not store file contents or passwords in the audit log.
    """
    if not isinstance(threat_name, str) or not threat_name.strip():
        return False

    if not isinstance(filename, str) or not filename.strip():
        return False

    details = (
        f"Threat detected: {threat_name.strip()}; "
        f"File: {filename.strip()}"
    )

    return record_event(
        user_id,
        "THREAT_DETECTED",
        details,
    )
