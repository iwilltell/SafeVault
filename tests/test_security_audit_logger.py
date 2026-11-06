
from app.security import audit_logger


def test_security_event_is_recorded(monkeypatch):
    recorded = {}

    def fake_record_event(user_id, event_type, details):
        recorded["user_id"] = user_id
        recorded["event_type"] = event_type
        recorded["details"] = details
        return True

    monkeypatch.setattr(
        audit_logger,
        "record_event",
        fake_record_event,
    )

    result = audit_logger.log_security_event(
        1,
        "eicar_test_signature",
        "sample.txt",
    )

    assert result is True
    assert recorded["user_id"] == 1
    assert recorded["event_type"] == "THREAT_DETECTED"
    assert "eicar_test_signature" in recorded["details"]
    assert "sample.txt" in recorded["details"]


def test_empty_threat_name_is_rejected(monkeypatch):
    monkeypatch.setattr(
        audit_logger,
        "record_event",
        lambda *args: True,
    )

    result = audit_logger.log_security_event(
        1,
        "",
        "sample.txt",
    )

    assert result is False


def test_empty_filename_is_rejected(monkeypatch):
    monkeypatch.setattr(
        audit_logger,
        "record_event",
        lambda *args: True,
    )

    result = audit_logger.log_security_event(
        1,
        "suspicious_file_extension",
        "",
    )

    assert result is False


def test_database_logging_failure_is_returned(monkeypatch):
    monkeypatch.setattr(
        audit_logger,
        "record_event",
        lambda *args: False,
    )

    result = audit_logger.log_security_event(
        1,
        "eicar_test_signature",
        "sample.txt",
    )

    assert result is False
