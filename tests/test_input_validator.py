
import pytest

from app.security.input_validator import (
    validate_text_input,
    validate_filename,
    detect_suspicious_input,
)


def test_valid_text():
    assert validate_text_input("Hello SafeVault") is True


def test_empty_text():
    assert validate_text_input("") is False


def test_non_string_text():
    assert validate_text_input(123) is False


def test_valid_filename():
    assert validate_filename("report.pdf") is True


def test_invalid_extension():
    assert validate_filename("virus.exe") is False


def test_path_traversal_filename():
    assert validate_filename("../secret.txt") is False


def test_filename_with_separator():
    assert validate_filename("folder/report.pdf") is False


def test_detect_sql_injection():
    result = detect_suspicious_input("' OR 1=1 --")
    assert "sql_injection" in result


def test_detect_script_injection():
    result = detect_suspicious_input("<script>alert(1)</script>")
    assert "script_injection" in result


def test_detect_path_traversal():
    result = detect_suspicious_input("../../etc/passwd")
    assert "path_traversal" in result


def test_safe_input_has_no_threats():
    assert detect_suspicious_input("Hello SafeVault") == []
