
from app.security.threat_detector import (
    scan_file_content,
    is_file_safe,
    EICAR_TEST_SIGNATURE,
)


def test_safe_text_file():
    result = scan_file_content("notes.txt", b"Hello SafeVault")
    assert result == []


def test_unsupported_file_type():
    result = scan_file_content("program.exe", b"some content")
    assert "unsupported_file_type" in result


def test_suspicious_extension():
    result = scan_file_content("program.exe", b"some content")
    assert "suspicious_file_extension" in result


def test_double_extension():
    result = scan_file_content("report.pdf.exe", b"some content")
    assert "double_extension" in result


def test_eicar_signature_detection():
    result = scan_file_content("test.txt", EICAR_TEST_SIGNATURE)
    assert "eicar_test_signature" in result


def test_windows_executable_detection():
    result = scan_file_content("sample.txt", b"MZ" + b"\x00" * 20)
    assert "windows_executable" in result


def test_linux_executable_detection():
    result = scan_file_content("sample.txt", b"\x7fELF" + b"\x00" * 20)
    assert "linux_elf_executable" in result


def test_safe_file():
    assert is_file_safe("notes.txt", b"My personal notes") is True


def test_unsafe_file():
    assert is_file_safe("program.exe", b"MZ" + b"\x00" * 20) is False


def test_invalid_content_type():
    result = scan_file_content("notes.txt", "not bytes")
    assert result == ["invalid_file_content"]
