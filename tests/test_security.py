import pytest
from dialekt_manifest import validate


def test_openai_key_rejected():
    result = validate("tests/fixtures/invalid/secret_openai_key.agent.yaml")
    assert not result.valid
    assert any(i.code.value == "security.openai_key" for i in result.errors)


def test_anthropic_key_rejected():
    result = validate("tests/fixtures/invalid/secret_anthropic_key.agent.yaml")
    assert not result.valid
    assert any(i.code.value == "security.anthropic_key" for i in result.errors)


def test_db_credentials_rejected():
    result = validate("tests/fixtures/invalid/secret_db_connection.agent.yaml")
    assert not result.valid
    assert any(i.code.value == "security.db_credentials" for i in result.errors)


def test_clean_manifest_no_security_errors():
    result = validate("tests/fixtures/valid/minimal.agent.yaml")
    security_errors = [i for i in result.errors if i.code.value.startswith("security.")]
    assert not security_errors


def test_entropy_scanner_catches_ascii_key_in_cyrillic_text():
    """ASCII secret embedded in Cyrillic text must be caught via token-based scan."""
    from dialekt_manifest.entropy import scan_entropy

    # Simulate a system_prompt line with Cyrillic + embedded high-entropy ASCII token
    # The ASCII part alone (40+ chars of mixed case+digits) should trigger entropy warning
    cyrillic_with_key = "  Используй ключ sk-proj-aBc123DeF456GhI789JkL012MnO345PqR678StU901VwX234 для доступа."
    issues = scan_entropy(cyrillic_with_key)
    assert issues, "Expected high-entropy warning for ASCII key in Cyrillic text"
    assert issues[0].code.value == "security.high_entropy"


def test_entropy_scanner_does_not_flag_pure_cyrillic():
    """Pure Cyrillic system_prompt text must NOT trigger entropy warnings."""
    from dialekt_manifest.entropy import scan_entropy

    cyrillic_only = "  Ты опытный SQL-аналитик для отдела продаж. Отвечай на языке пользователя."
    issues = scan_entropy(cyrillic_only)
    assert not issues, f"Expected no warnings for Cyrillic text, got: {[i.message for i in issues]}"
