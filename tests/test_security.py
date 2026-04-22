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
