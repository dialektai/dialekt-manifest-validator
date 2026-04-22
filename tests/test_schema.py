import pytest
from dialekt_manifest import validate

VALID_FIXTURES = [
    "tests/fixtures/valid/minimal.agent.yaml",
    "tests/fixtures/valid/sql_analyst.agent.yaml",
    "tests/fixtures/valid/scheduled_report.agent.yaml",
    "tests/fixtures/valid/carousel_generator.agent.yaml",
    "tests/fixtures/valid/code_review.agent.yaml",
]


@pytest.mark.parametrize("path", VALID_FIXTURES)
def test_valid_manifests_pass(path):
    result = validate(path)
    assert result.valid, f"Expected valid but got errors: {result.errors}"


def test_valid_manifests_no_errors():
    """All valid fixtures must produce zero errors and zero warnings."""
    for path in VALID_FIXTURES:
        result = validate(path)
        assert result.valid, f"{path}: expected valid, got errors: {[i.message for i in result.errors]}"
        assert not result.warnings, f"{path}: expected no warnings, got: {[i.message for i in result.warnings]}"


def test_missing_autonomy():
    result = validate("tests/fixtures/invalid/missing_autonomy.agent.yaml")
    assert not result.valid
    assert any(i.code.value == "schema.required" for i in result.errors)


def test_bad_uuid():
    result = validate("tests/fixtures/invalid/bad_uuid.agent.yaml")
    assert not result.valid
    assert any("uuid" in i.message.lower() or "uuid" in i.code.value.lower() for i in result.errors)


def test_bad_cron():
    result = validate("tests/fixtures/invalid/bad_cron.agent.yaml")
    assert not result.valid


def test_bad_timezone():
    result = validate("tests/fixtures/invalid/bad_timezone.agent.yaml")
    assert not result.valid
