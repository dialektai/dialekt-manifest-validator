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


def test_bad_uuid_invalid_format():
    """Completely malformed UUID string must be rejected."""
    result = validate("tests/fixtures/invalid/bad_uuid.agent.yaml")
    assert not result.valid
    assert any("uuid" in i.message.lower() or "uuid" in i.code.value.lower() for i in result.errors)


def test_bad_uuid_wrong_version():
    """Valid UUID format but version != 4 must be rejected (strict v4 enforcement)."""
    from dialekt_manifest import ManifestValidator
    # 9a8b7c6d-5432-1098-7654-fedcba098765 is version=None (NCS variant), not v4
    yaml_content = open("tests/fixtures/valid/minimal.agent.yaml").read()
    yaml_content = yaml_content.replace(
        '"550e8400-e29b-41d4-a716-446655440000"',
        '"9a8b7c6d-5432-1098-7654-fedcba098765"',
    )
    v = ManifestValidator()
    result = v.validate_string(yaml_content)
    assert not result.valid
    uuid_errors = [i for i in result.errors if "uuid" in i.message.lower() or "uuid v4" in i.message.lower()]
    assert uuid_errors, f"Expected UUID v4 error, got: {[i.message for i in result.errors]}"


def test_bad_cron():
    result = validate("tests/fixtures/invalid/bad_cron.agent.yaml")
    assert not result.valid


def test_bad_timezone():
    result = validate("tests/fixtures/invalid/bad_timezone.agent.yaml")
    assert not result.valid
