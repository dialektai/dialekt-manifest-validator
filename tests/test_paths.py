from dialekt_manifest import validate


def test_system_path_rejected():
    result = validate("tests/fixtures/invalid/unsafe_path.agent.yaml")
    assert not result.valid
    assert any(i.code.value == "path.system_dir" for i in result.errors)


def test_missing_filesystem_capability():
    result = validate("tests/fixtures/invalid/missing_filesystem_capability.agent.yaml")
    assert not result.valid
    assert any(i.code.value == "semantic.capability_missing" for i in result.errors)


def test_valid_path_passes():
    result = validate("tests/fixtures/valid/scheduled_report.agent.yaml")
    path_errors = [i for i in result.errors if i.code.value.startswith("path.")]
    assert not path_errors, f"Expected no path errors, got: {path_errors}"
