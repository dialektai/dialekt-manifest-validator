from dialekt_manifest import validate


def test_undeclared_variable_rejected():
    result = validate("tests/fixtures/invalid/undeclared_variable.agent.yaml")
    assert not result.valid
    assert any(i.code.value == "semantic.variable_undefined" for i in result.errors)


def test_declared_variables_pass():
    """sql_analyst has variables declared and used — should pass."""
    result = validate("tests/fixtures/valid/sql_analyst.agent.yaml")
    var_errors = [i for i in result.errors if i.code.value.startswith("semantic.variable")]
    assert not var_errors, f"Expected no variable errors, got: {var_errors}"


def test_no_variables_no_errors():
    """minimal agent has no variables — no variable errors expected."""
    result = validate("tests/fixtures/valid/minimal.agent.yaml")
    var_issues = [i for i in result.issues if "variable" in i.code.value]
    assert not var_issues, f"Expected no variable issues, got: {var_issues}"
