"""Tests for the spec 1.1.0 ``mcp_servers`` block.

Shape checks (Pydantic), semantic checks (version gate, capability
gate), and secret auto-extension behaviour.
"""
import copy
import yaml

import pytest

from dialekt_manifest import ManifestValidator


def _load(path: str) -> dict:
    return yaml.safe_load(open(path).read())


def _validate_dict(data: dict):
    return ManifestValidator().validate_dict(data)


def test_mcp_basic_fixture_validates():
    result = ManifestValidator().validate_file(
        "tests/fixtures/valid/mcp_basic.agent.yaml"
    )
    assert result.valid, (
        "mcp_basic fixture should validate. Errors: "
        f"{[i.message for i in result.errors]}"
    )


def test_old_manifest_without_mcp_servers_still_validates():
    """Regression guard — 1.0.1 manifests without mcp_servers unchanged."""
    result = ManifestValidator().validate_file(
        "tests/fixtures/valid/minimal.agent.yaml"
    )
    assert result.valid, (
        "minimal (1.0.1) should still validate after 1.1.0 changes. "
        f"Errors: {[i.message for i in result.errors]}"
    )


def test_mcp_servers_on_old_spec_version_rejected():
    """spec_version 1.0.1 + mcp_servers → semantic.mcp_servers_version error."""
    data = _load("tests/fixtures/valid/mcp_basic.agent.yaml")
    data["spec_version"] = "1.0.1"
    result = _validate_dict(data)
    assert not result.valid
    assert any(
        i.code.value == "semantic.mcp_servers_version" for i in result.errors
    ), (
        "Expected mcp_servers_version error. Got: "
        f"{[(i.code.value, i.message) for i in result.errors]}"
    )


def test_mcp_servers_without_capability_rejected():
    """mcp_servers non-empty + 'mcp_tools' missing → semantic error."""
    data = _load("tests/fixtures/valid/mcp_basic.agent.yaml")
    data["capabilities"]["groups"] = ["filesystem_read"]  # drop mcp_tools
    result = _validate_dict(data)
    assert not result.valid
    assert any(
        i.code.value == "semantic.mcp_capability_missing" for i in result.errors
    )


def test_mcp_stdio_missing_command_rejected():
    """transport=stdio but no command → pydantic model_validator error."""
    data = _load("tests/fixtures/valid/mcp_basic.agent.yaml")
    data["mcp_servers"][0].pop("command")
    result = _validate_dict(data)
    assert not result.valid


def test_mcp_stdio_with_url_rejected():
    """transport=stdio + url set → pydantic model_validator error."""
    data = _load("tests/fixtures/valid/mcp_basic.agent.yaml")
    data["mcp_servers"][0]["url"] = "http://should-not-be-here"
    result = _validate_dict(data)
    assert not result.valid


def test_mcp_http_without_url_rejected():
    data = _load("tests/fixtures/valid/mcp_basic.agent.yaml")
    # Second entry is the http one.
    data["mcp_servers"][1].pop("url")
    result = _validate_dict(data)
    assert not result.valid


def test_mcp_unknown_transport_rejected():
    data = _load("tests/fixtures/valid/mcp_basic.agent.yaml")
    data["mcp_servers"][0]["transport"] = "carrier-pigeon"
    result = _validate_dict(data)
    assert not result.valid


def test_mcp_bad_server_name_rejected():
    """Server name pattern requires lowercase kebab/underscore start."""
    data = _load("tests/fixtures/valid/mcp_basic.agent.yaml")
    data["mcp_servers"][0]["name"] = "Bad Name With Spaces"
    result = _validate_dict(data)
    assert not result.valid


def test_mcp_secret_auto_extension_warns():
    """${secrets.*} refs in env/auth.token that aren't declared in
    secrets_required → warning + auto-add to secrets_required."""
    data = _load("tests/fixtures/valid/mcp_basic.agent.yaml")
    # Reference a new secret that the fixture DOESN'T declare.
    data["mcp_servers"][0]["env"]["EXTRA_KEY"] = "${secrets.brand_new_token}"

    result = _validate_dict(data)
    # Warning fired.
    assert any(
        i.code.value == "semantic.mcp_secret_auto_added"
        for i in result.warnings
    ), (
        "Expected mcp_secret_auto_added warning. Got: "
        f"{[(i.code.value, i.message) for i in result.warnings]}"
    )
    # Manifest.secrets_required was extended.
    names = {s.name for s in result.manifest.secrets_required}
    assert "brand_new_token" in names


def test_mcp_secret_already_declared_no_warning():
    """Refs to already-declared secrets don't warn or double-add."""
    result = ManifestValidator().validate_file(
        "tests/fixtures/valid/mcp_basic.agent.yaml"
    )
    assert result.valid
    names = [s.name for s in (result.manifest.secrets_required or [])]
    assert names.count("github_token") == 1
    assert names.count("jira_token") == 1
    assert not any(
        i.code.value == "semantic.mcp_secret_auto_added" for i in result.warnings
    )


def test_mcp_tools_capability_valid():
    """mcp_tools alone in capabilities.groups is accepted (no other gates)."""
    data = _load("tests/fixtures/valid/minimal.agent.yaml")
    data["capabilities"]["groups"] = ["mcp_tools"]
    result = _validate_dict(data)
    assert result.valid, (
        f"Expected valid, got errors: {[i.message for i in result.errors]}"
    )


def test_empty_mcp_servers_list_warns():
    """Present-but-empty list is useless — warn."""
    data = _load("tests/fixtures/valid/minimal.agent.yaml")
    data["spec_version"] = "1.1.0"
    data["mcp_servers"] = []
    result = _validate_dict(data)
    assert any(
        i.code.value == "semantic.mcp_servers_version" and "empty" in i.message.lower()
        for i in result.warnings
    )
