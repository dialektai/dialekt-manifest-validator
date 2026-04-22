import subprocess
import sys
import json


def test_cli_valid_manifest_exit_0():
    result = subprocess.run(
        [sys.executable, "-m", "dialekt_manifest.cli", "tests/fixtures/valid/minimal.agent.yaml"],
        capture_output=True, text=True,
        cwd="/home/dias/projects/python/dialekt-manifest-validator"
    )
    # Exit 0 for valid
    assert result.returncode == 0, f"Expected exit 0, got {result.returncode}. stderr: {result.stderr}"


def test_cli_invalid_manifest_exit_nonzero():
    result = subprocess.run(
        [sys.executable, "-m", "dialekt_manifest.cli", "tests/fixtures/invalid/bad_uuid.agent.yaml"],
        capture_output=True, text=True,
        cwd="/home/dias/projects/python/dialekt-manifest-validator"
    )
    assert result.returncode != 0, f"Expected non-zero exit for invalid manifest, got 0"


def test_cli_emit_schema():
    result = subprocess.run(
        [sys.executable, "-m", "dialekt_manifest.cli", "--emit-schema"],
        capture_output=True, text=True,
        cwd="/home/dias/projects/python/dialekt-manifest-validator"
    )
    assert result.returncode == 0, f"Expected exit 0 for --emit-schema, got {result.returncode}. stderr: {result.stderr}"
    schema = json.loads(result.stdout)
    assert "properties" in schema or "$defs" in schema


def test_cli_json_output():
    result = subprocess.run(
        [sys.executable, "-m", "dialekt_manifest.cli",
         "--format", "json",
         "tests/fixtures/valid/minimal.agent.yaml"],
        capture_output=True, text=True,
        cwd="/home/dias/projects/python/dialekt-manifest-validator"
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert isinstance(output, list)
    assert output[0]["valid"] is True


def test_cli_multiple_files():
    result = subprocess.run(
        [sys.executable, "-m", "dialekt_manifest.cli",
         "tests/fixtures/valid/minimal.agent.yaml",
         "tests/fixtures/valid/code_review.agent.yaml"],
        capture_output=True, text=True,
        cwd="/home/dias/projects/python/dialekt-manifest-validator"
    )
    assert result.returncode == 0
