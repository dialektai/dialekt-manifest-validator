"""Shared pytest fixtures for dialekt-manifest-validator tests."""
import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VALID_DIR = FIXTURES_DIR / "valid"
INVALID_DIR = FIXTURES_DIR / "invalid"
