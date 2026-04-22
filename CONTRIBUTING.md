# Contributing

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=dialekt_manifest
```

## Adding New Validation Rules

1. Add error code to `src/dialekt_manifest/errors.py` (`ErrorCode` enum)
2. Implement check in the appropriate module:
   - Schema/format rules: `src/dialekt_manifest/schema.py` (Pydantic validators)
   - Semantic rules: `src/dialekt_manifest/validator.py` (`_check_*` functions)
   - Security patterns: `src/dialekt_manifest/security.py`
   - Path safety: `src/dialekt_manifest/paths.py`
3. Add test fixture in `tests/fixtures/invalid/`
4. Add test case in appropriate `tests/test_*.py`

## Code Style

- All public functions must have docstrings
- Type hints on all function signatures
- No bare `except:` — always catch specific exceptions
