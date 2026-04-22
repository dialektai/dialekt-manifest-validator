# dialekt-manifest-validator

Validator for dialekt agent manifests (spec v1.0.1).

## Installation

```bash
pip install dialekt-manifest-validator
```

## Usage

```bash
dialekt-validate-manifest agent.yaml
```

## Python API

```python
from dialekt_manifest import validate

result = validate("my-agent.agent.yaml")
if result.valid:
    print("Valid!")
else:
    for error in result.errors:
        print(f"Error: {error.message}")
```
