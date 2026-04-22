# dialekt-manifest-validator

**Catch broken agent manifests before they reach runtime.**

A Python library and CLI that validates [dialekt](https://github.com/dialektai/dialektai) `.agent.yaml` manifest files against [spec v1.0.1](https://github.com/dialektai/dialektai/blob/main/AGENT_MANIFEST_SPEC.md). Structural errors, semantic inconsistencies, and hardcoded secrets — all caught before import.

---

## 30-second start

```bash
pip install dialekt-manifest-validator
dialekt-validate-manifest my-agent.agent.yaml
```

**Valid:**
```
✓ my-agent.agent.yaml: "SQL Analyst" (1.0.0)
```

**Invalid:**
```
✗ my-agent.agent.yaml — 2 errors, 1 warning

  ✗ [security.openai_key] line 14: OpenAI API key detected
    → Remove this key. Declare it in `secrets_required` and store in OS keychain.

  ✗ [semantic.variable_undefined] system_prompt references {{company}} but it is not declared in `variables`
    → Add `company` to the `variables` section.

  ⚠ [semantic.streaming_image] output.streaming should be false for image format
    → Set output.streaming=false for image output.
```

---

## What it validates

| Layer | Examples |
|-------|---------|
| **Structure** | Required fields, correct types, UUID v4, semver, ISO 8601 timestamps |
| **Semantic** | Undeclared `{{variables}}`, broken environments, autonomy ordering, cron frequency |
| **Security** | OpenAI/Anthropic/GitHub/AWS/Telegram/Slack tokens, private keys, JWT, DB connection strings with credentials, high-entropy strings |
| **Paths** | Output paths targeting `/etc`, `~/.ssh`, Windows system dirs |
| **Capabilities** | `filesystem` destination without `filesystem_write` capability, etc. |

---

## CLI

```bash
# Validate one or more files
dialekt-validate-manifest agent.yaml
dialekt-validate-manifest agents/**/*.yaml

# JSON output (for CI pipelines)
dialekt-validate-manifest --format json agent.yaml

# Strict: treat warnings as errors
dialekt-validate-manifest --strict agent.yaml

# Schema only: skip security and semantic checks
dialekt-validate-manifest --schema-only agent.yaml

# Export JSON Schema for IDE autocompletion
dialekt-validate-manifest --emit-schema > schema.json
```

**Exit codes:** `0` = valid, `1` = warnings only, `2` = errors

---

## Python API

```python
from dialekt_manifest import validate

result = validate("my-agent.agent.yaml")

result.valid       # bool
result.errors      # list[Issue]
result.warnings    # list[Issue]
result.manifest    # parsed AgentManifest | None
```

```python
from dialekt_manifest import ManifestValidator

v = ManifestValidator(strict=True)
result = v.validate_file("agent.yaml")
result = v.validate_string(yaml_string)
result = v.validate_dict(data_dict)
```

```python
# JSON Schema for IDE integration
from dialekt_manifest import export_json_schema
import json

schema = export_json_schema()
print(json.dumps(schema, indent=2))
```

---

## IDE autocompletion (VSCode)

Install the [YAML extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml), then add to `.vscode/settings.json`:

```json
{
  "yaml.schemas": {
    "https://raw.githubusercontent.com/dialektai/dialekt-manifest-validator/main/schemas/agent-manifest-v1.0.1.json": [
      "*.agent.yaml",
      "*.agent.yml"
    ]
  }
}
```

---

## CI integration

**GitHub Actions:**
```yaml
- name: Validate agent manifests
  run: |
    pip install dialekt-manifest-validator==0.1.0
    dialekt-validate-manifest --strict agents/**/*.yaml
```

**pre-commit:**
```yaml
repos:
  - repo: local
    hooks:
      - id: dialekt-validate
        name: Validate agent manifests
        language: python
        additional_dependencies: [dialekt-manifest-validator==0.1.0]
        entry: dialekt-validate-manifest --strict
        files: \.agent\.(yaml|yml)$
```

---

## Spec

Agent manifest spec v1.0.1: [AGENT_MANIFEST_SPEC.md](https://github.com/dialektai/dialektai/blob/main/AGENT_MANIFEST_SPEC.md)

---

## License

[GNU Affero General Public License v3.0](LICENSE)

For commercial use without AGPL obligations: hello@dias.now
