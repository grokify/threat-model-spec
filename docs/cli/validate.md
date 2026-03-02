# tms validate

Validate threat model JSON files.

## Synopsis

```bash
tms validate <input.json> [flags]
```

## Description

The `validate` command checks threat model JSON files for:

- Valid JSON syntax
- Required fields present
- Correct field types
- Valid enum values
- Element ID uniqueness
- Valid references (from/to point to existing elements)
- Type-specific field requirements

## Flags

| Flag | Description |
|------|-------------|
| `--strict` | Use strict validation (includes warnings) |
| `--help`, `-h` | Show help |

## Examples

### Basic Validation

```bash
tms validate attack.json
```

Output:
```
Validation passed: attack.json
```

### Strict Validation

```bash
tms validate attack.json --strict
```

Output:
```
Strict validation passed: attack.json
```

### Validation Failure

```bash
tms validate invalid.json
```

Output:
```
Validation failed: type is required
```

## Validation Rules

### Required Fields

All diagrams require:

- `type` — Diagram type (dfd, attack-chain, sequence)
- `title` — Diagram title

### Type-Specific Requirements

| Type | Required Fields |
|------|-----------------|
| `dfd` | elements |
| `attack-chain` | elements, attacks |
| `sequence` | actors, messages |

### Element Validation

- IDs must be unique
- Labels are required
- Types must be valid enum values

### Reference Validation

- `from` and `to` in flows must reference existing elements
- `parentId` must reference existing boundaries
- `elementId` in targets must reference existing elements

### Attack Chain Validation

- Steps must be sequential (1, 2, 3...)
- MITRE technique IDs should match pattern (T####)

## Strict Mode

Strict validation (`--strict`) adds additional checks:

- Recommended fields present
- Description fields populated
- Framework mappings complete
- CVSS vector valid

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Validation passed |
| 1 | Validation failed |

## Integration

Use in CI/CD pipelines:

```bash
#!/bin/bash
for f in models/*.json; do
  tms validate "$f" --strict || exit 1
done
echo "All models valid"
```

## Validation vs Generate

Both commands validate input, but:

- `validate` — Only validates, provides detailed errors
- `generate` — Validates then generates output

Use `validate` for:

- CI/CD checks
- Pre-commit hooks
- Debugging validation errors

## See Also

- [generate](generate.md) — Generate diagrams
- [JSON IR Specification](../specification/index.md) — Schema reference
