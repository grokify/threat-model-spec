# tms generate

Generate D2 diagrams or STIX 2.1 bundles from threat model JSON files.

## Synopsis

```bash
tms generate <input.json> [flags]
```

## Description

The `generate` command converts threat model JSON (IR) files to either:

- **D2 diagrams** — Visual diagrams that can be rendered to SVG/PNG
- **STIX 2.1 bundles** — Structured threat intelligence format

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output file (default: stdout) |
| `--svg` | | Also render D2 to SVG (requires d2 CLI) |
| `--stix` | | Export to STIX 2.1 format instead of D2 |
| `--help` | `-h` | Show help |

## Examples

### Generate D2 Diagram

```bash
tms generate attack.json -o attack.d2
```

Output:
```
Generated D2: attack.d2
```

### Generate D2 and Render to SVG

```bash
tms generate attack.json -o attack.d2 --svg
```

Output:
```
Generated D2: attack.d2
Generated SVG: attack.svg
```

!!! note "D2 Required"
    The `--svg` flag requires the D2 CLI to be installed.
    See [d2lang.com](https://d2lang.com) for installation.

### Export to STIX 2.1

```bash
tms generate attack.json --stix -o attack.stix.json
```

Output:
```
Generated STIX: attack.stix.json
```

### Output to Stdout

Omit `-o` to print to stdout:

```bash
tms generate attack.json
```

### Pipe to D2

```bash
tms generate attack.json | d2 - attack.svg
```

## Input Format

The input must be a valid threat model JSON file:

```json
{
  "type": "attack-chain",
  "title": "Example Attack",
  "elements": [...],
  "attacks": [...]
}
```

See [JSON IR Specification](../specification/index.md) for full schema.

## D2 Output

The generated D2 includes:

- Element definitions with appropriate styles
- Trust boundaries as containers
- Flows/attacks as connections
- STRIDE annotations (if present)
- Legend (if enabled)

Example output:

```d2
direction: right

# Elements
attacker: Attacker {
  class: external-entity-malicious
}
browser: Victim Browser {
  class: browser
}

# Attack flows
attacker -> browser: "1. Serve malicious page" {
  class: attack-flow
}
```

## STIX 2.1 Output

The STIX bundle includes:

- **Identity** — Creator identity
- **Infrastructure** — For DFD elements
- **Threat Actors** — For malicious elements
- **Attack Patterns** — For attacks with MITRE mapping
- **Vulnerabilities** — For CWE mappings
- **Indicators** — For attack targets

Example output:

```json
{
  "type": "bundle",
  "id": "bundle--...",
  "objects": [
    {
      "type": "attack-pattern",
      "name": "Drive-by Compromise",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1189"
        }
      ]
    }
  ]
}
```

## Validation

The input is automatically validated before generation. If validation fails, an error is printed and no output is generated:

```bash
$ tms generate invalid.json -o out.d2
Validation failed: type is required
```

Use `tms validate` for more detailed validation output.

## See Also

- [validate](validate.md) — Validate without generating
- [JSON IR Specification](../specification/index.md) — Input format
- [D2 Styles](../styles/index.md) — Visual styling
