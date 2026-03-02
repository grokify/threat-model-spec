# CLI Reference

The `tms` (Threat Model Spec) CLI provides commands for generating and validating threat model diagrams.

## Installation

```bash
go install github.com/grokify/threat-model-spec/cmd/tms@latest
```

## Commands

| Command | Description |
|---------|-------------|
| `generate` | Generate D2 diagram or STIX 2.1 from JSON |
| `validate` | Validate a threat model JSON file |
| `version` | Print version information |
| `completion` | Generate shell completion scripts |

## Quick Reference

```bash
# Generate D2 diagram
tms generate model.json -o diagram.d2

# Generate D2 and render to SVG
tms generate model.json -o diagram.d2 --svg

# Export to STIX 2.1
tms generate model.json --stix -o model.stix.json

# Validate a model
tms validate model.json

# Strict validation
tms validate model.json --strict

# Print version
tms version
```

## Global Options

```
-h, --help   Show help for any command
```

## Shell Completion

Generate completion scripts for your shell:

=== "Bash"

    ```bash
    tms completion bash > /etc/bash_completion.d/tms
    ```

=== "Zsh"

    ```bash
    tms completion zsh > "${fpath[1]}/_tms"
    ```

=== "Fish"

    ```bash
    tms completion fish > ~/.config/fish/completions/tms.fish
    ```

=== "PowerShell"

    ```powershell
    tms completion powershell > tms.ps1
    ```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (validation failed, file not found, etc.) |

## Next Steps

- [generate](generate.md) — Generate D2 or STIX 2.1
- [validate](validate.md) — Validate threat models
