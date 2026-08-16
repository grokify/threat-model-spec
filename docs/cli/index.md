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
| [`analyze`](analyze.md) | Run a stage analysis (plan mode) or apply its results (apply mode) |
| [`gate`](gate.md) | Print a PDLC stage's recorded gate result (read-only) |
| [`report`](report.md) | Derive a framework-specific report (STRIDE, LINDDUN, MITRE ATT&CK, OWASP, attack-tree) |
| [`status`](status.md) | Summarize a model's PDLC lifecycle state across all stages |
| [`profile`](profile.md) | Print a built-in artifact-availability profile definition |
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

# Open a stage analysis run (plan mode)
tms analyze model.json --stage builder-definition --profile first-party docs/TRD.md

# Merge an agent's results (apply mode) — also computes and records the stage's Gate
tms analyze model.json --stage builder-definition --apply results.json --run run-builder-definition-1

# Read back a recorded gate
tms gate model.json --stage builder-definition

# Derive a STRIDE report
tms report model.json --framework stride

# Summarize lifecycle state across all stages
tms status model.json

# Inspect an artifact-availability profile
tms profile first-party

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
- [analyze](analyze.md) — Run a stage analysis and merge its results
- [gate](gate.md) — Read back a recorded stage gate
- [report](report.md) — Derive a framework-specific report
- [status](status.md) — Summarize lifecycle state across all stages
- [profile](profile.md) — Inspect an artifact-availability profile
