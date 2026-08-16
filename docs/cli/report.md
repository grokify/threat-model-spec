# tms report

Derive a framework-specific report from the canonical model.

## Synopsis

```bash
tms report <input.json> --framework <name> [flags]
```

## Description

`tms report` computes a `FrameworkReport` — STRIDE, LINDDUN, MITRE ATT&CK, OWASP, or attack-tree — from one canonical model. It is a **pure read command**: the report is always derived fresh from the model's current state, and `tms report` never writes to the model. (`ThreatModel.FrameworkReports` exists for callers who want to materialize a snapshot into the document itself, e.g. for an audit trail — that's a capability of the format, not something this command does.)

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--framework` | | Framework to report on: `stride`, `linddun`, `mitre-attack`, `owasp`, `attack-tree` (required) |
| `--format` | | Output format: `json` (default) or `markdown` |
| `--output` | `-o` | Output file (default: stdout) |
| `--help` | `-h` | Show help |

## Examples

### STRIDE Report (JSON)

```bash
tms report threat-model.json --framework stride
```

```json
{
  "id": "framework-report-stride",
  "framework": "stride",
  "strideBody": {
    "mappings": [
      {"category": "S", "name": "Spoofing", "description": "...", "affectedComponents": ["ws-gateway"]}
    ],
    "coverageByCategory": {"S": 1, "I": 1, "E": 1},
    "categoriesCovered": ["S", "I", "E"],
    "categoriesMissing": ["T", "R", "D"]
  }
}
```

### Markdown Report

```bash
tms report threat-model.json --framework stride --format markdown
```

```markdown
# STRIDE Report

## Coverage

| Category | Name | Mappings |
|----------|------|----------|
| S | Spoofing | 1 |
| T | Tampering | 0 |
...

## Uncovered Categories

- Tampering (T)
- Repudiation (R)
- Denial of Service (D)
```

### Write to a File

```bash
tms report threat-model.json --framework attack-tree -o report.json
```

```
Report written: report.json
```

### Stale Report Warning

If the model already carries a materialized `FrameworkReport` in `frameworkReports` whose `sourceRevision` no longer matches a fresh computation, `tms report` (and `tms validate`) print a warning to stderr:

```
Warning: framework report "framework-report-stride" (stride) is stale relative to the current model
```

## Frameworks

| Framework | Source diagram(s) used |
|-----------|-------------------------|
| `stride` | Findings/mappings tagged with STRIDE categories, model-wide |
| `linddun` | Findings/mappings tagged with LINDDUN categories, model-wide |
| `mitre-attack` | Attack-chain diagram steps, joined against any detection coverage matrix |
| `owasp` | Findings/mappings tagged with OWASP category IDs, model-wide |
| `attack-tree` | The model's attack-tree diagram if present; falls back to an attack-chain diagram, then the first diagram, inferring entry points from external-entity elements and targets from datastore elements |

## See Also

- [Framework Mappings](../specification/mappings.md) — the underlying `mappings` schema
- [status](status.md) — a lifecycle-level summary, not framework-specific
- [generate](generate.md) — D2/STIX generation, a different kind of derived output
