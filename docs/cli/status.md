# tms status

Summarize a model's PDLC lifecycle state.

## Synopsis

```bash
tms status <input.json> [flags]
```

## Description

`tms status` is a pure read command: for every PDLC stage, it reports how many `AnalysisRun`s exist, the most recent run's status, and the stage's recorded `Gate` result (if any) — plus a model-wide breakdown of `Finding`s by adjudication status. Nothing here is computed fresh the way [`tms report`](report.md) computes framework reports; it's a summary of what's already recorded in the model.

## Flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `--ci` | Exit non-zero if any recorded gate has failed |
| `--help`, `-h` | Show help |

## Examples

### Default Output

```bash
tms status threat-model.json
```

Output:
```
Threat Model Spec Self-Assessment (threat-model-spec-self-assessment)
Current stage: implementation

STAGE                    RUNS  LATEST STATUS     GATE
product-definition           1  completed         failed
builder-definition            1  completed         passed
implementation                1  completed         pending
deployment                    0  -                 -
builder-operations            0  -                 -
product-operations            0  -                 -

Findings: 2 total (0 candidate, 2 validated, 0 rejected, 0 insufficient-evidence)
```

A stage with zero runs shows `-` for both latest status and gate.

### JSON Output

```bash
tms status threat-model.json --json
```

```json
{
  "modelId": "threat-model-spec-self-assessment",
  "title": "Threat Model Spec Self-Assessment",
  "currentStage": "implementation",
  "stages": [
    {"stage": "product-definition", "runs": 1, "latestRunStatus": "completed", "gateResult": "failed"},
    {"stage": "builder-definition", "runs": 1, "latestRunStatus": "completed", "gateResult": "passed"},
    {"stage": "implementation", "runs": 1, "latestRunStatus": "completed", "gateResult": "pending"},
    {"stage": "deployment", "runs": 0},
    {"stage": "builder-operations", "runs": 0},
    {"stage": "product-operations", "runs": 0}
  ],
  "findings": {"total": 2, "candidate": 0, "validated": 2, "rejected": 0, "insufficientEvidence": 0}
}
```

### CI Enforcement

```bash
tms status threat-model.json --ci
```

Exits `1` if any stage's recorded `gateResult` is `failed` — regardless of which stage, unlike [`tms gate --ci`](gate.md) which checks a single named stage.

## See Also

- [gate](gate.md) — the recorded `Gate` detail for a single stage
- [analyze](analyze.md) — the command that opens runs and records gates
- [Lifecycle IR Objects](../specification/lifecycle-objects.md) — `AnalysisRun`, `Gate`, `Finding` field reference
