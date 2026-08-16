# tms gate

Print a PDLC stage's recorded gate result.

## Synopsis

```bash
tms gate <input.json> --stage <s> [flags]
```

## Description

`tms gate` is **read-only**: it reports a [`Gate`](../specification/lifecycle-objects.md#gate) already recorded in the model's `gates` array — written by [`tms analyze --apply`](analyze.md) — it does not compute one itself. There is no `tms gate --compute` or equivalent; gate computation only ever happens as part of an `analyze --apply` call.

## Flags

| Flag | Description |
|------|-------------|
| `--stage` | PDLC stage to evaluate (required) |
| `--ci` | Exit non-zero if the gate has not passed |
| `--json` | Output as JSON |
| `--help`, `-h` | Show help |

`--ci` treats a `pending` gate result (no recorded result yet) the same as `failed` — not passing.

## Examples

### Default Output

```bash
tms gate threat-model.json --stage deployment
```

Output:
```
Gate: stage=deployment result=passed
  - has-invariant equals true
Evaluated by: evaluation.EvaluateStageGate
```

### JSON Output

```bash
tms gate threat-model.json --stage deployment --json
```

```json
{
  "id": "gate-deployment",
  "stage": "deployment",
  "criteria": [{"metric": "has-invariant", "operator": "equals", "value": "true"}],
  "result": "passed",
  "evaluatedBy": "evaluation.EvaluateStageGate",
  "evaluatedAt": "2026-08-16T20:39:40Z"
}
```

### CI Enforcement

```bash
tms gate threat-model.json --stage deployment --ci
```

Exits `1` (no output beyond the default text report) if the recorded gate's `result` is `failed` or `pending`.

### No Gate Recorded

```bash
tms gate threat-model.json --stage product-operations
```

```
No gate recorded for stage "product-operations" in threat-model.json
```

Exits `1`. A stage only has a recorded gate after at least one `tms analyze --apply` call for it.

## See Also

- [analyze](analyze.md) — the only command that computes and writes a gate
- [status](status.md) — every stage's gate result at a glance, alongside run and finding counts
- [Lifecycle IR Objects](../specification/lifecycle-objects.md#gate) — the `Gate` object's full field reference
