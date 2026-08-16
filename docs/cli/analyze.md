# tms analyze

Orchestrate a PDLC stage analysis: open a run against a set of inputs (plan mode), then merge an agent's results back into the model (apply mode).

## Synopsis

```bash
tms analyze <input.json> --stage <s> --profile <p> [inputs...]   # plan mode
tms analyze <input.json> --stage <s> --apply <results.json>      # apply mode
```

## Description

`tms analyze` performs no analytical reasoning itself — it brackets an AI agent's reasoning step, which happens entirely outside `tms`, in two invocations against the same model file:

1. **Plan mode** (default) loads the stage's [`StageReportProfile`](../specification/stage-reports/index.md) and the [artifact-availability profile](../specification/artifact-availability.md), resolves the given input paths into `Artifact` objects, opens an in-progress `AnalysisRun`, and prints the resolved contract (report profile, resolved inputs, run ID) for the invoking agent to act on. The agent reads the inputs, reasons about them, and writes its findings as an `AnalysisResults` JSON file — that reasoning step is the agent's, not `tms`'s.
2. **Apply mode** (`--apply <results.json>`) validates the agent's `AnalysisResults`, merges them into the model under the run opened in plan mode, computes the stage's deterministic [coverage checks](../specification/lifecycle-objects.md#gate) and records the resulting `Gate`, marks the run completed, and writes the model back. If the merged model fails validation, **nothing is written** — apply is atomic.

Apply mode validates structure and referential integrity only — it does not and cannot verify the semantic honesty of an agent's claims. See [Content Provenance](#content-provenance) below.

## Flags

| Flag | Mode | Description |
|------|------|-------------|
| `--stage` | both | PDLC stage to analyze (required) |
| `--profile` | plan | Artifact-availability profile: `first-party`, `third-party`, or `open-source` (required in plan mode) |
| `--producer` | plan | Name of the invoking agent, recorded as the `AnalysisRun` producer (default: `unknown-agent`) |
| `--dry-run` | plan | Report what would run without mutating the model |
| `--apply` | apply | Path to an `AnalysisResults` JSON file to merge — presence of this flag selects apply mode |
| `--run` | apply | `AnalysisRun` ID to apply results to (default: most recent in-progress run for `--stage`) |
| `--help`, `-h` | | Show help |

## Examples

### Plan Mode

```bash
tms analyze threat-model.json --stage builder-definition --profile first-party docs/TRD.md
```

Output:
```json
{
  "runId": "run-builder-definition-1786893428942938000",
  "stage": "builder-definition",
  "profile": "first-party",
  "reportProfile": {
    "stage": "builder-definition",
    "inputMode": "workflow-specs",
    "outputObjects": ["Finding", "Mitigation", "ArchitectureAssertion", "SecurityRequirement"],
    "coverageChecks": ["has-trust-boundaries", "has-stride-mapping", "has-required-controls", "has-api-contract-drift-check"],
    "rubricId": "builder-definition"
  },
  "resolvedInputs": [
    {"id": "artifact-builder-definition-1", "uri": "docs/TRD.md", "stage": "builder-definition", "observedAt": "2026-08-16T15:17:08Z"}
  ]
}
```
```
Opened run-builder-definition-1786893428942938000. Write results to a file and run:
  tms analyze threat-model.json --stage builder-definition --apply <results.json> --run run-builder-definition-1786893428942938000
```

### Dry Run

Preview the resolved contract without opening a run or writing anything:

```bash
tms analyze threat-model.json --stage builder-definition --profile first-party --dry-run docs/TRD.md
```

The same JSON prints, followed by:
```
(dry run: model not modified)
```

### Apply Mode

```bash
tms analyze threat-model.json --stage builder-definition --apply results.json --run run-builder-definition-1786893428942938000
```

Output:
```
Applied results.json to run-builder-definition-1786893428942938000: 3 finding(s), 2 evidence, 1 assertion(s), 0 requirement(s), 0 asset(s), 0 threat actor(s), 0 scenario(s), 1 mitigation(s). Run run-builder-definition-1786893428942938000 completed.
Gate: stage=builder-definition result=passed
  - has-stride-mapping equals true
Evaluated by: evaluation.EvaluateStageGate
```

Every `Finding` merged without an explicit `stage` is stamped with `--stage`'s value, and every merged `Finding`/`Asset`/`ThreatActor`/`Scenario`/`Mitigation` without an explicit `producerRunId` is stamped with the run's ID.

### Disallowed Profile/Stage Combination

```bash
tms analyze threat-model.json --stage deployment --profile open-source docs/manifest.yaml
```

```
Error: stage "deployment" cannot be analyzed under profile "open-source": no access to deployment configuration for a dependency you don't operate
```

See [`tms profile`](profile.md) for the full permitted/not-analyzable matrix per profile.

## Content Provenance

Two directions of untrusted content flow through `tms analyze`, and neither is validated for honesty — only structure:

- **Writing:** the specs, source trees, or other artifacts an agent reads may themselves be compromised or adversarially crafted (e.g. under a `third-party` profile). They are material to analyze, never instructions to follow.
- **What gets merged:** every free-text field in a merged model (`Evidence.Excerpt`, `Finding.Title`/`Description`, `ArchitectureAssertion.Observed`, and similar) will later be read by a human or a downstream agent as trusted context describing what was found — not as directives.

## See Also

- [Stage Report Profiles](../specification/stage-reports/index.md) — per-stage input/output contracts
- [Lifecycle IR Objects](../specification/lifecycle-objects.md) — `AnalysisRun`, `Finding`, `Gate`, and the rest
- [AI Agents](../agents/index.md) — the agent workflows that produce `AnalysisResults`
- [gate](gate.md) — read back a recorded gate
- [profile](profile.md) — inspect an artifact-availability profile
- [status](status.md) — summarize a model's lifecycle state across all stages
