---
name: analyze-builder-operations
description: Run a Builder Operations-stage threat model analysis via the builder-operations-analyst agent and tms analyze
arguments:
  - name: model
    type: string
    required: true
    description: Path to the ThreatModel JSON file to analyze
  - name: inputs
    type: string
    required: true
    description: Space-separated paths to runtime-endpoint, telemetry, and/or incident artifacts
  - name: profile
    type: string
    required: false
    default: first-party
    description: Artifact-availability profile - first-party, third-party, or open-source
dependencies: [tms]
process:
  - Invoke the builder-operations-analyst agent with the given model, inputs, and profile
  - Agent runs `tms analyze --stage builder-operations` in plan mode to open a run
  - Agent assesses detection coverage against this product's actual Builder Definition-stage threats
  - Agent runs an adversarial critic pass before finalizing
  - Agent writes AnalysisResults and runs `tms analyze --stage builder-operations --apply` to merge and close the run
---

# Analyze: Builder Operations

Runs a full Builder Operations-stage analysis cycle by delegating to the
[`builder-operations-analyst`](../agents/builder-operations-analyst.md)
agent.

## Usage

```bash
/analyze-builder-operations model.json "telemetry/invoice-access-query.json" first-party
```

## What this does

1. Opens an `AnalysisRun` for the `builder-operations` stage against the
   resolved telemetry/incident/endpoint inputs (`tms analyze` plan mode).
2. The agent assesses detection coverage and control effectiveness against
   this product's own identified threats, grounds incident-related
   findings in cited evidence, and explicitly states dynamic-testing
   scope for the run.
3. Merges the agent's `Finding` results and closes the run (`tms analyze`
   apply mode) — no known gaps for this stage.
4. Runs `tms gate model.json --stage builder-operations --ci` to evaluate
   the stage gate.

## See Also

- Agent: `agents/specs/agents/builder-operations-analyst.md`
- Rubric: `evaluation/rubrics/stages/builder-operations.rubric.json`
- Report profile: `ir/stagereports/builder-operations.json`
