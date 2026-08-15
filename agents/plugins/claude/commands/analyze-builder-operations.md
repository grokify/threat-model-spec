---
description: Artifact-availability profile - first-party, third-party, or open-source
---

# Analyze Builder Operations

Artifact-availability profile - first-party, third-party, or open-source

## Process

1. Invoke the builder-operations-analyst agent with the given model, inputs, and profile
2. Agent runs `tms analyze --stage builder-operations` in plan mode to open a run
3. Agent assesses detection coverage against this product's actual Builder Definition-stage threats
4. Agent runs an adversarial critic pass before finalizing
5. Agent writes AnalysisResults and runs `tms analyze --stage builder-operations --apply` to merge and close the run

## Dependencies

- `tms`

## Instructions

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
