---
description: Artifact-availability profile - first-party, third-party, or open-source
---

# Analyze Builder Definition

Artifact-availability profile - first-party, third-party, or open-source

## Process

1. Invoke the builder-definition-analyst agent with the given model, inputs, and profile
2. Agent runs `tms analyze --stage builder-definition` in plan mode to open a run
3. Agent maps trust boundaries, STRIDE threats per boundary crossing, and required controls
4. Agent runs an adversarial critic pass before finalizing
5. Agent writes AnalysisResults (findings, evidence, architectureAssertions, securityRequirements, mitigations) and runs `tms analyze --stage builder-definition --apply` to merge and close the run

## Dependencies

- `tms`

## Instructions

# Analyze: Builder Definition

Runs a full Builder Definition-stage analysis cycle by delegating to the
[`builder-definition-analyst`](../agents/builder-definition-analyst.md)
agent.

## Usage

```bash
/analyze-builder-definition model.json "docs/TRD.md docs/TPD.md docs/IRD.md" first-party
```

## What this does

1. Opens an `AnalysisRun` for the `builder-definition` stage against the
   resolved TRD/TPD/IRD inputs (`tms analyze` plan mode).
2. The agent maps trust boundaries and STRIDE-analyzes every
   boundary-crossing flow, matching validated threats to specific
   mitigations, and checks API contract drift against any Product
   Definition draft.
3. Merges the agent's `Finding`/`Mitigation`/`ArchitectureAssertion`/
   `SecurityRequirement` results and closes the run (`tms analyze` apply
   mode) — the full output-object contract for this stage is directly
   supported, no manual model edits required.
4. Runs `tms validate --strict` to confirm the merged model is still
   referentially consistent.

## See Also

- Agent: `agents/specs/agents/builder-definition-analyst.md`
- Rubric: `evaluation/rubrics/stages/builder-definition.rubric.json`
- Report profile: `ir/stagereports/builder-definition.json`
