---
description: Artifact-availability profile - first-party, third-party, or open-source
---

# Analyze Product Definition

Artifact-availability profile - first-party, third-party, or open-source

## Process

1. Invoke the product-definition-analyst agent with the given model, inputs, and profile
2. Agent runs `tms analyze --stage product-definition` in plan mode to open a run
3. Agent reads every input spec, drafts Asset/ThreatActor/Scenario/SecurityRequirement objects
4. Agent runs an adversarial critic pass before finalizing
5. Agent writes AnalysisResults (findings, evidence, securityRequirements, assets, threatActors, scenarios) and runs `tms analyze --stage product-definition --apply` to merge and close the run

## Dependencies

- `tms`

## Instructions

# Analyze: Product Definition

Runs a full Product Definition-stage analysis cycle by delegating to the
[`product-definition-analyst`](../agents/product-definition-analyst.md)
agent.

## Usage

```bash
/analyze-product-definition model.json "docs/PRD.md docs/UXD.md" first-party
```

## What this does

1. Opens an `AnalysisRun` for the `product-definition` stage against the
   resolved spec inputs (`tms analyze` plan mode).
2. The agent reads the specs and derives assets, threat actors, abuse
   scenarios, and security invariants — see the agent spec for the full
   process, output-object contract, and worked example.
3. Merges the agent's `Asset`/`ThreatActor`/`Scenario`/
   `SecurityRequirement`/`Evidence` results and closes the run (`tms
   analyze` apply mode) — the full output-object contract for this stage
   is directly supported, no manual model edits required.
4. Runs `tms validate --strict` to confirm the merged model is still
   referentially consistent.

## See Also

- Agent: `agents/specs/agents/product-definition-analyst.md`
- Rubric: `evaluation/rubrics/stages/product-definition.rubric.json`
- Report profile: `ir/stagereports/product-definition.json`
