---
name: analyze-product-definition
description: Run a Product Definition-stage threat model analysis via the product-definition-analyst agent and tms analyze
arguments:
  - name: model
    type: string
    required: true
    description: Path to the ThreatModel JSON file to analyze
  - name: inputs
    type: string
    required: true
    description: Space-separated paths to product-definition workflow-spec artifacts (e.g. docs/PRD.md docs/UXD.md)
  - name: profile
    type: string
    required: false
    default: first-party
    description: Artifact-availability profile - first-party, third-party, or open-source
dependencies: [tms]
process:
  - Invoke the product-definition-analyst agent with the given model, inputs, and profile
  - Agent runs `tms analyze --stage product-definition` in plan mode to open a run
  - Agent reads every input spec, drafts Asset/ThreatActor/Scenario/SecurityRequirement objects
  - Agent runs an adversarial critic pass before finalizing
  - Agent writes AnalysisResults (findings, evidence, securityRequirements, assets, threatActors, scenarios) and runs `tms analyze --stage product-definition --apply` to merge and close the run
---

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
