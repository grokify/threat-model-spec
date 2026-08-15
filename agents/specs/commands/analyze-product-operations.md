---
name: analyze-product-operations
description: Run a Product Operations-stage threat model analysis via the product-operations-analyst agent and tms analyze
arguments:
  - name: model
    type: string
    required: true
    description: Path to the ThreatModel JSON file to analyze
  - name: inputs
    type: string
    required: true
    description: Space-separated paths to telemetry and/or incident artifacts
  - name: profile
    type: string
    required: false
    default: first-party
    description: Artifact-availability profile - first-party, third-party, or open-source
dependencies: [tms]
process:
  - Invoke the product-operations-analyst agent with the given model, inputs, and profile
  - Agent runs `tms analyze --stage product-operations` in plan mode to open a run
  - Agent checks every critical Product Definition-stage SecurityRequirement against production telemetry, and tracks adoption signal
  - Agent runs an adversarial critic pass before finalizing
  - Agent writes AnalysisResults and runs `tms analyze --stage product-operations --apply` to merge and close the run
---

# Analyze: Product Operations

Runs a full Product Operations-stage analysis cycle by delegating to the
[`product-operations-analyst`](../agents/product-operations-analyst.md)
agent.

## Usage

```bash
/analyze-product-operations model.json "telemetry/invoice-download-access.json telemetry/invoice-export-adoption.json" first-party
```

## What this does

1. Opens an `AnalysisRun` for the `product-operations` stage against the
   resolved telemetry/incident inputs (`tms analyze` plan mode). This
   stage runs in parallel with Builder Operations, not after it.
2. The agent checks every critical-criticality `SecurityRequirement` from
   Product Definition against production telemetry, and includes
   adoption/usage signal so an absence of incidents is never mistaken for
   validated safety.
3. Merges the agent's `Finding`/`ArchitectureAssertion` results and closes
   the run (`tms analyze` apply mode) — no known gaps for this stage.
4. Runs `tms gate model.json --stage product-operations --ci` to evaluate
   the stage gate.

## See Also

- Agent: `agents/specs/agents/product-operations-analyst.md`
- Rubric: `evaluation/rubrics/stages/product-operations.rubric.json`
- Report profile: `ir/stagereports/product-operations.json`
