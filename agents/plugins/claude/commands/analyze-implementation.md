---
description: Artifact-availability profile - first-party or open-source (third-party has no source access; implementation is not analyzable under that profile)
---

# Analyze Implementation

Artifact-availability profile - first-party or open-source (third-party has no source access; implementation is not analyzable under that profile)

## Process

1. Invoke the implementation-analyst agent with the given model, inputs, and profile
2. Agent runs `tms analyze --stage implementation` in plan mode to open a run
3. Agent works through the 5 implementation-stage ASPM domains, tracing reachability for each candidate finding
4. Agent runs an adversarial critic pass before finalizing
5. Agent writes AnalysisResults and runs `tms analyze --stage implementation --apply` to merge and close the run

## Dependencies

- `tms`

## Instructions

# Analyze: Implementation

Runs a full Implementation-stage analysis cycle by delegating to the
[`implementation-analyst`](../agents/implementation-analyst.md) agent.

## Usage

```bash
/analyze-implementation model.json "internal/billing/query.go go.sum sbom.spdx.json" first-party
```

## What this does

1. Opens an `AnalysisRun` for the `implementation` stage against the
   resolved source-tree/manifest/SBOM inputs (`tms analyze` plan mode).
2. The agent works through the 5 implementation-stage ASPM domains
   (git-posture, code-security, secret-pii-scan, open-source-security,
   sbom), tracing reachability for each candidate vulnerability and
   citing file+line evidence.
3. Merges the agent's `Finding`/`ArchitectureAssertion` results and closes
   the run (`tms analyze` apply mode) — no known gaps for this stage.
4. Runs `tms gate model.json --stage implementation --ci` to evaluate the
   stage gate.

## See Also

- Agent: `agents/specs/agents/implementation-analyst.md`
- Rubric: `evaluation/rubrics/stages/implementation.rubric.json`
- Report profile: `ir/stagereports/implementation.json`
