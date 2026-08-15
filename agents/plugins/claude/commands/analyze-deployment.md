---
description: Artifact-availability profile - first-party, third-party, or open-source
---

# Analyze Deployment

Artifact-availability profile - first-party, third-party, or open-source

## Process

1. Invoke the deployment-analyst agent with the given model, inputs, and profile
2. Agent runs `tms analyze --stage deployment` in plan mode to open a run
3. Agent works through the 4 deployment-stage ASPM domains, verifying required controls against actual deployed config
4. Agent runs an adversarial critic pass before finalizing
5. Agent writes AnalysisResults and runs `tms analyze --stage deployment --apply` to merge and close the run

## Dependencies

- `tms`

## Instructions

# Analyze: Deployment

Runs a full Deployment-stage analysis cycle by delegating to the
[`deployment-analyst`](../agents/deployment-analyst.md) agent.

## Usage

```bash
/analyze-deployment model.json "infra/invoices-service.tf k8s/invoices-service.yaml" first-party
```

## What this does

1. Opens an `AnalysisRun` for the `deployment` stage against the resolved
   IaC/manifest inputs (`tms analyze` plan mode).
2. The agent works through the 4 deployment-stage ASPM domains (iac-scan,
   cicd-posture, container-security, artifact-security), verifying every
   Builder Definition-required control against the actual deployed
   configuration and checking exposure drift.
3. Merges the agent's `Finding`/`ArchitectureAssertion` results and closes
   the run (`tms analyze` apply mode) — no known gaps for this stage.
4. Runs `tms gate model.json --stage deployment --ci` to evaluate the
   stage gate.

## See Also

- Agent: `agents/specs/agents/deployment-analyst.md`
- Rubric: `evaluation/rubrics/stages/deployment.rubric.json`
- Report profile: `ir/stagereports/deployment.json`
