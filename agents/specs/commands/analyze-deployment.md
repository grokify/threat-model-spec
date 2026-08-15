---
name: analyze-deployment
description: Run a Deployment-stage threat model analysis via the deployment-analyst agent and tms analyze
arguments:
  - name: model
    type: string
    required: true
    description: Path to the ThreatModel JSON file to analyze
  - name: inputs
    type: string
    required: true
    description: Space-separated paths to IaC and/or deployment manifest artifacts
  - name: profile
    type: string
    required: false
    default: first-party
    description: Artifact-availability profile - first-party, third-party, or open-source
dependencies: [tms]
process:
  - Invoke the deployment-analyst agent with the given model, inputs, and profile
  - Agent runs `tms analyze --stage deployment` in plan mode to open a run
  - Agent works through the 4 deployment-stage ASPM domains, verifying required controls against actual deployed config
  - Agent runs an adversarial critic pass before finalizing
  - Agent writes AnalysisResults and runs `tms analyze --stage deployment --apply` to merge and close the run
---

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
