# Threat Model Specification v0.8.0

This document describes the Threat Model Specification format, a JSON-based intermediate representation for security threat modeling diagrams.

## Overview

A threat model is defined in a single JSON file containing:

- **Metadata**: Title, description, version, authors, phase
- **Assets**: Protected assets with sensitivity classification
- **Scenarios**: What-if attack scenarios with preconditions
- **Risk Assessment**: FAIR-based risk quantification
- **Mappings**: Security framework references (MITRE ATT&CK, OWASP, STRIDE, etc.)
- **Diagrams**: Multiple diagram views (DFD, Attack Chain, Sequence, Attack Tree)
- **Security Lifecycle**: Threat actors, mitigations, detections, response actions
- **Role-Based Guidance**: Red Team, Blue Team, and Remediation guidance
- **Purple Team**: Atomic tests, detection coverage, security metrics
- **Supply Chain**: SBOM, VEX statements, dependency risks
- **Attack Graphs**: Path analysis and reachability
- **Agentic AI Modeling**: Agent capabilities, execution context, credential flows (v0.7.0)
- **PDLC Lifecycle Analysis**: Stage-tracked analysis runs, findings, gates, and framework reports (v0.8.0)

## What's New in v0.8.0

v0.8.0 makes the format PDLC-aware: a threat model can now accumulate stage-by-stage analysis produced by AI agents or human reviewers across the six-stage Product Development Lifecycle (product-definition, builder-definition, implementation, deployment, builder-operations, product-operations), track that analysis through gate evaluation, and export computed, framework-specific reports (STRIDE, LINDDUN, MITRE ATT&CK, OWASP, attack-tree) — all from one canonical model.

### PDLC Lifecycle Objects

Seven new top-level, optional `ThreatModel` fields track lifecycle-stage analysis. All new fields are additive — see [Migration from v0.7.0](#migration-from-v070).

`Artifact` records a source input an analysis was performed against:

```json
{
  "artifacts": [
    {"id": "artifact-1", "type": "source-tree", "uri": "cmd/tms/analyze.go", "stage": "implementation"}
  ]
}
```

`AnalysisRun` records who analyzed what, how, and when, including which artifact-availability profile governed the run:

```json
{
  "analysisRuns": [
    {
      "id": "run-1",
      "stage": "implementation",
      "profile": "first-party",
      "producer": {"type": "agent", "name": "implementation-analyst"},
      "inputArtifactIds": ["artifact-1"],
      "status": "completed"
    }
  ]
}
```

`Evidence` is inspectable material a `Finding`, `ArchitectureAssertion`, or `SecurityRequirement` cites — a tagged-union locator supporting `file` (path/line range), `document` (uri/section), `config` (path/key), `query` (data source/query/time window), or `url`:

```json
{
  "evidence": [
    {"id": "evidence-1", "locator": {"type": "file", "path": "cmd/tms/analyze.go", "startLine": 247, "endLine": 254}}
  ]
}
```

`Finding` is an analyzer's claim requiring adjudication — `observation`, `threat-candidate`, `vulnerability`, `weakness`, `drift`, or `control-gap` — tracked through a status lifecycle (`candidate` → `validated`/`rejected`/`insufficient-evidence`):

```json
{
  "findings": [
    {
      "id": "finding-1",
      "type": "vulnerability",
      "stage": "implementation",
      "title": "SQL injection via unsanitized query parameter",
      "evidenceIds": ["evidence-1"],
      "confidence": 0.95,
      "status": "validated",
      "aspmDomainId": "code-security"
    }
  ]
}
```

`SecurityRequirement` (invariants and prohibited outcomes) and `ArchitectureAssertion` (intended-vs-observed drift detection) round out the claim vocabulary; `Gate` records stage-gate evaluation criteria and results (`passed`/`failed`/`pending`).

### PDLC Stages and the ASPM Overlay

`Stage` is a six-value enum matching the [pdlc](https://github.com/ProductBuildersHQ/pdlc) module's canonical stage IDs: `product-definition`, `builder-definition`, `implementation`, `deployment`, `builder-operations`, `product-operations`. The two spec-driven stages consume categorized workflow specs; the four builder-side/operations stages consume artifacts by type.

Ten Application Security Posture Management (ASPM) domains overlay the three builder-side stages — `Finding.aspmDomainId` tags a builder-stage finding with its domain:

| Domain | Primary Stage |
|--------|----------------|
| `git-posture`, `code-security`, `secret-pii-scan`, `open-source-security`, `sbom` | implementation |
| `iac-scan`, `cicd-posture`, `container-security`, `artifact-security` | deployment |
| `cloud-context` | builder-operations |

### Stage Report Profiles and Artifact-Availability Profiles

A `StageReportProfile` (one per stage, embedded data) is the normative definition of what a stage analysis report must contain: input mode, required output objects, deterministic coverage checks, and a rubric ID.

An `ArtifactAvailabilityProfile` (`first-party`, `third-party`, or `open-source`) maps what artifacts are realistically available for an analysis target to which stages can be credibly analyzed at all — every stage is guaranteed accounted for, permitted or explicitly not-analyzable with a reason, never silently absent:

```json
{
  "profile": "third-party",
  "permittedStages": ["product-definition", "deployment", "builder-operations"],
  "notAnalyzableStages": [
    {"stage": "implementation", "reason": "no access to source code"}
  ]
}
```

### Stage Rubrics and Gate Evaluation

Six calibrated rubrics (`evaluation/rubrics/stages/`) grade a stage's analysis report; `EvaluateStageGate` aggregates deterministic coverage checks and a rubric evaluation result into a `Gate` — a coverage check that was never evaluated is distinct from one that was evaluated and failed, so an incomplete analysis never silently reads as a clean one.

### FrameworkReport

`FrameworkReport` is a computed, framework-specific view derived from the canonical model — STRIDE/LINDDUN coverage-by-category, a MITRE ATT&CK mapping-to-detection-coverage join, OWASP coverage-by-list, or an attack-tree/attack-graph path analysis:

```json
{
  "frameworkReports": [
    {
      "id": "framework-report-stride",
      "framework": "stride",
      "strideBody": {
        "mappings": [{"category": "S", "name": "Spoofing", "affectedComponents": ["ws-gateway"]}],
        "categoriesCovered": ["S"],
        "categoriesMissing": ["T", "R", "I", "D", "E"]
      }
    }
  ]
}
```

Computed-first: `tms report --framework <f>` derives a report fresh from the model every time. Storing one in `frameworkReports` is optional, for an audit snapshot — `tms validate` warns (does not fail) when a materialized report's `sourceRevision` digest no longer matches a fresh computation.

### `tms` CLI: Orchestration and Read Verbs

`tms analyze <model.json> --stage <s> --profile <p> [inputs...]` orchestrates a stage analysis around an AI agent's reasoning step, which happens entirely outside `tms`: plan mode resolves inputs and opens an `AnalysisRun`; apply mode (`--apply <results.json>`) validates and atomically merges the agent's `AnalysisResults` — a candidate model is validated in full before any bytes are written, so an invalid merge leaves the file untouched. `tms analyze` is the only command that writes to the model.

Four read verbs round out the CLI, each with human and `--json` output modes:

| Command | Purpose |
|---------|---------|
| `tms status <model.json>` | Per-stage run/gate summary and a findings breakdown; `--ci` exits non-zero on any failed gate |
| `tms report <model.json> --framework <f>` | Derive a FrameworkReport; `--format json\|markdown` |
| `tms gate <model.json> --stage <s>` | Read a recorded Gate result; `--ci` exits non-zero if not passed |
| `tms profile <name>` | Print a built-in ArtifactAvailabilityProfile definition |

### Agent Specifications

Six agnostic `multi-agent-spec` agent definitions (`agents/specs/agents/*-analyst.md`, one per PDLC stage) and matching `/analyze-<stage>` slash commands are generated into per-tool plugins (`agents/plugins/{claude,kiro,gemini}/`). Each agent's spec documents its inputs, an ordered process including an adversarial-critic step, its output-object contract, a rubric reference, and a worked example.

## New Types (v0.8.0)

| Type | Description |
|------|-------------|
| `Stage` | Six-value PDLC stage enum |
| `ASPMDomain` | One of ten Application Security Posture Management domains |
| `Artifact` | A source input an analysis run was performed against |
| `AnalysisRun` | Records who analyzed what, how, and when |
| `Evidence` | Tagged-union locator supporting `Finding`/`ArchitectureAssertion`/`SecurityRequirement` claims |
| `Finding` | An analyzer's claim requiring adjudication |
| `SecurityRequirement` | An invariant or prohibited outcome |
| `ArchitectureAssertion` | Intended-vs-observed drift detection |
| `Gate` | Stage-gate evaluation criteria and result |
| `Lifecycle` | Model-level lifecycle state (current stage) |
| `StageReportProfile` | Normative definition of a stage's report contents |
| `ArtifactAvailabilityProfile` | Maps available artifacts to analyzable stages |
| `FrameworkReport` | Computed framework-specific view (STRIDE/LINDDUN/MITRE ATT&CK/OWASP/attack-tree) |
| `AnalysisResults` | The output-object contract an analysis agent returns to `tms analyze --apply` |

`Asset`, `ThreatActor`, `Scenario`, and `Mitigation` (pre-existing v0.7 types) gained an optional `producerRunId` field recording which `AnalysisRun` produced them, when applicable.

## Formats

| Format | Schema | Description |
|--------|--------|--------------|
| ThreatModel | `threat-model.schema.json` | Full threat model with multiple diagrams |
| DiagramIR | `diagram.schema.json` | Single standalone diagram |

## ThreatModel

The canonical format for complete threat models.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier for the threat model |
| `title` | string | Human-readable title |
| `diagrams` | array | Array of DiagramView objects |

### Optional Fields

All v0.7.0 optional fields are unchanged. New in v0.8.0:

| Field | Type | Description |
|-------|------|-------------|
| `lifecycle` | object | Model-level lifecycle state (current stage) |
| `artifacts` | array | Source inputs analysis runs were performed against |
| `analysisRuns` | array | Analysis run records |
| `evidence` | array | Inspectable material supporting findings/assertions/requirements |
| `securityRequirements` | array | Invariants and prohibited outcomes |
| `architectureAssertions` | array | Intended-vs-observed drift detection |
| `findings` | array | Analyzer claims requiring adjudication |
| `gates` | array | Stage-gate evaluation criteria and results |
| `frameworkReports` | array | Materialized framework-specific report snapshots |

## JSON Schemas

- [threat-model.schema.json](./threat-model.schema.json)
- [diagram.schema.json](./diagram.schema.json)

## Migration from v0.7.0

v0.8.0 is fully backward compatible with v0.7.0. All new fields are optional; every v0.7.0-era document remains valid without modification.

To take advantage of new features:

1. Run stage analysis with `tms analyze`, one PDLC stage at a time, driven by a stage-analyst agent
2. Grade a stage's analysis and record a `Gate` result with `EvaluateStageGate`
3. Check lifecycle state at a glance with `tms status`
4. Export computed framework reports with `tms report --framework <f>`
5. Choose the right artifact-availability profile (`first-party`/`third-party`/`open-source`) for what you can actually observe about an analysis target
