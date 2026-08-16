# Lifecycle IR Objects

Beyond the diagram-centric `ThreatModel` fields (`diagrams`, `mappings`, `assets`, `threatActors`, `scenarios`, `mitigations`), the IR carries a second layer of objects for PDLC lifecycle-aware analysis: what was analyzed, when, by whom, what was found, and whether a stage's gate passed. These accumulate across multiple `tms analyze` runs over the lifetime of a model — a model can carry `product-definition` and `implementation`-stage analysis simultaneously, each with its own trail of runs, findings, and gates.

For how these objects get populated by an agent-driven analysis cycle, see [Stage Report Profiles](stage-reports/index.md) and [AI Agents](../agents/index.md). This page documents the objects themselves.

## Artifact

A source input an `AnalysisRun` was performed against — a spec document, a source tree, an SBOM, a deployment manifest, and so on.

```json
{
  "id": "artifact-implementation-1",
  "type": "source-tree",
  "uri": "internal/billing/",
  "revision": "a1b2c3d",
  "stage": "implementation",
  "observedAt": "2026-08-14T17:00:04Z"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `type` | string | No | Artifact kind — `product-spec`, `technical-spec`, `architecture-diagram`, `api-spec`, `source-tree`, `dependency-manifest`, `sbom`, `iac`, `deployment-manifest`, `runtime-endpoint`, `telemetry`, `incident` |
| `uri` | string | No | Repo-relative path or `repo://` URI |
| `revision` | string | No | Version analyzed, e.g. a git SHA |
| `stage` | string | No | PDLC stage this artifact belongs to |
| `digest` | string | No | Content hash at the analyzed revision |
| `observedAt` | string | No | RFC 3339 timestamp when observed/collected |

## AnalysisRun

Records who analyzed what, how, and when. `Finding`, `Evidence`, and `Gate` reference the `AnalysisRun` that produced them (`producerRunId` / `evaluatedBy`), giving every claim in the model a traceable origin.

```json
{
  "id": "run-implementation-1786726804355777000",
  "stage": "implementation",
  "profile": "first-party",
  "producer": {"type": "agent", "name": "implementation-analyst"},
  "inputArtifactIds": ["artifact-implementation-1"],
  "startedAt": "2026-08-14T17:00:04Z",
  "completedAt": "2026-08-14T17:05:40Z",
  "status": "completed"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `stage` | string | Yes | PDLC stage this run analyzed |
| `method` | string | No | Analysis method, e.g. `threat-modeling`, `sast`, `sca`, `dast`, `llm-judge` |
| `profile` | string | No | Artifact-availability profile that governed this run: `first-party`, `third-party`, `open-source` |
| `producer` | object | Yes | `{type, name, version}` — who or what performed the run |
| `inputArtifactIds` | array | No | `Artifact` IDs this run analyzed |
| `startedAt` / `completedAt` | string | No | RFC 3339 timestamps |
| `status` | string | Yes | `in-progress`, `completed`, or `failed` |

`tms analyze` opens a run in plan mode and completes it in apply mode — see [`tms analyze`](../cli/index.md).

## Evidence

A specific, locatable excerpt backing a `Finding`, `SecurityRequirement`, `ArchitectureAssertion`, or `Gate`.

```json
{
  "id": "evidence-billing-query-1",
  "artifactId": "artifact-implementation-1",
  "locator": {"type": "file", "path": "internal/billing/query.go", "startLine": 42, "endLine": 58},
  "excerpt": "query := fmt.Sprintf(\"SELECT * FROM invoices WHERE id = %s\", id)",
  "summary": "Invoice lookup builds SQL via string formatting, not a parameterized query."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `artifactId` | string | No | `Artifact` this evidence was extracted from |
| `locator` | object | Yes | Tagged union: `type` selects `file` (`path`/`startLine`/`endLine`), `document` (`uri`/`section`), `config` (`path`/`keyPath`), `query` (`dataSource`/`query`/`timeWindow`), or `url` (`url`/`observedAt`) |
| `digest` | string | No | Content hash of the referenced material |
| `excerpt` | string | No | Short relevant excerpt, reviewable inline |
| `summary` | string | No | One-line description of what this evidence shows |

## Finding

An analyzer's claim requiring adjudication: a threat candidate, vulnerability, weakness, drift assertion, or control gap. A near-direct fact (e.g. "admin-api is exposed to the public internet") is recorded as a `Finding` with `type: observation` and confidence near 1.0, rather than as a separate object type.

```json
{
  "id": "finding-sql-string-format",
  "type": "vulnerability",
  "stage": "implementation",
  "title": "Invoice lookup builds SQL via string formatting",
  "description": "internal/billing/query.go concatenates the id parameter directly into a SQL string instead of using a parameterized query, enabling SQL injection.",
  "targetRefs": ["component:billing-service"],
  "evidenceIds": ["evidence-billing-query-1"],
  "confidence": 0.95,
  "status": "validated",
  "strideThreats": ["T"],
  "owaspIds": ["A03:2021"],
  "mitreTechniques": ["T1190"],
  "producerRunId": "run-implementation-1786726804355777000"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `type` | string | Yes | `observation`, `threat-candidate`, `vulnerability`, `weakness`, `drift`, `control-gap` |
| `stage` | string | No | PDLC stage this finding was produced at |
| `title` / `description` | string | Yes / No | Summary and detailed explanation |
| `targetRefs` | array | No | Affected component/element/asset IDs |
| `evidenceIds` | array | No | `Evidence` IDs supporting this finding |
| `confidence` | number | No | Producer's confidence, 0.0–1.0 |
| `status` | string | Yes | `candidate`, `validated`, `rejected`, `insufficient-evidence` |
| `aspmDomainId` | string | No | ASPM domain, for builder-stage findings |
| `strideThreats` | array | No | STRIDE categories this finding evidences |
| `owaspIds` | array | No | OWASP Top-10 entries (API/LLM/Web/Agentic) this finding maps to |
| `mitreTechniques` | array | No | MITRE ATT&CK technique IDs this finding evidences |
| `producerRunId` | string | No | `AnalysisRun` that produced this finding |
| `promotedToId` | string | No | `Scenario` ID this finding was promoted to, once validated and synthesized |

## SecurityRequirement

An invariant or prohibited outcome derived from product-definition-stage analysis, with links to its origin and the runs/gates that verify it.

```json
{
  "id": "sr-tenant-isolation",
  "statement": "A principal can access resources only within its own tenant",
  "type": "invariant",
  "criticality": "critical",
  "originArtifactId": "artifact-product-definition-1",
  "verificationIds": ["run-implementation-1786726804355777000"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `statement` | string | Yes | The requirement in plain language |
| `type` | string | Yes | `invariant`, `prohibited-outcome`, `privacy-requirement`, `approval-requirement`, `recovery-requirement`, `detection-requirement` |
| `criticality` | string | No | `critical`, `high`, `medium`, `low` |
| `originArtifactId` | string | No | `Artifact` this requirement was derived from |
| `verificationIds` | array | No | `AnalysisRun` or `Gate` IDs that verify this requirement |

## ArchitectureAssertion

An intended-vs-observed property for drift detection — what the design required, what was actually observed, and whether the two agree.

```json
{
  "id": "assertion-admin-api-exposure",
  "subjectId": "admin-api",
  "predicate": "network-exposure",
  "expected": "private",
  "observed": "public",
  "expectedEvidenceIds": ["evidence-trd-network-design"],
  "observedEvidenceIds": ["evidence-ingress-config"],
  "status": "contradicted"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `subjectId` | string | Yes | Component/element this assertion is about |
| `predicate` | string | Yes | Property being asserted, e.g. `network-exposure` |
| `expected` | string | Yes | Value the design requires |
| `observed` | string | No | Value actually observed, once implementation/deployment evidence exists |
| `expectedEvidenceIds` / `observedEvidenceIds` | array | No | `Evidence` IDs supporting each side |
| `status` | string | Yes | `supported`, `contradicted`, `unverified` |

## Gate

A stage-gate evaluation: the criteria checked, who or what evaluated them, and the result. Enforcing gates (e.g. blocking CI) is deliberately the consuming pipeline's responsibility — `Gate` only records the outcome.

```json
{
  "id": "gate-implementation",
  "stage": "implementation",
  "criteria": [
    {"metric": "has-evidence-per-finding", "operator": "equals", "value": "true"},
    {"metric": "all-aspm-domains-covered", "operator": "equals", "value": "true"}
  ],
  "result": "failed",
  "evaluatedBy": "evaluation.EvaluateStageGate",
  "evidenceIds": ["evidence-billing-query-1"],
  "evaluatedAt": "2026-08-14T20:39:40Z"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `stage` | string | Yes | PDLC stage this gate evaluates |
| `criteria` | array | No | Deterministic checks evaluated: `{metric, operator, value}` |
| `result` | string | Yes | `passed`, `failed`, `pending` |
| `evaluatedBy` | string | No | Evaluator identifier, e.g. a policy engine or run ID |
| `evidenceIds` | array | No | `Evidence` IDs supporting this evaluation |
| `evaluatedAt` | string | No | RFC 3339 timestamp |

`tms analyze --apply` computes a subset of coverage checks deterministically from the model (`has-stride-mapping`, `has-prohibited-outcome`, `has-invariant`, `has-assets`, `has-threat-actor`, `has-evidence-per-finding`) and records the resulting `Gate` automatically; `tms gate` reads back an already-recorded gate and does not compute one itself.

## Lifecycle

Groups stage-tracking state for the model as a whole.

```json
{
  "currentStage": "implementation"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `currentStage` | string | No | PDLC stage most recently analyzed |

`currentStage` supersedes the older, deprecated top-level `phase` field: a lifecycle-aware model accumulates `AnalysisRuns`, `Findings`, and `Evidence` from multiple stages simultaneously, so `currentStage` records only the most recently active stage, not the model's sole phase.

## Next Steps

- [Stage Report Profiles](stage-reports/index.md) — per-stage input/output contracts these objects flow through
- [AI Agents](../agents/index.md) — the agent workflows that produce `AnalysisResults`
- [JSON IR Overview](index.md) — the diagram-centric `ThreatModel` fields
