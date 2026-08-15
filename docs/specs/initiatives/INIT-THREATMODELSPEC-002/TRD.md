# TRD — PDLC Threat Modeling — Stage Analysis Reports and Agent Workflows

**Initiative:** `INIT-THREATMODELSPEC-002`

## Architecture Overview

```
PDLC artifacts (specs, code, IaC, deployments, telemetry)
        │
        ▼
AI coding agent (Claude Code) ── runs ──▶ tms analyze --stage <s> --profile <p>
   (does the reasoning)                     (loads profile + inputs, drives workflow,
        │                                    writes the run, grades it — no reasoning)
        │  emit claims/patches
        ▼
Threat Model Spec IR (lifecycle objects + existing model)
        │
        ├── Deterministic validation (schema, referential integrity, stage rules)
        ├── structured-evaluation (rubric / claims / summary per stage)   ← judge layer
        ├── Framework report exports (STRIDE, LINDDUN, ATT&CK, OWASP, attack tree)
        ├── Diagram rendering (D2) and STIX 2.1 export (existing)
        └── Gate evaluation (recorded criteria → GO/NO-GO)
```

Spec first, analysis on top: Go structs in `ir/` remain the source of truth (JSON Schemas generated via invopop/jsonschema → schemakit lint → `//go:embed`). Built on the format, `tms analyze` and the shipped agent/subagent specs are the analysis-enablement layer — the agent reasons, `tms` orchestrates, grades, and stores; neither reimplements a scanner.

## 1. Lifecycle IR Objects (`ir/lifecycle.go`, `ir/evidence.go`, `ir/findings.go`)

New top-level optional fields on `ThreatModel`:

```go
type ThreatModel struct {
    // ... existing fields unchanged ...

    // Lifecycle groups stage-tracking state.
    Lifecycle *Lifecycle `json:"lifecycle,omitempty"`
    // Artifacts are the inputs analyses ran against.
    Artifacts []Artifact `json:"artifacts,omitempty"`
    // AnalysisRuns record who analyzed what, how, and when.
    AnalysisRuns []AnalysisRun `json:"analysisRuns,omitempty"`
    // Evidence is inspectable material findings and assertions cite.
    Evidence []Evidence `json:"evidence,omitempty"`
    // SecurityRequirements are invariants and prohibited outcomes with verification links.
    SecurityRequirements []SecurityRequirement `json:"securityRequirements,omitempty"`
    // ArchitectureAssertions capture intended vs. observed properties (drift detection).
    ArchitectureAssertions []ArchitectureAssertion `json:"architectureAssertions,omitempty"`
    // Findings are analyzer claims requiring adjudication.
    Findings []Finding `json:"findings,omitempty"`
    // Gates record stage-gate criteria and evaluation results.
    Gates []Gate `json:"gates,omitempty"`
    // FrameworkReports hold materialized framework-specific views.
    FrameworkReports []FrameworkReport `json:"frameworkReports,omitempty"`
}
```

Key type decisions:

- **Finding vs. Threat vs. Scenario.** Existing `Scenario`/threat objects are unchanged. `Finding` is a new concept: an analyzer's *claim* (type: `threat-candidate`, `vulnerability`, `weakness`, `drift`, `control-gap`) with `evidenceIds`, `confidence`, `status` (`candidate` → `validated`/`rejected`/`insufficient-evidence`), and `producerRunId`. A validated threat-candidate finding may be promoted to a Scenario/threat by a synthesis step; the finding records `promotedToId`.
- **Observation folded into Finding.** Rather than a fourth object type, near-direct facts are findings with `type: "observation"` and confidence ≈ 1.0 (resolves the ideation open question in favor of fewer object types; revisit only if dogfooding shows harm).
- **Evidence locators** are a tagged union: `file` (path, startLine, endLine), `document` (uri, section), `config` (path, keyPath), `query` (dataSource, query, timeWindow), `url` (url, observedAt). All carry `digest` and optional `excerpt`.
- **Stage** is a string enum whose values match pdlc's six stage IDs: `product-definition`, `builder-definition`, `implementation`, `deployment`, `builder-operations`, `product-operations`. threat-model-spec imports `github.com/ProductBuildersHQ/pdlc` directly for the `pdlc.Stage*` constants (it is not in the pdlc→visionspec→specification-workflow-spec dependency chain, so no cycle). `ir.ModelPhase` is deprecated (kept, documented as superseded by `Lifecycle.CurrentStage`).
- **IDs** follow existing repo conventions (kebab prefixed: `artifact-`, `run-`, `evidence-`, `finding-`, `req-`, `assert-`, `gate-`). Validation enforces referential integrity across all new reference fields (extends `ir/validate.go`).

## 2. PDLC Stages and Spec Categorization (multi-repo relationship)

The stage taxonomy is defined once and consumed downstream — threat-model-spec never learns individual spec types or workflows. Six stages: `product-definition`, `builder-definition`, `implementation`, `deployment`, `builder-operations`, `product-operations`.

```
productbuildershq-frameworks/  PDLC catalog entry: 6 stage IDs + AI-DLC crosswalk
        │  imported + re-exported by
        ▼
pdlc/  pdlc.Stages()/StageByID() + pdlc.Stage* ID constants (normative spec module)
        │                                    │
        │  string-constant convention        │  direct Go import
        │  (NO Go import — cycle:             │  (safe — TMS is outside the
        │   pdlc→visionspec→spec-wf-spec)     │   pdlc→visionspec→spec-wf-spec chain)
        ▼                                    ▼
specification-workflow-spec/           threat-model-spec/
  tags each SpecType with a              imports pdlc.Stage* AND
  PDLCStage string constant              specification-workflow-spec; carries the
  (matching pdlc's values)               conformance test asserting the two agree
        │                                    │
        │  workflow → {spec → PDLCStage} categorization
        └──────────────────┬─────────────────┘
                           ▼
threat-model-spec buckets a workflow's specs into the stages and analyzes BY STAGE
```

- **productbuildershq-frameworks** holds the machine-readable PDLC framework catalog entry (six stages, deliverables, gates, dependency graph, and the AI-DLC crosswalk), alongside the existing AIDLC entry. This is the source of truth for the stage IDs.
- **pdlc** re-exports the catalog via `pdlc.Stages()`, `pdlc.StageByID()`, and `pdlc.Stage*` ID constants, and describes the six-stage model normatively in `docs/specification/lifecycle.md`. Stage IDs are the normative machine-readable identifiers.
- **specification-workflow-spec** adds a `PDLCStage` field to `SpecType` in its registry (`pkg/spectype`) as **string constants that match pdlc's values by convention, not by Go import** — importing pdlc there would close a dependency cycle (`pdlc → visionspec → specification-workflow-spec`). Orthogonal to the existing `Category` (source/gtm/technical): e.g. `press`/`faq`/`prd`/`mrd` → `product-definition`; `trd`/`ird`/`tpd` → `builder-definition`. Execution-tracking types (`plan`, `roadmap`) carry no stage.
- **threat-model-spec** imports both `pdlc` (for the `pdlc.Stage*` constants, mirrored into an `ir.Stage` enum) and `specification-workflow-spec` (for the categorization registry) — it is the one repo in the chain that can safely import both, so it **carries the conformance test** asserting specification-workflow-spec's `PDLCStage` values equal pdlc's stage IDs. Given a workflow, it reads the registry to bucket specs into stages and analyzes by stage — so a new spec workflow or spec type requires **zero** threat-model-spec changes, provided the type is categorized upstream. Non-spec artifacts (code, IaC, deployment manifests, telemetry) are not workflow specs; the implementation/deployment/builder-operations stages ingest those by artifact type directly (see the ASPM overlay, §3).
- Security analysis is documented in pdlc as a per-stage cross-cutting activity pointing at threat-model-spec's report profiles (pdlc stays tool-neutral).

## 3. Stage Analysis Report Profiles (`docs/specification/stage-reports/`, `ir/report_profile.go`)

Each profile is both prose (normative spec section) and data (embedded JSON consumed by `tms`):

```go
type StageReportProfile struct {
    Stage         Stage    `json:"stage"`
    // InputMode is how this stage's inputs are resolved:
    //   "workflow-specs" — all specs a workflow categorizes into this PDLC stage
    //                      (product-definition, builder-definition); resolved via
    //                      the specification-workflow-spec registry, no list here.
    //   "artifact-types" — non-spec artifacts by type (implementation,
    //                      deployment, builder-operations, product-operations).
    InputMode      string         `json:"inputMode"`
    ArtifactTypes  []ArtifactType `json:"artifactTypes,omitempty"` // used when InputMode == artifact-types
    ASPMDomains    []ASPMDomain   `json:"aspmDomains,omitempty"`   // builder-side stages: the ASPM domains this stage's report organizes findings by
    OutputObjects  []string       `json:"outputObjects"`  // IR object types the report must populate
    CoverageChecks []string       `json:"coverageChecks"` // deterministic completeness checks
    RubricID       string         `json:"rubricId"`
}
```

Contents per stage as specified in PRD FR3 (product-definition → assets/abuse-cases/invariants; builder-definition → boundaries/threats/controls/API-contract-drift; implementation → findings/drift/control-verification, ASPM 1–5; deployment → exposure/exploitability/config, ASPM 6–9; builder-operations → detections/incidents/effectiveness, ASPM 10 + dynamic testing; product-operations → production abuse signal + invariant drift). The spec-driven stages (product-definition, builder-definition) declare no spec-type list — they consume whatever the workflow categorizes into that stage; the builder-side stages enumerate `ArtifactTypes` and, where applicable, `ASPMDomains`.

**ASPM overlay (`ir/aspm.go`).** `ASPMDomain` is a string enum of the 10 Application Security Posture Management domains, each with a primary PDLC stage:

```go
type ASPMDomain struct {
    ID           string `json:"id"`           // git-posture | code-security | secret-pii-scan | open-source-security | sbom | iac-scan | cicd-posture | container-security | artifact-security | cloud-context
    Name         string `json:"name"`
    PrimaryStage Stage  `json:"primaryStage"` // implementation | deployment | builder-operations
}
```

Mapping: implementation ← git-posture, code-security, secret-pii-scan, open-source-security, sbom; deployment ← iac-scan, cicd-posture, container-security, artifact-security; builder-operations ← cloud-context. Findings and evidence may carry an `aspmDomainId` so coverage is measurable per domain. Domains near a stage seam (git-posture, sbom, cicd-posture, iac-scan) carry a *primary* stage but their evidence may attach to an adjacent stage — the primary/cross-stage distinction is a field, not a hard partition. ASPM is the *static-posture* slice of the builder stages; dynamic testing (DAST, pen test, red team) rides alongside it and is not an ASPM domain.

**Artifact-availability profiles** (`first-party`, `third-party`, `open-source`) are data files mapping available artifact types → permitted stage analyses → report-scope annotations. `AnalysisRun.Profile` records which profile governed the run.

## 4. Agent Workflows (agnostic + generated) and the `tms analyze` Command

**Agnostic agent/workflow definitions (`agents/specs/`).** The repo already follows the `multi-agent-spec` convention: `agents/specs/agents/*.md`, `agents/specs/commands/*.md`, `agents/specs/skills/*.md` (today's diagram-creation agents), with generated tool plugins in `agents/plugins/claude/`. This initiative adds the six per-stage analysis agents to the same `agents/specs/` tree — one agent (and slash command) per stage, plus any shared skills. Each stage agent's definition carries the analysis contract: its inputs (resolved by the stage's `StageReportProfile` — categorized workflow specs for the spec-driven stages, artifact types for the code/deploy/ops stages), ordered analysis steps, output object contract (IR object types + schema fragment refs), adversarial-critic step, and rubric reference. Definitions are validated in tests (contracts parse, referenced rubrics exist, artifact types are known).

**Generated per-tool plugins (`agents/plugins/`).** `assistantkit` generates the Claude Code, Kiro, and Gemini plugins from `agents/specs/` into `agents/plugins/{claude,kiro,gemini}/`, exactly as the existing diagram agents are generated. No tool gets a hand-authored path — the agnostic spec is the single source. A generation-freshness test (same discipline as the schema `//go:embed` check) fails if `agents/plugins/` is stale relative to `agents/specs/`. This keeps the format's vendor-neutrality intact: Claude Code is one generation target among several.

**The `tms analyze` command (`cmd/tms`).** Orchestration entry point an AI coding agent invokes; performs no analytical reasoning itself. Shape:

```
tms analyze <model.json> --stage <stage> --profile <artifact-profile> [inputs...]
```

Steps: (1) load the stage's `StageReportProfile` and the artifact-availability profile; (2) resolve declared input artifacts, recording them as `Artifact` objects; (3) open an `AnalysisRun` (method, stage, profile, producer = invoking agent, status `in-progress`); (4) hand the agent the workflow spec and gathered inputs — the agent reasons and returns findings/evidence/claims as the output-object contract; (5) validate and write them into the model under the run; (6) grade via the stage rubric (structured-evaluation), attaching judge provenance; (7) close the run. The command mutates the model; it is the single writing verb (see UXD). Reasoning lives in the agent; orchestration, structured output, and grading live in `tms`. When no agent is driving (e.g. plain CI), `tms analyze --dry-run` reports what *would* run and what inputs are missing, without invoking an agent.

## 5. Evaluation Integration (`evaluation/`)

Existing: `evaluation/` loads rubric JSON and converts results to structured-evaluation `rubric.Rubric` and `claims.ClaimsReport`. Extensions:

- **Six stage rubrics** in `evaluation/rubrics/stages/` (`product-definition.rubric.json`, … `product-operations.rubric.json`) with categories per stage (e.g., builder-definition: boundary-coverage, threat-completeness, control-mapping, validation-plans, evidence-grounding; implementation: evidence-support, reachability, drift-detection, precondition-realism, ASPM-domain-coverage).
- **Gate summaries** via `summary.SummaryReport`: deterministic checks (schema valid, referential integrity, coverage checks) + rubric verdicts + claims verdicts → GO/NO-GO per stage gate; written back into `Gate.Result` with evidence.
- **Judge provenance:** map `rubric.JudgeMetadata` (judge id/model/version) + rubric version + run id onto `AnalysisRun` for judge-type runs, so every assessment is attributable.

### structured-evaluation gap assessment (FR5.4) — RESOLVED, RMI-THREATMODELSPEC-105

Verified against structured-evaluation v0.13.0, the actual dependency version, in `evaluation/pdlc_conventions.go`. All four candidate gaps resolved to "use an existing capability via a documented convention" — no upstream PR was needed for the first three; the fourth is a confirmed gap, deliberately deferred.

| Candidate gap | Resolution |
|---------------|------------|
| Structured evidence locators on `claims.Source` (file+line, query+window) vs. free-text | **No upstream change.** `ir.Evidence`/`EvidenceLocator` (RMI-103) is already the structured, typed locator; `claims.InternalValidation.EvidencePath` stays free-text by design (it locates evidence within the evaluated document, not an arbitrary artifact) — cite the `ir.Evidence` ID/Summary there. |
| `insufficient-evidence` verdict on claims/rubric | **No upstream change.** `claims.VerdictNeedsReview` already means this; `FindingStatusToVerdict`/`VerdictToFindingStatus` map it to/from `ir.FindingStatusInsufficientEvidence`, round-trip tested. |
| Stage/profile metadata on report envelope | **No upstream change.** `rubric.Rubric.ReviewType` is the intended carrier — `StageReviewType(stage)` sets it to the `ir.Stage` value. |
| Multi-judge disagreement representation | **Confirmed gap.** `combine.AggregateResults`/`AggregateWithDAG` aggregate *different* agents' results, not several judges scoring the *same* subject. Deliberately deferred per the rule below — no Phase 1 code needs it; first consumer is RMI-108/109 (Phase 2 rubrics/gates). |

Rule: prefer conventions over upstream changes; any upstream change must be additive and land before the TMS feature that needs it.

## 6. Framework Reports (`ir/framework_report.go`, `cmd/tms`)

```go
type FrameworkReport struct {
    ID          string    `json:"id"`
    Framework   string    `json:"framework"` // stride | linddun | mitre-attack | owasp | attack-tree
    GeneratedAt string    `json:"generatedAt,omitempty"`
    SourceRevision string `json:"sourceRevision,omitempty"` // model version/digest it was derived from
    Body        any       `json:"body"` // framework-specific typed payload (per-framework structs)
}
```

- **Computed-first:** `tms report --framework X` derives the report from the canonical model (STRIDE coverage from mappings + elements; LINDDUN from privacy mappings; ATT&CK from technique mappings + detection coverage matrix (exists); OWASP from owasp mappings + controls; attack-tree from existing attack-tree/attack-graph analysis).
- **Materialization optional:** reports can be stored in `FrameworkReports` with `SourceRevision` for audit snapshots; `tms validate` warns when a materialized report is stale relative to the model.
- Exports: JSON (typed payload) and Markdown (templated); reuses existing render patterns.

## 7. Schema and Compatibility

- All new fields optional; v0.7.0 documents validate against the new schema (regression test with existing examples).
- Regenerate via `go run cmd/genschema/main.go schema vNext` (positional args: output dir, then version — `genschema` takes no flags); copy to `docs/versions/vNext/`.
- Lint with `schemakit lint --property-case snake_case`, but treat it as a delta check against the current baseline (373 pre-existing errors as of v0.7.0), not a zero-errors gate — see the next point.
- JSON tags remain camelCase for consistency with the existing published spec (documented as a deliberate spec-local convention; the org snake_case rule is noted as not retroactively applied). This is why schemakit lint reports errors on this repo's schemas by design.

## 8. Testing Strategy

- Per-type enum/JSON round-trip/field tests (repo convention) for every new IR type.
- Referential-integrity validation tests across all new reference fields.
- Backward-compat suite: all v0.7.0-era example models validate unchanged.
- Report-profile and workflow-definition data files validated in tests.
- **Stage conformance test (FR1.4):** `ir.Stage` values equal `pdlc.Stage*` constants, and every `spectype.PDLCStage*` value (from specification-workflow-spec) resolves to a real `pdlc` stage ID. This is the single guard that the string-constant convention across the three repos cannot drift; it lives here because threat-model-spec is the only repo that imports both.
- **ASPM mapping test:** every `ASPMDomain.PrimaryStage` is one of implementation/deployment/builder-operations, and all 10 domains are present.
- Rubric calibration test: seeded-defect fixture model must produce non-passing categories under each stage rubric (guards against rubber-stamp rubrics).
- Framework export golden tests: canonical example model → expected STRIDE/ATT&CK/OWASP report snapshots.

## 9. Storage Note (out of scope, forward-compatible)

DoltDB persistence (judge_runs / judge_assessments append-only tables, Dolt commit audit envelope) is deferred to a follow-on initiative. This TRD's requirement on it: all IDs are stable strings and all assessments carry producer run IDs, so tabular persistence needs no schema change.
