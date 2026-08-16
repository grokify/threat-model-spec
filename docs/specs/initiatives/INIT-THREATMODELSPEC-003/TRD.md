# PDLC Lifecycle Analysis — Follow-On Hardening and Persistence — TRD

**Initiative:** `INIT-THREATMODELSPEC-003`
**Repository:** `github.com/grokify/threat-model-spec`

## Architecture Overview

Three independent work streams over the v0.8.0 codebase: (1) an additive IR change on `ir.Finding` plus deterministic coverage-check computation; (2) an authoring-guidance fix resolved by spike; (3) documentation. A fourth stream — an embedded-Dolt persistence package inside this repo — was originally planned and is now cancelled; see §4.

## 1. Finding Framework Categorization (`ir/findings.go`)

`Finding` gains three optional fields, mirroring the flat-optional-field style already on the struct (`ASPMDomainID`, `Stage`):

```go
// STRIDECategories tags this finding with the STRIDE categories it
// evidences (S, T, R, I, D, E).
STRIDECategories []STRIDEThreat `json:"strideCategories,omitempty"`

// OWASPIds references OWASP Top-10 entries (API/LLM/Web/Agentic lists),
// e.g. "API2:2023". Validated via ValidateOWASPID.
OWASPIds []string `json:"owaspIds,omitempty"`

// AttackTechniqueIds references MITRE ATT&CK techniques, e.g.
// "T1059.001". Validated via ValidateTechniqueID.
AttackTechniqueIds []string `json:"attackTechniqueIds,omitempty"`
```

- Reuses the existing `STRIDEThreat` enum (`ir/types.go`) and the existing `ValidateOWASPID` / `ValidateTechniqueID` validators — no new vocabulary.
- `ir/validate.go` lifecycle validation warns on invalid values (consistent with existing OWASP-mapping validation behavior).
- Schema regenerated via `go run cmd/genschema/main.go` at the next release version; all additions optional → every v0.8.0 model validates unchanged.

### Deterministic coverage checks

`evaluation.EvaluateStageGate` currently receives `CoverageCheckResults map[string]bool` filled in by the caller — self-reported. Add a computed layer:

```go
// evaluation/coverage.go
// ComputeCoverageChecks evaluates every check ID in the stage's profile
// that is deterministically computable from the model, returning results
// plus the IDs it could not compute (which remain caller-supplied).
func ComputeCoverageChecks(model *ir.ThreatModel, stage ir.Stage) (CoverageCheckResults, []string, error)
```

Computable in this initiative:

| Check ID | Stage | Computation |
|---|---|---|
| `has-stride-mapping` | builder-definition | every `threat-candidate` Finding at this stage carries ≥1 `strideCategories` entry |
| `has-prohibited-outcome` | product-definition | ≥1 `SecurityRequirement` with `type: prohibited-outcome` |
| `has-assets` / `has-threat-actor` | product-definition | non-empty `Assets` / `ThreatActors` |
| `has-invariant` | product-definition | ≥1 `SecurityRequirement` with `type: invariant` |
| `has-evidence-per-finding` | builder stages | every stage Finding has ≥1 resolvable `evidenceIds` entry |

`tms gate` and `tms analyze --apply` call `ComputeCoverageChecks` first and only accept caller-supplied booleans for the non-computable remainder. A caller-supplied value for a computable check is ignored with a warning — computed truth wins.

### Agent-spec updates

`builder-definition-analyst` (and `implementation-analyst`, whose findings also reason about STRIDE) specs instruct populating `strideCategories`; worked examples updated. Plugins regenerated with assistantkit; freshness tests keep specs/plugins in sync.

## 2. prohibited-outcome Spike (`agents/specs/`, `examples/`)

Evidence so far: the enum value `SecurityRequirementTypeProhibitedOutcome` exists (`ir/findings.go:130`) and `has-prohibited-outcome` is declared in the product-definition profile — but the product-definition agent spec's process steps and worked example only ever author `type: invariant`. Working hypothesis: **authoring gap**.

Spike protocol:

1. Inspect both dogfood models' `securityRequirements` and the agent spec's guidance; confirm no path ever prompts a prohibited-outcome.
2. If confirmed: add explicit guidance ("derive at least one prohibited outcome — a state that must never occur, as distinct from an invariant that must always hold") + a worked-example entry; regenerate plugins; add a prohibited-outcome requirement to the flagship example (`openclaw-websocket-takeover.json`) where one genuinely applies.
3. If the distinction proves artificial in practice: write the decision into `docs/specification/` and relax the coverage check — the enum value stays (schema compat), the check changes.

Deliverable either way: a written root-cause note in the spike's RMI and the corresponding fix, not just analysis.

## 3. CLI Reference (`docs/cli/`, `mkdocs.yml`)

Five new pages — `gate.md`, `analyze.md`, `report.md`, `status.md`, `profile.md` — following the existing `generate.md`/`validate.md` format (synopsis, flags, examples against `examples/*.json`, exit codes). Nav order matches verb workflow: analyze → gate → report → status → profile. `mkdocs build --strict` gates the change.

## 4. Persistence — Cancelled

**This section is retained as a record of the original design and why it was abandoned, not as a build plan.**

The original plan below — an Ent-over-embedded-Dolt store package living inside `threat-model-spec` itself — was cancelled before implementation. Root cause: it conflicts with the open-core split that governs the broader ProductBuildersHQ ecosystem (documented in `visionstudio-cloud`'s README): *capture and record locally = open (`visionstudio`); aggregate, serve, and analyze in the cloud = private (`visionstudio-cloud`)*. `threat-model-spec` is a public, standalone spec plus a local `tms` CLI, used by anyone independent of this organization's tooling — giving it its own database would mean every external `tms` user's optional persistence feature depends on a repo-specific Ent schema and migration cadence that has nothing to do with the spec itself. The `ThreatModel` JSON document already is the local record; nothing more is needed for `threat-model-spec`'s own scope.

Where this capability actually belongs instead:

- A **local, open** history of judge/gate runs, if ever wanted, is `visionstudio`'s concern, not this repo's — it already has `JudgeResult`/`JudgeRubric` entities doing almost exactly this for spec-quality grading (a `structured-evaluation` rubric report stored as JSON, keyed to an initiative), and extending that pattern with a threat-model-shaped entity would be a natural, non-breaking addition there.
- **Premium, hosted, multi-tenant** threat-modeling history and cross-repo/cross-initiative aggregation belongs in `visionstudio-cloud`, which already exists as real infrastructure for exactly this kind of paid capability (multi-tenant serving, per-tenant metering, tenant provisioning). It would import `threat-model-spec` as a library (or invoke `tms`) to perform analysis, then own storing and serving results multi-tenant. That work is scoped as its own initiative in `visionstudio-cloud`, informed by but not implemented in this repo.

### Original design (abandoned)

<details>
<summary>Ent-over-embedded-Dolt store package (not built)</summary>

- **Stack:** Ent (`entgo.io/ent`) over embedded Dolt (`github.com/dolthub/driver`, MySQL-compatible), opt-in via `--data-dir`/`TMS_DATA_DIR`, default location `~/.productbuildershq/tms`.
- **Schema (append-only):** five entities — `analysis_runs` (run_id, model_id, stage, profile, status, opened_at, completed_at), `judge_runs` (judge_run_id, run_id, rubric_id, evaluated_by, evaluated_at), `judge_assessments` (judge_run_id, category_id, score, severity), `gates` (run_id, stage, result, check_results JSON, evaluated_at), `framework_reports` (model_id, framework, digest, body JSON, computed_at). All IDs reuse the IR's stable strings — no mapping layer.
- **Audit envelope:** one Dolt commit per `tms` write batch (`tms: <verb> <run-id>`) — Dolt's commit graph as the audit trail, no separate table.
- **Write/read paths:** write hooks in `cmd/tms` after analyze/gate/report; a `tms history` read verb.

Of the five tables, only `framework_reports` was genuinely threat-model-spec-domain-specific (STRIDE/LINDDUN/MITRE/OWASP/attack-tree). `judge_runs`/`judge_assessments` are `structured-evaluation`'s vocabulary, not this repo's; `analysis_runs`/`gates` map to this IR's types but are structurally generic. This overlap with `structured-evaluation` and `visionstudio`'s existing `JudgeResult`/`JudgeRubric` was itself part of why the design was reconsidered.

</details>

## 5. Deferred: Empirical Dogfood (data-gated)

Not designed here beyond acceptance criteria (PRD FR5); the stage report profiles already define the contracts. Target requirements, verbatim from the profiles: `deployment` needs `iac` + `deployment-manifest` artifacts covering 4 ASPM domains; `builder-operations` needs `runtime-endpoint` + `telemetry` + `incident`; `product-operations` needs `telemetry` + `incident`. Execution starts when a qualifying target is named.

## 6. Compatibility and Testing Strategy

- Schema: additive only; `TestExamplesValidate` (all five canonical examples) must stay green with zero example edits before any retrofit commits.
- Coverage-check semantics change (computed > self-reported) is behavior-visible in `tms gate`: called out in CHANGELOG and release notes.
- Per-package conventions unchanged: enum value tests, JSON round-trips, golden files (`UPDATE_GOLDEN=1`), calibration fixtures.
