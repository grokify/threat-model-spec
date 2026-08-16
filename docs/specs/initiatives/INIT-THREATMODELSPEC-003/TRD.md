# PDLC Lifecycle Analysis — Follow-On Hardening and Persistence — TRD

**Initiative:** `INIT-THREATMODELSPEC-003`
**Repository:** `github.com/grokify/threat-model-spec`

## Architecture Overview

Four independent work streams over the v0.8.0 codebase: (1) an additive IR change on `ir.Finding` plus deterministic coverage-check computation; (2) an authoring-guidance fix resolved by spike; (3) documentation; (4) a new, opt-in storage package. Nothing changes for a user who ignores the new store — the JSON ThreatModel document remains the source of truth; the store is an append-only audit/history projection of it.

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

## 4. Persistence — Fuller Store (`store/`)

### Stack and operating model

- **Ent** (`entgo.io/ent`) over **embedded Dolt** (`github.com/dolthub/driver`, MySQL-compatible) — the org-standard pairing, and the same embedded-local model visionstudio uses (`~/.productbuildershq/visionstudio`). Versions verified against upstream releases at implementation time per org convention.
- Opt-in: `--data-dir` flag / `TMS_DATA_DIR` env on `tms`. Unset → the store package is never initialized; every existing code path is untouched (success metric: byte-identical output).
- Default location when enabled without a path: `~/.productbuildershq/tms`.

### Schema (append-only)

Five Ent entities, one row per event, no updates or deletes (append-only enforced by the store API surface — no update/delete methods generated into the public interface):

| Table | Row per | Key columns |
|---|---|---|
| `analysis_runs` | AnalysisRun opened or completed | run_id, model_id, stage, profile, status, opened_at, completed_at |
| `judge_runs` | rubric evaluation executed | judge_run_id, run_id, rubric_id, evaluated_by, evaluated_at |
| `judge_assessments` | per-category assessment within a judge run | judge_run_id, category_id, score, severity |
| `gates` | Gate evaluated | run_id, stage, result, check_results (JSON), evaluated_at |
| `framework_reports` | FrameworkReport materialized | model_id, framework, digest, body (JSON), computed_at |

All IDs are the IR's stable strings (INIT-002 TRD §9 guaranteed this: "all IDs are stable strings and all assessments carry producer run IDs, so tabular persistence needs no schema change") — no mapping layer.

### Audit envelope

Each `tms` write batch (e.g. one `analyze --apply`) commits once to Dolt with message `tms: <verb> <run-id>` — Dolt's commit graph *is* the audit trail. No separate audit table.

### Write and read paths

- Write hooks in `cmd/tms`: after a successful model write in `analyze` (plan: run opened; apply: run completed + judge rows if grading ran), after `gate`, after `report`.
- Read verb: `tms history <model.json|--model-id id>` — lists persisted runs (stage, status, gate result, timestamps), `--format json|table`.

### Testing

Unit tests against a `t.TempDir()` embedded Dolt database — no external server, CI-safe on all three OSes (embedded driver needs no `dolt` binary). Round-trip test: full plan→apply→gate cycle with store enabled, assert row counts and single-commit-per-batch; disabled-store test asserts output parity.

## 5. Deferred: Empirical Dogfood (data-gated)

Not designed here beyond acceptance criteria (PRD FR5); the stage report profiles already define the contracts. Target requirements, verbatim from the profiles: `deployment` needs `iac` + `deployment-manifest` artifacts covering 4 ASPM domains; `builder-operations` needs `runtime-endpoint` + `telemetry` + `incident`; `product-operations` needs `telemetry` + `incident`. Execution starts when a qualifying target is named.

## 6. Compatibility and Testing Strategy

- Schema: additive only; `TestExamplesValidate` (all five canonical examples) must stay green with zero example edits before any retrofit commits.
- Coverage-check semantics change (computed > self-reported) is behavior-visible in `tms gate`: called out in CHANGELOG and release notes.
- Per-package conventions unchanged: enum value tests, JSON round-trips, golden files (`UPDATE_GOLDEN=1`), calibration fixtures.
- Store package targets the same bar as the rest of the repo: unit tests, no integration-test-only coverage.
