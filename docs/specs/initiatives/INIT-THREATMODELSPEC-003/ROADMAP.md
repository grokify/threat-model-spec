# PDLC Lifecycle Analysis — Follow-On Hardening and Persistence — Roadmap

**Initiative:** `INIT-THREATMODELSPEC-003`
**Repository:** `github.com/grokify/threat-model-spec`

> RMI IDs are stable and permanent. Commits implementing an item carry the trailer `Refs: RMI-<REPOSLUG>-<NNN>`. Phase status is derived from member RMIs — a phase is complete only when all its required RMIs are complete.

This initiative uses the RMI-THREATMODELSPEC-2xx block (INIT-001 used 0xx, INIT-002 used 1xx).

## Phase 1 — IR Hardening and CLI Docs

**Theme:** The gaps both dogfood runs hit identically get structural fixes — framework categorization becomes queryable data with deterministically computed coverage checks, prohibited-outcome gets authored, and the CLI reference catches up to the shipped verbs

- [ ] `RMI-THREATMODELSPEC-200` Finding framework categorization fields
  - `strideCategories`/`owaspIds`/`attackTechniqueIds` on `ir.Finding`, validated via existing `STRIDEThreat`/`ValidateOWASPID`/`ValidateTechniqueID`; lifecycle-validation warnings; schema regenerated, all v0.8.0 examples validate unchanged; enum/round-trip tests
- [ ] `RMI-THREATMODELSPEC-201` Deterministic coverage-check computation
  - `evaluation.ComputeCoverageChecks` computing has-stride-mapping, has-prohibited-outcome, has-assets, has-threat-actor, has-invariant, has-evidence-per-finding from the model; `tms gate`/`analyze --apply` prefer computed results over self-reports (warning on conflict); agent specs + regenerated plugins populate the new fields
- [ ] `RMI-THREATMODELSPEC-202` prohibited-outcome spike and resolution
  - Root-cause note (authoring vs design gap) with evidence from both dogfood models; expected fix: product-definition agent guidance + worked example + flagship-example requirement; alternative fix: documented decision + coverage-check change (enum value stays)
- [ ] `RMI-THREATMODELSPEC-203` CLI reference pages for the five undocumented verbs
  - docs/cli/{analyze,gate,report,status,profile}.md in the generate/validate page format; mkdocs nav; strict build green

## Phase 2 — Persistence (Fuller Store)

**Theme:** Analysis history outlives the JSON document — an opt-in embedded Dolt store records runs, assessments, gates, and framework reports append-only with a Dolt-commit audit envelope, while `tms` without a store stays byte-identical to v0.8.0

- [ ] `RMI-THREATMODELSPEC-204` Store package: Ent schema over embedded Dolt
  - `store/` with five append-only entities (analysis_runs, judge_runs, judge_assessments, gates, framework_reports); embedded `dolthub/driver` (no dolt binary); `--data-dir`/`TMS_DATA_DIR` opt-in with `~/.productbuildershq/tms` default; dependency versions verified at implementation time
- [ ] `RMI-THREATMODELSPEC-205` tms persistence integration and history verb
  - Write hooks in analyze/gate/report with one Dolt commit per write batch (`tms: <verb> <run-id>`); `tms history` read verb (table/json); parity test proves disabled-store output identical; store round-trip test on all three CI OSes
- [ ] `RMI-THREATMODELSPEC-206` v0.9.0 release
  - CHANGELOG.json + regenerated CHANGELOG.md, release notes, versioned specification (schema changed in RMI-200), mkdocs nav, README; push, CI green on ubuntu/macos/windows, tag, record release in visionstudio

## Phase 3 — Empirical Dogfood (deferred, data-gated)

**Theme:** The three never-dogfooded stages and builder-definition's rubric get real-run evidence — execution starts when a target satisfying the data requirements is named, not before

- [ ] `RMI-THREATMODELSPEC-207` builder-definition rubric empirical discrimination
  - A real, known-imperfect design target analyzed at builder-definition; acceptance: non-uniform category scores on real content (or a documented rubric recalibration if it still rubber-stamps)
- [ ] `RMI-THREATMODELSPEC-208` Dogfood run 3: deployment, builder-operations, product-operations
  - Acceptance = data requirements from the stage profiles: target with real `iac` + `deployment-manifest` (4 ASPM domains), reachable `runtime-endpoint` + `telemetry` + ≥1 `incident` record; full plan→apply→gate cycles, results as a canonical example
- [ ] `RMI-THREATMODELSPEC-209` Success-metric review and initiative close-out
  - Verify PRD success metrics with evidence; log any new residual gaps; release if warranted; transition initiative
