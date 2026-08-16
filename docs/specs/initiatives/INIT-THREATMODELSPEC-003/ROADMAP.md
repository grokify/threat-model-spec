# PDLC Lifecycle Analysis — Follow-On Hardening and Persistence — Roadmap

**Initiative:** `INIT-THREATMODELSPEC-003`
**Repository:** `github.com/grokify/threat-model-spec`

> RMI IDs are stable and permanent. Commits implementing an item carry the trailer `Refs: RMI-<REPOSLUG>-<NNN>`. Phase status is derived from member RMIs — a phase is complete only when all its required RMIs are complete.

This initiative uses the RMI-THREATMODELSPEC-2xx block (INIT-001 used 0xx, INIT-002 used 1xx).

## Phase 1 — IR Hardening and CLI Docs

**Theme:** The gaps both dogfood runs hit identically get structural fixes — framework categorization becomes queryable data with deterministically computed coverage checks, prohibited-outcome gets authored, and the CLI reference catches up to the shipped verbs

- [x] `RMI-THREATMODELSPEC-200` Finding framework categorization fields
  - `strideCategories`/`owaspIds`/`attackTechniqueIds` on `ir.Finding`, validated via existing `STRIDEThreat`/`ValidateOWASPID`/`ValidateTechniqueID`; lifecycle-validation warnings; schema regenerated, all v0.8.0 examples validate unchanged; enum/round-trip tests
- [x] `RMI-THREATMODELSPEC-201` Deterministic coverage-check computation
  - `evaluation.ComputeCoverageChecks` computing has-stride-mapping, has-prohibited-outcome, has-assets, has-threat-actor, has-invariant, has-evidence-per-finding from the model; `tms gate`/`analyze --apply` prefer computed results over self-reports (warning on conflict); agent specs + regenerated plugins populate the new fields
- [x] `RMI-THREATMODELSPEC-202` prohibited-outcome spike and resolution
  - Root-cause note (authoring vs design gap) with evidence from both dogfood models; expected fix: product-definition agent guidance + worked example + flagship-example requirement; alternative fix: documented decision + coverage-check change (enum value stays)
- [x] `RMI-THREATMODELSPEC-203` CLI reference pages for the five undocumented verbs
  - docs/cli/{analyze,gate,report,status,profile}.md in the generate/validate page format; mkdocs nav; strict build green
- [x] `RMI-THREATMODELSPEC-210` Document lifecycle IR objects in the Specification guide *(added mid-phase — the published guide predated INIT-002's whole lifecycle-IR layer)*
  - New Lifecycle IR Objects specification page; wired into nav

## Phase 2 — Persistence (Cancelled)

**Theme:** ~~Analysis history outlives the JSON document — an opt-in embedded Dolt store records runs, assessments, gates, and framework reports append-only with a Dolt-commit audit envelope, while `tms` without a store stays byte-identical to v0.8.0~~

**Cancelled.** `threat-model-spec` does not get its own persistence layer. Per `visionstudio-cloud`'s open-core split — *capture and record locally = open (`visionstudio`); aggregate, serve, and analyze in the cloud = private (`visionstudio-cloud`)* — an embedded Dolt store inside this repo doesn't fit: `threat-model-spec` stays a pure JSON IR spec plus a local, standalone `tms` CLI with no database at all. The `ThreatModel` JSON document already is the local record. Threat-modeling history/aggregation as a paid, multi-tenant capability belongs in `visionstudio-cloud` instead, as its own initiative there — informed by, but not implemented in, this repo.

- [x] ~~`RMI-THREATMODELSPEC-204` Store package: Ent schema over embedded Dolt~~ — cancelled
- [x] ~~`RMI-THREATMODELSPEC-205` tms persistence integration and history verb~~ — cancelled
- [x] ~~`RMI-THREATMODELSPEC-206` v0.9.0 release~~ — cancelled (a v0.9.0 release may still happen for unrelated reasons, but not as this RMI)

## Phase 3 — Empirical Dogfood (deferred, data-gated)

**Theme:** The three never-dogfooded stages and builder-definition's rubric get real-run evidence — execution starts when a target satisfying the data requirements is named, not before

- [ ] `RMI-THREATMODELSPEC-207` builder-definition rubric empirical discrimination
  - A real, known-imperfect design target analyzed at builder-definition; acceptance: non-uniform category scores on real content (or a documented rubric recalibration if it still rubber-stamps)
- [ ] `RMI-THREATMODELSPEC-208` Dogfood run 3: deployment, builder-operations, product-operations
  - Acceptance = data requirements from the stage profiles: target with real `iac` + `deployment-manifest` (4 ASPM domains), reachable `runtime-endpoint` + `telemetry` + ≥1 `incident` record; full plan→apply→gate cycles, results as a canonical example
- [ ] `RMI-THREATMODELSPEC-209` Success-metric review and initiative close-out
  - Verify PRD success metrics with evidence; log any new residual gaps; release if warranted; transition initiative
