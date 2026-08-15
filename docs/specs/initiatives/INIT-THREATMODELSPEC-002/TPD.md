# TPD — PDLC Threat Modeling — Stage Analysis Reports and Agent Workflows

**Initiative:** `INIT-THREATMODELSPEC-002`
**Technical Plan Document — delivery phases, sequencing, and verification**

Depends on INIT-THREATMODELSPEC-001 (clean baseline) completing first. RMI block: `RMI-THREATMODELSPEC-1xx`.

## Delivery Phases

### Phase 1 — Foundations: stage codification and IR core

The one-way-door decisions land here, validated by dogfooding before the schema version is finalized.

1. **[done]** Codify the six PDLC stages: `frameworks/pdlc/` catalog entry in productbuildershq-frameworks (stages, deliverables, gates, dependency graph, AI-DLC crosswalk); pdlc re-exports via `pdlc.Stages()`/`StageByID()`/`Stage*` constants; `docs/specification/lifecycle.md` rewritten for the six-stage model.
2. **[done]** Add `PDLCStage` to `SpecType` in specification-workflow-spec (`pkg/spectype`) as **string constants matching pdlc's values** (not a Go import — cycle); categorize the 18 core spec types (PRD → product-definition, TRD → builder-definition, plan/roadmap → none); registry tests.
3. Lifecycle IR objects in `ir/`: Artifact, AnalysisRun, Evidence (locator union), SecurityRequirement, ArchitectureAssertion, Finding, Gate — plus the `ir.Stage` enum (mirroring `pdlc.Stage*`) and the `ASPMDomain` overlay — with validation, tests, schema regeneration.
4. structured-evaluation gap assessment against real fixture reports; file/land any additive upstream PRs.
5. Stage conformance test (FR1.4): `ir.Stage` == `pdlc.Stage*`, and every `spectype.PDLCStage*` resolves to a real pdlc stage — the drift guard across the three repos, living here because TMS is the only repo importing both. Plus a categorization test bucketing a sample workflow's specs into stages via the registry, and an ASPM-mapping test.

**Exit:** a hand-authored lifecycle model for one of our own products validates; v0.7.0 examples still validate; conformance + gap assessment resolved. (Items 1–2 landed ahead of the initiative as prerequisite cross-repo work; see the productbuildershq-frameworks / pdlc / specification-workflow-spec commits.)

### Phase 2 — Stage report profiles and rubrics

1. Six StageReportProfile definitions (prose spec + embedded data): contents, inputs, coverage checks; builder-side profiles reference their ASPM domains.
2. Artifact-availability profiles (first-party, third-party, open-source) as data + spec section.
3. Six stage rubrics in `evaluation/rubrics/stages/`; rubric calibration fixtures (seeded defects).
4. Gate evaluation: summary-report aggregation → `Gate.Result`; `tms gate --ci`.

**Exit:** each rubric discriminates on calibration fixtures; profiles validated in tests.

### Phase 3 — Agent workflows (agnostic + generated) and `tms analyze`

1. Six per-stage analysis agents authored as agnostic `multi-agent-spec` definitions in `agents/specs/` (inputs, steps, output contracts, critic pass, rubric ref, worked example each).
2. `assistantkit` generation of `agents/plugins/{claude,kiro,gemini}/` from the specs; generation-freshness test (fails if plugins stale vs. specs).
3. `tms analyze` command in `cmd/tms` (load profile → resolve inputs → open AnalysisRun → agent reasons → write + validate → grade → close; `--dry-run` for agent-less CI).
4. Definition-validation tests (contracts parse, rubric/artifact references resolve).
5. Dogfood run 1: first-party analysis of a PBHQ-ecosystem product across product-definition, builder-definition, implementation stages, driven by a generated agent (Claude Code) calling `tms analyze` (agent-executed, judge-graded).

**Exit:** dogfood model has ≥3 stages of graded analysis runs produced via `tms analyze`; workflow/spec defects fixed from findings.

### Phase 4 — Framework reports and CLI

1. FrameworkReport IR type + per-framework typed payloads.
2. Computed exports: STRIDE, LINDDUN, ATT&CK, OWASP, attack-tree — JSON + Markdown, golden tests.
3. `tms` verbs: `status`, `report`, `gate`, `profile` (validate extended in Phase 1).
4. Staleness warning for materialized reports.

**Exit:** ≥4 framework reports export from the dogfood model.

### Phase 5 — External-profile dogfood, spec, and release

1. Dogfood run 2: one third-party (docs + live site) or open-source (docs + code) assessment under a partial profile.
2. Versioned specification document (`docs/versions/vNext/`), release notes, changelog, mkdocs nav, README.
3. Success-metric review against PRD; residual gaps logged as follow-on RMIs (DoltDB persistence initiative seeded).

**Exit:** release tagged after CI; all PRD success metrics evidenced.

## Sequencing Rationale

- pdlc codification precedes IR finalization (stage enum mirrors it, not vice versa).
- Gap assessment precedes rubric/gate work (upstream changes are the long pole if needed).
- Workflow definitions precede framework exports: dogfood-produced models are the export test data.
- Two dogfood runs (first-party full-stack, then partial-profile) are the empirical checks on the one-way-door design before the schema version is declared stable.

## Verification per Phase

| Phase | Verification |
|-------|-------------|
| 1 | `go test ./...`, schemakit lint delta (no *new* errors vs. the 373 pre-existing camelCase baseline — see TRD §7, not a zero-errors gate), v0.7.0 backward-compat suite, pdlc conformance test |
| 2 | Rubric calibration fixtures produce non-uniform scores; profile data validates |
| 3 | Dogfood run 1 artifacts committed as examples; judge grades recorded |
| 4 | Golden-file export tests; CLI smoke tests in cmd tests |
| 5 | Full pre-release checklist (repo CLAUDE.md); success-metric evidence in release notes |

## Risks to the Plan

| Risk | Trigger | Response |
|------|---------|----------|
| Upstream structured-evaluation change needed but slow | Gap assessment finds a non-additive need | Convention-based workaround in TMS; upstream later |
| IR shape wrong under dogfood | Phase 3 dogfood produces unfillable/ambiguous objects | Revise before vNext freeze — schema not versioned until Phase 5 |
| Scope creep into agent implementation | Phase 3 pressure to "just build the agent" | Reference agents live outside; only definitions + one worked example in-repo |

## Roadmap Note

Detailed RMIs (RMI-THREATMODELSPEC-101…) will be drafted in ROADMAP.md for this initiative after spec approval, one phase group per delivery phase above, and imported into visionstudio.
