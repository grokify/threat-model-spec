# PDLC Threat Modeling — Stage Analysis Reports and Agent Workflows — Roadmap

**Initiative:** `INIT-THREATMODELSPEC-002`
**Repository:** `github.com/grokify/threat-model-spec`

> RMI IDs are stable and permanent. Commits implementing an item carry the trailer `Refs: RMI-<REPOSLUG>-<NNN>`. Phase status is derived from member RMIs — a phase is complete only when all its required RMIs are complete.

This initiative uses the RMI-THREATMODELSPEC-1xx block (0xx was INIT-THREATMODELSPEC-001). The six-stage PDLC taxonomy it consumes landed ahead of this initiative as cross-repo prerequisite work in `productbuildershq-frameworks`, `pdlc`, and `specification-workflow-spec`; those changes are tracked in their own repos. The RMIs below are the threat-model-spec-side work.

## Phase 1 — Foundations: IR core and stage conformance

**Theme:** Lifecycle IR objects, the stage enum, and the ASPM overlay land additively; the cross-repo string-constant convention gets its drift guard here — the one-way-door core, validated before the schema version is finalized

- [ ] `RMI-THREATMODELSPEC-101` ir.Stage enum and cross-repo conformance test
  - `ir.Stage` mirrors `pdlc.Stage*` (import pdlc directly — TMS is outside the pdlc→visionspec→spec-workflow-spec cycle); test asserts `ir.Stage` == `pdlc.Stage*` and every `spectype.PDLCStage*` resolves to a real pdlc stage. This is the drift guard for the whole three-repo convention.
- [ ] `RMI-THREATMODELSPEC-102` ASPMDomain overlay type
  - `ir.ASPMDomain` (10 domains) with primary-stage mapping (implementation 1–5, deployment 6–9, builder-operations 10); primary/cross-stage handling; mapping test asserting all 10 present and each primary stage valid
- [ ] `RMI-THREATMODELSPEC-103` Lifecycle IR objects
  - Artifact, AnalysisRun, Evidence (tagged-union locator: file/document/config/query/url), SecurityRequirement, ArchitectureAssertion, Finding (Observation folded in), Gate — as optional ThreatModel fields; referential-integrity validation in `ir/validate.go`; per-type enum/JSON round-trip/field tests
- [ ] `RMI-THREATMODELSPEC-104` Schema regeneration and backward compatibility
  - Regenerate schemas for the new types; backward-compat suite proving all v0.7.0-era example models validate unchanged; `phase` documented as deprecated in favor of `Lifecycle.CurrentStage`
- [ ] `RMI-THREATMODELSPEC-105` structured-evaluation gap assessment
  - Assess evidence-locator types, insufficient-evidence verdict, stage/profile metadata, multi-judge disagreement against real fixtures; land additive upstream PRs only where confirmed; prefer conventions over upstream changes

## Phase 2 — Stage report profiles and rubrics

**Theme:** The six per-stage report profiles and their rubrics become concrete, embedded, and calibrated so a stage analysis has a defined contract and a discriminating grader

- [ ] `RMI-THREATMODELSPEC-106` Six StageReportProfile definitions
  - Prose spec + embedded data per stage; `InputMode` (workflow-specs for the two spec-driven stages, artifact-types for builder-side); builder-side profiles reference their `ASPMDomains`; coverage checks
- [ ] `RMI-THREATMODELSPEC-107` Artifact-availability profiles
  - first-party / third-party / open-source as data + spec section, mapping available artifacts to permitted stage analyses and report-scope annotations; `AnalysisRun.Profile` records which governed a run
- [ ] `RMI-THREATMODELSPEC-108` Six stage rubrics with calibration fixtures
  - `evaluation/rubrics/stages/product-definition.rubric.json` … `product-operations.rubric.json`; seeded-defect fixtures; calibration test that each rubric produces non-passing categories on its fixture (guards against rubber-stamp rubrics)
- [ ] `RMI-THREATMODELSPEC-109` Gate evaluation
  - `summary.SummaryReport` aggregation (deterministic checks + rubric + claims verdicts) → GO/NO-GO written into `Gate.Result` with evidence; `tms gate --stage <s> --ci`

## Phase 3 — Agent workflows and `tms analyze`

**Theme:** The six per-stage agents ship as agnostic specs with generated per-tool plugins, `tms analyze` orchestrates them, and dogfood run 1 exercises the whole loop end-to-end on a first-party product

- [ ] `RMI-THREATMODELSPEC-110` Six agnostic agent/workflow definitions
  - One `multi-agent-spec` agent (+ slash command) per stage in `agents/specs/`; inputs, ordered steps, output-object contract, adversarial-critic step, rubric ref, one worked example each; definition-validation tests (contracts parse, rubric/artifact refs resolve)
- [ ] `RMI-THREATMODELSPEC-111` assistantkit plugin generation
  - Generate `agents/plugins/{claude,kiro,gemini}/` from `agents/specs/`; generation-freshness test fails if plugins are stale relative to specs (same discipline as the schema embed check)
- [ ] `RMI-THREATMODELSPEC-112` tms analyze command
  - `cmd/tms`: load profile → resolve inputs (record Artifacts) → open AnalysisRun → agent reasons/returns objects → validate + write → grade via stage rubric with judge provenance → close; `--dry-run` reports would-run + missing inputs without invoking an agent; the single writing verb
- [ ] `RMI-THREATMODELSPEC-113` Dogfood run 1 (first-party)
  - First-party analysis of a PBHQ-ecosystem product across product-definition, builder-definition, implementation stages via a generated agent calling `tms analyze`; committed as an example; workflow/spec defects fixed from findings

## Phase 4 — Framework reports and CLI

**Theme:** Any threat model exports framework-specific reports from one canonical model, and the read-side `tms` verbs round out the CLI

- [ ] `RMI-THREATMODELSPEC-114` FrameworkReport IR type
  - `ir.FrameworkReport` + per-framework typed payloads (stride/linddun/mitre-attack/owasp/attack-tree); computed-first, optional materialization with `SourceRevision`
- [ ] `RMI-THREATMODELSPEC-115` Framework report exports
  - `tms report --framework X` derives each report from the canonical model; JSON + Markdown; golden-file tests against the canonical example; `tms validate` warns on stale materialized reports
- [ ] `RMI-THREATMODELSPEC-116` tms read verbs
  - `tms status` (lifecycle state), `tms report`, `tms gate`, `tms profile`; two output modes (human/JSON) with meaningful CI exit codes; errors name the object and the rule

## Phase 5 — External-profile dogfood, spec, and release

**Theme:** A partial-artifact assessment proves the third-party/OSS profiles, then the versioned specification ships after CI

- [ ] `RMI-THREATMODELSPEC-117` Dogfood run 2 (partial profile)
  - One third-party (docs + live site) or open-source (docs + code) assessment under a partial profile; report carries `profile:` and explicit not-analyzed scope; validates the artifact-availability design before schema freeze
- [ ] `RMI-THREATMODELSPEC-118` Versioned specification and docs
  - `docs/versions/vNext/` specification + copied schemas; release notes; CHANGELOG.json + regenerated CHANGELOG.md; mkdocs nav; README; per the repo release workflow
- [ ] `RMI-THREATMODELSPEC-119` Success-metric review and release
  - Verify all PRD success metrics with evidence; push and wait for CI; tag; record the release in visionstudio; log residual gaps (DoltDB persistence) as a follow-on initiative
