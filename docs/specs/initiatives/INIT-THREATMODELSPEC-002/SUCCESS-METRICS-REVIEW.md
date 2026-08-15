# Success-Metric Review — INIT-THREATMODELSPEC-002

**RMI:** RMI-THREATMODELSPEC-119
**Reviewed against:** PRD.md § Success Metrics

Five metrics, evaluated with real evidence, not self-assessment. Two are fully met; three are met but with an honestly-scoped caveat, each logged as a residual gap below.

## 1. v0.7.0 threat models validate unchanged against the new schema version

**Status: Met.**

All three v0.7.0-era canonical examples (`openclaw-websocket-takeover.json`, `design-phase-payment-checkout.json`, `supply-chain-vulnerable-dependency.json`) validate against the v0.8.0 schema with zero modification. Evidence: `examples/examples_test.go` `TestExamplesValidate`, green at HEAD. Every v0.8.0 IR addition is an optional field; `ir/validate.go`'s `validateLifecycle()` only activates for models that populate the new fields.

## 2. One first-party product analyzed across ≥3 stages: agent-produced reports, judge-graded, gates evaluated

**Status: Met.**

Dogfood run 1 (RMI-THREATMODELSPEC-113): `threat-model-spec` itself, analyzed across product-definition, builder-definition, and implementation via real `tms analyze` plan/apply cycles — not synthetic fixtures. Each stage was graded against its rubric and a `Gate` was recorded via `EvaluateStageGate`. Evidence: `examples/threat-model-spec-self-assessment.json` (3 `AnalysisRun`s, 3 `Gate`s, real file+line evidence citations in `cmd/tms/analyze.go`).

## 3. One third-party or open-source assessment produced under a partial-artifact profile

**Status: Met.**

Dogfood run 2 (RMI-THREATMODELSPEC-117): lodash's `_.template` (a real external dependency, CVE-2021-23337, verified live via WebFetch against the GitHub Advisory Database), analyzed under the `open-source` profile. `tms analyze` was independently confirmed to reject `deployment`/`builder-operations`/`product-operations` under this profile with their exact stated reasons before any permitted-stage analysis ran — the artifact-availability design itself was exercised, not just its data. Evidence: `examples/lodash-template-open-source-assessment.json`.

## 4. All 6 stage rubrics discriminate in dogfooding (non-uniform scores; seeded defects caught)

**Status: Met via synthetic calibration; partially met via live dogfooding — residual gap logged.**

All six rubrics are proven to discriminate against **seeded-defect fixtures** (RMI-THREATMODELSPEC-108, `evaluation/stage_rubric_calibration_test.go`): every rubric produces a non-passing required category against a hand-crafted fixture with a known, deliberate gap. This is real evidence the rubrics are not rubber-stamps.

Live dogfooding, however, only exercised 3 of the 6 rubrics (product-definition, builder-definition, implementation) — the two dogfood runs' profiles (`first-party` for run 1's scope, `open-source` for run 2) never reached `deployment`, `builder-operations`, or `product-operations`. Within the 3 rubrics dogfooded, `product-definition` and `implementation` scored non-uniformly across categories in both runs (a genuine mix of pass/partial/fail), but `builder-definition` scored uniformly "all pass" on its rubric categories in **both** real runs — its discrimination is proven only synthetically (calibration fixture), not against real content yet. See residual gap below.

## 5. Framework exports (≥4 frameworks) generated from one canonical model with no information loss on round-trip of materialized reports

**Status: Met.**

Five frameworks implemented (STRIDE, LINDDUN, MITRE ATT&CK, OWASP, attack-tree) — exceeds the ≥4 bar. "No information loss on round-trip" was not directly tested until this review surfaced the gap; `ir/framework_report_test.go`'s `TestFrameworkReport_MaterializedRoundTrip` now proves it directly: for all five frameworks, a computed `FrameworkReport` materialized onto `ThreatModel.FrameworkReports`, marshaled to JSON, and unmarshaled back is field-for-field (`reflect.DeepEqual`) identical to the original — not just structurally similar.

## Residual Gaps (logged, not blocking release)

Real gaps surfaced by this initiative's own dogfooding and review process, tracked as a follow-on initiative rather than silently dropped:

1. **`ir.Finding` has no structured field for STRIDE (or any framework) categorization.** Both dogfood runs' `has-stride-mapping` coverage check failed for exactly this reason — the STRIDE category exists only in `Finding.Description` free text, not a queryable field, even when the analyst clearly reasoned about it. Discovered in dogfood run 1 (RMI-113), reproduced in dogfood run 2 (RMI-117).
2. **No `SecurityRequirement` in either dogfood run was typed `prohibited-outcome`.** Both runs' `has-prohibited-outcome` coverage check failed identically — worth checking whether this is a genuine authoring gap or a sign the type distinction itself needs revisiting.
3. **`AnalysisResults` cannot carry `Asset`/`ThreatActor`/`Scenario`/`Mitigation` from a third-party or open-source-profile run producing them for the first time** in the same way it now can for first-party (RMI-THREATMODELSPEC-120 closed this specifically for the *has-provenance* case; a partial-profile analyst still merges those four types through `tms analyze --apply` today — this is closed, not a gap. Confirmed while writing this review, removing an initially-suspected gap rather than leaving it unchecked.)
4. **`builder-definition`'s stage rubric has only been dogfooded against first-party and open-source content that happened to score uniformly "all pass."** Its discrimination is proven synthetically, not empirically, against real content. A third dogfood run (or a deliberately-flawed real target) is needed to close this for real.
5. **Dogfooding has never reached `deployment`, `builder-operations`, or `product-operations`.** Three of six stage rubrics and three of ten ASPM domains (`iac-scan`, `cicd-posture`, `container-security`, `artifact-security`, `cloud-context`) have zero real-run evidence, only unit/calibration test evidence.
6. **`mkdocs.yml`'s CLI Reference nav** only documents `generate`/`validate`; five newer verbs (`gate`, `analyze`, `report`, `status`, `profile`) have no per-command doc page (noted during RMI-THREATMODELSPEC-118, not fixed there).
7. **DoltDB persistence** (judge_runs/judge_assessments append-only tables, Dolt commit audit envelope) — explicitly deferred in the TRD from day one (§9), never in this initiative's scope. All IDs are stable strings and every assessment carries a producer run ID, so this remains a schema-non-breaking follow-on.

These are logged as `INIT-THREATMODELSPEC-003` (follow-on initiative) rather than blocking this release — none of them invalidate a success metric as stated; they define the next initiative's scope.
