# PDLC Threat Modeling — Stage Analysis Reports and Agent Workflows

**Six-Page Narrative — INIT-THREATMODELSPEC-002**

## 1. Introduction

Threat Model Spec today is a snapshot format: it describes the architecture, threats, and mitigations of a system that already exists, renders diagrams, and exports STIX. This narrative proposes evolving it into the canonical **lifecycle security IR** for AI-accelerated product development: one threat model per product that accumulates evidence-backed analysis from product definition through production operations, produced by agents, graded by LLM judges, and consumed by gates, diagrams, and reports.

This is a one-way-door decision. The IR shape (how claims, evidence, artifacts, and stages relate) and the PDLC stage taxonomy become interface commitments that agent workflows, judge rubrics, DoltDB storage, and downstream ecosystem tools (pdlc-workflows, visionstudio) will build against. Reversing them after adoption means migrating every producer and consumer.

### Tenets (unless you know better ones)

1. **One evolving model, many producers, many views.** Frameworks (STRIDE, LINDDUN, ATT&CK, OWASP) are projections over one canonical model, never separate source-of-truth documents.
2. **Spec first; analysis enabled on top.** The IR is the foundation and the primary deliverable. Built on it, Threat Model Spec also *enables* analysis: it ships a `tms analyze` command that AI coding agents (e.g. Claude Code) invoke, plus agent/subagent and workflow specs those agents execute. The agent supplies the analytical reasoning; Threat Model Spec supplies the command surface, the specs, the structured output target, and the grading. It does not reimplement SAST/DAST/SCA scanners (it consumes their output) and is not an autonomous hosted analysis service.
3. **Every consequential claim carries evidence.** Observed facts, interpretations, and judgments are distinct object types; a judge may return "insufficient evidence."
4. **Analyze what exists.** Stage analyses are defined by required inputs; artifact-availability profiles make partial analysis (third-party, open-source) a first-class mode, not a degraded one.
5. **Additive evolution.** Existing threat models stay valid; lifecycle semantics arrive as optional objects in a new schema version.

### Simplifying Assumptions

- The stage set is fixed at six: Product Definition, Builder Definition, Implementation, Deployment, Builder Operations, Product Operations — the split of AWS AI-DLC's three phases (Inception/Construction/Operation) into product and builder lenses. Red teaming and adversarial assurance attach to stages (Builder Operations) rather than being their own stage.
- Threat Model Spec analyzes by these 6 stages only. The mapping from concrete spec types to stages lives in specification-workflow-spec (which tags each spec type with a stage as string constants matching pdlc's values — not a Go import, to avoid a dependency cycle); threat-model-spec never enumerates spec types or parses workflows. This keeps it decoupled from the dozens of spec workflows and is a deliberate implementation simplification.
- structured-evaluation is the only judge-report framework we target.
- CI/CD enforcement stays outside the spec; the IR records gate criteria and results only.

## 2. Customer Problem

### Who is the customer?

Security engineers and AI-native development teams in the grokify/plexusone/ProductBuildersHQ ecosystem first, then external teams adopting the open-source format. Secondary: builders of security agents and tooling who need an interchange format.

### What problem are they facing?

AI generation accelerates code production faster than human security review scales. Design-time threat models go stale within days; implementation drifts from design silently; analysis results scatter across scanner-specific formats; and LLM-produced findings arrive as unverified prose. Teams either slow down (gate everything on human review) or fly blind (ship on ungraded agent output).

### How do they solve it today?

Point-in-time threat modeling workshops, per-tool dashboards (SAST in one, DAST in another, SIEM in a third), and manual synthesis in documents. Traceability from "product harm" to "control verified in production" effectively does not exist. For third-party and open-source assessment, teams rely on questionnaires and ad-hoc review with no structured output.

## 3. Solution

### The customer experience

A team defines (or an agent bootstraps) a threat model at product-definition time containing assets, abuse cases, and invariants. At each subsequent stage, an agent workflow reads the stage's artifacts, appends an analysis run with claims and evidence to the same model, and a judge grades the report against the stage rubric. `tms` renders current-state diagrams, exports framework reports (STRIDE, LINDDUN, ATT&CK, OWASP), and evaluates stage gates. When deployment evidence contradicts a design assumption, the model records a contradicted architecture assertion with both pieces of evidence attached.

### Key capabilities

1. **Lifecycle IR objects:** `artifacts`, `analysisRuns`, `evidence`, `securityRequirements` (invariants, prohibited outcomes), `architectureAssertions` (intended vs. observed), `findings`, `gates`, replacing reliance on the singular `phase` field.
2. **Stage analysis report profiles:** normative definitions of report contents, required/optional inputs, and coverage expectations for each of the six stages (the builder-side stages structured by ASPM domains).
3. **Agent workflow definitions (agnostic, generated per tool):** per-stage specifications of the analysis procedure — inputs, steps, output objects, and evaluation criteria — authored once as agnostic `multi-agent-spec` definitions in `agents/specs/`, with `assistantkit` generating the Claude Code, Kiro, and Gemini plugins in `agents/plugins/` (the repo's existing convention).
4. **`tms analyze` command:** the CLI entry point an AI coding agent invokes to run a stage workflow — it loads the stage profile, gathers the declared input artifacts, drives the agent, and writes the resulting analysis run into the model. The reasoning is the agent's; the orchestration and structured output are `tms`'s.
5. **Artifact-availability profiles:** first-party (all stages), third-party (docs + live site), open-source (docs + code), determining which analyses are credible.
6. **Per-stage evaluation:** structured-evaluation rubrics per stage, claims verification against evidence, GO/NO-GO gate summaries; judge provenance on every assessment.
7. **Framework reports in the IR:** held and exportable per framework from one model.
8. **PDLC codification:** the AI-accelerated stage set specified normatively in ProductBuildersHQ/pdlc, referenced (not duplicated) by threat-model-spec.

### What this is NOT

Not a reimplementation of SAST/DAST/SCA scanners (it consumes their output), not a SOC, not a policy engine, not a telemetry store, not an autonomous hosted analysis service, and not a new set of per-framework file formats.

## 4. Why Now?

### Market timing

AI-agent development pipelines are becoming the norm internally (visionstudio, omniagent ecosystem) and externally. OWASP's Agentic Security Top 10 (2026) signals the industry turn toward agent-aware security. No open format yet occupies "agent-produced, judge-graded, lifecycle security analysis" — SARIF is scanner-output-only, OTM is architecture-only.

### Internal readiness

The hard prerequisites already exist: threat-model-spec v0.7.0 has the security-domain vocabulary (assets, scenarios, risk, detections, red/blue team, SBOM/VEX, attack graphs); structured-evaluation v0.6.0 provides rubric/claims/summary reports; the PDLC repo provides the lifecycle-spec home; INIT-THREATMODELSPEC-001 cleans the baseline. The design groundwork is captured (docs/design ideation, 2026-08).

## 5. Business Case

### Customer impact

Security review keeps pace with AI-speed development: analysis happens per stage automatically, humans review graded findings instead of raw output, and one traceability chain runs from product harm to production signal. Third-party and open-source assessment gains a structured, comparable output format.

### Investment required

One schema-design cycle (the one-way-door core), Go types + generated schemas, six stage report profiles and workflow definitions, six rubrics, structured-evaluation gap assessment (likely small PRs), and dogfooding on our own repos. PDLC stage codification across pdlc / productbuildershq-frameworks / specification-workflow-spec landed ahead as prerequisite work. No new infrastructure; DoltDB persistence is an optional later phase.

### Return on investment

Internally: every ecosystem repo gets stage-gated security analysis at near-zero marginal cost once workflows exist. Externally: positions Threat Model Spec as the interchange format in a space with no incumbent, driving adoption of the whole toolchain.

## 6. Decision Analysis

### One-Way Door Decisions

1. **IR object model:** the Artifact → Observation/Claim → Evidence decomposition and how analysis runs, findings, and assessments relate. Everything downstream builds on this shape.
2. **Stage taxonomy:** the six PDLC stages and their boundaries, codified in productbuildershq-frameworks + pdlc for the whole ecosystem.
3. **Deprecation path for `phase`:** retained-but-deprecated in favor of lifecycle objects.
4. **Boundary declaration:** spec-first, with analysis *enabled* through a `tms analyze` command and agent/workflow specs (the agent reasons; `tms` orchestrates, grades, and stores) — not by reimplementing scanners or becoming an autonomous hosted service. This ordering — format as foundation, agent-driven analysis as the layer on top — is the durable product identity.

### Two-Way Door Decisions

Report profile field details, individual rubric contents, which framework exports ship first, CLI verb naming, DoltDB table design, and artifact-type enumerations — all revisable per schema version.

## 7. Risks and Dependencies

### Key risks

| Risk | Mitigation |
|------|-----------|
| Schema over-design before real agent usage | Dogfood each phase on our own repos before finalizing the version |
| Judge grading uncalibrated (rubber-stamps or over-rejects) | Seeded calibration findings; "insufficient evidence" verdict; confidence routing to humans |
| Scope creep into building scanners/agents | Tenet 2; workflows ship as definitions, reference agents live outside the spec repo |
| structured-evaluation extensions stall | Gap assessment early (Phase 1); extensions are additive PRs to a repo we control |

### Dependencies

INIT-THREATMODELSPEC-001 (clean baseline — required), ProductBuildersHQ/productbuildershq-frameworks + pdlc (six-stage taxonomy), ProductBuildersHQ/specification-workflow-spec (spec→stage categorization), plexusone/structured-evaluation (judge reports), plexusone/multi-agent-spec + assistantkit (agnostic agent specs + generation), grokify/schemakit (schema linting).

### Open questions

Whether Observation and Claim merge into one object with a `kind` discriminator; whether framework reports are materialized objects or computed exports (leaning: computed, with optional materialization); minimum viable evidence-locator set.

## 8. Post-Launch Iteration

### Launch success criteria

- Next schema version published with lifecycle objects; existing v0.7.0 models validate unchanged
- All six stage report profiles + workflow definitions + rubrics shipped
- One first-party product analyzed end-to-end across at least three stages, judge-graded, with framework reports exported
- One third-party or open-source assessment produced with a partial-artifact profile
- PDLC stages codified and cross-referenced from both repos

### Iteration plan

v-next+1: DoltDB persistence with judge provenance; reference agent implementations; operations-stage SIEM/XDR reference patterns; coverage metrics maturation based on dogfood data.

### Long-term ownership

threat-model-spec maintainers own the IR and report profiles; pdlc maintainers own stage definitions; structured-evaluation maintainers own judge-report types. Cross-repo changes coordinate through visionstudio initiatives.
