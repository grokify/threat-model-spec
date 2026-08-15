# PRD — PDLC Threat Modeling — Stage Analysis Reports and Agent Workflows

**Initiative:** `INIT-THREATMODELSPEC-002`
**Home repo:** `github.com/grokify/threat-model-spec`
**Related repos:** `github.com/ProductBuildersHQ/pdlc` (stage taxonomy), `github.com/ProductBuildersHQ/specification-workflow-spec` (spec→stage categorization), `github.com/plexusone/structured-evaluation` (judge reports), `github.com/plexusone/multi-agent-spec` + `github.com/plexusone/assistantkit` (agnostic agent specs + generation)

## Overview

Evolve Threat Model Spec from a point-in-time system snapshot into a lifecycle-aware security-analysis IR. Define what a Threat Model Spec Analysis Report contains at each stage of the AI-accelerated PDLC, what inputs each stage analysis requires, and the agent workflows that produce them. Integrate structured-evaluation for per-stage LLM-as-a-Judge grading, and make the IR hold and export framework-specific reports.

**Product ordering: spec first, analysis enabled on top.** The IR/format is the foundation and the primary deliverable. Built on it, the project also *enables* analysis by shipping (a) a `tms analyze` command that AI coding agents (e.g. Claude Code) invoke to run a stage workflow, and (b) agent/subagent and workflow specs those agents execute. The analytical reasoning is the AI agent's; Threat Model Spec supplies the command surface, the specs, the structured output target, and the grading. It does not reimplement SAST/DAST/SCA scanners (it consumes their output) and is not an autonomous hosted analysis service.

## Problem Statement

1. **Staleness:** A threat model created at design time diverges from the implemented and deployed system with no mechanism to record or detect the drift.
2. **Fragmentation:** Spec review, SAST, DAST, red team, and SOC results have no shared format; traceability from product harm to production signal doesn't exist.
3. **Trust:** LLM/agent-generated findings are unverified prose; humans must re-review everything or accept ungraded output.
4. **Partial-artifact analysis:** Assessing third-party products (docs + live site) or open-source dependencies (docs + code) has no structured output or defined scope.

## Goals

1. Codify the six PDLC stages — Product Definition, Builder Definition, Implementation, Deployment, Builder Operations, Product Operations — normatively in ProductBuildersHQ/pdlc (the six-stage split of AWS AI-DLC's three phases: Inception → Product/Builder Definition, Construction → Implementation/Deployment, Operation → Builder/Product Operations). threat-model-spec imports the stage IDs; specification-workflow-spec declares matching string constants (it cannot import pdlc — see FR1.4).
2. Have specification-workflow-spec tag each spec type with its PDLC stage, so threat-model-spec can categorize any workflow's specs into the PDLC stages and analyze **by stage** — decoupled from knowledge of individual spec types or workflows.
3. Define per-stage Threat Model Spec Analysis Report profiles: contents, inputs (by stage), coverage expectations.
4. Define per-stage agent workflow specifications: analysis procedure, input artifacts, output IR objects, evaluation criteria.
5. Extend the IR with lifecycle objects (artifacts, analysis runs, evidence, requirements, assertions, gates) — additively.
6. Integrate structured-evaluation: one rubric per stage, claims verification, GO/NO-GO gate summaries; extend the library only where gaps are confirmed.
7. Hold and export framework-specific reports (STRIDE, LINDDUN, MITRE ATT&CK, OWASP, attack tree) as views over one model.
8. Support artifact-availability profiles: first-party, third-party, open-source.

## Non-Goals

1. Reimplementing scanners (SAST/DAST/SCA) or running SOC monitoring. Threat Model Spec *enables* AI-agent-driven analysis via the `tms analyze` command and agent/workflow specs — the agent reasons, `tms` orchestrates, grades, and stores — but it does not replace dedicated scanners; it consumes their output.
2. A hosted or autonomous agent runtime. The repo ships agnostic agent/workflow *specs* (multi-agent-spec) and the per-tool plugins generated from them, plus the `tms analyze` command those agents call — not a long-running hosted analysis service.
3. CI/CD policy enforcement — gates are recorded, not enforced.
4. Embedding bulk operational data (logs/telemetry) — referenced by query, window, and digest only.
5. Per-framework file formats — frameworks remain views over the canonical IR.

## Target Users

| User | Need |
|------|------|
| Security engineer | Continuous, evidence-backed threat model; graded findings; framework exports for stakeholders |
| Analysis agent (producer) | Clear input requirements, output object contract, and evaluation criteria per stage |
| LLM judge (evaluator) | Stage rubric, evidence to verify claims against, verdict vocabulary including "insufficient evidence" |
| Consumer tooling | Stable schema for gates, diagrams, reports, tickets, STIX export |
| Assessor of external products | Defined partial-artifact profiles and credible-report scope for third-party/OSS targets |

## Functional Requirements

### FR1 — PDLC stages and spec categorization (pdlc + specification-workflow-spec)

| ID | Requirement | Priority |
|----|-------------|----------|
| FR1.1 | pdlc repo defines the six-stage set: Product Definition, Builder Definition, Implementation, Deployment, Builder Operations, Product Operations — as stable machine-readable stage IDs (Go constants + an embedded framework catalog entry re-exported from productbuildershq-frameworks), with entry/exit criteria and artifact types per stage | P0 |
| FR1.2 | `specification-workflow-spec` tags each `SpecType` in its registry with a `PDLCStage` (orthogonal to the existing `Category`: e.g. PRD is `category=source`, `pdlcStage=product-definition`; TRD is `category=technical`, `pdlcStage=builder-definition`). Only the two spec-driven stages (product-definition, builder-definition) appear here — later stages consume non-spec artifacts. Execution-tracking spec types (plan, roadmap) carry no stage. | P0 |
| FR1.3 | threat-model-spec consumes the categorization: given any workflow definition, it buckets that workflow's specs into the PDLC stages via the registry and analyzes **by stage**, without hardcoding knowledge of individual spec types or workflows | P0 |
| FR1.4 | Stage IDs originate in pdlc. threat-model-spec imports them directly. specification-workflow-spec declares matching string constants rather than importing pdlc — importing pdlc there would close a dependency cycle (`pdlc → visionspec → specification-workflow-spec`). A conformance test in **threat-model-spec** (the one repo that can safely import both pdlc and specification-workflow-spec) verifies specification-workflow-spec's `PDLCStage` values match pdlc's stage IDs, so the string-constant convention cannot silently drift. | P0 |
| FR1.5 | Security analysis is defined as a cross-cutting activity per stage in the pdlc lifecycle spec | P1 |

### FR2 — Lifecycle IR objects (threat-model-spec)

| ID | Requirement | Priority |
|----|-------------|----------|
| FR2.1 | `artifacts`: analyzed inputs with type, URI, revision, stage, digest | P0 |
| FR2.2 | `analysisRuns`: producer identity/version, method, stage, input artifacts, timestamps, status | P0 |
| FR2.3 | `evidence`: artifact reference + locator (path/lines, manifest path, log query + window) + digest + excerpt | P0 |
| FR2.4 | `securityRequirements`: invariants, prohibited outcomes, privacy/approval/recovery/detection requirements with origin artifact and verification links | P0 |
| FR2.5 | `architectureAssertions`: intended vs. observed with expected/observed evidence and status (supported/contradicted/unverified) | P0 |
| FR2.6 | `findings`: analyzer claims with type (threat/vulnerability/weakness/drift), evidence refs, confidence, status | P0 |
| FR2.7 | `gates`: stage, criteria, result, evaluator, evidence | P1 |
| FR2.8 | Existing objects (assets, scenarios, diagrams, mitigations, detections) unchanged; `phase` deprecated but retained; all new objects optional | P0 |
| FR2.9 | Stable IDs and provenance (producer run) on all new objects | P0 |

### FR3 — Stage analysis report profiles

| ID | Requirement | Priority |
|----|-------------|----------|
| FR3.1 | Product Definition report: assets, actors, abuse cases, invariants, prohibited outcomes, privacy requirements | P0 |
| FR3.2 | Builder Definition report: components, flows, trust boundaries, STRIDE/LINDDUN threats, required controls, validation plans; drift of the finalized API contract from the Product Definition draft | P0 |
| FR3.3 | Implementation report: evidence-backed findings, drift assertions, control implementation verification; organized by ASPM domains 1–5 (git posture, code security, secret/PII scan, open source security, SBOM) | P0 |
| FR3.4 | Deployment report: runtime exposure, exploitability, configuration findings, deployed-control verification; organized by ASPM domains 6–9 (IaC scan, CI/CD posture, container security, artifact security) | P0 |
| FR3.5 | Builder Operations report: detection coverage, incidents, observed techniques, control effectiveness; ASPM domain 10 (cloud context) plus dynamic-testing findings (DAST, penetration testing, red teaming) | P1 |
| FR3.6 | Product Operations report: abuse/fraud signal observed in production, adoption-driven risk changes, and drift between the shipped product and the Product Definition's security invariants (feeds the next baseline revision) | P1 |
| FR3.7 | Each profile declares its inputs by PDLC stage, not by individual spec type: the spec-driven stages (product-definition, builder-definition) consume whatever specs a workflow categorizes into that stage (via FR1.3); the builder-side stages (implementation, deployment, builder-operations) consume non-spec artifacts by type (code, IaC, deployment manifests, telemetry). Plus coverage expectations. | P0 |
| FR3.8 | ASPM domain taxonomy: an `ASPMDomain` enum (the 10 domains) owned by threat-model-spec, each carrying its primary PDLC stage (mapping onto implementation/deployment/builder-operations). Findings and evidence may be tagged by domain so coverage is measurable per domain within a stage. Straddling domains (git posture, SBOM, CI/CD, IaC) carry a primary stage but evidence may attach to adjacent stages. | P0 |

### FR4 — Agent workflows and the `tms analyze` command

| ID | Requirement | Priority |
|----|-------------|----------|
| FR4.1 | One workflow definition per stage: inputs, analysis steps, output objects, evaluation criteria — framework-neutral (executable by any agent runtime) | P0 |
| FR4.2 | Artifact-availability profiles (first-party, third-party, open-source) map available artifacts to permitted stage analyses and report scope | P0 |
| FR4.3 | Reports record the profile that produced them | P0 |
| FR4.4 | Adversarial-critic pass defined (missing components, unstated assumptions, invalid mitigations) | P1 |
| FR4.5 | `tms analyze --stage <stage> --profile <profile> <inputs>`: orchestration command that loads the stage profile, resolves declared input artifacts, drives the invoking AI agent through the workflow, writes the resulting analysis run into the model, and grades it — performing no analytical reasoning of its own | P0 |
| FR4.6 | Per-stage agent/workflow definitions authored as agnostic `multi-agent-spec` specs in `agents/specs/` (agents, commands, skills, loops), extending the repo's existing `agents/specs/` convention | P0 |
| FR4.7 | `assistantkit` generates per-tool plugins (Claude Code, Kiro, Gemini) into `agents/plugins/`; a generation-freshness test asserts the plugins are up to date with the specs (same discipline as the schema `//go:embed` check) | P0 |
| FR4.8 | Any generated agent (Claude Code, Kiro, Gemini) can run a stage workflow and invoke `tms analyze`; no tool-specific hand-authoring — the agnostic spec is the single source | P1 |

### FR5 — Evaluation integration (structured-evaluation)

| ID | Requirement | Priority |
|----|-------------|----------|
| FR5.1 | One rubric per stage (6 rubrics), versioned, in the threat-model-spec repo | P0 |
| FR5.2 | Claims reports verify factual assertions (CVEs, exposures, code refs) against cited evidence | P0 |
| FR5.3 | Summary reports aggregate rubric + claims + deterministic validation into stage-gate GO/NO-GO | P1 |
| FR5.4 | Gap assessment of structured-evaluation; additive upstream PRs only where confirmed (candidates: evidence locators, stage/profile metadata, insufficient-evidence verdict) | P0 |
| FR5.5 | Judge provenance (judge id, model, rubric version, run id) on every assessment | P0 |

### FR6 — Framework reports

| ID | Requirement | Priority |
|----|-------------|----------|
| FR6.1 | IR can hold framework report objects: STRIDE coverage, LINDDUN privacy, ATT&CK technique mapping, OWASP checklist, attack-tree analysis | P0 |
| FR6.2 | `tms` exports each framework report (JSON + Markdown) from a threat model | P0 |
| FR6.3 | Framework reports are derivable views; materialized copies record source-model revision | P1 |

## Success Metrics

1. v0.7.0 threat models validate unchanged against the new schema version.
2. One first-party product analyzed across ≥3 stages: agent-produced reports, judge-graded, gates evaluated.
3. One third-party or open-source assessment produced under a partial-artifact profile.
4. All 6 stage rubrics discriminate in dogfooding (non-uniform scores; seeded defects caught).
5. Framework exports (≥4 frameworks) generated from one canonical model with no information loss on round-trip of materialized reports.

## Dependencies

| Dependency | Purpose |
|------------|---------|
| INIT-THREATMODELSPEC-001 | Clean baseline (v0.7.0 artifacts, examples, PRD reset) |
| ProductBuildersHQ/pdlc | Normative PDLC stage definitions (the six stage IDs), re-exported from productbuildershq-frameworks |
| ProductBuildersHQ/productbuildershq-frameworks | Machine-readable PDLC framework catalog entry (stages, AI-DLC crosswalk); imported transitively via pdlc |
| ProductBuildersHQ/specification-workflow-spec | Spec-type registry that tags each spec type with its PDLC stage; the source of the workflow→stage categorization threat-model-spec consumes |
| plexusone/structured-evaluation | Rubric/claims/summary report types |
| plexusone/multi-agent-spec | Agnostic agent/workflow definition format for `agents/specs/` |
| plexusone/assistantkit | Generates per-tool plugins (Claude Code, Kiro, Gemini) from the agnostic specs |
| grokify/schemakit | Schema linting |
| invopop/jsonschema | Schema generation from Go types |
