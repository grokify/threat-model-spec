# Threat Model Spec

## Product Requirements Document

### Overview

Threat Model Spec is an open-source, vendor-neutral JSON intermediate representation (IR) for security threat modeling. It standardizes how threat models — architecture, threats, risk, mitigations, detections, and framework mappings — are represented, exchanged, and rendered, so that security data can move between diagramming tools, analysis agents, evaluation pipelines, and threat-intelligence formats without being re-modeled at every boundary.

The IR is the source of truth. Diagrams (D2/SVG), STIX 2.1 bundles, and LLM-as-Judge evaluation reports are all *views* generated from it — not separate formats that drift from one another.

> This document supersedes the original "D2TM" PRD, which scoped the project narrowly as a diagrams-as-code styling library. The project has since grown into a general threat-modeling data format; this revision documents the current, shipped product boundary as of v0.7.0.

### Problem Statement

Security teams need to represent threat models in a way that is:

1. Version-controllable and diffable (data, not a GUI-tool proprietary file)
2. Structured enough for programmatic analysis, not just prose or free-form diagrams
3. Mappable to established frameworks (STRIDE, LINDDUN, MITRE ATT&CK/ATLAS, OWASP, CWE/CVE/CVSS) without re-deriving that mapping per tool
4. Renderable to visual diagrams and exportable to threat-intelligence formats (STIX) from one canonical source
5. Usable by AI agents and LLM judges as a structured target to fill in and grade, not just a document to summarize

Existing tools are GUI-first and proprietary (Threat Dragon, IriusRisk), or are diagramming-only with no security semantics (generic diagram-as-code tools), or are static-analysis-output formats with no architecture/threat/risk vocabulary (SARIF). No open format combines diagrams-as-code, a full security-domain vocabulary, and framework-neutral interchange in one IR.

### Goals

1. **Canonical IR** — One JSON-based `ThreatModel` type is the source of truth; diagrams, STIX exports, and evaluation reports are derived views over it.
2. **Diagrams-as-Code** — Diagrams are defined in the IR and rendered to D2/SVG; multiple diagram types (DFD, attack chain, sequence, attack tree) share one underlying model.
3. **Full Security-Domain Vocabulary** — Assets, scenarios, risk assessment (FAIR), mitigations, threat actors, detections, response playbooks, red/blue/purple team guidance, supply chain data (SBOM/VEX), and attack-path analysis, not diagrams alone.
4. **Framework-Neutral Mappings** — STRIDE, LINDDUN, MITRE ATT&CK/ATLAS, OWASP (API/LLM/Web/Agentic), CWE, CVE, CVSS, NIST CSF, CIS Controls, ISO 27001, and major compliance frameworks are all representable as structured references, not free text.
5. **Threat-Intelligence Interoperability** — Threat models export to STIX 2.1 for sharing with external threat-intel systems.
6. **Agent- and Judge-Friendly Structure** — The IR is a concrete, typed target that AI agents can fill in and that LLM-as-Judge pipelines (via `structured-evaluation` integration) can grade, rather than free-form prose.
7. **Go-First, Schema-Generated** — Go structs are the source of truth; JSON Schemas are generated from them, never hand-written, so the schema can never drift from the types that produce and consume it.

### Non-Goals

1. **GUI diagram editor** — This is a data format and library; editing happens in code/text editors or via agents, using existing D2 tooling for rendering.
2. **Performing security analysis** — Threat Model Spec does not implement SAST, DAST, penetration testing, red teaming, or SOC/SIEM monitoring. It is the data format those activities' inputs and outputs are represented in — a scanner or agent produces findings; Threat Model Spec is where those findings live, referenceable and mappable to threats, assets, and controls. This is a deliberate boundary, not an oversight: the project standardizes analysis results, evidence, and relationships; it does not become a scanner or a SOC itself.
3. **A policy or CI/CD enforcement engine** — Gate criteria and results can be recorded in the model, but enforcing them in a pipeline is the consuming system's responsibility.
4. **A telemetry or log store** — Operational data (SIEM/XDR output, traces) is referenced by query, time window, and digest, not embedded wholesale.
5. **Runtime agent execution** — The IR can *model* AI agent capabilities, execution context, and tool permissions for threat analysis purposes (see `AgentCapabilities`, `ExecutionContext`), but Threat Model Spec does not run agents, execute tools, or manage agent runtime state.

### Target Users

- **Security engineers** modeling threats at design time or against an implemented system, who need diagrams, framework mappings, and a durable record of decisions.
- **Red team members** documenting attack chains and exploitation guidance for penetration test reports.
- **Blue team / detection engineers** recording detection coverage, IOCs, and hunting queries tied to specific threats.
- **Developers** consuming remediation guidance (vulnerable/secure code patterns, review checklists) for vulnerabilities that affect their code.
- **AI agents and analysis pipelines** that programmatically fill in, extend, or grade threat models as part of a larger security workflow.
- **Security researchers** publishing vulnerability disclosures with a clear visual and structured explanation.

### Use Cases

#### UC1: Threat Model for an Architecture Review

A security engineer creates a DFD with trust boundaries and STRIDE annotations for a system under design or review, and captures assets, risk assessment, and mitigations alongside it.

#### UC2: Attack Chain / Vulnerability Disclosure

A researcher or red team member documents a multi-stage attack chain with MITRE ATT&CK mapping, exploitation guidance, and remediation, for a penetration test report or a responsible disclosure write-up.

#### UC3: Framework-Mapped Compliance Reporting

A team maps existing threats and controls to NIST CSF, CIS Controls, or a compliance framework (SOC 2, PCI-DSS, HIPAA, GDPR) to support an audit, using structured mappings rather than a manually maintained spreadsheet.

#### UC4: Supply Chain Risk Tracking

A team links a threat model to an SBOM, records VEX statements for known CVEs affecting their dependencies, and tracks dependency risk alongside the rest of the threat model.

#### UC5: Agent-Assisted Threat Modeling with LLM-as-Judge Evaluation

An AI agent produces or extends a threat model from an architecture description; a judge pipeline (via the `evaluation` package and `structured-evaluation` rubrics) grades the result for evidence support, technical correctness, and completeness before a human reviews it.

#### UC6: Programmatic Generation and CI Integration

A CI/CD pipeline validates threat model JSON against the schema, regenerates diagrams from infrastructure-as-code definitions, or exports to STIX for a downstream threat-intel platform.

### Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR1 | Canonical `ThreatModel` JSON IR with framework mappings and multiple diagram views | P0 |
| FR2 | Go types for the full security-domain vocabulary: assets, scenarios, risk, mitigations, threat actors, detections, red/blue/remediation guidance | P0 |
| FR3 | JSON Schema generated from Go types (never hand-written), versioned per release | P0 |
| FR4 | D2 style library and Go rendering for DFD, attack chain, sequence, and attack tree diagrams | P0 |
| FR5 | Framework mapping types: STRIDE, LINDDUN, MITRE ATT&CK/ATLAS, OWASP (API/LLM/Web/Agentic), CWE, CVE, CVSS | P0 |
| FR6 | Control and compliance framework mappings: NIST CSF, CIS Controls, ISO 27001, SOC 2, PCI-DSS, HIPAA, GDPR, FedRAMP | P1 |
| FR7 | STIX 2.1 export for threat intelligence sharing | P1 |
| FR8 | Supply chain fields: SBOM reference, VEX statements, dependency risk | P1 |
| FR9 | Attack graph construction and path analysis (all-paths, shortest-path, critical-path, reachability) | P1 |
| FR10 | LLM-as-Judge evaluation integration (`evaluation` package) with embedded rubrics and `structured-evaluation` report conversion | P1 |
| FR11 | `tms` CLI: generate (D2/SVG/STIX), validate (plain and strict) | P0 |
| FR12 | Type-specific validation with referential integrity checks and a strict mode | P0 |
| FR13 | Agentic AI threat modeling fields: agent capabilities, execution context, credential flow tracking | P1 |
| FR14 | Reusable attack pattern templates referenceable across models | P2 |

### Non-Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NFR1 | All D2 styles must render correctly to SVG via D2 CLI | P0 |
| NFR2 | Go code must pass `golangci-lint` with zero issues | P0 |
| NFR3 | Every IR type has enum, JSON round-trip, and field tests | P0 |
| NFR4 | JSON Schemas validate against generated Go types with no drift | P0 |
| NFR5 | Backward compatibility: new fields are additive; existing valid documents remain valid across minor versions | P0 |
| NFR6 | Documentation with runnable, validated examples for each major capability area | P1 |

### Success Metrics

1. Threat models pass `tms validate --strict` and render correctly via D2 CLI and the online playground.
2. Schema regenerates from Go types with zero manual edits and passes `schemakit lint`.
3. Canonical examples in `examples/` cover: a fully implemented vulnerability, a design-phase (pre-implementation) model, and a supply-chain model — each validated in CI.
4. STIX 2.1 export produces spec-conformant bundles consumable by external threat-intel tooling.
5. The library is used by other security projects and by AI agent workflows to produce and grade threat models programmatically.

### Dependencies

| Dependency | Purpose | Required |
|------------|---------|----------|
| Go 1.25+ | Go library and CLI | Yes |
| D2 CLI v0.6+ | Rendering D2 to SVG | Yes (for SVG rendering only) |
| `github.com/invopop/jsonschema` | JSON Schema generation from Go types | Yes (build-time) |
| `github.com/grokify/schemakit` | Schema linting for Go-friendliness | Yes (build-time) |
| `github.com/plexusone/structured-evaluation` | LLM-as-Judge report types for the `evaluation` package | Yes |

### References

- [D2 Language](https://d2lang.com)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [STRIDE Threat Model](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro.html)
- [OpenClaw Vulnerability — Oasis Security](https://www.oasis.security/blog/openclaw-vulnerability)
