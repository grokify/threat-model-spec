# Product Requirements Document: v0.6.0 - Comprehensive Security Enhancement

> **Version:** 0.6.0
> **Status:** Complete
> **Date:** 2026-04-28

## Overview

Major enhancement to threat-model-spec adding OWASP ASI support, role-based security guidance, risk quantification, threat intelligence export, and purple team capabilities.

## Problem Statement

Current threat-model-spec documents **what** threats exist but has significant gaps:

| Area | Gap |
|------|-----|
| **Framework Coverage** | No OWASP Agentic (ASI 2026) support |
| **Red Team** | No exploitation guidance, tools, or payload patterns |
| **Blue Team** | No detection rules, IOCs, or hunting queries |
| **Developers** | No vulnerable/secure code patterns or review checklists |
| **Incident Response** | Basic response actions only, no full playbooks |
| **Risk Quantification** | No FAIR scoring, EPSS, or business impact analysis |
| **Threat Intelligence** | No STIX export, KEV mapping, or TI sharing |
| **Purple Team** | No detection coverage matrix or adversary emulation integration |
| **Metrics** | No MTTD/MTTR tracking or coverage metrics |

## Solution

Transform threat-model-spec from documentation into an actionable security platform:

### Section A: OWASP ASI Support
- Add `OWASPCategoryAgentic` for ASI 2026
- Add `ASIIds` field to Attack struct
- Comprehensive OWASP reference data (40 entries across 4 lists)

### Section B: Role-Based Security Data
- **Red Team**: Exploitation steps, tools, difficulty ratings, payload patterns
- **Blue Team**: Sigma rules, IOCs, log sources, hunting queries
- **Remediation**: Vulnerable/secure code patterns, checklists, libraries
- **Playbooks**: Incident response procedures with phases and contacts

### Section C: Risk Quantification
- **FAIR Integration**: Factor Analysis of Information Risk scoring
- **Business Impact**: Revenue, customer, regulatory impact assessment
- **EPSS Mapping**: Exploit Prediction Scoring System integration

### Section D: Threat Intelligence
- **STIX 2.1 Export**: Export IOCs, threat actors, attack patterns
- **KEV Mapping**: CISA Known Exploited Vulnerabilities catalog
- **Threat Actor Enrichment**: TTPs, motivations, targeting patterns

### Section E: Purple Team
- **Atomic Red Team**: Map to ART test IDs for validation
- **Detection Coverage**: MITRE ATT&CK coverage heatmap data
- **Exercise Planning**: Purple team exercise structures

### Section F: Security Metrics
- **MTTD/MTTR**: Track detection and response times per threat
- **Coverage Metrics**: Percentage of attack surface covered
- **Trend Analysis**: Risk changes over time

### Section G: Supply Chain Security
- **SBOM Integration**: Link threat models to CycloneDX/SPDX SBOMs
- **Component References**: Map threats to vulnerable dependencies
- **VEX Statements**: Document vulnerability exploitability status
- **OpenVEX Export**: Share VEX data in standard format

### Section H: Vulnerability Management
- **SSVC Assessment**: CISA's Stakeholder-Specific Vulnerability Categorization
- **Decision Trees**: Calculate prioritization (track, track*, attend, act)
- **Context-Aware Prioritization**: Combine exploitation status with business context

### Section I: Attack Path Analysis
- **Graph Model**: Build attack graphs from threat model data
- **Path Finding**: Identify all possible attack paths
- **Risk Scoring**: Calculate cumulative risk along paths
- **Reachability Analysis**: Determine exposure from entry points

## Target Users

| User | Primary Sections |
|------|------------------|
| **Threat Modelers** | A, B, C |
| **Penetration Testers** | B (Red Team), E |
| **SOC Analysts** | B (Blue Team), D, F |
| **Security Engineers** | B, D, E |
| **Developers** | A, B (Remediation) |
| **DevSecOps** | B (Test Integration), F |
| **Incident Responders** | B (Playbooks), D |
| **Security Leaders** | C, F |
| **GRC/Compliance** | A, C |

## User Stories

### Security Analyst
> As a security analyst documenting AI agent vulnerabilities, I want to map attack steps to ASI categories so that I can demonstrate compliance with OWASP's agentic security guidance.

### Red Team Lead
> As a red team lead, I want exploitation guidance with tool recommendations so that my team can efficiently test for known vulnerabilities.

### SOC Manager
> As a SOC manager, I want Sigma-format detection rules so that I can import them directly into our SIEM without manual conversion.

### Security Champion
> As a security champion, I want code review checklists and secure patterns so that I can help developers fix vulnerabilities correctly.

### DevSecOps Engineer
> As a DevSecOps engineer, I want threat models that link to executable test cases so that I can automate security validation in CI/CD.

### CISO
> As a CISO, I want quantified risk scores and business impact analysis so that I can communicate security priorities to the board.

### Threat Intelligence Analyst
> As a TI analyst, I want to export threat data in STIX format so that I can share intelligence with partners and import into our TIP.

### Purple Team Lead
> As a purple team lead, I want detection coverage matrices so that I can identify gaps and plan exercises to validate defenses.

## Requirements

### Functional Requirements

#### Section A: OWASP ASI Support

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| A1 | Support `agentic` as OWASP category | Must | Done |
| A2 | Add `asiIds` field to Attack struct | Must | Done |
| A3 | Include all 10 ASI entries with names/descriptions | Must | Done |
| A4 | Include all 10 API Security entries | Must | Done |
| A5 | Include all 10 LLM Top 10 entries | Must | Done |
| A6 | Include all 10 Web Top 10 entries | Must | Done |
| A7 | Provide `ValidateOWASPID()` function | Should | Done |
| A8 | Provide `GetOWASPEntry()` lookup function | Should | Done |

#### Section B: Role-Based Security Data

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| B1 | Red team exploitation guidance with steps, tools, difficulty | Must | Done |
| B2 | Blue team detection rules in Sigma format | Must | Done |
| B3 | IOC tracking with type, value, confidence | Must | Done |
| B4 | Log source definitions for monitoring | Should | Done |
| B5 | Hunting queries for proactive defense | Should | Done |
| B6 | Vulnerable code patterns by language | Must | Done |
| B7 | Secure code patterns (fixes) by language | Must | Done |
| B8 | Code review checklists | Should | Done |
| B9 | Library recommendations for mitigation | Should | Done |
| B10 | app-test-spec test case references | Must | Done |
| B11 | Incident response playbooks | Should | Done |
| B12 | Per-attack-step role notes | Should | Done |

#### Section C: Risk Quantification

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| C1 | FAIR risk factor types (LEF, LM, TCap, etc.) | Should | Done |
| C2 | Business impact assessment types | Should | Done |
| C3 | EPSS score integration | Could | Done |
| C4 | Risk calculation helpers | Could | Done |

#### Section D: Threat Intelligence

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| D1 | STIX 2.1 bundle export | Should | Done |
| D2 | STIX indicator objects from IOCs | Should | Done |
| D3 | STIX attack-pattern objects | Should | Done |
| D4 | KEV catalog ID mapping | Could | Done |
| D5 | Threat actor STIX export | Could | Done |

#### Section E: Purple Team

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| E1 | Atomic Red Team test ID mapping | Should | Done |
| E2 | Detection coverage matrix data | Should | Done |
| E3 | MITRE ATT&CK coverage calculation | Should | Done |
| E4 | Purple team exercise types | Could | Deferred |

#### Section F: Security Metrics

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| F1 | MTTD/MTTR tracking fields | Should | Done |
| F2 | Detection efficacy metrics | Could | Done |
| F3 | Coverage percentage calculation | Could | Done |

#### Section G: Supply Chain Security

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| G1 | SBOM reference type (CycloneDX, SPDX) | Should | Pending |
| G2 | Component reference linking threats to dependencies | Should | Pending |
| G3 | Dependency risk scoring | Could | Pending |
| G4 | VEX statement support | Should | Pending |
| G5 | VEX status enum (not_affected, affected, fixed, under_investigation) | Should | Pending |
| G6 | VEX justification enum | Should | Pending |
| G7 | OpenVEX export function | Could | Pending |

#### Section H: Vulnerability Management

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| H1 | SSVC assessment struct | Should | Pending |
| H2 | Exploitation status enum (none, poc, active) | Should | Pending |
| H3 | Automatable enum (no, yes) | Should | Pending |
| H4 | Technical impact enum (partial, total) | Should | Pending |
| H5 | Mission prevalence enum | Should | Pending |
| H6 | Public well-being enum | Should | Pending |
| H7 | SSVC decision calculation (track, track*, attend, act) | Should | Pending |

#### Section I: Attack Path Analysis

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| I1 | Attack graph data model | Could | Pending |
| I2 | Graph node types (element, threat, control) | Could | Pending |
| I3 | Graph edge types (flow, attack, mitigation) | Could | Pending |
| I4 | Build graph from ThreatModel | Could | Pending |
| I5 | Find all paths between nodes | Could | Pending |
| I6 | Find shortest/critical paths | Could | Pending |
| I7 | Calculate path risk scores | Could | Pending |
| I8 | Reachability analysis | Could | Pending |

### Non-Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NF1 | Backward compatible (all new fields omitempty) | Must |
| NF2 | All tests pass | Must |
| NF3 | Linting passes | Must |
| NF4 | JSON schemas regenerated | Must |
| NF5 | Sigma rules exportable to standard format | Should |
| NF6 | STIX 2.1 compliant export | Should |

## Success Metrics

1. All four OWASP Top 10 lists have complete reference data (40 entries) ✓
2. Role-based guidance usable for Red Team, Blue Team, Remediation ✓
3. Detection rules exportable in Sigma format ✓
4. STIX 2.1 bundles validate against official schema ✓
5. Risk scores calculable using FAIR methodology ✓
6. Existing threat models remain valid (backward compatible) ✓
7. SBOM references linkable to threat model components
8. VEX statements exportable in OpenVEX format
9. SSVC decisions calculable from threat data
10. Attack paths computable with risk scoring

## Out of Scope (v0.6.0)

- Auto-generation of app-test-spec tests from threat models
- TAXII server integration
- Nuclei template generation
- IDE integration for code patterns
- Web UI for browsing data
- OWASP Mobile Top 10

## Dependencies

| Dependency | Purpose |
|------------|---------|
| app-test-spec | Test case format for security validation |
| agent-dast | DAST tool that consumes app-test-spec |
| Sigma | Portable detection rule format |
| STIX 2.1 | Threat intelligence exchange format |
| FAIR | Risk quantification methodology |
| CycloneDX | SBOM format for software composition |
| SPDX | Alternative SBOM format |
| OpenVEX | Vulnerability exploitability exchange format |
| SSVC | CISA vulnerability prioritization framework |

## Risks

| Risk | Mitigation |
|------|------------|
| Scope creep | Prioritize Must/Should; defer Could to future |
| Detection rules outdated | Include `validUntil` dates |
| Code patterns incomplete | Start with Go, Python, JS |
| STIX complexity | Start with indicators, expand later |
