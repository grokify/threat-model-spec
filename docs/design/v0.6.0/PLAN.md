# Implementation Plan: v0.6.0 - Comprehensive Security Enhancement

> **Status:** In Progress
> **Started:** 2026-04-28

## Overview

This plan covers all enhancements from v0.5.0 to v0.6.0, organized into six sections with corresponding implementation phases.

## Implementation Phases

### Section A: OWASP ASI Support (Phases 17-19)

**Status:** Complete

| Phase | Description | Status |
|-------|-------------|--------|
| 17 | Core ASI Support | Complete |
| 18 | OWASP Reference Data | Complete |
| 19 | Validation & Documentation | Complete |

### Section B: Role-Based Security Data (Phases 20-25)

**Status:** Complete

| Phase | Description | Status |
|-------|-------------|--------|
| 20 | Red Team Data Types | Complete |
| 21 | Blue Team Data Types | Complete |
| 22 | Remediation Data Types | Complete |
| 23 | app-test-spec Integration | Complete |
| 24 | Incident Playbooks | Complete |
| 25 | ThreatModel & Attack Integration | Complete |

### Section C: Risk Quantification (Phases 26-27)

**Status:** Complete

| Phase | Description | Status |
|-------|-------------|--------|
| 26 | FAIR Risk Assessment | Complete |
| 27 | Business Impact & EPSS | Complete |

### Section D: Threat Intelligence (Phases 28-29)

**Status:** Complete

| Phase | Description | Status |
|-------|-------------|--------|
| 28 | STIX 2.1 Export | Complete |
| 29 | KEV Catalog Integration | Complete |

### Section E: Purple Team (Phases 30-31)

**Status:** Complete

| Phase | Description | Status |
|-------|-------------|--------|
| 30 | Atomic Red Team Mapping | Complete |
| 31 | Detection Coverage Matrix | Complete |

### Section F: Security Metrics (Phase 32)

**Status:** Complete

| Phase | Description | Status |
|-------|-------------|--------|
| 32 | MTTD/MTTR & Coverage Metrics | Complete |

### Section G: Supply Chain Security (Phases 34-35)

**Status:** Pending

| Phase | Description | Status |
|-------|-------------|--------|
| 34 | SBOM Integration | Pending |
| 35 | VEX Support | Pending |

### Section H: Vulnerability Management (Phase 36)

**Status:** Pending

| Phase | Description | Status |
|-------|-------------|--------|
| 36 | SSVC Decision Trees | Pending |

### Section I: Attack Path Analysis (Phases 37-38)

**Status:** Pending

| Phase | Description | Status |
|-------|-------------|--------|
| 37 | Graph Data Model | Pending |
| 38 | Path Computation | Pending |

---

## Detailed Phase Plans

### Phase 17: Core ASI Support ✓

| Task | Status | Description |
|------|--------|-------------|
| 17.1 | [x] | Add `OWASPCategoryAgentic` to `ir/mappings.go` |
| 17.2 | [x] | Update `OWASPCategory.JSONSchema()` to include "agentic" |
| 17.3 | [x] | Add `ASIIds []string` field to Attack struct |
| 17.4 | [x] | Add unit tests for new category and field |

### Phase 18: OWASP Reference Data ✓

| Task | Status | Description |
|------|--------|-------------|
| 18.1 | [x] | Create `ir/owasp_reference.go` with OWASPEntry type |
| 18.2 | [x] | Add OWASP API Security Top 10 (2023) - 10 entries |
| 18.3 | [x] | Add OWASP LLM Top 10 (2025) - 10 entries |
| 18.4 | [x] | Add OWASP Web Top 10 (2021) - 10 entries |
| 18.5 | [x] | Add OWASP Agentic Top 10 (ASI 2026) - 10 entries |
| 18.6 | [x] | Add GetOWASPEntry() and ValidateOWASPID() functions |
| 18.7 | [x] | Add unit tests for reference data |

### Phase 19: Validation & Documentation ✓

| Task | Status | Description |
|------|--------|-------------|
| 19.1 | [x] | Add ValidateOWASPMappings() to `ir/validate.go` |
| 19.2 | [x] | Update README.md with ASI support |

### Phase 20: Red Team Data Types ✓

| Task | Status | Description |
|------|--------|-------------|
| 20.1 | [x] | Create `ir/redteam.go` with ExploitationGuidance struct |
| 20.2 | [x] | Add ExploitationStep type for ordered attack steps |
| 20.3 | [x] | Add OffensiveTool type for tool recommendations |
| 20.4 | [x] | Add PayloadPattern type for generic payload templates |
| 20.5 | [x] | Add ExploitDifficulty enum |
| 20.6 | [x] | Add unit tests with JSON round-trip verification |

### Phase 21: Blue Team Data Types ✓

| Task | Status | Description |
|------|--------|-------------|
| 21.1 | [x] | Create `ir/blueteam.go` with DefenseGuidance struct |
| 21.2 | [x] | Add DetectionRule type with format support |
| 21.3 | [x] | Add DetectionFormat enum (sigma, yara, splunk, etc.) |
| 21.4 | [x] | Add IOC type with type, value, confidence |
| 21.5 | [x] | Add IOCType enum |
| 21.6 | [x] | Add LogSource type for monitoring |
| 21.7 | [x] | Add HuntingQuery type for threat hunting |
| 21.8 | [x] | Add AlertThreshold type |
| 21.9 | [x] | Add unit tests with JSON round-trip verification |

### Phase 22: Remediation Data Types ✓

| Task | Status | Description |
|------|--------|-------------|
| 22.1 | [x] | Create `ir/remediation.go` with RemediationGuidance struct |
| 22.2 | [x] | Add CodePattern type for vulnerable/secure patterns |
| 22.3 | [x] | Add ChecklistItem type for review checklists |
| 22.4 | [x] | Add Library type for recommended libraries |
| 22.5 | [x] | Add ConfigChange type for configuration fixes |
| 22.6 | [x] | Add TestingApproach type |
| 22.7 | [x] | Add unit tests with JSON round-trip verification |

### Phase 23: app-test-spec Integration ✓

| Task | Status | Description |
|------|--------|-------------|
| 23.1 | [x] | Create `ir/testref.go` with TestReference struct |
| 23.2 | [x] | Add TestPurpose enum |
| 23.3 | [x] | Add TestSuiteReference type |
| 23.4 | [x] | Add TestRef to Attack struct |
| 23.5 | [x] | Add TestSuites to ThreatModel struct |
| 23.6 | [x] | Add TestRefs to ExploitationGuidance and TestingApproach |
| 23.7 | [x] | Add unit tests with JSON round-trip verification |

### Phase 24: Incident Playbooks ✓

| Task | Status | Description |
|------|--------|-------------|
| 24.1 | [x] | Create `ir/playbook.go` with IncidentPlaybook struct |
| 24.2 | [x] | Add PlaybookStep type for ordered response steps |
| 24.3 | [x] | Add PlaybookPhase enum |
| 24.4 | [x] | Add Contact type for incident contacts |
| 24.5 | [x] | Add Playbooks to ThreatModel struct |
| 24.6 | [x] | Add unit tests with JSON round-trip verification |

### Phase 25: ThreatModel & Attack Integration ✓

| Task | Status | Description |
|------|--------|-------------|
| 25.1 | [x] | Add RedTeam, BlueTeam, Remediation fields to ThreatModel |
| 25.2 | [x] | Add RedTeamNotes, BlueTeamNotes, RemediationNote to Attack |
| 25.3 | [x] | Regenerate JSON schemas |
| 25.4 | [x] | All tests pass, linting passes |

### Phase 26: FAIR Risk Assessment ✓

| Task | Status | Description |
|------|--------|-------------|
| 26.1 | [x] | Create `ir/fair.go` with FAIRAssessment struct |
| 26.2 | [x] | Add FrequencyEstimate type (LEF components) |
| 26.3 | [x] | Add LossEstimate type (LM components) |
| 26.4 | [x] | Add ALE calculation helper |
| 26.5 | [x] | Add RiskAssessment to ThreatModel |
| 26.6 | [x] | Add unit tests |

### Phase 27: Business Impact & EPSS ✓

| Task | Status | Description |
|------|--------|-------------|
| 27.1 | [x] | Add BusinessImpact struct to `ir/fair.go` |
| 27.2 | [x] | Create `ir/epss.go` with EPSSData struct |
| 27.3 | [x] | Add GetEPSSScore() lookup function (static data or API) |
| 27.4 | [x] | Add BusinessImpact and EPSSData to ThreatModel |
| 27.5 | [x] | Add unit tests |

### Phase 28: STIX 2.1 Export ✓

| Task | Status | Description |
|------|--------|-------------|
| 28.1 | [x] | Create `ir/stix_export.go` with export functions |
| 28.2 | [x] | Implement IOC to STIX Indicator conversion |
| 28.3 | [x] | Implement ThreatActor to STIX Threat-Actor conversion |
| 28.4 | [x] | Implement Attack to STIX Attack-Pattern conversion |
| 28.5 | [x] | Implement ThreatModel.ExportSTIXBundle() |
| 28.6 | [x] | Add unit tests with STIX schema validation |

### Phase 29: KEV Catalog Integration ✓

| Task | Status | Description |
|------|--------|-------------|
| 29.1 | [x] | Create `ir/kev.go` with KEVEntry struct |
| 29.2 | [x] | Add embedded KEV catalog data (or fetch function) |
| 29.3 | [x] | Add GetKEVEntry() and IsInKEV() functions |
| 29.4 | [x] | Add KEVData field to CVEMapping |
| 29.5 | [x] | Add unit tests |

### Phase 30: Atomic Red Team Mapping ✓

| Task | Status | Description |
|------|--------|-------------|
| 30.1 | [x] | Create `ir/atomicredteam.go` with AtomicTestMapping struct |
| 30.2 | [x] | Add AtomicTests field to ThreatModel |
| 30.3 | [x] | Add AtomicTestID field to Attack (optional) |
| 30.4 | [x] | Add validation for technique ID format |
| 30.5 | [x] | Add unit tests |

### Phase 31: Detection Coverage Matrix ✓

| Task | Status | Description |
|------|--------|-------------|
| 31.1 | [x] | Create `ir/coverage.go` with DetectionCoverageMatrix struct |
| 31.2 | [x] | Add TechniqueCoverage struct |
| 31.3 | [x] | Add CoverageSummary struct |
| 31.4 | [x] | Add CalculateCoverage() function |
| 31.5 | [x] | Add DetectionCoverage to ThreatModel |
| 31.6 | [x] | Add unit tests |

### Phase 32: Security Metrics ✓

| Task | Status | Description |
|------|--------|-------------|
| 32.1 | [x] | Create `ir/metrics.go` with SecurityMetrics struct |
| 32.2 | [x] | Add Duration type for time measurements |
| 32.3 | [x] | Add Metrics field to ThreatModel |
| 32.4 | [x] | Add unit tests |

### Phase 33: Final Integration & Release ✓

| Task | Status | Description |
|------|--------|-------------|
| 33.1 | [x] | Update version to v0.6.0 in genschema |
| 33.2 | [x] | Regenerate all JSON schemas |
| 33.3 | [x] | Update README.md with all new features |
| 33.4 | [x] | Add CHANGELOG entry for v0.6.0 |
| 33.5 | [x] | Extend openclaw.json with sample data |
| 33.6 | [x] | Run full test suite |
| 33.7 | [x] | Run linter |
| 33.8 | [ ] | Tag release |

---

## Section G: Supply Chain Security

### Phase 34: SBOM Integration

| Task | Status | Description |
|------|--------|-------------|
| 34.1 | [ ] | Create `ir/sbom.go` with SBOMReference struct |
| 34.2 | [ ] | Add SBOMFormat enum (cyclonedx, spdx) |
| 34.3 | [ ] | Add ComponentReference struct for linking threats to components |
| 34.4 | [ ] | Add DependencyRisk struct for vulnerable dependency tracking |
| 34.5 | [ ] | Add SBOM field to ThreatModel |
| 34.6 | [ ] | Add ComponentRefs to Attack struct |
| 34.7 | [ ] | Add unit tests |

### Phase 35: VEX Support

| Task | Status | Description |
|------|--------|-------------|
| 35.1 | [ ] | Create `ir/vex.go` with VEXStatement struct |
| 35.2 | [ ] | Add VEXStatus enum (not_affected, affected, fixed, under_investigation) |
| 35.3 | [ ] | Add VEXJustification enum (component_not_present, vulnerable_code_not_present, etc.) |
| 35.4 | [ ] | Add VEXStatements field to ThreatModel |
| 35.5 | [ ] | Add VEX export function (OpenVEX format) |
| 35.6 | [ ] | Add unit tests |

## Section H: Vulnerability Management

### Phase 36: SSVC Decision Trees

| Task | Status | Description |
|------|--------|-------------|
| 36.1 | [ ] | Create `ir/ssvc.go` with SSVCAssessment struct |
| 36.2 | [ ] | Add Exploitation enum (none, poc, active) |
| 36.3 | [ ] | Add Automatable enum (no, yes) |
| 36.4 | [ ] | Add TechnicalImpact enum (partial, total) |
| 36.5 | [ ] | Add MissionPrevalence enum (minimal, support, essential) |
| 36.6 | [ ] | Add PublicWellBeing enum (minimal, material, irreversible) |
| 36.7 | [ ] | Add SSVCDecision enum (track, track*, attend, act) |
| 36.8 | [ ] | Add CalculateSSVCDecision() function |
| 36.9 | [ ] | Add SSVCAssessment to ThreatEntry |
| 36.10 | [ ] | Add unit tests |

## Section I: Attack Path Analysis

### Phase 37: Graph Data Model

| Task | Status | Description |
|------|--------|-------------|
| 37.1 | [ ] | Create `ir/attackgraph.go` with AttackGraph struct |
| 37.2 | [ ] | Add GraphNode struct (element, threat, or control) |
| 37.3 | [ ] | Add GraphEdge struct with edge types (flow, attack, mitigation) |
| 37.4 | [ ] | Add BuildAttackGraph() from ThreatModel |
| 37.5 | [ ] | Add ToJSON() and FromJSON() for graph serialization |
| 37.6 | [ ] | Add unit tests |

### Phase 38: Path Computation

| Task | Status | Description |
|------|--------|-------------|
| 38.1 | [ ] | Add AttackPath struct (sequence of nodes/edges) |
| 38.2 | [ ] | Add FindAllPaths(source, target) function |
| 38.3 | [ ] | Add FindShortestPath(source, target) function |
| 38.4 | [ ] | Add CalculatePathRisk(path) function |
| 38.5 | [ ] | Add FindCriticalPaths() for highest-risk paths |
| 38.6 | [ ] | Add ReachabilityAnalysis() for exposure assessment |
| 38.7 | [ ] | Add unit tests |

---

## Priority Matrix

| Priority | Phases | Rationale |
|----------|--------|-----------|
| **P0 - Critical** | 17-33 | Core functionality, complete |
| **P1 - High** | 34-35 | SBOM/VEX - supply chain is major attack vector |
| **P2 - Medium** | 36 | SSVC - complements EPSS for prioritization |
| **P3 - Lower** | 37-38 | Attack paths - advanced analysis capability |

## Dependencies

```
Section A-F (Complete) ──► Section G (Supply Chain) ──► Section I (Attack Paths)
                       └──► Section H (SSVC)        ──┘
```

## Testing Strategy

| Section | Test Coverage |
|---------|---------------|
| A | OWASPCategory, ASIIds, reference data lookup, validation |
| B | All role types, JSON round-trip, enum values |
| C | FAIR calculations, estimate validation |
| D | STIX schema compliance, IOC conversion |
| E | Technique ID validation, coverage calculation |
| F | Duration formatting, metric aggregation |
| G | SBOM format validation, VEX status, component linking |
| H | SSVC decision calculation, enum validation |
| I | Graph construction, path finding, risk calculation |

## Success Criteria

1. [x] Section A: All OWASP reference data complete (40 entries)
2. [x] Section B: Role-based types usable and tested
3. [x] Section C: FAIR risk scores calculable
4. [x] Section D: STIX bundles validate against official schema
5. [x] Section E: Detection coverage calculable from threat model
6. [x] Section F: Metrics trackable per threat
7. [x] All tests pass
8. [x] Linting passes
9. [x] Backward compatible with v0.5.0 threat models
10. [ ] Section G: SBOM references linkable to threats, VEX exportable
11. [ ] Section H: SSVC decisions calculable from threat data
12. [ ] Section I: Attack paths computable from threat model graph
