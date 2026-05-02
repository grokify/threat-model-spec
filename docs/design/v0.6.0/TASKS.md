# v0.6.0 Tasks - Comprehensive Security Enhancement

> **Status:** In Progress
> **Started:** 2026-04-28

---

## Section A: OWASP ASI Support ✓

### Phase 17: Core ASI Support ✓

| Task | Status | Description |
|------|--------|-------------|
| 17.1 | [x] | Add `OWASPCategoryAgentic` to `ir/mappings.go` |
| 17.2 | [x] | Update `OWASPCategory.JSONSchema()` to include "agentic" |
| 17.3 | [x] | Add `ASIIds []string` field to Attack struct in `ir/diagram.go` |
| 17.4 | [x] | Add unit tests for new category and field |

### Phase 18: OWASP Reference Data ✓

| Task | Status | Description |
|------|--------|-------------|
| 18.1 | [x] | Create `ir/owasp_reference.go` with OWASPEntry type |
| 18.2 | [x] | Add OWASP API Security Top 10 (2023) reference data |
| 18.3 | [x] | Add OWASP LLM Top 10 (2025) reference data |
| 18.4 | [x] | Add OWASP Web Top 10 (2021) reference data |
| 18.5 | [x] | Add OWASP Agentic Top 10 (ASI 2026) reference data |
| 18.6 | [x] | Add GetOWASPEntry() and ValidateOWASPID() functions |
| 18.7 | [x] | Add unit tests for reference data |

### Phase 19: Validation & Documentation ✓

| Task | Status | Description |
|------|--------|-------------|
| 19.1 | [x] | Add ValidateOWASPMappings() to `ir/validate.go` |
| 19.2 | [x] | Update README.md with ASI support |

---

## Section B: Role-Based Security Data ✓

### Phase 20: Red Team Data Types ✓

| Task | Status | Description |
|------|--------|-------------|
| 20.1 | [x] | Create `ir/redteam.go` with ExploitationGuidance struct |
| 20.2 | [x] | Add ExploitationStep type for ordered attack steps |
| 20.3 | [x] | Add OffensiveTool type for tool recommendations |
| 20.4 | [x] | Add PayloadPattern type for generic payload templates |
| 20.5 | [x] | Add ExploitDifficulty enum (trivial, low, medium, high, expert) |
| 20.6 | [x] | Add unit tests for all red team types |
| 20.7 | [x] | Verify JSON serialization round-trip |

### Phase 21: Blue Team Data Types ✓

| Task | Status | Description |
|------|--------|-------------|
| 21.1 | [x] | Create `ir/blueteam.go` with DefenseGuidance struct |
| 21.2 | [x] | Add DetectionRule type with Sigma format support |
| 21.3 | [x] | Add DetectionFormat enum (sigma, yara, splunk, elastic, kql, snort, suricata, custom) |
| 21.4 | [x] | Add IOC type with type, value, confidence, expiration |
| 21.5 | [x] | Add IOCType enum (ip, domain, url, hash, filepath, email, registry, process, certificate, pattern) |
| 21.6 | [x] | Add LogSource type for monitoring recommendations |
| 21.7 | [x] | Add HuntingQuery type for proactive threat hunting |
| 21.8 | [x] | Add AlertThreshold type for monitoring thresholds |
| 21.9 | [x] | Add unit tests for all blue team types |
| 21.10 | [x] | Verify JSON serialization round-trip |

### Phase 22: Remediation Data Types ✓

| Task | Status | Description |
|------|--------|-------------|
| 22.1 | [x] | Create `ir/remediation.go` with RemediationGuidance struct |
| 22.2 | [x] | Add CodePattern type for vulnerable/secure patterns |
| 22.3 | [x] | Add ChecklistItem type for review checklists |
| 22.4 | [x] | Add Library type for recommended libraries |
| 22.5 | [x] | Add ConfigChange type for configuration fixes |
| 22.6 | [x] | Add TestingApproach type for verification guidance |
| 22.7 | [x] | Add unit tests for all remediation types |
| 22.8 | [x] | Verify JSON serialization round-trip |

### Phase 23: app-test-spec Integration ✓

| Task | Status | Description |
|------|--------|-------------|
| 23.1 | [x] | Create `ir/testref.go` with TestReference struct |
| 23.2 | [x] | Add TestPurpose enum (exploitation, detection, remediation, regression) |
| 23.3 | [x] | Add TestSuiteReference type for suite-level references |
| 23.4 | [x] | Add TestRef field to Attack struct |
| 23.5 | [x] | Add TestSuites field to ThreatModel struct |
| 23.6 | [x] | Add TestRefs to ExploitationGuidance and TestingApproach |
| 23.7 | [x] | Add unit tests for test reference types |

### Phase 24: Incident Playbooks ✓

| Task | Status | Description |
|------|--------|-------------|
| 24.1 | [x] | Create `ir/playbook.go` with IncidentPlaybook struct |
| 24.2 | [x] | Add PlaybookStep type for ordered response steps |
| 24.3 | [x] | Add PlaybookPhase enum for IR phases |
| 24.4 | [x] | Add Contact type for incident contacts |
| 24.5 | [x] | Add Playbooks field to ThreatModel struct |
| 24.6 | [x] | Add unit tests for playbook types |
| 24.7 | [x] | Verify JSON serialization round-trip |

### Phase 25: ThreatModel & Attack Integration ✓

| Task | Status | Description |
|------|--------|-------------|
| 25.1 | [x] | Add RedTeam, BlueTeam, Remediation fields to ThreatModel |
| 25.2 | [x] | Add RedTeamNotes, BlueTeamNotes, RemediationNote to Attack |
| 25.3 | [x] | Regenerate JSON schemas |
| 25.4 | [x] | All tests pass, linting passes |

---

## Section C: Risk Quantification ✓

### Phase 26: FAIR Risk Assessment ✓

| Task | Status | Description |
|------|--------|-------------|
| 26.1 | [x] | Create `ir/fair.go` with FAIRAssessment struct |
| 26.2 | [x] | Add FrequencyEstimate type (min, max, mostLikely, confidence) |
| 26.3 | [x] | Add LossEstimate type (min, max, mostLikely, currency) |
| 26.4 | [x] | Add CalculateALE() function for Annualized Loss Expectancy |
| 26.5 | [x] | Add RiskAssessment field to ThreatModel |
| 26.6 | [x] | Add unit tests for FAIR types |
| 26.7 | [x] | Add unit tests for ALE calculation |

### Phase 27: Business Impact & EPSS ✓

| Task | Status | Description |
|------|--------|-------------|
| 27.1 | [x] | Add BusinessImpact struct (revenue, customer, regulatory, reputation, operational) |
| 27.2 | [x] | Create `ir/epss.go` with EPSSData struct |
| 27.3 | [x] | Add EPSSScore lookup (static data or FIRST API) |
| 27.4 | [x] | Add BusinessImpact field to ThreatModel |
| 27.5 | [x] | Add EPSSData field to ThreatModel |
| 27.6 | [x] | Add unit tests for business impact |
| 27.7 | [x] | Add unit tests for EPSS data |

---

## Section D: Threat Intelligence ✓

### Phase 28: STIX 2.1 Export ✓

| Task | Status | Description |
|------|--------|-------------|
| 28.1 | [x] | Create `ir/stix_export.go` with STIXExportOptions struct |
| 28.2 | [x] | Implement IOC.ToSTIXIndicator() method |
| 28.3 | [x] | Implement ThreatActor.ToSTIXThreatActor() method |
| 28.4 | [x] | Implement Attack.ToSTIXAttackPattern() method |
| 28.5 | [x] | Implement DetectionRule.ToSTIXCourseOfAction() method |
| 28.6 | [x] | Implement ThreatModel.ExportSTIXBundle() method |
| 28.7 | [x] | Add unit tests with STIX 2.1 schema validation |

### Phase 29: KEV Catalog Integration ✓

| Task | Status | Description |
|------|--------|-------------|
| 29.1 | [x] | Create `ir/kev.go` with KEVEntry struct |
| 29.2 | [x] | Add embedded KEV catalog data (or API fetch function) |
| 29.3 | [x] | Add GetKEVEntry(cveID) function |
| 29.4 | [x] | Add IsInKEV(cveID) function |
| 29.5 | [x] | Add KEVStatus for threat model reports |
| 29.6 | [x] | Add unit tests for KEV lookup |

---

## Section E: Purple Team ✓

### Phase 30: Atomic Red Team Mapping ✓

| Task | Status | Description |
|------|--------|-------------|
| 30.1 | [x] | Create `ir/atomicredteam.go` with AtomicTestMapping struct |
| 30.2 | [x] | Add fields: TechniqueID, AtomicTests, Validated, LastRun, Result |
| 30.3 | [x] | Add AtomicTests []AtomicTestMapping to ThreatModel |
| 30.4 | [x] | Add AtomicTestID optional field to Attack |
| 30.5 | [x] | Add validation for MITRE technique ID format |
| 30.6 | [x] | Add unit tests |

### Phase 31: Detection Coverage Matrix ✓

| Task | Status | Description |
|------|--------|-------------|
| 31.1 | [x] | Create `ir/coverage.go` with DetectionCoverageMatrix struct |
| 31.2 | [x] | Add TechniqueCoverage struct (techniqueId, name, tactic, coverage, detectionIds) |
| 31.3 | [x] | Add CoverageSummary struct (total, full, partial, none, percent) |
| 31.4 | [x] | Add CalculateCoverage(techniques, detections) function |
| 31.5 | [x] | Add DetectionCoverage *DetectionCoverageMatrix to ThreatModel |
| 31.6 | [x] | Add unit tests for coverage calculation |

---

## Section F: Security Metrics ✓

### Phase 32: MTTD/MTTR & Coverage Metrics ✓

| Task | Status | Description |
|------|--------|-------------|
| 32.1 | [x] | Create `ir/metrics.go` with SecurityMetrics struct |
| 32.2 | [x] | Add Duration type (value, unit) for time measurements |
| 32.3 | [x] | Add MTTD, MTTR, MTTC fields |
| 32.4 | [x] | Add DetectionRate, FalsePositiveRate fields |
| 32.5 | [x] | Add Metrics *SecurityMetrics to ThreatModel |
| 32.6 | [x] | Add unit tests |

---

## Final Integration

### Phase 33: Release Preparation

| Task | Status | Description |
|------|--------|-------------|
| 33.1 | [x] | Update version to v0.6.0 in `cmd/genschema/main.go` |
| 33.2 | [x] | Regenerate JSON schemas to schema/ and docs/versions/v0.6.0/ |
| 33.3 | [x] | Update README.md with all new features |
| 33.4 | [x] | Add CHANGELOG.md entry for v0.6.0 |
| 33.5 | [x] | Extend openclaw.json with sample role/risk/metrics data |
| 33.6 | [x] | Run full test suite: `go test ./...` |
| 33.7 | [x] | Run linter: `golangci-lint run` |
| 33.8 | [ ] | Create git commit |
| 33.9 | [ ] | Tag v0.6.0 release |

---

## Section G: Supply Chain Security

### Phase 34: SBOM Integration ✓

| Task | Status | Description |
|------|--------|-------------|
| 34.1 | [x] | Create `ir/sbom.go` with SBOMReference struct |
| 34.2 | [x] | Add SBOMFormat enum (cyclonedx, spdx) |
| 34.3 | [x] | Add ComponentReference struct for linking threats to components |
| 34.4 | [x] | Add DependencyRisk struct for vulnerable dependency tracking |
| 34.5 | [x] | Add SBOM field to ThreatModel |
| 34.6 | [x] | Add ComponentRefs to Attack struct |
| 34.7 | [x] | Add unit tests |

### Phase 35: VEX Support ✓

| Task | Status | Description |
|------|--------|-------------|
| 35.1 | [x] | Create `ir/vex.go` with VEXStatement struct |
| 35.2 | [x] | Add VEXStatus enum (not_affected, affected, fixed, under_investigation) |
| 35.3 | [x] | Add VEXJustification enum (component_not_present, vulnerable_code_not_present, etc.) |
| 35.4 | [x] | Add VEXStatements field to ThreatModel |
| 35.5 | [x] | Add VEX export function (OpenVEX format) |
| 35.6 | [x] | Add unit tests |

---

## Section H: Vulnerability Management

### Phase 36: SSVC Decision Trees ✓

| Task | Status | Description |
|------|--------|-------------|
| 36.1 | [x] | Create `ir/ssvc.go` with SSVCAssessment struct |
| 36.2 | [x] | Add Exploitation enum (none, poc, active) |
| 36.3 | [x] | Add Automatable enum (no, yes) |
| 36.4 | [x] | Add TechnicalImpact enum (partial, total) |
| 36.5 | [x] | Add MissionPrevalence enum (minimal, support, essential) |
| 36.6 | [x] | Add PublicWellBeing enum (minimal, material, irreversible) |
| 36.7 | [x] | Add SSVCDecision enum (track, track*, attend, act) |
| 36.8 | [x] | Add CalculateSSVCDecision() function |
| 36.9 | [x] | Add SSVCAssessment to ThreatEntry |
| 36.10 | [x] | Add unit tests |

---

## Section I: Attack Path Analysis ✓

### Phase 37: Graph Data Model ✓

| Task | Status | Description |
|------|--------|-------------|
| 37.1 | [x] | Create `ir/attackgraph.go` with AttackGraph struct |
| 37.2 | [x] | Add GraphNode struct (element, threat, or control) |
| 37.3 | [x] | Add GraphEdge struct with edge types (flow, attack, mitigation) |
| 37.4 | [x] | Add BuildAttackGraph() from ThreatModel |
| 37.5 | [x] | Add ToJSON() and FromJSON() for graph serialization |
| 37.6 | [x] | Add unit tests |

### Phase 38: Path Computation ✓

| Task | Status | Description |
|------|--------|-------------|
| 38.1 | [x] | Add AttackPath struct (sequence of nodes/edges) |
| 38.2 | [x] | Add FindAllPaths(source, target) function |
| 38.3 | [x] | Add FindShortestPath(source, target) function |
| 38.4 | [x] | Add CalculatePathRisk(path) function |
| 38.5 | [x] | Add FindCriticalPaths() for highest-risk paths |
| 38.6 | [x] | Add ReachabilityAnalysis() for exposure assessment |
| 38.7 | [x] | Add unit tests |

---

## Files Summary

### Created (Section A & B - Complete)

| File | Section | Description |
|------|---------|-------------|
| `ir/owasp_reference.go` | A | 40 OWASP entries across 4 lists |
| `ir/owasp_reference_test.go` | A | OWASP reference tests |
| `ir/mappings_test.go` | A | Mappings tests |
| `ir/redteam.go` | B | ExploitationGuidance, steps, tools, patterns |
| `ir/redteam_test.go` | B | Red team tests |
| `ir/blueteam.go` | B | DefenseGuidance, rules, IOCs, queries |
| `ir/blueteam_test.go` | B | Blue team tests |
| `ir/remediation.go` | B | RemediationGuidance, patterns, checklists |
| `ir/remediation_test.go` | B | Remediation tests |
| `ir/playbook.go` | B | IncidentPlaybook, steps, contacts |
| `ir/playbook_test.go` | B | Playbook tests |
| `ir/testref.go` | B | TestReference, TestSuiteReference |
| `ir/testref_test.go` | B | Test reference tests |

### Created (Sections C-F - Complete)

| File | Section | Description |
|------|---------|-------------|
| `ir/fair.go` | C | FAIR risk assessment types |
| `ir/fair_test.go` | C | FAIR tests |
| `ir/epss.go` | C | EPSS scoring types |
| `ir/epss_test.go` | C | EPSS tests |
| `ir/stix_export.go` | D | STIX 2.1 export functions |
| `ir/stix_export_test.go` | D | STIX export tests |
| `ir/kev.go` | D | KEV catalog types |
| `ir/kev_test.go` | D | KEV tests |
| `ir/atomicredteam.go` | E | Atomic Red Team mapping |
| `ir/atomicredteam_test.go` | E | ART tests |
| `ir/coverage.go` | E | Detection coverage matrix |
| `ir/coverage_test.go` | E | Coverage tests |
| `ir/metrics.go` | F | Security metrics types |
| `ir/metrics_test.go` | F | Metrics tests |

### Modified (Complete)

| File | Changes |
|------|---------|
| `ir/mappings.go` | Added OWASPCategoryAgentic |
| `ir/diagram.go` | Added ASIIds, role notes, TestRef to Attack |
| `ir/threat_model.go` | Added RedTeam, BlueTeam, Remediation, Playbooks, TestSuites |
| `ir/validate.go` | Added ValidateOWASPMappings() |

### Modified (Sections C-F - Complete)

| File | Changes |
|------|---------|
| `ir/threat_model.go` | Added RiskAssessment, BusinessImpact, EPSSData, AtomicTests, DetectionCoverage, Metrics |

### Created (Sections G-I - Complete)

| File | Section | Description |
|------|---------|-------------|
| `ir/sbom.go` | G | SBOM references, component linking |
| `ir/sbom_test.go` | G | SBOM tests |
| `ir/vex.go` | G | VEX statements, status, justifications |
| `ir/vex_test.go` | G | VEX tests |
| `ir/ssvc.go` | H | SSVC decision trees, enums |
| `ir/ssvc_test.go` | H | SSVC tests |
| `ir/attackgraph.go` | I | Attack graph model, nodes, edges |
| `ir/attackgraph_test.go` | I | Graph tests |
| `ir/attackpath.go` | I | Path computation, risk calculation |
| `ir/attackpath_test.go` | I | Path tests |

### Modified (Sections G-I - Complete)

| File | Changes |
|------|---------|
| `ir/threat_model.go` | Added SBOM, VEXStatements, DependencyRisks fields |
| `ir/diagram.go` | Added ComponentRefs to Attack |
| `ir/mitigations.go` | Added SSVCAssessment to ThreatEntry |

---

## Progress Summary

| Section | Phases | Status | Completion |
|---------|--------|--------|------------|
| A: OWASP ASI | 17-19 | Complete | 100% |
| B: Role-Based | 20-25 | Complete | 100% |
| C: Risk | 26-27 | Complete | 100% |
| D: Threat Intel | 28-29 | Complete | 100% |
| E: Purple Team | 30-31 | Complete | 100% |
| F: Metrics | 32 | Complete | 100% |
| G: Supply Chain | 34-35 | Complete | 100% |
| H: Vuln Mgmt | 36 | Complete | 100% |
| I: Attack Paths | 37-38 | Complete | 100% |
| Final | 33 | In Progress | 78% |
| **Overall** | 17-38 | In Progress | ~97% |
