# Threat Model Spec Development Tasks

## Completed Phases (Historical)

<details>
<summary>Phase 1-5: Initial Development (Complete)</summary>

### Phase 1: D2 Style Library (Core) ✓

| Task | Status | Description |
|------|--------|-------------|
| 1.1 | [x] | Create `d2/styles/stride.d2` - STRIDE threat annotation styles |
| 1.2 | [x] | Create `d2/styles/dfd.d2` - DFD element styles |
| 1.3 | [x] | Create `d2/styles/trustboundary.d2` - Trust boundary styles |
| 1.4 | [x] | Create `d2/styles/attackflow.d2` - Attack flow styles |
| 1.5 | [x] | Create `d2/styles/all.d2` - Combined import file |
| 1.6 | [x] | Test styles render correctly with D2 CLI |

### Phase 2: OpenClaw Diagram Example ✓

| Task | Status | Description |
|------|--------|-------------|
| 2.1 | [x] | Create attack chain diagram |
| 2.2 | [x] | Add STRIDE threat annotations |
| 2.3 | [x] | Add MITRE ATT&CK mapping |
| 2.4 | [x] | Generate SVG output |
| 2.5 | [x] | Create README with vulnerability explanation |

### Phase 3: Go Library ✓

| Task | Status | Description |
|------|--------|-------------|
| 3.1-3.10 | [x] | STRIDE, kill chain, diagram types, rendering, tests |

### Phase 4: Vulnerable Demo Service ✓

| Task | Status | Description |
|------|--------|-------------|
| 4.1-4.5 | [x] | WebSocket server, auth, auto-approve, mock data |

### Phase 5: Attack Demonstration ✓

| Task | Status | Description |
|------|--------|-------------|
| 5.1-5.8 | [x] | Malicious page, brute-force, exfiltration, automation |

</details>

---

## Enhancement Phases (Complete)

### Phase 7: Mitigations and Threat Status ✓

**Priority:** High | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 7.1 | [x] | Create `ir/mitigations.go` with Mitigation and MitigationStatus types |
| 7.2 | [x] | Add ThreatStatus enum for threat lifecycle tracking |
| 7.3 | [x] | Add Mitigations field to DiagramIR and ThreatModel |
| 7.4 | [x] | Add validation for mitigation references |
| 7.5 | [x] | Update D2 rendering to show mitigation status |
| 7.6 | [x] | Update STIX export for mitigations |
| 7.7 | [x] | Add unit tests for mitigation types |

### Phase 8: Control Framework Mappings ✓

**Priority:** High | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 8.1 | [x] | Create `ir/controls.go` with control framework types |
| 8.2 | [x] | Add NISTCSFMapping for NIST Cybersecurity Framework |
| 8.3 | [x] | Add CISControlMapping for CIS Controls v8 |
| 8.4 | [x] | Add ISO27001Mapping for ISO 27001 |
| 8.5 | [x] | Add Controls field to Mappings struct |
| 8.6 | [ ] | Add validation for control references |
| 8.7 | [ ] | Update STIX export for controls |
| 8.8 | [x] | Add unit tests for control types |

### Phase 9: Compliance Framework References ✓

**Priority:** Medium | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 9.1 | [x] | Create `ir/compliance.go` with compliance types |
| 9.2 | [x] | Add ComplianceMapping for regulatory frameworks |
| 9.3 | [x] | Add ComplianceFramework enum (SOC2, PCI-DSS, HIPAA, GDPR) |
| 9.4 | [x] | Add Compliance field to Mappings struct |
| 9.5 | [ ] | Add validation for compliance references |
| 9.6 | [x] | Add unit tests for compliance types |

### Phase 10: LINDDUN Privacy Framework ✓

**Priority:** Medium | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 10.1 | [x] | Create `ir/linddun.go` with LINDDUN types |
| 10.2 | [x] | Add LINDDUNThreat enum (L, I, N, D, Di, U, Nc) |
| 10.3 | [x] | Add LINDDUNMapping with affected data types |
| 10.4 | [x] | Add LINDDUN field to Mappings struct |
| 10.5 | [x] | Add D2 styling for LINDDUN threats |
| 10.6 | [x] | Add unit tests for LINDDUN types |

### Phase 11: Threat Actors ✓

**Priority:** Medium | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 11.1 | [x] | Create `ir/threat_actor.go` with threat actor types |
| 11.2 | [x] | Add ThreatActor struct with sophistication, motivation, resources |
| 11.3 | [x] | Add ThreatActorType enum |
| 11.4 | [x] | Add ThreatActors field to ThreatModel |
| 11.5 | [ ] | Add validation for threat actor references |
| 11.6 | [x] | Add unit tests for threat actor types |

### Phase 12: Detection Capabilities ✓

**Priority:** Medium | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 12.1 | [x] | Create `ir/detection.go` with detection types |
| 12.2 | [x] | Add Detection struct with method, data source, coverage |
| 12.3 | [x] | Add DetectionCoverage enum |
| 12.4 | [x] | Add Detections field to DiagramIR |
| 12.5 | [x] | Add validation for detection references |
| 12.6 | [x] | Add unit tests for detection types |

### Phase 13: Assumptions and Prerequisites ✓

**Priority:** Low | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 13.1 | [x] | Create `ir/assumptions.go` with assumption types |
| 13.2 | [x] | Add Assumption struct with impact and validation status |
| 13.3 | [x] | Add Assumptions field to ThreatModel |
| 13.4 | [ ] | Add validation for assumption references |
| 13.5 | [x] | Add unit tests for assumption types |

### Phase 14: CVE References ✓

**Priority:** Low | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 14.1 | [x] | Add CVEMapping to `ir/mappings.go` |
| 14.2 | [x] | Add CVE field to Mappings struct |
| 14.3 | [x] | Add URL generation for CVE references (in STIX export) |
| 14.4 | [ ] | Add unit tests for CVE mapping |

### Phase 15: Attack Trees Diagram Type ✓

**Priority:** Low | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 15.1 | [x] | Add `attack-tree` to DiagramType enum |
| 15.2 | [x] | Create AttackTreeNode struct for hierarchical decomposition |
| 15.3 | [x] | Add AND/OR node logic types |
| 15.4 | [x] | Add D2 rendering for attack trees |
| 15.5 | [x] | Add validation for attack tree structure |
| 15.6 | [x] | Add unit tests for attack tree types |

### Phase 16: Schema and Documentation ✓

**Priority:** High | **Status:** Complete

| Task | Status | Description |
|------|--------|-------------|
| 16.1 | [x] | Regenerate JSON schemas after type additions |
| 16.2 | [x] | Update embedded schemas in schema/ directory |
| 16.3 | [ ] | Validate schemas with schemago lint |
| 16.4 | [x] | Update README with new features |
| 16.5 | [ ] | Update MkDocs documentation |
| 16.6 | [x] | Add changelog entries |

---

## Current Focus

**Status**: All Enhancement Phases Complete

**Completed**: Phases 7-16 (All type implementations, attack trees, documentation)

**Remaining**: Optional items (schemago validation, MkDocs docs, some validation tasks)

---

## Implementation Summary

### New Files Created

| File | Description |
|------|-------------|
| `ir/mitigations.go` | Mitigation, MitigationStatus, ThreatStatus, ThreatEntry |
| `ir/controls.go` | NIST CSF, CIS Controls v8, ISO 27001 mappings |
| `ir/compliance.go` | SOC 2, PCI-DSS, HIPAA, GDPR, and other compliance frameworks |
| `ir/linddun.go` | LINDDUN privacy threat framework |
| `ir/threat_actor.go` | ThreatActor profiles with sophistication, motivation, resources |
| `ir/detection.go` | Detection and ResponseAction types |
| `ir/assumptions.go` | Assumption and Prerequisite types |
| `ir/attack_tree.go` | AttackTreeNode, AttackTree with AND/OR logic |

### New Test Files

| File | Tests |
|------|-------|
| `ir/mitigations_test.go` | MitigationStatus, ThreatStatus, JSON serialization |
| `ir/controls_test.go` | NIST CSF, CIS, ISO 27001 mappings |
| `ir/compliance_test.go` | All compliance frameworks |
| `ir/linddun_test.go` | LINDDUN threats, names, descriptions |
| `ir/threat_actor_test.go` | Threat actor types, sophistication, motivation |
| `ir/detection_test.go` | Detection coverage, data sources |
| `ir/assumptions_test.go` | Assumption types, validation status |
| `ir/validate_security_test.go` | Validation tests for new security fields |
| `ir/attack_tree_test.go` | Attack tree node types, AND/OR logic, rendering |

### Updated Files

| File | Changes |
|------|---------|
| `ir/mappings.go` | Added CVE, LINDDUN, Controls, Compliance fields |
| `ir/diagram.go` | Added Threats, Mitigations, Detections, ResponseActions, AttackTree, Legend |
| `ir/types.go` | Added DiagramTypeAttackTree constant |
| `ir/threat_model.go` | Added ThreatActors, Assumptions, Prerequisites, Mitigations |
| `ir/validate.go` | Added validation for new security fields, attack trees |
| `ir/render.go` | Added LINDDUN legend, mitigations rendering, attack tree rendering |
| `stix/export.go` | Added export for CVE, OWASP, mitigations, threat entries |
| `stix/types.go` | Added CourseOfAction, Malware, Tool types |
| `README.md` | Updated with all new framework tables and features |
| `CHANGELOG.md` | Added [Unreleased] section with new features |

---

---

## v0.6.0: Comprehensive Security Enhancement

> **Design Docs:** [`docs/design/v0.6.0/`](docs/design/v0.6.0/)
>
> **Status:** In Progress (~50% complete)

This release combines OWASP ASI support, role-based security data, risk quantification, threat intelligence export, purple team capabilities, and security metrics.

---

### Section A: OWASP ASI Support ✓

#### Phase 17: Core ASI Support ✓

| Task | Status | Description |
|------|--------|-------------|
| 17.1 | [x] | Add `OWASPCategoryAgentic` to `ir/mappings.go` |
| 17.2 | [x] | Update `OWASPCategory.JSONSchema()` to include "agentic" |
| 17.3 | [x] | Add `ASIIds []string` field to Attack struct |
| 17.4 | [x] | Add unit tests for new category and field |

#### Phase 18: OWASP Reference Data ✓

| Task | Status | Description |
|------|--------|-------------|
| 18.1 | [x] | Create `ir/owasp_reference.go` with OWASPEntry type |
| 18.2 | [x] | Add OWASP API Security Top 10 (2023) - 10 entries |
| 18.3 | [x] | Add OWASP LLM Top 10 (2025) - 10 entries |
| 18.4 | [x] | Add OWASP Web Top 10 (2021) - 10 entries |
| 18.5 | [x] | Add OWASP Agentic Top 10 (ASI 2026) - 10 entries |
| 18.6 | [x] | Add GetOWASPEntry() and ValidateOWASPID() functions |
| 18.7 | [x] | Add unit tests for reference data |

#### Phase 19: Validation & Documentation ✓

| Task | Status | Description |
|------|--------|-------------|
| 19.1 | [x] | Add ValidateOWASPMappings() to `ir/validate.go` |
| 19.2 | [x] | Update README.md with ASI support |

---

### Section B: Role-Based Security Data ✓

#### Phase 20: Red Team Data Types ✓

| Task | Status | Description |
|------|--------|-------------|
| 20.1 | [x] | Create `ir/redteam.go` with ExploitationGuidance struct |
| 20.2 | [x] | Add ExploitationStep type for ordered attack steps |
| 20.3 | [x] | Add OffensiveTool type for tool recommendations |
| 20.4 | [x] | Add PayloadPattern type for generic payload templates |
| 20.5 | [x] | Add ExploitDifficulty enum |
| 20.6 | [x] | Add unit tests with JSON round-trip verification |

#### Phase 21: Blue Team Data Types ✓

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

#### Phase 22: Remediation Data Types ✓

| Task | Status | Description |
|------|--------|-------------|
| 22.1 | [x] | Create `ir/remediation.go` with RemediationGuidance struct |
| 22.2 | [x] | Add CodePattern type for vulnerable/secure patterns |
| 22.3 | [x] | Add ChecklistItem type for review checklists |
| 22.4 | [x] | Add Library type for recommended libraries |
| 22.5 | [x] | Add ConfigChange type for configuration fixes |
| 22.6 | [x] | Add TestingApproach type |
| 22.7 | [x] | Add unit tests with JSON round-trip verification |

#### Phase 23: app-test-spec Integration ✓

| Task | Status | Description |
|------|--------|-------------|
| 23.1 | [x] | Create `ir/testref.go` with TestReference struct |
| 23.2 | [x] | Add TestPurpose enum |
| 23.3 | [x] | Add TestSuiteReference type |
| 23.4 | [x] | Add TestRef to Attack struct |
| 23.5 | [x] | Add TestSuites to ThreatModel struct |
| 23.6 | [x] | Add TestRefs to ExploitationGuidance and TestingApproach |
| 23.7 | [x] | Add unit tests with JSON round-trip verification |

#### Phase 24: Incident Playbooks ✓

| Task | Status | Description |
|------|--------|-------------|
| 24.1 | [x] | Create `ir/playbook.go` with IncidentPlaybook struct |
| 24.2 | [x] | Add PlaybookStep type for ordered response steps |
| 24.3 | [x] | Add PlaybookPhase enum |
| 24.4 | [x] | Add Contact type for incident contacts |
| 24.5 | [x] | Add Playbooks to ThreatModel struct |
| 24.6 | [x] | Add unit tests with JSON round-trip verification |

#### Phase 25: ThreatModel & Attack Integration ✓

| Task | Status | Description |
|------|--------|-------------|
| 25.1 | [x] | Add RedTeam, BlueTeam, Remediation fields to ThreatModel |
| 25.2 | [x] | Add RedTeamNotes, BlueTeamNotes, RemediationNote to Attack |
| 25.3 | [x] | Regenerate JSON schemas |
| 25.4 | [x] | All tests pass, linting passes |

---

### Section C: Risk Quantification (Pending)

#### Phase 26: FAIR Risk Assessment

| Task | Status | Description |
|------|--------|-------------|
| 26.1 | [ ] | Create `ir/fair.go` with FAIRAssessment struct |
| 26.2 | [ ] | Add FrequencyEstimate type (LEF components) |
| 26.3 | [ ] | Add LossEstimate type (LM components) |
| 26.4 | [ ] | Add ALE calculation helper |
| 26.5 | [ ] | Add RiskAssessment to ThreatModel |
| 26.6 | [ ] | Add unit tests |

#### Phase 27: Business Impact & EPSS

| Task | Status | Description |
|------|--------|-------------|
| 27.1 | [ ] | Add BusinessImpact struct to `ir/fair.go` |
| 27.2 | [ ] | Create `ir/epss.go` with EPSSData struct |
| 27.3 | [ ] | Add GetEPSSScore() lookup function |
| 27.4 | [ ] | Add BusinessImpact and EPSSData to ThreatModel |
| 27.5 | [ ] | Add unit tests |

---

### Section D: Threat Intelligence (Pending)

#### Phase 28: STIX 2.1 Export

| Task | Status | Description |
|------|--------|-------------|
| 28.1 | [ ] | Create `ir/stix_export.go` with export functions |
| 28.2 | [ ] | Implement IOC to STIX Indicator conversion |
| 28.3 | [ ] | Implement ThreatActor to STIX Threat-Actor conversion |
| 28.4 | [ ] | Implement Attack to STIX Attack-Pattern conversion |
| 28.5 | [ ] | Implement ThreatModel.ExportSTIXBundle() |
| 28.6 | [ ] | Add unit tests with STIX schema validation |

#### Phase 29: KEV Catalog Integration

| Task | Status | Description |
|------|--------|-------------|
| 29.1 | [ ] | Create `ir/kev.go` with KEVEntry struct |
| 29.2 | [ ] | Add embedded KEV catalog data (or fetch function) |
| 29.3 | [ ] | Add GetKEVEntry() and IsInKEV() functions |
| 29.4 | [ ] | Add KEVData field to CVEMapping |
| 29.5 | [ ] | Add unit tests |

---

### Section E: Purple Team (Pending)

#### Phase 30: Atomic Red Team Mapping

| Task | Status | Description |
|------|--------|-------------|
| 30.1 | [ ] | Create `ir/atomicredteam.go` with AtomicTestMapping struct |
| 30.2 | [ ] | Add AtomicTests field to ThreatModel |
| 30.3 | [ ] | Add AtomicTestID field to Attack (optional) |
| 30.4 | [ ] | Add validation for technique ID format |
| 30.5 | [ ] | Add unit tests |

#### Phase 31: Detection Coverage Matrix

| Task | Status | Description |
|------|--------|-------------|
| 31.1 | [ ] | Create `ir/coverage.go` with DetectionCoverageMatrix struct |
| 31.2 | [ ] | Add TechniqueCoverage struct |
| 31.3 | [ ] | Add CoverageSummary struct |
| 31.4 | [ ] | Add CalculateCoverage() function |
| 31.5 | [ ] | Add DetectionCoverage to ThreatModel |
| 31.6 | [ ] | Add unit tests |

---

### Section F: Security Metrics (Pending)

#### Phase 32: MTTD/MTTR & Coverage Metrics

| Task | Status | Description |
|------|--------|-------------|
| 32.1 | [ ] | Create `ir/metrics.go` with SecurityMetrics struct |
| 32.2 | [ ] | Add Duration type for time measurements |
| 32.3 | [ ] | Add Metrics field to ThreatModel |
| 32.4 | [ ] | Add unit tests |

---

### Final Integration

#### Phase 33: Release Preparation

| Task | Status | Description |
|------|--------|-------------|
| 33.1 | [x] | Update version to v0.6.0 in `cmd/genschema/main.go` |
| 33.2 | [x] | Regenerate JSON schemas to schema/ and docs/versions/v0.6.0/ |
| 33.3 | [ ] | Update README.md with all new features |
| 33.4 | [ ] | Add CHANGELOG.md entry for v0.6.0 |
| 33.5 | [ ] | Extend openclaw.json with sample role/risk/metrics data |
| 33.6 | [ ] | Run full test suite: `go test ./...` |
| 33.7 | [ ] | Run linter: `golangci-lint run` |
| 33.8 | [ ] | Create git commit |
| 33.9 | [ ] | Tag v0.6.0 release |

---

### Progress Summary

| Section | Phases | Status | Completion |
|---------|--------|--------|------------|
| A: OWASP ASI | 17-19 | Complete | 100% |
| B: Role-Based | 20-25 | Complete | 100% |
| C: Risk | 26-27 | Pending | 0% |
| D: Threat Intel | 28-29 | Pending | 0% |
| E: Purple Team | 30-31 | Pending | 0% |
| F: Metrics | 32 | Pending | 0% |
| Final | 33 | In Progress | 25% |
| **Overall** | 17-33 | In Progress | ~50% |

---

## Design Documentation

Version-specific design documents are located in `docs/design/v0.X.0/`:

| Version | Status | Documents |
|---------|--------|-----------|
| v0.6.0 | In Progress | [PRD](docs/design/v0.6.0/PRD.md), [TRD](docs/design/v0.6.0/TRD.md), [PLAN](docs/design/v0.6.0/PLAN.md), [TASKS](docs/design/v0.6.0/TASKS.md) |

---

## Notes

- All new fields use `omitempty` for backward compatibility
- Existing JSON files remain valid after enhancements
- Go structs are the source of truth (Go-first approach)
- JSON schemas generated from Go types using invopop/jsonschema
- All tests pass, linting passes
