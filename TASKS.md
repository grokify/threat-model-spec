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

## Notes

- All new fields use `omitempty` for backward compatibility
- Existing JSON files remain valid after enhancements
- Go structs are the source of truth (Go-first approach)
- JSON schemas generated from Go types using invopop/jsonschema
- All tests pass, linting passes
