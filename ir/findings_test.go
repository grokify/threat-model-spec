package ir

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingType_JSONSchema(t *testing.T) {
	schema := FindingType("").JSONSchema()
	if len(schema.Enum) != 6 {
		t.Errorf("expected 6 enum values, got %d", len(schema.Enum))
	}
}

func TestFindingStatus_JSONSchema(t *testing.T) {
	schema := FindingStatus("").JSONSchema()
	if len(schema.Enum) != 4 {
		t.Errorf("expected 4 enum values, got %d", len(schema.Enum))
	}
}

func TestSecurityRequirementType_JSONSchema(t *testing.T) {
	schema := SecurityRequirementType("").JSONSchema()
	if len(schema.Enum) != 6 {
		t.Errorf("expected 6 enum values, got %d", len(schema.Enum))
	}
}

func TestArchitectureAssertionStatus_JSONSchema(t *testing.T) {
	schema := ArchitectureAssertionStatus("").JSONSchema()
	if len(schema.Enum) != 3 {
		t.Errorf("expected 3 enum values, got %d", len(schema.Enum))
	}
}

func TestFinding_JSON(t *testing.T) {
	f := Finding{
		ID:              "finding-017",
		Type:            FindingTypeThreatCandidate,
		Stage:           StageBuilderDefinition,
		Title:           "Forged webhook changes payment state",
		Description:     "Signature validation can be bypassed",
		TargetRefs:      []string{"component:webhook-handler"},
		EvidenceIDs:     []string{"evidence-1"},
		Confidence:      0.86,
		Status:          FindingStatusCandidate,
		STRIDEThreats:   []STRIDEThreat{STRIDESpoofing, STRIDETampering},
		OWASPIds:        []string{"API2:2023"},
		MITRETechniques: []string{"T1110", "T1110.001"},
		ProducerRunID:   "run-1",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Confidence != 0.86 {
		t.Errorf("Confidence = %v, want 0.86", decoded.Confidence)
	}
	if decoded.Type != FindingTypeThreatCandidate {
		t.Errorf("Type = %q, want %q", decoded.Type, FindingTypeThreatCandidate)
	}
	if len(decoded.STRIDEThreats) != 2 || decoded.STRIDEThreats[0] != STRIDESpoofing {
		t.Errorf("STRIDEThreats = %v, want [S T]", decoded.STRIDEThreats)
	}
	if len(decoded.OWASPIds) != 1 || decoded.OWASPIds[0] != "API2:2023" {
		t.Errorf("OWASPIds = %v, want [API2:2023]", decoded.OWASPIds)
	}
	if len(decoded.MITRETechniques) != 2 {
		t.Errorf("MITRETechniques = %v, want 2 entries", decoded.MITRETechniques)
	}
}

func TestFinding_FrameworkFieldsOmitEmpty(t *testing.T) {
	f := Finding{ID: "finding-plain", Type: FindingTypeObservation, Title: "plain", Status: FindingStatusCandidate}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	for _, key := range []string{"strideThreats", "owaspIds", "mitreTechniques"} {
		if strings.Contains(string(data), `"`+key+`"`) {
			t.Errorf("marshaled Finding with no framework mappings should omit %q, got %s", key, data)
		}
	}
}

func TestThreatModelValidateFindingFrameworkMappings(t *testing.T) {
	tests := []struct {
		name         string
		findings     []Finding
		wantWarnings int
	}{
		{
			name: "valid mappings produce no warnings",
			findings: []Finding{{
				ID:              "finding-1",
				STRIDEThreats:   []STRIDEThreat{STRIDESpoofing},
				OWASPIds:        []string{"API2:2023"},
				MITRETechniques: []string{"T1110"},
			}},
			wantWarnings: 0,
		},
		{
			name:         "unrecognized STRIDE category",
			findings:     []Finding{{ID: "finding-2", STRIDEThreats: []STRIDEThreat{"X"}}},
			wantWarnings: 1,
		},
		{
			name:         "unrecognized OWASP ID",
			findings:     []Finding{{ID: "finding-3", OWASPIds: []string{"NOTREAL:2023"}}},
			wantWarnings: 1,
		},
		{
			name:         "unrecognized MITRE technique ID",
			findings:     []Finding{{ID: "finding-4", MITRETechniques: []string{"not-a-technique"}}},
			wantWarnings: 1,
		},
		{
			name:         "no framework mappings produces no warnings",
			findings:     []Finding{{ID: "finding-5"}},
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm := &ThreatModel{Findings: tt.findings}
			warnings := tm.ValidateFindingFrameworkMappings()
			if len(warnings) != tt.wantWarnings {
				t.Errorf("ValidateFindingFrameworkMappings() returned %d warnings, want %d: %v", len(warnings), tt.wantWarnings, warnings)
			}
		})
	}
}

func TestFinding_ObservationType(t *testing.T) {
	// Observation is folded into Finding rather than a separate object type
	// — verify the type/confidence convention documented on Finding holds.
	f := Finding{
		ID:         "finding-obs-1",
		Type:       FindingTypeObservation,
		Title:      "admin-api is exposed to public-internet",
		Confidence: 0.97,
		Status:     FindingStatusValidated,
	}
	if f.Type != FindingTypeObservation {
		t.Errorf("Type = %q, want %q", f.Type, FindingTypeObservation)
	}
	if f.Confidence < 0.9 {
		t.Errorf("Confidence = %v, expected near 1.0 for an observation", f.Confidence)
	}
}

func TestSecurityRequirement_JSON(t *testing.T) {
	req := SecurityRequirement{
		ID:               "req-tenant-isolation",
		Statement:        "A principal can access resources only within its tenant",
		Type:             SecurityRequirementTypeInvariant,
		Criticality:      "critical",
		OriginArtifactID: "artifact-prd-1",
		VerificationIDs:  []string{"run-authz-static", "run-authz-dynamic"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded SecurityRequirement
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.VerificationIDs) != 2 {
		t.Errorf("VerificationIDs = %v, want 2 entries", decoded.VerificationIDs)
	}
}

func TestArchitectureAssertion_JSON(t *testing.T) {
	a := ArchitectureAssertion{
		ID:                  "assert-admin-private",
		SubjectID:           "admin-api",
		Predicate:           "network-exposure",
		Expected:            "private",
		Observed:            "public",
		ExpectedEvidenceIDs: []string{"evidence-trd-14"},
		ObservedEvidenceIDs: []string{"evidence-ingress-7"},
		Status:              ArchitectureAssertionStatusContradicted,
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded ArchitectureAssertion
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Status != ArchitectureAssertionStatusContradicted {
		t.Errorf("Status = %q, want %q", decoded.Status, ArchitectureAssertionStatusContradicted)
	}
	if decoded.Expected == decoded.Observed {
		t.Error("Expected and Observed should differ for a contradicted assertion fixture")
	}
}
