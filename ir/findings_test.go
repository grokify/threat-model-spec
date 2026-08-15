package ir

import (
	"encoding/json"
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
		ID:            "finding-017",
		Type:          FindingTypeThreatCandidate,
		Stage:         StageBuilderDefinition,
		Title:         "Forged webhook changes payment state",
		Description:   "Signature validation can be bypassed",
		TargetRefs:    []string{"component:webhook-handler"},
		EvidenceIDs:   []string{"evidence-1"},
		Confidence:    0.86,
		Status:        FindingStatusCandidate,
		ProducerRunID: "run-1",
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
