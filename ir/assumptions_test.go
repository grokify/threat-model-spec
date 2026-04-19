package ir

import (
	"encoding/json"
	"testing"
)

func TestAssumptionType_JSONSchema(t *testing.T) {
	schema := AssumptionType("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 7 {
		t.Errorf("expected 7 enum values, got %d", len(schema.Enum))
	}
}

func TestValidationStatus_JSONSchema(t *testing.T) {
	schema := ValidationStatus("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 4 {
		t.Errorf("expected 4 enum values, got %d", len(schema.Enum))
	}
}

func TestAssumption_JSON(t *testing.T) {
	a := Assumption{
		ID:                  "assume-1",
		Title:               "Network segmentation is in place",
		Description:         "Internal network is segmented with firewalls between zones",
		Type:                AssumptionTypeSecurity,
		Rationale:           "Defense in depth strategy",
		Impact:              "Lateral movement would be easier if segmentation fails",
		ImpactSeverity:      "high",
		ValidationStatus:    ValidationStatusValidated,
		ValidationMethod:    "Network diagram review and penetration testing",
		ValidatedDate:       "2024-01-15T10:00:00Z",
		Owner:               "network-team",
		RelatedComponentIDs: []string{"firewall", "vpc"},
		Notes:               "Annual review required",
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Assumption
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != a.ID {
		t.Errorf("expected ID %q, got %q", a.ID, decoded.ID)
	}
	if decoded.Type != AssumptionTypeSecurity {
		t.Errorf("expected type %q, got %q", AssumptionTypeSecurity, decoded.Type)
	}
	if decoded.ValidationStatus != ValidationStatusValidated {
		t.Errorf("expected status %q, got %q", ValidationStatusValidated, decoded.ValidationStatus)
	}
	if len(decoded.RelatedComponentIDs) != 2 {
		t.Errorf("expected 2 related components, got %d", len(decoded.RelatedComponentIDs))
	}
}

func TestPrerequisite_JSON(t *testing.T) {
	p := Prerequisite{
		ID:               "prereq-1",
		Title:            "Attacker has network access",
		Description:      "Attacker can reach the target network",
		Type:             AssumptionTypeThreat,
		Required:         true,
		Status:           "met",
		DependsOn:        []string{"prereq-0"},
		RelatedThreatIDs: []string{"threat-1", "threat-2"},
		Notes:            "Assumed for external threat scenarios",
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Prerequisite
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != p.ID {
		t.Errorf("expected ID %q, got %q", p.ID, decoded.ID)
	}
	if !decoded.Required {
		t.Error("expected required to be true")
	}
	if len(decoded.RelatedThreatIDs) != 2 {
		t.Errorf("expected 2 related threats, got %d", len(decoded.RelatedThreatIDs))
	}
}

func TestAssumptionType_Values(t *testing.T) {
	types := []AssumptionType{
		AssumptionTypeTrust,
		AssumptionTypeSecurity,
		AssumptionTypeOperational,
		AssumptionTypeEnvironment,
		AssumptionTypeThreat,
		AssumptionTypeCompliance,
		AssumptionTypeDependency,
	}

	for _, typ := range types {
		t.Run(string(typ), func(t *testing.T) {
			data, err := json.Marshal(typ)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded AssumptionType
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != typ {
				t.Errorf("expected %q, got %q", typ, decoded)
			}
		})
	}
}

func TestValidationStatus_Values(t *testing.T) {
	statuses := []ValidationStatus{
		ValidationStatusNotValidated,
		ValidationStatusValidated,
		ValidationStatusInvalidated,
		ValidationStatusPending,
	}

	for _, s := range statuses {
		t.Run(string(s), func(t *testing.T) {
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded ValidationStatus
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != s {
				t.Errorf("expected %q, got %q", s, decoded)
			}
		})
	}
}
