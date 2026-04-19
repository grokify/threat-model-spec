package ir

import (
	"encoding/json"
	"testing"
)

func TestMitigationStatus_JSONSchema(t *testing.T) {
	schema := MitigationStatus("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 6 {
		t.Errorf("expected 6 enum values, got %d", len(schema.Enum))
	}
}

func TestThreatStatus_JSONSchema(t *testing.T) {
	schema := ThreatStatus("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	// 8 values: potential, theoretical, identified, analyzing, mitigated, accepted, transferred, monitoring
	if len(schema.Enum) != 8 {
		t.Errorf("expected 8 enum values, got %d", len(schema.Enum))
	}
}

func TestMitigation_JSON(t *testing.T) {
	m := Mitigation{
		ID:               "mit-1",
		Title:            "Implement Origin Validation",
		Description:      "Validate WebSocket Origin header",
		ThreatIDs:        []string{"threat-1", "threat-2"},
		STRIDECategories: []STRIDEThreat{STRIDESpoofing, STRIDETampering},
		ControlID:        "CIS-16.4",
		Status:           MitigationStatusImplemented,
		Owner:            "security-team",
		Effectiveness:    "high",
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Mitigation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != m.ID {
		t.Errorf("expected ID %q, got %q", m.ID, decoded.ID)
	}
	if decoded.Status != MitigationStatusImplemented {
		t.Errorf("expected status %q, got %q", MitigationStatusImplemented, decoded.Status)
	}
	if len(decoded.ThreatIDs) != 2 {
		t.Errorf("expected 2 threatIds, got %d", len(decoded.ThreatIDs))
	}
	if len(decoded.STRIDECategories) != 2 {
		t.Errorf("expected 2 strideCategories, got %d", len(decoded.STRIDECategories))
	}
}

func TestThreatEntry_JSON(t *testing.T) {
	te := ThreatEntry{
		ID:               "threat-1",
		Title:            "Missing Origin Validation",
		Description:      "WebSocket server does not validate Origin header",
		STRIDECategory:   STRIDESpoofing,
		AffectedElements: []string{"ws-server", "api-gateway"},
		Status:           ThreatStatusMitigated,
		Severity:         "high",
		Likelihood:       "medium",
		MitigationIDs:    []string{"mit-1"},
	}

	data, err := json.Marshal(te)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ThreatEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != te.ID {
		t.Errorf("expected ID %q, got %q", te.ID, decoded.ID)
	}
	if decoded.Status != ThreatStatusMitigated {
		t.Errorf("expected status %q, got %q", ThreatStatusMitigated, decoded.Status)
	}
	if decoded.STRIDECategory != STRIDESpoofing {
		t.Errorf("expected strideCategory %q, got %q", STRIDESpoofing, decoded.STRIDECategory)
	}
}

func TestMitigationStatus_Values(t *testing.T) {
	tests := []struct {
		status MitigationStatus
		valid  bool
	}{
		{MitigationStatusPlanned, true},
		{MitigationStatusImplemented, true},
		{MitigationStatusPartial, true},
		{MitigationStatusAccepted, true},
		{MitigationStatusTransferred, true},
		{MitigationStatusNotApplicable, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			data, err := json.Marshal(tt.status)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded MitigationStatus
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != tt.status {
				t.Errorf("expected %q, got %q", tt.status, decoded)
			}
		})
	}
}

func TestThreatStatus_Values(t *testing.T) {
	tests := []struct {
		status ThreatStatus
		valid  bool
	}{
		{ThreatStatusPotential, true},
		{ThreatStatusTheoretical, true},
		{ThreatStatusIdentified, true},
		{ThreatStatusAnalyzing, true},
		{ThreatStatusMitigated, true},
		{ThreatStatusAccepted, true},
		{ThreatStatusTransferred, true},
		{ThreatStatusMonitoring, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			data, err := json.Marshal(tt.status)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded ThreatStatus
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != tt.status {
				t.Errorf("expected %q, got %q", tt.status, decoded)
			}
		})
	}
}
