package ir

import (
	"testing"
)

func TestCredentialFlow_IsExfiltrated(t *testing.T) {
	tests := []struct {
		name     string
		flow     CredentialFlow
		expected bool
	}{
		{
			name: "normal flow without exfiltration",
			flow: CredentialFlow{
				Stages: []CredentialFlowEvent{
					{Stage: CredentialStageCreated},
					{Stage: CredentialStageTransmitted},
				},
			},
			expected: false,
		},
		{
			name: "flow with exfiltration",
			flow: CredentialFlow{
				Stages: []CredentialFlowEvent{
					{Stage: CredentialStageCreated},
					{Stage: CredentialStageTransmitted},
					{Stage: CredentialStageExfiltrated},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flow.IsExfiltrated(); got != tt.expected {
				t.Errorf("IsExfiltrated() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCredentialFlow_IsReused(t *testing.T) {
	tests := []struct {
		name     string
		flow     CredentialFlow
		expected bool
	}{
		{
			name: "no replay attack",
			flow: CredentialFlow{
				Stages: []CredentialFlowEvent{
					{Stage: CredentialStageCreated},
					{Stage: CredentialStageExfiltrated},
				},
			},
			expected: false,
		},
		{
			name: "replay attack",
			flow: CredentialFlow{
				Stages: []CredentialFlowEvent{
					{Stage: CredentialStageCreated},
					{Stage: CredentialStageExfiltrated},
					{Stage: CredentialStageReused},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flow.IsReused(); got != tt.expected {
				t.Errorf("IsReused() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCredentialFlow_GetExfiltrationPath(t *testing.T) {
	flow := CredentialFlow{
		Stages: []CredentialFlowEvent{
			{Stage: CredentialStageCreated, ElementID: "app"},
			{Stage: CredentialStageStored, ElementID: "storage"},
			{Stage: CredentialStageTransmitted, ElementID: "gateway"},
			{Stage: CredentialStageExfiltrated, ElementID: "attacker"},
			{Stage: CredentialStageReused, ElementID: "target"},
		},
	}

	path := flow.GetExfiltrationPath()

	if path == nil {
		t.Fatal("Expected non-nil path")
	}

	// Path should include events up to and including exfiltration
	if len(path) != 4 {
		t.Errorf("Expected 4 events in path, got %d", len(path))
	}

	if path[len(path)-1].Stage != CredentialStageExfiltrated {
		t.Error("Last event in path should be exfiltration")
	}
}

func TestCredentialFlow_GetVulnerableTransmissions(t *testing.T) {
	flow := CredentialFlow{
		Stages: []CredentialFlowEvent{
			{Stage: CredentialStageTransmitted, TransportProtocol: "https", Encrypted: true},
			{Stage: CredentialStageTransmitted, TransportProtocol: "http", Encrypted: false},
			{Stage: CredentialStageTransmitted, TransportProtocol: "ws", Encrypted: false},
			{Stage: CredentialStageTransmitted, TransportMechanism: "query-param"},
		},
	}

	vulns := flow.GetVulnerableTransmissions()

	// Should detect http, ws, and query-param as vulnerable
	if len(vulns) != 3 {
		t.Errorf("Expected 3 vulnerable transmissions, got %d", len(vulns))
	}
}

func TestCredentialFlowStage_JSONSchema(t *testing.T) {
	schema := CredentialStageCreated.JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Expected type 'string', got %s", schema.Type)
	}
	if len(schema.Enum) != 7 {
		t.Errorf("Expected 7 enum values, got %d", len(schema.Enum))
	}
}

func TestCredentialType_JSONSchema(t *testing.T) {
	schema := CredentialTypeBearerToken.JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Expected type 'string', got %s", schema.Type)
	}
	if len(schema.Enum) != 10 {
		t.Errorf("Expected 10 enum values, got %d", len(schema.Enum))
	}
}
