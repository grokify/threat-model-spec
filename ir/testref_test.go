package ir

import (
	"encoding/json"
	"testing"
)

func TestTestPurpose(t *testing.T) {
	tests := []struct {
		name     string
		input    TestPurpose
		expected string
	}{
		{"exploitation", TestPurposeExploitation, "exploitation"},
		{"detection", TestPurposeDetection, "detection"},
		{"remediation", TestPurposeRemediation, "remediation"},
		{"regression", TestPurposeRegression, "regression"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.input) != tt.expected {
				t.Errorf("TestPurpose = %v, want %v", tt.input, tt.expected)
			}
		})
	}
}

func TestTestPurposeJSONSchema(t *testing.T) {
	var p TestPurpose
	schema := p.JSONSchema()

	if schema.Type != "string" {
		t.Errorf("JSONSchema Type = %v, want string", schema.Type)
	}
	if len(schema.Enum) != 4 {
		t.Errorf("JSONSchema Enum length = %v, want 4", len(schema.Enum))
	}

	expected := []any{"exploitation", "detection", "remediation", "regression"}
	for i, v := range expected {
		if schema.Enum[i] != v {
			t.Errorf("JSONSchema Enum[%d] = %v, want %v", i, schema.Enum[i], v)
		}
	}
}

func TestTestReferenceJSON(t *testing.T) {
	ref := TestReference{
		TestID:      "openclaw-websocket-exploit-001",
		TestFile:    "tests/security/openclaw-websocket.yaml",
		Purpose:     TestPurposeExploitation,
		Description: "Validates WebSocket localhost takeover vulnerability",
		SuiteID:     "openclaw-security",
		AttackStep:  3,
		Automated:   true,
		Tool:        "agent-dast",
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal TestReference: %v", err)
	}

	// Unmarshal back
	var decoded TestReference
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal TestReference: %v", err)
	}

	// Verify fields
	if decoded.TestID != "openclaw-websocket-exploit-001" {
		t.Errorf("TestID = %v, want openclaw-websocket-exploit-001", decoded.TestID)
	}
	if decoded.TestFile != "tests/security/openclaw-websocket.yaml" {
		t.Errorf("TestFile = %v, want tests/security/openclaw-websocket.yaml", decoded.TestFile)
	}
	if decoded.Purpose != TestPurposeExploitation {
		t.Errorf("Purpose = %v, want exploitation", decoded.Purpose)
	}
	if decoded.AttackStep != 3 {
		t.Errorf("AttackStep = %v, want 3", decoded.AttackStep)
	}
	if !decoded.Automated {
		t.Error("Automated = false, want true")
	}
	if decoded.Tool != "agent-dast" {
		t.Errorf("Tool = %v, want agent-dast", decoded.Tool)
	}
}

func TestTestSuiteReferenceJSON(t *testing.T) {
	suite := TestSuiteReference{
		SuiteID:     "openclaw-security-suite",
		SuiteFile:   "tests/security/openclaw-suite.yaml",
		Description: "Security test suite for OpenClaw vulnerabilities",
		Tests: []TestReference{
			{
				TestID:  "exploit-001",
				Purpose: TestPurposeExploitation,
			},
			{
				TestID:  "detect-001",
				Purpose: TestPurposeDetection,
			},
			{
				TestID:  "fix-001",
				Purpose: TestPurposeRemediation,
			},
		},
		Tags:      []string{"security", "websocket", "critical"},
		CIEnabled: true,
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal TestSuiteReference: %v", err)
	}

	// Unmarshal back
	var decoded TestSuiteReference
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal TestSuiteReference: %v", err)
	}

	// Verify fields
	if decoded.SuiteID != "openclaw-security-suite" {
		t.Errorf("SuiteID = %v, want openclaw-security-suite", decoded.SuiteID)
	}
	if len(decoded.Tests) != 3 {
		t.Errorf("Tests length = %v, want 3", len(decoded.Tests))
	}
	if decoded.Tests[0].Purpose != TestPurposeExploitation {
		t.Errorf("Tests[0].Purpose = %v, want exploitation", decoded.Tests[0].Purpose)
	}
	if decoded.Tests[1].Purpose != TestPurposeDetection {
		t.Errorf("Tests[1].Purpose = %v, want detection", decoded.Tests[1].Purpose)
	}
	if decoded.Tests[2].Purpose != TestPurposeRemediation {
		t.Errorf("Tests[2].Purpose = %v, want remediation", decoded.Tests[2].Purpose)
	}
	if len(decoded.Tags) != 3 {
		t.Errorf("Tags length = %v, want 3", len(decoded.Tags))
	}
	if !decoded.CIEnabled {
		t.Error("CIEnabled = false, want true")
	}
}

func TestTestReferenceMinimal(t *testing.T) {
	// Test with minimal required fields
	ref := TestReference{
		TestID:  "test-001",
		Purpose: TestPurposeRegression,
	}

	data, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("Failed to marshal minimal TestReference: %v", err)
	}

	var decoded TestReference
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal minimal TestReference: %v", err)
	}

	if decoded.TestID != "test-001" {
		t.Errorf("TestID = %v, want test-001", decoded.TestID)
	}
	if decoded.TestFile != "" {
		t.Errorf("TestFile = %v, want empty string", decoded.TestFile)
	}
	if decoded.AttackStep != 0 {
		t.Errorf("AttackStep = %v, want 0", decoded.AttackStep)
	}
}
