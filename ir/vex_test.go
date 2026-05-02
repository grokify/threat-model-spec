package ir

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVEXStatementJSONRoundTrip(t *testing.T) {
	stmt := VEXStatement{
		ID:              "vex-stmt-1",
		VulnerabilityID: "CVE-2024-12345",
		Status:          VEXStatusNotAffected,
		Justification:   VEXJustificationVulnerableCodeNotPresent,
		ImpactStatement: "The vulnerable code path is not included in our build",
		Products:        []string{"pkg:npm/my-app@1.0.0"},
		Supplier:        "Example Corp",
		Timestamp:       time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	data, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal VEXStatement: %v", err)
	}

	var decoded VEXStatement
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal VEXStatement: %v", err)
	}

	if decoded.VulnerabilityID != "CVE-2024-12345" {
		t.Errorf("VulnerabilityID = %s, want CVE-2024-12345", decoded.VulnerabilityID)
	}
	if decoded.Status != VEXStatusNotAffected {
		t.Errorf("Status = %s, want not_affected", decoded.Status)
	}
	if decoded.Justification != VEXJustificationVulnerableCodeNotPresent {
		t.Errorf("Justification = %s, want vulnerable_code_not_present", decoded.Justification)
	}
	if len(decoded.Products) != 1 {
		t.Fatalf("Products length = %d, want 1", len(decoded.Products))
	}
}

func TestVEXDocumentJSONRoundTrip(t *testing.T) {
	doc := &VEXDocument{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        "https://example.com/vex/2024-001",
		Author:    "security@example.com",
		Role:      "vendor",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Version:   "1",
		Tooling:   "threat-model-spec/v0.6.0",
		Statements: []VEXStatement{
			{
				VulnerabilityID: "CVE-2024-12345",
				Status:          VEXStatusNotAffected,
				Justification:   VEXJustificationComponentNotPresent,
				Products:        []string{"pkg:golang/example.com/app@v1.0.0"},
			},
			{
				VulnerabilityID: "CVE-2024-67890",
				Status:          VEXStatusFixed,
				Products:        []string{"pkg:golang/example.com/app@v1.1.0"},
				ImpactStatement: "Fixed in version 1.1.0",
			},
		},
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal VEXDocument: %v", err)
	}

	var decoded VEXDocument
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal VEXDocument: %v", err)
	}

	if decoded.Context != "https://openvex.dev/ns/v0.2.0" {
		t.Errorf("Context = %s, want https://openvex.dev/ns/v0.2.0", decoded.Context)
	}
	if decoded.Author != "security@example.com" {
		t.Errorf("Author = %s, want security@example.com", decoded.Author)
	}
	if len(decoded.Statements) != 2 {
		t.Fatalf("Statements length = %d, want 2", len(decoded.Statements))
	}
}

func TestNewVEXDocument(t *testing.T) {
	doc := NewVEXDocument("security@example.com")

	if doc.Context != "https://openvex.dev/ns/v0.2.0" {
		t.Errorf("Context = %s, want https://openvex.dev/ns/v0.2.0", doc.Context)
	}
	if doc.Author != "security@example.com" {
		t.Errorf("Author = %s, want security@example.com", doc.Author)
	}
	if doc.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if doc.Version != "1" {
		t.Errorf("Version = %s, want 1", doc.Version)
	}
}

func TestVEXDocumentAddStatement(t *testing.T) {
	doc := NewVEXDocument("test@example.com")

	stmt := VEXStatement{
		VulnerabilityID: "CVE-2024-11111",
		Status:          VEXStatusAffected,
		Products:        []string{"pkg:npm/test@1.0.0"},
	}

	doc.AddStatement(stmt)

	if len(doc.Statements) != 1 {
		t.Fatalf("Statements length = %d, want 1", len(doc.Statements))
	}
	if doc.Statements[0].Timestamp.IsZero() {
		t.Error("Statement timestamp should be set automatically")
	}
}

func TestNewNotAffectedStatement(t *testing.T) {
	stmt := NewNotAffectedStatement(
		"CVE-2024-12345",
		VEXJustificationInlineMitigationsAlreadyExist,
		[]string{"pkg:npm/app@1.0.0"},
		"WAF rules prevent exploitation",
	)

	if stmt.Status != VEXStatusNotAffected {
		t.Errorf("Status = %s, want not_affected", stmt.Status)
	}
	if stmt.Justification != VEXJustificationInlineMitigationsAlreadyExist {
		t.Errorf("Justification = %s, want inline_mitigations_already_exist", stmt.Justification)
	}
	if stmt.ImpactStatement != "WAF rules prevent exploitation" {
		t.Errorf("ImpactStatement = %s, want WAF rules prevent exploitation", stmt.ImpactStatement)
	}
}

func TestNewAffectedStatement(t *testing.T) {
	stmt := NewAffectedStatement(
		"CVE-2024-12345",
		[]string{"pkg:npm/app@1.0.0"},
		"Upgrade to version 1.1.0",
	)

	if stmt.Status != VEXStatusAffected {
		t.Errorf("Status = %s, want affected", stmt.Status)
	}
	if stmt.ActionStatement != "Upgrade to version 1.1.0" {
		t.Errorf("ActionStatement = %s, want Upgrade to version 1.1.0", stmt.ActionStatement)
	}
}

func TestNewFixedStatement(t *testing.T) {
	stmt := NewFixedStatement(
		"CVE-2024-12345",
		[]string{"pkg:npm/app@1.1.0"},
		"Patched in version 1.1.0",
	)

	if stmt.Status != VEXStatusFixed {
		t.Errorf("Status = %s, want fixed", stmt.Status)
	}
}

func TestNewUnderInvestigationStatement(t *testing.T) {
	stmt := NewUnderInvestigationStatement(
		"CVE-2024-12345",
		[]string{"pkg:npm/app@1.0.0"},
	)

	if stmt.Status != VEXStatusUnderInvestigation {
		t.Errorf("Status = %s, want under_investigation", stmt.Status)
	}
}

func TestVEXStatementIsValid(t *testing.T) {
	tests := []struct {
		name  string
		stmt  VEXStatement
		valid bool
	}{
		{
			name: "valid not_affected with justification",
			stmt: VEXStatement{
				VulnerabilityID: "CVE-2024-12345",
				Status:          VEXStatusNotAffected,
				Justification:   VEXJustificationComponentNotPresent,
			},
			valid: true,
		},
		{
			name: "invalid not_affected without justification",
			stmt: VEXStatement{
				VulnerabilityID: "CVE-2024-12345",
				Status:          VEXStatusNotAffected,
			},
			valid: false,
		},
		{
			name: "valid affected without justification",
			stmt: VEXStatement{
				VulnerabilityID: "CVE-2024-12345",
				Status:          VEXStatusAffected,
			},
			valid: true,
		},
		{
			name: "valid fixed",
			stmt: VEXStatement{
				VulnerabilityID: "CVE-2024-12345",
				Status:          VEXStatusFixed,
			},
			valid: true,
		},
		{
			name: "invalid - missing vulnerability ID",
			stmt: VEXStatement{
				Status: VEXStatusAffected,
			},
			valid: false,
		},
		{
			name: "invalid - missing status",
			stmt: VEXStatement{
				VulnerabilityID: "CVE-2024-12345",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stmt.IsValid()
			if got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestVEXStatusConstants(t *testing.T) {
	// Verify status constants match OpenVEX specification
	if VEXStatusNotAffected != "not_affected" {
		t.Errorf("VEXStatusNotAffected = %s, want not_affected", VEXStatusNotAffected)
	}
	if VEXStatusAffected != "affected" {
		t.Errorf("VEXStatusAffected = %s, want affected", VEXStatusAffected)
	}
	if VEXStatusFixed != "fixed" {
		t.Errorf("VEXStatusFixed = %s, want fixed", VEXStatusFixed)
	}
	if VEXStatusUnderInvestigation != "under_investigation" {
		t.Errorf("VEXStatusUnderInvestigation = %s, want under_investigation", VEXStatusUnderInvestigation)
	}
}

func TestVEXJustificationConstants(t *testing.T) {
	// Verify justification constants match OpenVEX specification
	justifications := map[VEXJustification]string{
		VEXJustificationComponentNotPresent:                       "component_not_present",
		VEXJustificationVulnerableCodeNotPresent:                  "vulnerable_code_not_present",
		VEXJustificationVulnerableCodeNotInExecutePath:            "vulnerable_code_not_in_execute_path",
		VEXJustificationVulnerableCodeCannotBeControlledByAdversary: "vulnerable_code_cannot_be_controlled_by_adversary",
		VEXJustificationInlineMitigationsAlreadyExist:             "inline_mitigations_already_exist",
	}

	for constant, expected := range justifications {
		if string(constant) != expected {
			t.Errorf("Justification constant = %s, want %s", constant, expected)
		}
	}
}
