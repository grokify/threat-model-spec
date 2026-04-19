package ir

import (
	"encoding/json"
	"testing"
)

func TestComplianceFramework_JSONSchema(t *testing.T) {
	schema := ComplianceFramework("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 10 {
		t.Errorf("expected 10 enum values, got %d", len(schema.Enum))
	}
}

func TestSOC2TrustServiceCategory_JSONSchema(t *testing.T) {
	schema := SOC2TrustServiceCategory("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 5 {
		t.Errorf("expected 5 enum values, got %d", len(schema.Enum))
	}
}

func TestComplianceMapping_JSON(t *testing.T) {
	m := ComplianceMapping{
		Framework:       ComplianceFrameworkSOC2,
		RequirementID:   "CC6.1",
		RequirementName: "Logical and Physical Access Controls",
		Category:        "Common Criteria",
		Description:     "Access controls are implemented",
		Status:          "compliant",
		Evidence:        "Access control policy document, audit logs",
		URL:             "https://www.aicpa.org/soc2",
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ComplianceMapping
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Framework != ComplianceFrameworkSOC2 {
		t.Errorf("expected framework %q, got %q", ComplianceFrameworkSOC2, decoded.Framework)
	}
	if decoded.RequirementID != "CC6.1" {
		t.Errorf("expected requirementId %q, got %q", "CC6.1", decoded.RequirementID)
	}
	if decoded.Status != "compliant" {
		t.Errorf("expected status %q, got %q", "compliant", decoded.Status)
	}
}

func TestComplianceFramework_Values(t *testing.T) {
	frameworks := []ComplianceFramework{
		ComplianceFrameworkSOC2,
		ComplianceFrameworkPCIDSS,
		ComplianceFrameworkHIPAA,
		ComplianceFrameworkGDPR,
		ComplianceFrameworkCCPA,
		ComplianceFrameworkFedRAMP,
		ComplianceFrameworkNISTSP80053,
		ComplianceFrameworkNISTSP800171,
		ComplianceFrameworkSOX,
		ComplianceFrameworkGLBA,
	}

	for _, f := range frameworks {
		t.Run(string(f), func(t *testing.T) {
			data, err := json.Marshal(f)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded ComplianceFramework
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != f {
				t.Errorf("expected %q, got %q", f, decoded)
			}
		})
	}
}

func TestSOC2TrustServiceCategory_Values(t *testing.T) {
	categories := []SOC2TrustServiceCategory{
		SOC2Security,
		SOC2Availability,
		SOC2ProcessingIntegrity,
		SOC2Confidentiality,
		SOC2Privacy,
	}

	for _, c := range categories {
		t.Run(string(c), func(t *testing.T) {
			data, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded SOC2TrustServiceCategory
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != c {
				t.Errorf("expected %q, got %q", c, decoded)
			}
		})
	}
}

func TestComplianceMapping_AllFrameworks(t *testing.T) {
	tests := []struct {
		framework ComplianceFramework
		reqID     string
	}{
		{ComplianceFrameworkSOC2, "CC6.1"},
		{ComplianceFrameworkPCIDSS, "3.5.1"},
		{ComplianceFrameworkHIPAA, "164.312(a)(1)"},
		{ComplianceFrameworkGDPR, "Article 32"},
		{ComplianceFrameworkCCPA, "1798.100"},
		{ComplianceFrameworkFedRAMP, "AC-2"},
		{ComplianceFrameworkNISTSP80053, "AC-2(1)"},
		{ComplianceFrameworkNISTSP800171, "3.1.1"},
		{ComplianceFrameworkSOX, "Section 404"},
		{ComplianceFrameworkGLBA, "Safeguards Rule"},
	}

	for _, tt := range tests {
		t.Run(string(tt.framework), func(t *testing.T) {
			m := ComplianceMapping{
				Framework:     tt.framework,
				RequirementID: tt.reqID,
			}
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded ComplianceMapping
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded.Framework != tt.framework {
				t.Errorf("expected framework %q, got %q", tt.framework, decoded.Framework)
			}
		})
	}
}
