package ir

import (
	"encoding/json"
	"testing"
)

func TestNISTCSFFunction_JSONSchema(t *testing.T) {
	schema := NISTCSFFunction("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 5 {
		t.Errorf("expected 5 enum values, got %d", len(schema.Enum))
	}
}

func TestNISTCSFMapping_JSON(t *testing.T) {
	m := NISTCSFMapping{
		Function:        NISTCSFProtect,
		Category:        "PR.AC",
		CategoryName:    "Identity Management, Authentication and Access Control",
		Subcategory:     "PR.AC-1",
		SubcategoryName: "Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes",
		Description:     "Implement multi-factor authentication",
		URL:             "https://www.nist.gov/cyberframework",
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded NISTCSFMapping
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Function != NISTCSFProtect {
		t.Errorf("expected function %q, got %q", NISTCSFProtect, decoded.Function)
	}
	if decoded.Category != "PR.AC" {
		t.Errorf("expected category %q, got %q", "PR.AC", decoded.Category)
	}
}

func TestCISControlMapping_JSON(t *testing.T) {
	m := CISControlMapping{
		ControlID:           "16",
		ControlName:         "Application Software Security",
		SafeguardID:         "16.4",
		SafeguardName:       "Establish and Manage an Inventory of Third-party Software Components",
		ImplementationGroup: "IG2",
		AssetType:           "Software",
		SecurityFunction:    "Identify",
		Description:         "Track third-party components",
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded CISControlMapping
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ControlID != "16" {
		t.Errorf("expected controlId %q, got %q", "16", decoded.ControlID)
	}
	if decoded.ImplementationGroup != "IG2" {
		t.Errorf("expected implementationGroup %q, got %q", "IG2", decoded.ImplementationGroup)
	}
}

func TestISO27001Mapping_JSON(t *testing.T) {
	m := ISO27001Mapping{
		ControlID:   "A.9.2.3",
		ControlName: "Management of privileged access rights",
		Domain:      "A.9 Access control",
		Objective:   "To ensure authorized user access and to prevent unauthorized access to systems and services",
		Description: "Restrict privileged access",
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ISO27001Mapping
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ControlID != "A.9.2.3" {
		t.Errorf("expected controlId %q, got %q", "A.9.2.3", decoded.ControlID)
	}
}

func TestControls_JSON(t *testing.T) {
	c := Controls{
		NISTCSF: []NISTCSFMapping{
			{Function: NISTCSFIdentify, Category: "ID.AM"},
			{Function: NISTCSFProtect, Category: "PR.AC"},
		},
		CIS: []CISControlMapping{
			{ControlID: "1", ControlName: "Inventory and Control of Enterprise Assets"},
		},
		ISO27001: []ISO27001Mapping{
			{ControlID: "A.5.1", ControlName: "Information security policies"},
		},
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Controls
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(decoded.NISTCSF) != 2 {
		t.Errorf("expected 2 NIST CSF mappings, got %d", len(decoded.NISTCSF))
	}
	if len(decoded.CIS) != 1 {
		t.Errorf("expected 1 CIS mapping, got %d", len(decoded.CIS))
	}
	if len(decoded.ISO27001) != 1 {
		t.Errorf("expected 1 ISO 27001 mapping, got %d", len(decoded.ISO27001))
	}
}

func TestNISTCSFFunction_Values(t *testing.T) {
	functions := []NISTCSFFunction{
		NISTCSFIdentify,
		NISTCSFProtect,
		NISTCSFDetect,
		NISTCSFRespond,
		NISTCSFRecover,
	}

	for _, f := range functions {
		t.Run(string(f), func(t *testing.T) {
			data, err := json.Marshal(f)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded NISTCSFFunction
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != f {
				t.Errorf("expected %q, got %q", f, decoded)
			}
		})
	}
}
