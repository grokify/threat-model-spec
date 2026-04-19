package ir

import (
	"encoding/json"
	"testing"
)

func TestLINDDUNThreat_JSONSchema(t *testing.T) {
	schema := LINDDUNThreat("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 7 {
		t.Errorf("expected 7 enum values, got %d", len(schema.Enum))
	}
}

func TestGetLINDDUNName(t *testing.T) {
	tests := []struct {
		threat   LINDDUNThreat
		expected string
	}{
		{LINDDUNLinkability, "Linkability"},
		{LINDDUNIdentifiability, "Identifiability"},
		{LINDDUNNonRepudiation, "Non-repudiation"},
		{LINDDUNDetectability, "Detectability"},
		{LINDDUNDisclosure, "Disclosure of Information"},
		{LINDDUNUnawareness, "Unawareness"},
		{LINDDUNNonCompliance, "Non-compliance"},
	}

	for _, tt := range tests {
		t.Run(string(tt.threat), func(t *testing.T) {
			name := GetLINDDUNName(tt.threat)
			if name != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, name)
			}
		})
	}
}

func TestGetLINDDUNDescription(t *testing.T) {
	tests := []struct {
		threat      LINDDUNThreat
		shouldExist bool
	}{
		{LINDDUNLinkability, true},
		{LINDDUNIdentifiability, true},
		{LINDDUNNonRepudiation, true},
		{LINDDUNDetectability, true},
		{LINDDUNDisclosure, true},
		{LINDDUNUnawareness, true},
		{LINDDUNNonCompliance, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.threat), func(t *testing.T) {
			desc := GetLINDDUNDescription(tt.threat)
			if tt.shouldExist && desc == "" {
				t.Errorf("expected non-empty description for %q", tt.threat)
			}
		})
	}
}

func TestLINDDUNMapping_JSON(t *testing.T) {
	m := LINDDUNMapping{
		Category:           LINDDUNIdentifiability,
		Name:               "Identifiability",
		Description:        "User can be identified from browsing patterns",
		AffectedDataTypes:  []string{"pii", "behavioral"},
		AffectedComponents: []string{"analytics", "tracking"},
		DataSubjects:       []string{"customers", "website-visitors"},
		PrivacyPrinciple:   "data minimization",
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded LINDDUNMapping
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Category != LINDDUNIdentifiability {
		t.Errorf("expected category %q, got %q", LINDDUNIdentifiability, decoded.Category)
	}
	if len(decoded.AffectedDataTypes) != 2 {
		t.Errorf("expected 2 affected data types, got %d", len(decoded.AffectedDataTypes))
	}
	if len(decoded.DataSubjects) != 2 {
		t.Errorf("expected 2 data subjects, got %d", len(decoded.DataSubjects))
	}
}

func TestDataCategory_JSONSchema(t *testing.T) {
	schema := DataCategory("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 9 {
		t.Errorf("expected 9 enum values, got %d", len(schema.Enum))
	}
}

func TestDataCategory_Values(t *testing.T) {
	categories := []DataCategory{
		DataCategoryPII,
		DataCategoryPHI,
		DataCategoryFinancial,
		DataCategoryBiometric,
		DataCategoryLocation,
		DataCategoryBehavioral,
		DataCategoryGenetic,
		DataCategoryMinor,
		DataCategorySensitive,
	}

	for _, c := range categories {
		t.Run(string(c), func(t *testing.T) {
			data, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded DataCategory
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != c {
				t.Errorf("expected %q, got %q", c, decoded)
			}
		})
	}
}

func TestLINDDUNThreat_Values(t *testing.T) {
	threats := []LINDDUNThreat{
		LINDDUNLinkability,
		LINDDUNIdentifiability,
		LINDDUNNonRepudiation,
		LINDDUNDetectability,
		LINDDUNDisclosure,
		LINDDUNUnawareness,
		LINDDUNNonCompliance,
	}

	for _, threat := range threats {
		t.Run(string(threat), func(t *testing.T) {
			data, err := json.Marshal(threat)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded LINDDUNThreat
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != threat {
				t.Errorf("expected %q, got %q", threat, decoded)
			}
		})
	}
}
