package ir

import (
	"encoding/json"
	"testing"
)

func TestOWASPCategory_Values(t *testing.T) {
	tests := []struct {
		name     string
		category OWASPCategory
		expected string
	}{
		{"api", OWASPCategoryAPI, "api"},
		{"llm", OWASPCategoryLLM, "llm"},
		{"web", OWASPCategoryWeb, "web"},
		{"agentic", OWASPCategoryAgentic, "agentic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.category) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.category)
			}
		})
	}
}

func TestOWASPCategory_JSONSchema(t *testing.T) {
	schema := OWASPCategory("").JSONSchema()

	if schema.Type != "string" {
		t.Errorf("expected type 'string', got %s", schema.Type)
	}

	expectedEnums := []any{"api", "llm", "web", "agentic"}
	if len(schema.Enum) != len(expectedEnums) {
		t.Errorf("expected %d enums, got %d", len(expectedEnums), len(schema.Enum))
	}

	for i, expected := range expectedEnums {
		if schema.Enum[i] != expected {
			t.Errorf("expected enum[%d] = %v, got %v", i, expected, schema.Enum[i])
		}
	}
}

func TestOWASPMapping_JSON(t *testing.T) {
	mapping := OWASPMapping{
		Category:    OWASPCategoryAgentic,
		ID:          "ASI02:2026",
		Name:        "Tool Misuse & Exploitation",
		Description: "Attackers exploit agent's access to tools to perform unauthorized actions.",
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	}

	data, err := json.Marshal(mapping)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded OWASPMapping
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Category != OWASPCategoryAgentic {
		t.Errorf("expected category 'agentic', got %s", decoded.Category)
	}
	if decoded.ID != "ASI02:2026" {
		t.Errorf("expected ID 'ASI02:2026', got %s", decoded.ID)
	}
}

func TestAttack_ASIIds_JSON(t *testing.T) {
	attack := Attack{
		Step:      1,
		From:      "attacker",
		To:        "gateway",
		Label:     "WebSocket connection",
		ASIIds:    []string{"ASI02:2026", "ASI03:2026"},
		OWASPIds:  []string{"API8:2023"},
	}

	data, err := json.Marshal(attack)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Attack
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(decoded.ASIIds) != 2 {
		t.Errorf("expected 2 ASI IDs, got %d", len(decoded.ASIIds))
	}
	if decoded.ASIIds[0] != "ASI02:2026" {
		t.Errorf("expected first ASI ID 'ASI02:2026', got %s", decoded.ASIIds[0])
	}
	if decoded.ASIIds[1] != "ASI03:2026" {
		t.Errorf("expected second ASI ID 'ASI03:2026', got %s", decoded.ASIIds[1])
	}
}

func TestAttack_ASIIds_Omitempty(t *testing.T) {
	// Test that ASIIds is omitted when empty
	attack := Attack{
		Step:  1,
		From:  "attacker",
		To:    "gateway",
		Label: "Test attack",
	}

	data, err := json.Marshal(attack)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Check that asiIds is not present in JSON
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, exists := raw["asiIds"]; exists {
		t.Error("asiIds should be omitted when empty")
	}
}
