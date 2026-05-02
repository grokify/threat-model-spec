package ir

import "testing"

func TestOWASPAPITop10_Count(t *testing.T) {
	if len(OWASPAPITop10) != 10 {
		t.Errorf("expected 10 API entries, got %d", len(OWASPAPITop10))
	}
}

func TestOWASPLLMTop10_Count(t *testing.T) {
	if len(OWASPLLMTop10) != 10 {
		t.Errorf("expected 10 LLM entries, got %d", len(OWASPLLMTop10))
	}
}

func TestOWASPWebTop10_Count(t *testing.T) {
	if len(OWASPWebTop10) != 10 {
		t.Errorf("expected 10 Web entries, got %d", len(OWASPWebTop10))
	}
}

func TestOWASPAgenticTop10_Count(t *testing.T) {
	if len(OWASPAgenticTop10) != 10 {
		t.Errorf("expected 10 Agentic entries, got %d", len(OWASPAgenticTop10))
	}
}

func TestGetOWASPEntry_API(t *testing.T) {
	tests := []struct {
		id   string
		name string
	}{
		{"API1:2023", "Broken Object Level Authorization"},
		{"API2:2023", "Broken Authentication"},
		{"API8:2023", "Security Misconfiguration"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			entry := GetOWASPEntry(tt.id)
			if entry == nil {
				t.Fatalf("expected entry for %s, got nil", tt.id)
			}
			if entry.Name != tt.name {
				t.Errorf("expected name %q, got %q", tt.name, entry.Name)
			}
			if entry.Category != OWASPCategoryAPI {
				t.Errorf("expected category %q, got %q", OWASPCategoryAPI, entry.Category)
			}
		})
	}
}

func TestGetOWASPEntry_LLM(t *testing.T) {
	tests := []struct {
		id   string
		name string
	}{
		{"LLM01:2025", "Prompt Injection"},
		{"LLM06:2025", "Excessive Agency"},
		{"LLM10:2025", "Unbounded Consumption"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			entry := GetOWASPEntry(tt.id)
			if entry == nil {
				t.Fatalf("expected entry for %s, got nil", tt.id)
			}
			if entry.Name != tt.name {
				t.Errorf("expected name %q, got %q", tt.name, entry.Name)
			}
			if entry.Category != OWASPCategoryLLM {
				t.Errorf("expected category %q, got %q", OWASPCategoryLLM, entry.Category)
			}
		})
	}
}

func TestGetOWASPEntry_Web(t *testing.T) {
	tests := []struct {
		id   string
		name string
	}{
		{"A01:2021", "Broken Access Control"},
		{"A07:2021", "Identification and Authentication Failures"},
		{"A10:2021", "Server-Side Request Forgery (SSRF)"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			entry := GetOWASPEntry(tt.id)
			if entry == nil {
				t.Fatalf("expected entry for %s, got nil", tt.id)
			}
			if entry.Name != tt.name {
				t.Errorf("expected name %q, got %q", tt.name, entry.Name)
			}
			if entry.Category != OWASPCategoryWeb {
				t.Errorf("expected category %q, got %q", OWASPCategoryWeb, entry.Category)
			}
		})
	}
}

func TestGetOWASPEntry_Agentic(t *testing.T) {
	tests := []struct {
		id   string
		name string
	}{
		{"ASI01:2026", "Agentic Prompt Injection"},
		{"ASI02:2026", "Tool Misuse & Exploitation"},
		{"ASI03:2026", "Agent Identity & Privilege Abuse"},
		{"ASI04:2026", "Agentic Supply Chain Compromise"},
		{"ASI05:2026", "Unexpected Code Execution"},
		{"ASI09:2026", "Human-Agent Trust Exploitation"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			entry := GetOWASPEntry(tt.id)
			if entry == nil {
				t.Fatalf("expected entry for %s, got nil", tt.id)
			}
			if entry.Name != tt.name {
				t.Errorf("expected name %q, got %q", tt.name, entry.Name)
			}
			if entry.Category != OWASPCategoryAgentic {
				t.Errorf("expected category %q, got %q", OWASPCategoryAgentic, entry.Category)
			}
		})
	}
}

func TestGetOWASPEntry_NotFound(t *testing.T) {
	entry := GetOWASPEntry("INVALID:2023")
	if entry != nil {
		t.Errorf("expected nil for invalid ID, got %+v", entry)
	}
}

func TestValidateOWASPID(t *testing.T) {
	validIDs := []string{
		"API1:2023", "API2:2023", "API8:2023",
		"LLM01:2025", "LLM06:2025",
		"A01:2021", "A07:2021",
		"ASI02:2026", "ASI03:2026", "ASI09:2026",
	}

	for _, id := range validIDs {
		t.Run(id, func(t *testing.T) {
			if !ValidateOWASPID(id) {
				t.Errorf("expected %s to be valid", id)
			}
		})
	}

	invalidIDs := []string{
		"INVALID:2023",
		"API99:2023",
		"LLM99:2025",
		"A99:2021",
		"ASI99:2026",
		"",
	}

	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			if ValidateOWASPID(id) {
				t.Errorf("expected %s to be invalid", id)
			}
		})
	}
}

func TestGetOWASPCategory(t *testing.T) {
	tests := []struct {
		id       string
		expected OWASPCategory
	}{
		{"API1:2023", OWASPCategoryAPI},
		{"LLM01:2025", OWASPCategoryLLM},
		{"A01:2021", OWASPCategoryWeb},
		{"ASI02:2026", OWASPCategoryAgentic},
		{"INVALID:2023", ""},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			category := GetOWASPCategory(tt.id)
			if category != tt.expected {
				t.Errorf("expected category %q, got %q", tt.expected, category)
			}
		})
	}
}

func TestGetAllOWASPEntries(t *testing.T) {
	tests := []struct {
		category OWASPCategory
		expected int
	}{
		{OWASPCategoryAPI, 10},
		{OWASPCategoryLLM, 10},
		{OWASPCategoryWeb, 10},
		{OWASPCategoryAgentic, 10},
		{"invalid", 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			entries := GetAllOWASPEntries(tt.category)
			if len(entries) != tt.expected {
				t.Errorf("expected %d entries, got %d", tt.expected, len(entries))
			}
		})
	}
}

func TestOWASPEntry_URLsNotEmpty(t *testing.T) {
	// Verify all entries have URLs
	allMaps := []map[string]OWASPEntry{
		OWASPAPITop10,
		OWASPLLMTop10,
		OWASPWebTop10,
		OWASPAgenticTop10,
	}

	for _, m := range allMaps {
		for id, entry := range m {
			if entry.URL == "" {
				t.Errorf("entry %s has empty URL", id)
			}
			if entry.Name == "" {
				t.Errorf("entry %s has empty Name", id)
			}
			if entry.Description == "" {
				t.Errorf("entry %s has empty Description", id)
			}
		}
	}
}
