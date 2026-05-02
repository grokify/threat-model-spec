package ir

import (
	"strings"
	"testing"
)

func TestDiagramIRValidateOWASPMappings(t *testing.T) {
	tests := []struct {
		name         string
		diagram      DiagramIR
		wantWarnings int
		wantContains []string
	}{
		{
			name: "valid OWASP mappings",
			diagram: DiagramIR{
				Type: DiagramTypeAttack,
				Mappings: &Mappings{
					OWASP: []OWASPMapping{
						{ID: "API2:2023", Category: OWASPCategoryAPI},
						{ID: "LLM06:2025", Category: OWASPCategoryLLM},
						{ID: "A01:2021", Category: OWASPCategoryWeb},
						{ID: "ASI02:2026", Category: OWASPCategoryAgentic},
					},
				},
			},
			wantWarnings: 0,
		},
		{
			name: "invalid OWASP ID in mappings",
			diagram: DiagramIR{
				Type: DiagramTypeAttack,
				Mappings: &Mappings{
					OWASP: []OWASPMapping{
						{ID: "INVALID:2023", Category: OWASPCategoryAPI},
					},
				},
			},
			wantWarnings: 1,
			wantContains: []string{"INVALID:2023"},
		},
		{
			name: "invalid OWASP ID in attack step",
			diagram: DiagramIR{
				Type: DiagramTypeAttack,
				Attacks: []Attack{
					{
						Step:     1,
						Label:    "Test Attack",
						OWASPIds: []string{"API2:2023", "BADID:2025"},
					},
				},
			},
			wantWarnings: 1,
			wantContains: []string{"BADID:2025", "attacks[step=1]"},
		},
		{
			name: "multiple invalid IDs",
			diagram: DiagramIR{
				Type: DiagramTypeAttack,
				Mappings: &Mappings{
					OWASP: []OWASPMapping{
						{ID: "FAKE1:2023"},
					},
				},
				Attacks: []Attack{
					{Step: 1, Label: "Attack 1", OWASPIds: []string{"FAKE2:2023"}},
					{Step: 2, Label: "Attack 2", OWASPIds: []string{"FAKE3:2023", "API2:2023"}},
				},
			},
			wantWarnings: 3,
			wantContains: []string{"FAKE1", "FAKE2", "FAKE3"},
		},
		{
			name: "valid ASI IDs",
			diagram: DiagramIR{
				Type: DiagramTypeAttack,
				Attacks: []Attack{
					{
						Step:   1,
						Label:  "Test Attack",
						ASIIds: []string{"ASI02:2026", "ASI03:2026", "ASI09:2026"},
					},
				},
			},
			wantWarnings: 0,
		},
		{
			name: "invalid ASI ID in attack step",
			diagram: DiagramIR{
				Type: DiagramTypeAttack,
				Attacks: []Attack{
					{
						Step:   1,
						Label:  "Test Attack",
						ASIIds: []string{"ASI99:2026"},
					},
				},
			},
			wantWarnings: 1,
			wantContains: []string{"ASI99:2026"},
		},
		{
			name:         "nil mappings - no warnings",
			diagram:      DiagramIR{Type: DiagramTypeDFD},
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := tt.diagram.ValidateOWASPMappings()

			if len(warnings) != tt.wantWarnings {
				t.Errorf("ValidateOWASPMappings() returned %d warnings, want %d", len(warnings), tt.wantWarnings)
				for _, w := range warnings {
					t.Logf("  warning: %s", w)
				}
			}

			for _, want := range tt.wantContains {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected warning containing %q, but not found in %v", want, warnings)
				}
			}
		})
	}
}

func TestThreatModelValidateOWASPMappings(t *testing.T) {
	tests := []struct {
		name         string
		tm           ThreatModel
		wantWarnings int
		wantContains []string
	}{
		{
			name: "valid OWASP mappings at all levels",
			tm: ThreatModel{
				ID:    "test",
				Title: "Test",
				Mappings: &Mappings{
					OWASP: []OWASPMapping{
						{ID: "API2:2023", Category: OWASPCategoryAPI},
					},
				},
				Diagrams: []DiagramView{
					{
						Type: DiagramTypeAttack,
						Attacks: []Attack{
							{Step: 1, Label: "Attack", OWASPIds: []string{"LLM06:2025"}},
						},
					},
				},
			},
			wantWarnings: 0,
		},
		{
			name: "invalid OWASP ID at threat model level",
			tm: ThreatModel{
				ID:    "test",
				Title: "Test",
				Mappings: &Mappings{
					OWASP: []OWASPMapping{
						{ID: "INVALID:2023"},
					},
				},
				Diagrams: []DiagramView{
					{Type: DiagramTypeDFD},
				},
			},
			// Expect 2 warnings: one from ThreatModel level, one from inherited mappings in diagram
			wantWarnings: 2,
			wantContains: []string{"INVALID:2023"},
		},
		{
			name: "invalid OWASP ID in diagram",
			tm: ThreatModel{
				ID:    "test",
				Title: "Test",
				Diagrams: []DiagramView{
					{
						Type: DiagramTypeAttack,
						Attacks: []Attack{
							{Step: 1, Label: "Attack", OWASPIds: []string{"BADID:2023"}},
						},
					},
				},
			},
			wantWarnings: 1,
			wantContains: []string{"BADID:2023", "diagrams[0]"},
		},
		{
			name: "errors in multiple diagrams",
			tm: ThreatModel{
				ID:    "test",
				Title: "Test",
				Diagrams: []DiagramView{
					{
						Type: DiagramTypeAttack,
						Attacks: []Attack{
							{Step: 1, Label: "Attack 1", OWASPIds: []string{"BAD1:2023"}},
						},
					},
					{
						Type: DiagramTypeAttack,
						Attacks: []Attack{
							{Step: 1, Label: "Attack 2", OWASPIds: []string{"BAD2:2023"}},
						},
					},
				},
			},
			wantWarnings: 2,
			wantContains: []string{"diagrams[0]", "diagrams[1]"},
		},
		{
			name: "no mappings - no warnings",
			tm: ThreatModel{
				ID:    "test",
				Title: "Test",
				Diagrams: []DiagramView{
					{Type: DiagramTypeDFD},
				},
			},
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := tt.tm.ValidateOWASPMappings()

			if len(warnings) != tt.wantWarnings {
				t.Errorf("ValidateOWASPMappings() returned %d warnings, want %d", len(warnings), tt.wantWarnings)
				for _, w := range warnings {
					t.Logf("  warning: %s", w)
				}
			}

			for _, want := range tt.wantContains {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected warning containing %q, but not found in %v", want, warnings)
				}
			}
		})
	}
}

func TestValidateOWASPMappingsAllCategories(t *testing.T) {
	// Test that all OWASP categories are properly validated
	validIDs := []string{
		// API Security Top 10
		"API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023",
		"API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023",
		// LLM Top 10
		"LLM01:2025", "LLM02:2025", "LLM03:2025", "LLM04:2025", "LLM05:2025",
		"LLM06:2025", "LLM07:2025", "LLM08:2025", "LLM09:2025", "LLM10:2025",
		// Web Top 10
		"A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
		"A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021",
		// Agentic (ASI) Top 10
		"ASI01:2026", "ASI02:2026", "ASI03:2026", "ASI04:2026", "ASI05:2026",
		"ASI06:2026", "ASI07:2026", "ASI08:2026", "ASI09:2026", "ASI10:2026",
	}

	for _, id := range validIDs {
		if !ValidateOWASPID(id) {
			t.Errorf("ValidateOWASPID(%q) = false, want true", id)
		}
	}

	// Test a diagram with all valid IDs
	var owaspMappings []OWASPMapping
	for _, id := range validIDs {
		owaspMappings = append(owaspMappings, OWASPMapping{ID: id})
	}

	diagram := DiagramIR{
		Type: DiagramTypeDFD,
		Mappings: &Mappings{
			OWASP: owaspMappings,
		},
	}

	warnings := diagram.ValidateOWASPMappings()
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings for valid OWASP IDs, got %d", len(warnings))
		for _, w := range warnings {
			t.Logf("  warning: %s", w)
		}
	}
}
