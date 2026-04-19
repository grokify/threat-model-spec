package ir

import (
	"encoding/json"
	"testing"
)

func TestThreatActorType_JSONSchema(t *testing.T) {
	schema := ThreatActorType("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 8 {
		t.Errorf("expected 8 enum values, got %d", len(schema.Enum))
	}
}

func TestSophistication_JSONSchema(t *testing.T) {
	schema := Sophistication("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 5 {
		t.Errorf("expected 5 enum values, got %d", len(schema.Enum))
	}
}

func TestMotivation_JSONSchema(t *testing.T) {
	schema := Motivation("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 9 {
		t.Errorf("expected 9 enum values, got %d", len(schema.Enum))
	}
}

func TestResourceLevel_JSONSchema(t *testing.T) {
	schema := ResourceLevel("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 5 {
		t.Errorf("expected 5 enum values, got %d", len(schema.Enum))
	}
}

func TestThreatActor_JSON(t *testing.T) {
	ta := ThreatActor{
		ID:                 "apt-29",
		Name:               "APT29",
		Type:               ThreatActorTypeNationState,
		Aliases:            []string{"Cozy Bear", "The Dukes"},
		Description:        "Russian state-sponsored threat group",
		Sophistication:     SophisticationAdvanced,
		Motivations:        []Motivation{MotivationEspionage, MotivationDisruption},
		Resources:          ResourceLevelExtensive,
		PrimaryGoals:       []string{"Intelligence collection", "Long-term access"},
		TTPs:               []string{"T1566", "T1059", "T1078"},
		TargetedIndustries: []string{"Government", "Defense", "Technology"},
		TargetedRegions:    []string{"North America", "Europe"},
		KnownCampaigns:     []string{"SolarWinds", "CozyDuke"},
		References:         []string{"https://attack.mitre.org/groups/G0016/"},
	}

	data, err := json.Marshal(ta)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ThreatActor
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != ta.ID {
		t.Errorf("expected ID %q, got %q", ta.ID, decoded.ID)
	}
	if decoded.Type != ThreatActorTypeNationState {
		t.Errorf("expected type %q, got %q", ThreatActorTypeNationState, decoded.Type)
	}
	if decoded.Sophistication != SophisticationAdvanced {
		t.Errorf("expected sophistication %q, got %q", SophisticationAdvanced, decoded.Sophistication)
	}
	if len(decoded.Aliases) != 2 {
		t.Errorf("expected 2 aliases, got %d", len(decoded.Aliases))
	}
	if len(decoded.Motivations) != 2 {
		t.Errorf("expected 2 motivations, got %d", len(decoded.Motivations))
	}
	if len(decoded.TTPs) != 3 {
		t.Errorf("expected 3 TTPs, got %d", len(decoded.TTPs))
	}
}

func TestThreatActorType_Values(t *testing.T) {
	types := []ThreatActorType{
		ThreatActorTypeNationState,
		ThreatActorTypeCriminal,
		ThreatActorTypeHacktivist,
		ThreatActorTypeInsider,
		ThreatActorTypeCompetitor,
		ThreatActorTypeTerrorist,
		ThreatActorTypeScriptKiddie,
		ThreatActorTypeResearcher,
	}

	for _, typ := range types {
		t.Run(string(typ), func(t *testing.T) {
			data, err := json.Marshal(typ)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded ThreatActorType
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != typ {
				t.Errorf("expected %q, got %q", typ, decoded)
			}
		})
	}
}

func TestSophistication_Values(t *testing.T) {
	levels := []Sophistication{
		SophisticationNone,
		SophisticationLow,
		SophisticationMedium,
		SophisticationHigh,
		SophisticationAdvanced,
	}

	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			data, err := json.Marshal(level)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded Sophistication
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != level {
				t.Errorf("expected %q, got %q", level, decoded)
			}
		})
	}
}

func TestMotivation_Values(t *testing.T) {
	motivations := []Motivation{
		MotivationFinancial,
		MotivationEspionage,
		MotivationDisruption,
		MotivationDestruction,
		MotivationIdeological,
		MotivationRevenge,
		MotivationNotoriety,
		MotivationCuriosity,
		MotivationCompetitive,
	}

	for _, m := range motivations {
		t.Run(string(m), func(t *testing.T) {
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded Motivation
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != m {
				t.Errorf("expected %q, got %q", m, decoded)
			}
		})
	}
}

func TestResourceLevel_Values(t *testing.T) {
	levels := []ResourceLevel{
		ResourceLevelMinimal,
		ResourceLevelLimited,
		ResourceLevelModerate,
		ResourceLevelExtensive,
		ResourceLevelUnlimited,
	}

	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			data, err := json.Marshal(level)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded ResourceLevel
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != level {
				t.Errorf("expected %q, got %q", level, decoded)
			}
		})
	}
}
