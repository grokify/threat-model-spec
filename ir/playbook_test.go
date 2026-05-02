package ir

import (
	"encoding/json"
	"testing"
)

func TestPlaybookPhase(t *testing.T) {
	tests := []struct {
		name     string
		input    PlaybookPhase
		expected string
	}{
		{"preparation", PlaybookPhasePreparation, "preparation"},
		{"identification", PlaybookPhaseIdentification, "identification"},
		{"containment", PlaybookPhaseContainment, "containment"},
		{"eradication", PlaybookPhaseEradication, "eradication"},
		{"recovery", PlaybookPhaseRecovery, "recovery"},
		{"lessons-learned", PlaybookPhaseLessonsLearned, "lessons-learned"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.input) != tt.expected {
				t.Errorf("PlaybookPhase = %v, want %v", tt.input, tt.expected)
			}
		})
	}
}

func TestPlaybookPhaseJSONSchema(t *testing.T) {
	var p PlaybookPhase
	schema := p.JSONSchema()

	if schema.Type != "string" {
		t.Errorf("JSONSchema Type = %v, want string", schema.Type)
	}
	if len(schema.Enum) != 6 {
		t.Errorf("JSONSchema Enum length = %v, want 6", len(schema.Enum))
	}
}

func TestIncidentPlaybookJSON(t *testing.T) {
	playbook := IncidentPlaybook{
		ID:          "pb-openclaw-compromise",
		Name:        "OpenClaw API Key Compromise Response",
		Description: "Incident response playbook for OpenClaw WebSocket localhost takeover",
		ThreatType:  "credential-theft",
		Severity:    "high",
		Steps: []PlaybookStep{
			{
				Step:        1,
				Phase:       PlaybookPhaseIdentification,
				Action:      "Identify compromised systems",
				Description: "Review WebSocket connection logs for unauthorized origins",
				Owner:       "SOC",
				TimeMinutes: 15,
				Checklist: []string{
					"Check WebSocket logs for non-localhost origins",
					"Review API usage for anomalies",
				},
			},
			{
				Step:        2,
				Phase:       PlaybookPhaseContainment,
				Action:      "Rotate compromised API keys",
				Description: "Immediately rotate all API keys stored in OpenClaw",
				Owner:       "DevOps",
				TimeMinutes: 10,
				Dependencies: []int{1},
				Automated:   true,
				Commands: []string{
					"openclaw config rotate-keys --all",
					"openclaw auth revoke-devices --unknown",
				},
			},
			{
				Step:        3,
				Phase:       PlaybookPhaseContainment,
				Action:      "Block malicious origins",
				Description: "Update WebSocket origin allowlist",
				Owner:       "Security",
				TimeMinutes: 5,
				Dependencies: []int{1},
			},
			{
				Step:             4,
				Phase:            PlaybookPhaseEradication,
				Action:           "Update OpenClaw to patched version",
				Description:      "Update to v2026.2.25 or later",
				Owner:            "DevOps",
				TimeMinutes:      30,
				Dependencies:     []int{2, 3},
				EscalationTrigger: "If update fails, escalate to Security Lead",
			},
			{
				Step:        5,
				Phase:       PlaybookPhaseRecovery,
				Action:      "Verify fix and monitor",
				Description: "Confirm WebSocket origin validation is working",
				Owner:       "Security",
				TimeMinutes: 30,
				Dependencies: []int{4},
			},
		},
		Contacts: []Contact{
			{
				Name:    "Security Team",
				Role:    "Security Lead",
				Email:   "security@example.com",
				Slack:   "#security-incidents",
				Primary: true,
			},
			{
				Name:      "On-Call Engineer",
				Role:      "DevOps",
				PagerDuty: "devops-oncall",
			},
		},
		Tools: []string{
			"OpenClaw CLI",
			"Log analysis tools",
			"API key rotation scripts",
		},
		MITRETechniques: []string{"T1552", "T1110", "T1189"},
		SLAMinutes:      60,
		LastReviewed:    "2026-04-01",
		Owner:           "Security Team",
		Tags:            []string{"credential-theft", "websocket", "api-keys"},
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(playbook, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal IncidentPlaybook: %v", err)
	}

	// Unmarshal back
	var decoded IncidentPlaybook
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal IncidentPlaybook: %v", err)
	}

	// Verify fields
	if decoded.ID != "pb-openclaw-compromise" {
		t.Errorf("ID = %v, want pb-openclaw-compromise", decoded.ID)
	}
	if len(decoded.Steps) != 5 {
		t.Errorf("Steps length = %v, want 5", len(decoded.Steps))
	}
	if decoded.Steps[0].Phase != PlaybookPhaseIdentification {
		t.Errorf("Steps[0].Phase = %v, want identification", decoded.Steps[0].Phase)
	}
	if decoded.Steps[1].Phase != PlaybookPhaseContainment {
		t.Errorf("Steps[1].Phase = %v, want containment", decoded.Steps[1].Phase)
	}
	if !decoded.Steps[1].Automated {
		t.Error("Steps[1].Automated = false, want true")
	}
	if len(decoded.Steps[1].Commands) != 2 {
		t.Errorf("Steps[1].Commands length = %v, want 2", len(decoded.Steps[1].Commands))
	}
	if len(decoded.Contacts) != 2 {
		t.Errorf("Contacts length = %v, want 2", len(decoded.Contacts))
	}
	if !decoded.Contacts[0].Primary {
		t.Error("Contacts[0].Primary = false, want true")
	}
	if decoded.SLAMinutes != 60 {
		t.Errorf("SLAMinutes = %v, want 60", decoded.SLAMinutes)
	}
	if len(decoded.MITRETechniques) != 3 {
		t.Errorf("MITRETechniques length = %v, want 3", len(decoded.MITRETechniques))
	}
}

func TestPlaybookStepJSON(t *testing.T) {
	step := PlaybookStep{
		Step:              3,
		Phase:             PlaybookPhaseContainment,
		Action:            "Isolate affected system",
		Description:       "Disconnect system from network to prevent further damage",
		Owner:             "IT Operations",
		Automated:         false,
		TimeMinutes:       5,
		Dependencies:      []int{1, 2},
		EscalationTrigger: "If system cannot be isolated, escalate to Security",
		Notes:             "Document the isolation time",
		Commands:          []string{"networkctl disconnect eth0"},
		Checklist:         []string{"System offline", "Document timestamp"},
	}

	data, err := json.Marshal(step)
	if err != nil {
		t.Fatalf("Failed to marshal PlaybookStep: %v", err)
	}

	var decoded PlaybookStep
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal PlaybookStep: %v", err)
	}

	if decoded.Step != 3 {
		t.Errorf("Step = %v, want 3", decoded.Step)
	}
	if decoded.Phase != PlaybookPhaseContainment {
		t.Errorf("Phase = %v, want containment", decoded.Phase)
	}
	if len(decoded.Dependencies) != 2 {
		t.Errorf("Dependencies length = %v, want 2", len(decoded.Dependencies))
	}
	if len(decoded.Checklist) != 2 {
		t.Errorf("Checklist length = %v, want 2", len(decoded.Checklist))
	}
}

func TestContactJSON(t *testing.T) {
	contact := Contact{
		Name:         "John Smith",
		Role:         "Security Lead",
		Email:        "john.smith@example.com",
		Phone:        "+1-555-123-4567",
		Slack:        "@johnsmith",
		PagerDuty:    "security-lead",
		Availability: "24/7",
		Primary:      true,
	}

	data, err := json.Marshal(contact)
	if err != nil {
		t.Fatalf("Failed to marshal Contact: %v", err)
	}

	var decoded Contact
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Contact: %v", err)
	}

	if decoded.Name != "John Smith" {
		t.Errorf("Name = %v, want 'John Smith'", decoded.Name)
	}
	if decoded.Role != "Security Lead" {
		t.Errorf("Role = %v, want 'Security Lead'", decoded.Role)
	}
	if !decoded.Primary {
		t.Error("Primary = false, want true")
	}
	if decoded.PagerDuty != "security-lead" {
		t.Errorf("PagerDuty = %v, want 'security-lead'", decoded.PagerDuty)
	}
}

func TestPlaybookMinimal(t *testing.T) {
	// Test with minimal required fields
	playbook := IncidentPlaybook{
		ID:   "pb-minimal",
		Name: "Minimal Playbook",
	}

	data, err := json.Marshal(playbook)
	if err != nil {
		t.Fatalf("Failed to marshal minimal IncidentPlaybook: %v", err)
	}

	var decoded IncidentPlaybook
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal minimal IncidentPlaybook: %v", err)
	}

	if decoded.ID != "pb-minimal" {
		t.Errorf("ID = %v, want pb-minimal", decoded.ID)
	}
	if len(decoded.Steps) != 0 {
		t.Errorf("Steps = %v, want empty", decoded.Steps)
	}
}
