package ir

import (
	"encoding/json"
	"testing"
)

func TestExploitDifficulty(t *testing.T) {
	tests := []struct {
		name     string
		input    ExploitDifficulty
		expected string
	}{
		{"trivial", ExploitDifficultyTrivial, "trivial"},
		{"low", ExploitDifficultyLow, "low"},
		{"medium", ExploitDifficultyMedium, "medium"},
		{"high", ExploitDifficultyHigh, "high"},
		{"expert", ExploitDifficultyExpert, "expert"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.input) != tt.expected {
				t.Errorf("ExploitDifficulty = %v, want %v", tt.input, tt.expected)
			}
		})
	}
}

func TestExploitDifficultyJSONSchema(t *testing.T) {
	var d ExploitDifficulty
	schema := d.JSONSchema()

	if schema.Type != "string" {
		t.Errorf("JSONSchema Type = %v, want string", schema.Type)
	}
	if len(schema.Enum) != 5 {
		t.Errorf("JSONSchema Enum length = %v, want 5", len(schema.Enum))
	}

	expected := []any{"trivial", "low", "medium", "high", "expert"}
	for i, v := range expected {
		if schema.Enum[i] != v {
			t.Errorf("JSONSchema Enum[%d] = %v, want %v", i, schema.Enum[i], v)
		}
	}
}

func TestExploitationGuidanceJSON(t *testing.T) {
	guidance := ExploitationGuidance{
		Prerequisites: []string{
			"Target must have WebSocket gateway enabled",
			"Target must be running vulnerable version",
		},
		ExploitationSteps: []ExploitationStep{
			{
				Step:           1,
				Action:         "Connect to WebSocket gateway",
				Description:    "Open WebSocket connection to localhost:9999",
				ExpectedResult: "Connection accepted",
			},
			{
				Step:           2,
				Action:         "Brute-force authentication",
				Description:    "Try common passwords without rate limiting",
				Tool:           "custom-script",
				MITRETechnique: "T1110",
			},
		},
		Tools: []OffensiveTool{
			{
				Name:     "Burp Suite",
				Purpose:  "WebSocket interception and modification",
				URL:      "https://portswigger.net/burp",
				Category: "proxy",
			},
		},
		PayloadPatterns: []PayloadPattern{
			{
				Type:        "websocket",
				Pattern:     `{"cmd":"auth","password":"{PAYLOAD}"}`,
				Description: "WebSocket authentication payload",
				Variants:    []string{`{"cmd":"authenticate","pass":"{PAYLOAD}"}`},
			},
		},
		SuccessIndicators: []string{
			"Receive auth_success response",
			"Can request API keys",
		},
		Difficulty:    ExploitDifficultyLow,
		TimeToExploit: "< 1 minute",
		SkillLevel:    "beginner",
		Notes:         "No rate limiting makes brute-force trivial",
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(guidance, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal ExploitationGuidance: %v", err)
	}

	// Unmarshal back
	var decoded ExploitationGuidance
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ExploitationGuidance: %v", err)
	}

	// Verify fields
	if len(decoded.Prerequisites) != 2 {
		t.Errorf("Prerequisites length = %v, want 2", len(decoded.Prerequisites))
	}
	if len(decoded.ExploitationSteps) != 2 {
		t.Errorf("ExploitationSteps length = %v, want 2", len(decoded.ExploitationSteps))
	}
	if decoded.ExploitationSteps[1].MITRETechnique != "T1110" {
		t.Errorf("MITRETechnique = %v, want T1110", decoded.ExploitationSteps[1].MITRETechnique)
	}
	if len(decoded.Tools) != 1 {
		t.Errorf("Tools length = %v, want 1", len(decoded.Tools))
	}
	if decoded.Tools[0].Name != "Burp Suite" {
		t.Errorf("Tool Name = %v, want Burp Suite", decoded.Tools[0].Name)
	}
	if len(decoded.PayloadPatterns) != 1 {
		t.Errorf("PayloadPatterns length = %v, want 1", len(decoded.PayloadPatterns))
	}
	if decoded.Difficulty != ExploitDifficultyLow {
		t.Errorf("Difficulty = %v, want low", decoded.Difficulty)
	}
	if decoded.TimeToExploit != "< 1 minute" {
		t.Errorf("TimeToExploit = %v, want < 1 minute", decoded.TimeToExploit)
	}
}

func TestExploitationStepJSON(t *testing.T) {
	step := ExploitationStep{
		Step:           3,
		Action:         "Exfiltrate API keys",
		Description:    "Request API keys from agent config",
		Example:        `ws.send('{"cmd":"get_config"}')`,
		ExpectedResult: "Receive config containing API keys",
		MITRETechnique: "T1552",
	}

	data, err := json.Marshal(step)
	if err != nil {
		t.Fatalf("Failed to marshal ExploitationStep: %v", err)
	}

	var decoded ExploitationStep
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ExploitationStep: %v", err)
	}

	if decoded.Step != 3 {
		t.Errorf("Step = %v, want 3", decoded.Step)
	}
	if decoded.Action != "Exfiltrate API keys" {
		t.Errorf("Action = %v, want 'Exfiltrate API keys'", decoded.Action)
	}
	if decoded.MITRETechnique != "T1552" {
		t.Errorf("MITRETechnique = %v, want T1552", decoded.MITRETechnique)
	}
}

func TestOffensiveToolJSON(t *testing.T) {
	tool := OffensiveTool{
		Name:     "sqlmap",
		Purpose:  "SQL injection detection and exploitation",
		URL:      "https://sqlmap.org",
		Template: "sqlmap -u '{URL}' --batch --dbs",
		Category: "scanner",
		License:  "open-source",
	}

	data, err := json.Marshal(tool)
	if err != nil {
		t.Fatalf("Failed to marshal OffensiveTool: %v", err)
	}

	var decoded OffensiveTool
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal OffensiveTool: %v", err)
	}

	if decoded.Name != "sqlmap" {
		t.Errorf("Name = %v, want sqlmap", decoded.Name)
	}
	if decoded.Category != "scanner" {
		t.Errorf("Category = %v, want scanner", decoded.Category)
	}
}

func TestPayloadPatternJSON(t *testing.T) {
	pattern := PayloadPattern{
		Type:         "sqli",
		Pattern:      "' OR '1'='1",
		Description:  "Basic SQL injection test",
		Variants:     []string{"' OR 1=1--", "' OR ''='"},
		Encoding:     "none",
		BypassTarget: "basic input validation",
	}

	data, err := json.Marshal(pattern)
	if err != nil {
		t.Fatalf("Failed to marshal PayloadPattern: %v", err)
	}

	var decoded PayloadPattern
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal PayloadPattern: %v", err)
	}

	if decoded.Type != "sqli" {
		t.Errorf("Type = %v, want sqli", decoded.Type)
	}
	if len(decoded.Variants) != 2 {
		t.Errorf("Variants length = %v, want 2", len(decoded.Variants))
	}
	if decoded.BypassTarget != "basic input validation" {
		t.Errorf("BypassTarget = %v, want 'basic input validation'", decoded.BypassTarget)
	}
}
