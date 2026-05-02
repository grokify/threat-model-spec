package ir

import (
	"encoding/json"
	"testing"
)

func TestRemediationGuidanceJSON(t *testing.T) {
	guidance := RemediationGuidance{
		VulnerablePatterns: []CodePattern{
			{
				Language:    "go",
				Description: "WebSocket server without origin validation",
				Code:        `http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {\n    upgrader.Upgrade(w, r, nil) // No origin check!\n})`,
				Explanation: "Accepts connections from any origin",
				CWE:         "CWE-346",
				Framework:   "gorilla/websocket",
			},
		},
		SecurePatterns: []CodePattern{
			{
				Language:    "go",
				Description: "WebSocket server with origin validation",
				Code:        `upgrader := websocket.Upgrader{\n    CheckOrigin: func(r *http.Request) bool {\n        origin := r.Header.Get("Origin")\n        return origin == "" || origin == "http://localhost"\n    },\n}`,
				Explanation: "Only allows connections from trusted origins",
				Framework:   "gorilla/websocket",
			},
		},
		ReviewChecklist: []ChecklistItem{
			{
				Item:     "Verify WebSocket origin validation is implemented",
				Required: true,
				Category: "authentication",
				Severity: "critical",
			},
			{
				Item:     "Confirm rate limiting is applied to auth endpoint",
				Required: true,
				Category: "rate-limiting",
				Severity: "critical",
			},
			{
				Item:     "Check that device registration requires explicit approval",
				Required: true,
				Category: "authorization",
				Severity: "high",
			},
		},
		RecommendedLibraries: []Library{
			{
				Name:           "gorilla/websocket",
				Language:       "go",
				Purpose:        "WebSocket implementation with CheckOrigin support",
				URL:            "https://github.com/gorilla/websocket",
				InstallCommand: "go get github.com/gorilla/websocket",
			},
		},
		ConfigurationChanges: []ConfigChange{
			{
				Setting:         "websocket.allowed_origins",
				Value:           `["http://localhost", "https://localhost"]`,
				Description:     "Restrict WebSocket connections to localhost only",
				CurrentValue:    `["*"]`,
				RestartRequired: true,
			},
		},
		TestingApproach: &TestingApproach{
			SecurityTests: []string{
				"Test that connections from non-localhost origins are rejected",
				"Test that brute-force is rate limited",
			},
			RegressionTests: []string{
				"Ensure legitimate localhost connections still work",
			},
			AcceptanceCriteria: []string{
				"Origin validation rejects external origins",
				"Rate limiting triggers after 5 failed attempts",
			},
		},
		TimeToFix:  "2-4 hours",
		Complexity: "medium",
		BreakingChanges: []string{
			"Browser extensions that relied on connecting to localhost may break",
		},
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(guidance, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal RemediationGuidance: %v", err)
	}

	// Unmarshal back
	var decoded RemediationGuidance
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal RemediationGuidance: %v", err)
	}

	// Verify fields
	if len(decoded.VulnerablePatterns) != 1 {
		t.Errorf("VulnerablePatterns length = %v, want 1", len(decoded.VulnerablePatterns))
	}
	if decoded.VulnerablePatterns[0].CWE != "CWE-346" {
		t.Errorf("VulnerablePattern CWE = %v, want CWE-346", decoded.VulnerablePatterns[0].CWE)
	}
	if len(decoded.SecurePatterns) != 1 {
		t.Errorf("SecurePatterns length = %v, want 1", len(decoded.SecurePatterns))
	}
	if len(decoded.ReviewChecklist) != 3 {
		t.Errorf("ReviewChecklist length = %v, want 3", len(decoded.ReviewChecklist))
	}
	if !decoded.ReviewChecklist[0].Required {
		t.Error("ReviewChecklist[0].Required = false, want true")
	}
	if len(decoded.RecommendedLibraries) != 1 {
		t.Errorf("RecommendedLibraries length = %v, want 1", len(decoded.RecommendedLibraries))
	}
	if decoded.TestingApproach == nil {
		t.Error("TestingApproach = nil, want non-nil")
	}
	if decoded.TimeToFix != "2-4 hours" {
		t.Errorf("TimeToFix = %v, want '2-4 hours'", decoded.TimeToFix)
	}
	if decoded.Complexity != "medium" {
		t.Errorf("Complexity = %v, want medium", decoded.Complexity)
	}
}

func TestCodePatternJSON(t *testing.T) {
	pattern := CodePattern{
		Language:    "python",
		Description: "SQL injection vulnerable code",
		Code:        `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`,
		Explanation: "String interpolation allows SQL injection",
		CWE:         "CWE-89",
		Framework:   "sqlite3",
		FilePath:    "app/db/queries.py",
		LineRange:   "45-47",
	}

	data, err := json.Marshal(pattern)
	if err != nil {
		t.Fatalf("Failed to marshal CodePattern: %v", err)
	}

	var decoded CodePattern
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal CodePattern: %v", err)
	}

	if decoded.Language != "python" {
		t.Errorf("Language = %v, want python", decoded.Language)
	}
	if decoded.CWE != "CWE-89" {
		t.Errorf("CWE = %v, want CWE-89", decoded.CWE)
	}
	if decoded.LineRange != "45-47" {
		t.Errorf("LineRange = %v, want 45-47", decoded.LineRange)
	}
}

func TestChecklistItemJSON(t *testing.T) {
	item := ChecklistItem{
		Item:     "Verify input sanitization",
		Required: true,
		Notes:    "Check all user inputs are sanitized before use",
		Category: "validation",
		Severity: "high",
	}

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("Failed to marshal ChecklistItem: %v", err)
	}

	var decoded ChecklistItem
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ChecklistItem: %v", err)
	}

	if decoded.Item != "Verify input sanitization" {
		t.Errorf("Item = %v, want 'Verify input sanitization'", decoded.Item)
	}
	if !decoded.Required {
		t.Error("Required = false, want true")
	}
	if decoded.Category != "validation" {
		t.Errorf("Category = %v, want validation", decoded.Category)
	}
}

func TestLibraryJSON(t *testing.T) {
	lib := Library{
		Name:           "DOMPurify",
		Language:       "javascript",
		Purpose:        "XSS sanitization",
		URL:            "https://github.com/cure53/DOMPurify",
		Examples:       []string{`DOMPurify.sanitize(userInput)`},
		Version:        "3.0.0",
		InstallCommand: "npm install dompurify",
		License:        "Apache-2.0",
		Alternatives:   []string{"sanitize-html", "xss"},
	}

	data, err := json.Marshal(lib)
	if err != nil {
		t.Fatalf("Failed to marshal Library: %v", err)
	}

	var decoded Library
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Library: %v", err)
	}

	if decoded.Name != "DOMPurify" {
		t.Errorf("Name = %v, want DOMPurify", decoded.Name)
	}
	if decoded.Version != "3.0.0" {
		t.Errorf("Version = %v, want 3.0.0", decoded.Version)
	}
	if len(decoded.Alternatives) != 2 {
		t.Errorf("Alternatives length = %v, want 2", len(decoded.Alternatives))
	}
}

func TestConfigChangeJSON(t *testing.T) {
	change := ConfigChange{
		Setting:         "security.cors.allowed_origins",
		Value:           "localhost",
		Description:     "Restrict CORS to localhost only",
		Platform:        "nginx",
		File:            "/etc/nginx/conf.d/security.conf",
		CurrentValue:    "*",
		Impact:          "Cross-origin requests from other domains will be blocked",
		RestartRequired: true,
	}

	data, err := json.Marshal(change)
	if err != nil {
		t.Fatalf("Failed to marshal ConfigChange: %v", err)
	}

	var decoded ConfigChange
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ConfigChange: %v", err)
	}

	if decoded.Setting != "security.cors.allowed_origins" {
		t.Errorf("Setting = %v, want security.cors.allowed_origins", decoded.Setting)
	}
	if decoded.CurrentValue != "*" {
		t.Errorf("CurrentValue = %v, want *", decoded.CurrentValue)
	}
	if !decoded.RestartRequired {
		t.Error("RestartRequired = false, want true")
	}
}

func TestTestingApproachJSON(t *testing.T) {
	approach := TestingApproach{
		UnitTests: []string{
			"Test origin validation rejects external origins",
			"Test origin validation accepts localhost",
		},
		IntegrationTests: []string{
			"Test full WebSocket connection flow with origin check",
		},
		SecurityTests: []string{
			"Test brute-force protection triggers after N attempts",
			"Test exfiltration is blocked from external origins",
		},
		RegressionTests: []string{
			"Test existing functionality still works",
		},
		ManualTests: []string{
			"Manually verify browser behavior from malicious site",
		},
		TestRefs: []TestReference{
			{
				TestID:  "ws-origin-check-001",
				Purpose: TestPurposeRemediation,
			},
		},
		AcceptanceCriteria: []string{
			"All unit tests pass",
			"Security scan shows no vulnerabilities",
		},
		Tools: []string{"go test", "nuclei", "burp"},
	}

	data, err := json.Marshal(approach)
	if err != nil {
		t.Fatalf("Failed to marshal TestingApproach: %v", err)
	}

	var decoded TestingApproach
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal TestingApproach: %v", err)
	}

	if len(decoded.UnitTests) != 2 {
		t.Errorf("UnitTests length = %v, want 2", len(decoded.UnitTests))
	}
	if len(decoded.SecurityTests) != 2 {
		t.Errorf("SecurityTests length = %v, want 2", len(decoded.SecurityTests))
	}
	if len(decoded.TestRefs) != 1 {
		t.Errorf("TestRefs length = %v, want 1", len(decoded.TestRefs))
	}
	if decoded.TestRefs[0].Purpose != TestPurposeRemediation {
		t.Errorf("TestRef Purpose = %v, want remediation", decoded.TestRefs[0].Purpose)
	}
	if len(decoded.Tools) != 3 {
		t.Errorf("Tools length = %v, want 3", len(decoded.Tools))
	}
}
