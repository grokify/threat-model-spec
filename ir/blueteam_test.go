package ir

import (
	"encoding/json"
	"testing"
)

func TestDetectionFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    DetectionFormat
		expected string
	}{
		{"sigma", DetectionFormatSigma, "sigma"},
		{"yara", DetectionFormatYara, "yara"},
		{"splunk", DetectionFormatSplunk, "splunk"},
		{"elastic", DetectionFormatElastic, "elastic"},
		{"kql", DetectionFormatKQL, "kql"},
		{"snort", DetectionFormatSnort, "snort"},
		{"suricata", DetectionFormatSuricata, "suricata"},
		{"custom", DetectionFormatCustom, "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.input) != tt.expected {
				t.Errorf("DetectionFormat = %v, want %v", tt.input, tt.expected)
			}
		})
	}
}

func TestDetectionFormatJSONSchema(t *testing.T) {
	var f DetectionFormat
	schema := f.JSONSchema()

	if schema.Type != "string" {
		t.Errorf("JSONSchema Type = %v, want string", schema.Type)
	}
	if len(schema.Enum) != 8 {
		t.Errorf("JSONSchema Enum length = %v, want 8", len(schema.Enum))
	}
}

func TestIOCType(t *testing.T) {
	tests := []struct {
		name     string
		input    IOCType
		expected string
	}{
		{"ip", IOCTypeIP, "ip"},
		{"domain", IOCTypeDomain, "domain"},
		{"url", IOCTypeURL, "url"},
		{"hash", IOCTypeHash, "hash"},
		{"filepath", IOCTypeFilepath, "filepath"},
		{"email", IOCTypeEmail, "email"},
		{"registry", IOCTypeRegistry, "registry"},
		{"process", IOCTypeProcess, "process"},
		{"certificate", IOCTypeCert, "certificate"},
		{"pattern", IOCTypePattern, "pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.input) != tt.expected {
				t.Errorf("IOCType = %v, want %v", tt.input, tt.expected)
			}
		})
	}
}

func TestIOCTypeJSONSchema(t *testing.T) {
	var i IOCType
	schema := i.JSONSchema()

	if schema.Type != "string" {
		t.Errorf("JSONSchema Type = %v, want string", schema.Type)
	}
	if len(schema.Enum) != 10 {
		t.Errorf("JSONSchema Enum length = %v, want 10", len(schema.Enum))
	}
}

func TestDefenseGuidanceJSON(t *testing.T) {
	guidance := DefenseGuidance{
		DetectionRules: []DetectionRule{
			{
				ID:          "detect-websocket-bruteforce",
				Name:        "WebSocket Brute Force Detection",
				Format:      DetectionFormatSigma,
				Rule:        "title: WebSocket Auth Brute Force\nstatus: experimental",
				Description: "Detects rapid WebSocket authentication attempts",
				Severity:    "high",
				FalsePositives: []string{
					"Legitimate load testing",
				},
				MITRETechniques: []string{"T1110"},
			},
		},
		IOCs: []IOC{
			{
				Type:        IOCTypeDomain,
				Value:       "attacker-c2.example.com",
				Description: "Known C2 domain for data exfiltration",
				Confidence:  "high",
				ValidUntil:  "2026-12-31",
			},
		},
		LogSources: []LogSource{
			{
				Name:        "WebSocket Server Logs",
				Description: "Logs from the WebSocket gateway",
				Fields:      []string{"origin", "timestamp", "cmd", "status"},
				Category:    "application",
			},
		},
		HuntingQueries: []HuntingQuery{
			{
				Name:        "Hunt for Unauthorized WebSocket Connections",
				Platform:    DetectionFormatSplunk,
				Query:       `index=websocket origin!="localhost" | stats count by origin`,
				Hypothesis:  "Malicious websites may connect to localhost WebSocket",
			},
		},
		MonitoringRecommendations: []string{
			"Monitor WebSocket connection origins",
			"Alert on failed authentication spikes",
		},
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(guidance, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal DefenseGuidance: %v", err)
	}

	// Unmarshal back
	var decoded DefenseGuidance
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal DefenseGuidance: %v", err)
	}

	// Verify fields
	if len(decoded.DetectionRules) != 1 {
		t.Errorf("DetectionRules length = %v, want 1", len(decoded.DetectionRules))
	}
	if decoded.DetectionRules[0].Format != DetectionFormatSigma {
		t.Errorf("DetectionRule Format = %v, want sigma", decoded.DetectionRules[0].Format)
	}
	if len(decoded.IOCs) != 1 {
		t.Errorf("IOCs length = %v, want 1", len(decoded.IOCs))
	}
	if decoded.IOCs[0].Type != IOCTypeDomain {
		t.Errorf("IOC Type = %v, want domain", decoded.IOCs[0].Type)
	}
	if len(decoded.LogSources) != 1 {
		t.Errorf("LogSources length = %v, want 1", len(decoded.LogSources))
	}
	if len(decoded.HuntingQueries) != 1 {
		t.Errorf("HuntingQueries length = %v, want 1", len(decoded.HuntingQueries))
	}
	if decoded.HuntingQueries[0].Platform != DetectionFormatSplunk {
		t.Errorf("HuntingQuery Platform = %v, want splunk", decoded.HuntingQueries[0].Platform)
	}
	if len(decoded.MonitoringRecommendations) != 2 {
		t.Errorf("MonitoringRecommendations length = %v, want 2", len(decoded.MonitoringRecommendations))
	}
}

func TestDetectionRuleJSON(t *testing.T) {
	rule := DetectionRule{
		ID:          "rule-001",
		Name:        "Localhost WebSocket from Browser",
		Format:      DetectionFormatSigma,
		Rule:        "title: OpenClaw Localhost WebSocket from Browser\nstatus: experimental\nlogsource:\n  category: webserver",
		Description: "Detects browser connections to localhost WebSocket",
		Severity:    "high",
		FalsePositives: []string{
			"Legitimate web development tools",
		},
		MITRETechniques: []string{"T1189", "T1110"},
		Tags:            []string{"openclaw", "websocket", "localhost"},
		Status:          "experimental",
		Author:          "Security Team",
		Date:            "2026-02-01",
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("Failed to marshal DetectionRule: %v", err)
	}

	var decoded DetectionRule
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal DetectionRule: %v", err)
	}

	if decoded.ID != "rule-001" {
		t.Errorf("ID = %v, want rule-001", decoded.ID)
	}
	if decoded.Format != DetectionFormatSigma {
		t.Errorf("Format = %v, want sigma", decoded.Format)
	}
	if len(decoded.MITRETechniques) != 2 {
		t.Errorf("MITRETechniques length = %v, want 2", len(decoded.MITRETechniques))
	}
	if decoded.Status != "experimental" {
		t.Errorf("Status = %v, want experimental", decoded.Status)
	}
}

func TestIOCJSON(t *testing.T) {
	ioc := IOC{
		Type:          IOCTypeHash,
		Value:         "d41d8cd98f00b204e9800998ecf8427e",
		Description:   "MD5 hash of malicious payload",
		Confidence:    "high",
		ValidUntil:    "2026-06-01",
		Source:        "Internal analysis",
		MalwareFamily: "OpenClaw-Stealer",
		Tags:          []string{"credential-theft", "api-key"},
	}

	data, err := json.Marshal(ioc)
	if err != nil {
		t.Fatalf("Failed to marshal IOC: %v", err)
	}

	var decoded IOC
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal IOC: %v", err)
	}

	if decoded.Type != IOCTypeHash {
		t.Errorf("Type = %v, want hash", decoded.Type)
	}
	if decoded.Confidence != "high" {
		t.Errorf("Confidence = %v, want high", decoded.Confidence)
	}
	if decoded.MalwareFamily != "OpenClaw-Stealer" {
		t.Errorf("MalwareFamily = %v, want OpenClaw-Stealer", decoded.MalwareFamily)
	}
}

func TestLogSourceJSON(t *testing.T) {
	source := LogSource{
		Name:          "Windows Security Event Log",
		Description:   "Windows security audit events",
		EventIDs:      []string{"4624", "4625", "4648"},
		Fields:        []string{"TargetUserName", "LogonType", "IpAddress"},
		Category:      "authentication",
		Platform:      "windows",
		RetentionDays: 90,
	}

	data, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("Failed to marshal LogSource: %v", err)
	}

	var decoded LogSource
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal LogSource: %v", err)
	}

	if decoded.Name != "Windows Security Event Log" {
		t.Errorf("Name = %v, want 'Windows Security Event Log'", decoded.Name)
	}
	if len(decoded.EventIDs) != 3 {
		t.Errorf("EventIDs length = %v, want 3", len(decoded.EventIDs))
	}
	if decoded.RetentionDays != 90 {
		t.Errorf("RetentionDays = %v, want 90", decoded.RetentionDays)
	}
}

func TestHuntingQueryJSON(t *testing.T) {
	query := HuntingQuery{
		Name:            "Hunt for WebSocket Exfiltration",
		Description:     "Identify potential data exfiltration via WebSocket",
		Platform:        DetectionFormatKQL,
		Query:           `WebSocketLogs | where Origin != "localhost" | summarize count() by Origin`,
		Hypothesis:      "Attackers may use WebSocket to exfiltrate data",
		DataSources:     []string{"WebSocketLogs", "NetworkTraffic"},
		MITRETechniques: []string{"T1041"},
		ExpectedResults: "Any non-localhost origins are suspicious",
		Author:          "Threat Hunter",
	}

	data, err := json.Marshal(query)
	if err != nil {
		t.Fatalf("Failed to marshal HuntingQuery: %v", err)
	}

	var decoded HuntingQuery
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal HuntingQuery: %v", err)
	}

	if decoded.Platform != DetectionFormatKQL {
		t.Errorf("Platform = %v, want kql", decoded.Platform)
	}
	if len(decoded.DataSources) != 2 {
		t.Errorf("DataSources length = %v, want 2", len(decoded.DataSources))
	}
	if decoded.Author != "Threat Hunter" {
		t.Errorf("Author = %v, want 'Threat Hunter'", decoded.Author)
	}
}

func TestAlertThresholdJSON(t *testing.T) {
	threshold := AlertThreshold{
		Metric:      "failed_auth_attempts",
		Threshold:   "10",
		Window:      "5m",
		Severity:    "high",
		Description: "Alert when more than 10 failed auth attempts in 5 minutes",
	}

	data, err := json.Marshal(threshold)
	if err != nil {
		t.Fatalf("Failed to marshal AlertThreshold: %v", err)
	}

	var decoded AlertThreshold
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AlertThreshold: %v", err)
	}

	if decoded.Metric != "failed_auth_attempts" {
		t.Errorf("Metric = %v, want failed_auth_attempts", decoded.Metric)
	}
	if decoded.Window != "5m" {
		t.Errorf("Window = %v, want 5m", decoded.Window)
	}
}
