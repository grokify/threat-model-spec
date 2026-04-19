package ir

import (
	"encoding/json"
	"testing"
)

func TestDetectionCoverage_JSONSchema(t *testing.T) {
	schema := DetectionCoverage("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 3 {
		t.Errorf("expected 3 enum values, got %d", len(schema.Enum))
	}
}

func TestDataSourceType_JSONSchema(t *testing.T) {
	schema := DataSourceType("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 11 {
		t.Errorf("expected 11 enum values, got %d", len(schema.Enum))
	}
}

func TestDetection_JSON(t *testing.T) {
	d := Detection{
		ID:              "det-1",
		Title:           "WebSocket Origin Header Bypass Detection",
		Description:     "Detects connections with missing or invalid Origin headers",
		ThreatIDs:       []string{"threat-1"},
		AttackSteps:     []int{1, 2},
		MITRETechniques: []string{"T1189"},
		Method:          "Log analysis for Origin header anomalies",
		DataSources:     []DataSourceType{DataSourceTypeLogs, DataSourceTypeWAF},
		Coverage:        DetectionCoverageFull,
		LatencySeconds:  60,
		FalsePositiveRate: "low",
		DetectionLogic:  "origin_header IS NULL OR origin_header NOT IN allowed_origins",
		Tool:            "Splunk",
		PlaybookID:      "playbook-ws-origin",
		AlertSeverity:   "high",
		Enabled:         true,
	}

	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Detection
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != d.ID {
		t.Errorf("expected ID %q, got %q", d.ID, decoded.ID)
	}
	if decoded.Coverage != DetectionCoverageFull {
		t.Errorf("expected coverage %q, got %q", DetectionCoverageFull, decoded.Coverage)
	}
	if len(decoded.DataSources) != 2 {
		t.Errorf("expected 2 data sources, got %d", len(decoded.DataSources))
	}
	if len(decoded.AttackSteps) != 2 {
		t.Errorf("expected 2 attack steps, got %d", len(decoded.AttackSteps))
	}
	if !decoded.Enabled {
		t.Error("expected enabled to be true")
	}
}

func TestResponseAction_JSON(t *testing.T) {
	r := ResponseAction{
		ID:                  "resp-1",
		Title:               "Block Suspicious WebSocket Connection",
		Description:         "Automatically block connections with invalid Origin",
		TriggerDetectionIDs: []string{"det-1"},
		ActionType:          "block",
		Automated:           true,
		PlaybookURL:         "https://wiki.example.com/playbooks/ws-block",
		Owner:               "security-ops",
		EscalationPath:      "security-ops -> soc-lead -> ciso",
		SLAMinutes:          15,
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ResponseAction
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != r.ID {
		t.Errorf("expected ID %q, got %q", r.ID, decoded.ID)
	}
	if !decoded.Automated {
		t.Error("expected automated to be true")
	}
	if decoded.SLAMinutes != 15 {
		t.Errorf("expected SLA 15 minutes, got %d", decoded.SLAMinutes)
	}
}

func TestDetectionCoverage_Values(t *testing.T) {
	coverages := []DetectionCoverage{
		DetectionCoverageNone,
		DetectionCoveragePartial,
		DetectionCoverageFull,
	}

	for _, c := range coverages {
		t.Run(string(c), func(t *testing.T) {
			data, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded DetectionCoverage
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != c {
				t.Errorf("expected %q, got %q", c, decoded)
			}
		})
	}
}

func TestDataSourceType_Values(t *testing.T) {
	sources := []DataSourceType{
		DataSourceTypeLogs,
		DataSourceTypeSIEM,
		DataSourceTypeEDR,
		DataSourceTypeNDR,
		DataSourceTypeIDS,
		DataSourceTypeWAF,
		DataSourceTypeCloudTrail,
		DataSourceTypeAPIGateway,
		DataSourceTypeNetworkCapture,
		DataSourceTypeUserBehavior,
		DataSourceTypeAuditLog,
	}

	for _, s := range sources {
		t.Run(string(s), func(t *testing.T) {
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded DataSourceType
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != s {
				t.Errorf("expected %q, got %q", s, decoded)
			}
		})
	}
}
