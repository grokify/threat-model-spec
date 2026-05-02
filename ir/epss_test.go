package ir

import (
	"encoding/json"
	"testing"
)

func TestEPSSDataJSONRoundTrip(t *testing.T) {
	data := EPSSData{
		CVE:        "CVE-2024-12345",
		EPSSScore:  0.45,
		Percentile: 95.5,
		DateScored: "2026-04-28",
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal EPSSData: %v", err)
	}

	var decoded EPSSData
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal EPSSData: %v", err)
	}

	if decoded.CVE != "CVE-2024-12345" {
		t.Errorf("CVE = %s, want CVE-2024-12345", decoded.CVE)
	}
	if decoded.EPSSScore != 0.45 {
		t.Errorf("EPSSScore = %f, want 0.45", decoded.EPSSScore)
	}
	if decoded.Percentile != 95.5 {
		t.Errorf("Percentile = %f, want 95.5", decoded.Percentile)
	}
}

func TestEPSSRiskLevel(t *testing.T) {
	tests := []struct {
		score    float64
		expected EPSSRiskLevel
	}{
		{0.8, EPSSRiskCritical},
		{0.7, EPSSRiskCritical},
		{0.5, EPSSRiskHigh},
		{0.3, EPSSRiskHigh},
		{0.2, EPSSRiskMedium},
		{0.1, EPSSRiskMedium},
		{0.05, EPSSRiskLow},
		{0.0, EPSSRiskLow},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			data := EPSSData{EPSSScore: tt.score}
			if got := data.RiskLevel(); got != tt.expected {
				t.Errorf("RiskLevel() for score %f = %s, want %s", tt.score, got, tt.expected)
			}
		})
	}
}

func TestEPSSRiskLevelByPercentile(t *testing.T) {
	tests := []struct {
		percentile float64
		expected   EPSSRiskLevel
	}{
		{99.5, EPSSRiskCritical},
		{99.0, EPSSRiskCritical},
		{97.0, EPSSRiskHigh},
		{95.0, EPSSRiskHigh},
		{90.0, EPSSRiskMedium},
		{80.0, EPSSRiskMedium},
		{50.0, EPSSRiskLow},
		{10.0, EPSSRiskLow},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			data := EPSSData{Percentile: tt.percentile}
			if got := data.RiskLevelByPercentile(); got != tt.expected {
				t.Errorf("RiskLevelByPercentile() for percentile %f = %s, want %s", tt.percentile, got, tt.expected)
			}
		})
	}
}

func TestEPSSPriorityMethods(t *testing.T) {
	tests := []struct {
		score          float64
		isPriority     bool
		isHighPriority bool
	}{
		{0.5, true, true},
		{0.3, true, true},
		{0.29, true, false},
		{0.1, true, false},
		{0.09, false, false},
		{0.0, false, false},
	}

	for _, tt := range tests {
		data := EPSSData{EPSSScore: tt.score}

		if got := data.IsPriority(); got != tt.isPriority {
			t.Errorf("IsPriority() for score %f = %v, want %v", tt.score, got, tt.isPriority)
		}
		if got := data.IsHighPriority(); got != tt.isHighPriority {
			t.Errorf("IsHighPriority() for score %f = %v, want %v", tt.score, got, tt.isHighPriority)
		}
	}
}

func TestEPSSCatalogLookup(t *testing.T) {
	catalog := EPSSCatalog{
		Entries: map[string]EPSSData{
			"CVE-2024-0001": {CVE: "CVE-2024-0001", EPSSScore: 0.5, Percentile: 95.0},
			"CVE-2024-0002": {CVE: "CVE-2024-0002", EPSSScore: 0.1, Percentile: 80.0},
			"CVE-2024-0003": {CVE: "CVE-2024-0003", EPSSScore: 0.05, Percentile: 50.0},
		},
		LastUpdated: "2026-04-28",
		Source:      "FIRST EPSS API",
	}

	// Test GetEPSSScore
	entry := catalog.GetEPSSScore("CVE-2024-0001")
	if entry == nil {
		t.Fatal("GetEPSSScore() returned nil for existing CVE")
	}
	if entry.EPSSScore != 0.5 {
		t.Errorf("EPSSScore = %f, want 0.5", entry.EPSSScore)
	}

	// Test non-existent CVE
	entry = catalog.GetEPSSScore("CVE-9999-9999")
	if entry != nil {
		t.Error("GetEPSSScore() should return nil for non-existent CVE")
	}

	// Test GetHighPriorityCVEs
	highPriority := catalog.GetHighPriorityCVEs()
	if len(highPriority) != 1 {
		t.Errorf("GetHighPriorityCVEs() returned %d entries, want 1", len(highPriority))
	}

	// Test GetPriorityCVEs
	priority := catalog.GetPriorityCVEs()
	if len(priority) != 2 {
		t.Errorf("GetPriorityCVEs() returned %d entries, want 2", len(priority))
	}
}

func TestEPSSCatalogNil(t *testing.T) {
	var catalog *EPSSCatalog

	// Should not panic on nil catalog
	entry := catalog.GetEPSSScore("CVE-2024-0001")
	if entry != nil {
		t.Error("GetEPSSScore() on nil catalog should return nil")
	}

	highPriority := catalog.GetHighPriorityCVEs()
	if len(highPriority) != 0 {
		t.Error("GetHighPriorityCVEs() on nil catalog should return empty slice")
	}

	priority := catalog.GetPriorityCVEs()
	if len(priority) != 0 {
		t.Error("GetPriorityCVEs() on nil catalog should return empty slice")
	}
}

func TestEPSSCatalogJSONRoundTrip(t *testing.T) {
	catalog := EPSSCatalog{
		Entries: map[string]EPSSData{
			"CVE-2024-0001": {CVE: "CVE-2024-0001", EPSSScore: 0.5, Percentile: 95.0},
			"CVE-2024-0002": {CVE: "CVE-2024-0002", EPSSScore: 0.1, Percentile: 80.0},
		},
		LastUpdated: "2026-04-28",
		Source:      "FIRST EPSS API",
	}

	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal EPSSCatalog: %v", err)
	}

	var decoded EPSSCatalog
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal EPSSCatalog: %v", err)
	}

	if len(decoded.Entries) != 2 {
		t.Errorf("Entries count = %d, want 2", len(decoded.Entries))
	}
	if decoded.Source != "FIRST EPSS API" {
		t.Errorf("Source = %s, want FIRST EPSS API", decoded.Source)
	}
}
