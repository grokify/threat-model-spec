package ir

import (
	"encoding/json"
	"math"
	"testing"
)

func TestDetectionCoverageMatrixJSONRoundTrip(t *testing.T) {
	matrix := DetectionCoverageMatrix{
		Techniques: []TechniqueCoverage{
			{
				TechniqueID:   "T1059.001",
				TechniqueName: "PowerShell",
				Tactic:        "execution",
				Coverage:      CoverageLevelFull,
				DetectionIDs:  []string{"rule-1", "rule-2"},
				DataSources:   []string{"Process Creation", "Script Execution"},
			},
			{
				TechniqueID:   "T1059.003",
				TechniqueName: "Windows Command Shell",
				Tactic:        "execution",
				Coverage:      CoverageLevelPartial,
				DetectionIDs:  []string{"rule-3"},
			},
		},
		LastUpdated: "2026-04-28",
		Source:      "SIEM Analysis",
	}

	data, err := json.MarshalIndent(matrix, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal DetectionCoverageMatrix: %v", err)
	}

	var decoded DetectionCoverageMatrix
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal DetectionCoverageMatrix: %v", err)
	}

	if len(decoded.Techniques) != 2 {
		t.Errorf("Techniques count = %d, want 2", len(decoded.Techniques))
	}
	if decoded.Techniques[0].Coverage != CoverageLevelFull {
		t.Errorf("First technique coverage = %s, want full", decoded.Techniques[0].Coverage)
	}
	if decoded.Source != "SIEM Analysis" {
		t.Errorf("Source = %s, want SIEM Analysis", decoded.Source)
	}
}

func TestCalculateCoverage(t *testing.T) {
	techniques := []TechniqueCoverage{
		{TechniqueID: "T1059.001", Tactic: "execution", Coverage: CoverageLevelFull},
		{TechniqueID: "T1059.002", Tactic: "execution", Coverage: CoverageLevelSubstantial},
		{TechniqueID: "T1059.003", Tactic: "execution", Coverage: CoverageLevelPartial},
		{TechniqueID: "T1059.004", Tactic: "execution", Coverage: CoverageLevelMinimal},
		{TechniqueID: "T1566.001", Tactic: "initial-access", Coverage: CoverageLevelNone},
		{TechniqueID: "T1566.002", Tactic: "initial-access", Coverage: CoverageLevelNone},
	}

	summary := CalculateCoverage(techniques)

	if summary.TotalTechniques != 6 {
		t.Errorf("TotalTechniques = %d, want 6", summary.TotalTechniques)
	}
	if summary.CoveredFull != 1 {
		t.Errorf("CoveredFull = %d, want 1", summary.CoveredFull)
	}
	if summary.CoveredSubstantial != 1 {
		t.Errorf("CoveredSubstantial = %d, want 1", summary.CoveredSubstantial)
	}
	if summary.CoveredPartial != 1 {
		t.Errorf("CoveredPartial = %d, want 1", summary.CoveredPartial)
	}
	if summary.CoveredMinimal != 1 {
		t.Errorf("CoveredMinimal = %d, want 1", summary.CoveredMinimal)
	}
	if summary.NotCovered != 2 {
		t.Errorf("NotCovered = %d, want 2", summary.NotCovered)
	}

	// CoveragePercent = 4/6 * 100 = 66.67%
	expectedCoverage := float64(4) / float64(6) * 100
	if summary.CoveragePercent != expectedCoverage {
		t.Errorf("CoveragePercent = %f, want %f", summary.CoveragePercent, expectedCoverage)
	}

	// EffectiveCoveragePercent = (1.0 + 0.75 + 0.5 + 0.25 + 0 + 0) / 6 * 100 = 41.67%
	expectedEffective := 2.5 / 6.0 * 100
	if math.Abs(summary.EffectiveCoveragePercent-expectedEffective) > 0.0001 {
		t.Errorf("EffectiveCoveragePercent = %f, want %f", summary.EffectiveCoveragePercent, expectedEffective)
	}

	// Check gaps by tactic
	if summary.GapsByTactic["initial-access"] != 2 {
		t.Errorf("GapsByTactic[initial-access] = %d, want 2", summary.GapsByTactic["initial-access"])
	}
}

func TestCalculateCoverageEmpty(t *testing.T) {
	summary := CalculateCoverage([]TechniqueCoverage{})

	if summary.TotalTechniques != 0 {
		t.Errorf("TotalTechniques = %d, want 0", summary.TotalTechniques)
	}
	if summary.CoveragePercent != 0 {
		t.Errorf("CoveragePercent = %f, want 0", summary.CoveragePercent)
	}
}

func TestCoverageLevels(t *testing.T) {
	validLevels := []CoverageLevel{
		CoverageLevelNone,
		CoverageLevelMinimal,
		CoverageLevelPartial,
		CoverageLevelSubstantial,
		CoverageLevelFull,
	}

	for _, level := range validLevels {
		tc := TechniqueCoverage{
			TechniqueID: "T1059",
			Coverage:    level,
		}

		data, err := json.Marshal(tc)
		if err != nil {
			t.Errorf("Failed to marshal TechniqueCoverage with level %s: %v", level, err)
		}

		var decoded TechniqueCoverage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("Failed to unmarshal TechniqueCoverage with level %s: %v", level, err)
		}

		if decoded.Coverage != level {
			t.Errorf("Coverage = %s, want %s", decoded.Coverage, level)
		}
	}
}

func TestDetectionCoverageMatrixMethods(t *testing.T) {
	matrix := DetectionCoverageMatrix{
		Techniques: []TechniqueCoverage{
			{TechniqueID: "T1059.001", Tactic: "execution", Coverage: CoverageLevelFull},
			{TechniqueID: "T1059.002", Tactic: "execution", Coverage: CoverageLevelNone},
			{TechniqueID: "T1566.001", Tactic: "initial-access", Coverage: CoverageLevelNone},
			{TechniqueID: "T1078", Tactic: "privilege-escalation", Coverage: CoverageLevelPartial},
		},
	}

	// Test GetGaps
	gaps := matrix.GetGaps()
	if len(gaps) != 2 {
		t.Errorf("GetGaps() returned %d gaps, want 2", len(gaps))
	}

	// Test GetCoverageByTactic
	byTactic := matrix.GetCoverageByTactic()
	if len(byTactic["execution"]) != 2 {
		t.Errorf("Execution tactics = %d, want 2", len(byTactic["execution"]))
	}
	if len(byTactic["initial-access"]) != 1 {
		t.Errorf("Initial-access tactics = %d, want 1", len(byTactic["initial-access"]))
	}

	// Test GetTechniqueCoverage
	tc := matrix.GetTechniqueCoverage("T1059.001")
	if tc == nil {
		t.Fatal("GetTechniqueCoverage() returned nil for existing technique")
	}
	if tc.Coverage != CoverageLevelFull {
		t.Errorf("Coverage = %s, want full", tc.Coverage)
	}

	// Test GetTechniqueCoverage for non-existing
	tc = matrix.GetTechniqueCoverage("T9999")
	if tc != nil {
		t.Error("GetTechniqueCoverage() should return nil for non-existing technique")
	}
}

func TestCoverageSummaryJSONRoundTrip(t *testing.T) {
	summary := CoverageSummary{
		TotalTechniques:          100,
		CoveredFull:              20,
		CoveredSubstantial:       30,
		CoveredPartial:           25,
		CoveredMinimal:           10,
		NotCovered:               15,
		CoveragePercent:          85.0,
		EffectiveCoveragePercent: 65.0,
		GapsByTactic: map[string]int{
			"initial-access": 5,
			"execution":      3,
			"persistence":    7,
		},
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal CoverageSummary: %v", err)
	}

	var decoded CoverageSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal CoverageSummary: %v", err)
	}

	if decoded.TotalTechniques != 100 {
		t.Errorf("TotalTechniques = %d, want 100", decoded.TotalTechniques)
	}
	if decoded.GapsByTactic["initial-access"] != 5 {
		t.Errorf("GapsByTactic[initial-access] = %d, want 5", decoded.GapsByTactic["initial-access"])
	}
}
