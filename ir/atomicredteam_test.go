package ir

import (
	"encoding/json"
	"testing"
)

func TestAtomicTestMappingJSONRoundTrip(t *testing.T) {
	mapping := AtomicTestMapping{
		TechniqueID:   "T1059.001",
		AtomicTests:   []string{"T1059.001-1", "T1059.001-2"},
		Validated:     true,
		LastRun:       "2026-04-28T10:00:00Z",
		Result:        AtomicTestResultPassed,
		Notes:         "Tested in lab environment",
		Platform:      "windows",
		ExecutionTime: 30,
	}

	data, err := json.MarshalIndent(mapping, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal AtomicTestMapping: %v", err)
	}

	var decoded AtomicTestMapping
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AtomicTestMapping: %v", err)
	}

	if decoded.TechniqueID != "T1059.001" {
		t.Errorf("TechniqueID = %s, want T1059.001", decoded.TechniqueID)
	}
	if len(decoded.AtomicTests) != 2 {
		t.Errorf("AtomicTests count = %d, want 2", len(decoded.AtomicTests))
	}
	if decoded.Result != AtomicTestResultPassed {
		t.Errorf("Result = %s, want passed", decoded.Result)
	}
	if !decoded.Validated {
		t.Error("Validated should be true")
	}
}

func TestValidateTechniqueID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"T1059", true},
		{"T1059.001", true},
		{"T1234", true},
		{"T1234.123", true},
		{"T123", false},         // Too few digits
		{"T12345", false},       // Too many digits
		{"T1234.12", false},     // Too few subtechnique digits
		{"T1234.1234", false},   // Too many subtechnique digits
		{"1234", false},         // Missing T prefix
		{"TA0001", false},       // Tactic, not technique
		{"", false},             // Empty
		{"T1059.001.001", false}, // Too many levels
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := ValidateTechniqueID(tt.id); got != tt.valid {
				t.Errorf("ValidateTechniqueID(%s) = %v, want %v", tt.id, got, tt.valid)
			}
		})
	}
}

func TestValidateAtomicTestID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"T1059-1", true},
		{"T1059.001-1", true},
		{"T1059.001-12", true},
		{"T1234-99", true},
		{"T1234.123-1", true},
		{"T1059", false},       // No test number
		{"T1059.001", false},   // No test number
		{"T1059-", false},      // Missing test number
		{"T1059-a", false},     // Non-numeric test number
		{"1059-1", false},      // Missing T prefix
		{"", false},            // Empty
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := ValidateAtomicTestID(tt.id); got != tt.valid {
				t.Errorf("ValidateAtomicTestID(%s) = %v, want %v", tt.id, got, tt.valid)
			}
		})
	}
}

func TestAtomicTestResults(t *testing.T) {
	validResults := []AtomicTestResult{
		AtomicTestResultPassed,
		AtomicTestResultFailed,
		AtomicTestResultBlocked,
		AtomicTestResultSkipped,
		AtomicTestResultError,
	}

	for _, result := range validResults {
		mapping := AtomicTestMapping{
			TechniqueID: "T1059",
			Result:      result,
		}

		data, err := json.Marshal(mapping)
		if err != nil {
			t.Errorf("Failed to marshal mapping with result %s: %v", result, err)
		}

		var decoded AtomicTestMapping
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("Failed to unmarshal mapping with result %s: %v", result, err)
		}

		if decoded.Result != result {
			t.Errorf("Result = %s, want %s", decoded.Result, result)
		}
	}
}

func TestCalculateAtomicTestSummary(t *testing.T) {
	tests := []AtomicTestMapping{
		{TechniqueID: "T1059.001", Validated: true, Result: AtomicTestResultPassed},
		{TechniqueID: "T1059.002", Validated: true, Result: AtomicTestResultPassed},
		{TechniqueID: "T1059.003", Validated: true, Result: AtomicTestResultBlocked},
		{TechniqueID: "T1059.004", Validated: true, Result: AtomicTestResultFailed},
		{TechniqueID: "T1059.005", Validated: false, Result: AtomicTestResultPassed}, // Not validated
	}

	summary := CalculateAtomicTestSummary(tests)

	if summary.TotalTests != 4 {
		t.Errorf("TotalTests = %d, want 4 (excluding non-validated)", summary.TotalTests)
	}
	if summary.Passed != 2 {
		t.Errorf("Passed = %d, want 2", summary.Passed)
	}
	if summary.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", summary.Blocked)
	}
	if summary.Failed != 1 {
		t.Errorf("Failed = %d, want 1", summary.Failed)
	}

	expectedPassRate := 0.5 // 2 out of 4
	if summary.PassRate != expectedPassRate {
		t.Errorf("PassRate = %f, want %f", summary.PassRate, expectedPassRate)
	}

	expectedBlockRate := 0.25 // 1 out of 4
	if summary.BlockRate != expectedBlockRate {
		t.Errorf("BlockRate = %f, want %f", summary.BlockRate, expectedBlockRate)
	}
}

func TestCalculateAtomicTestSummaryEmpty(t *testing.T) {
	summary := CalculateAtomicTestSummary([]AtomicTestMapping{})

	if summary.TotalTests != 0 {
		t.Errorf("TotalTests = %d, want 0", summary.TotalTests)
	}
	if summary.PassRate != 0 {
		t.Errorf("PassRate = %f, want 0", summary.PassRate)
	}
}

func TestGetAtomicTestURL(t *testing.T) {
	tests := []struct {
		techniqueID string
		wantURL     string
	}{
		{"T1059", "https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1059"},
		{"T1059.001", "https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1059"},
		{"T1566", "https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1566"},
	}

	for _, tt := range tests {
		t.Run(tt.techniqueID, func(t *testing.T) {
			if got := GetAtomicTestURL(tt.techniqueID); got != tt.wantURL {
				t.Errorf("GetAtomicTestURL(%s) = %s, want %s", tt.techniqueID, got, tt.wantURL)
			}
		})
	}
}

func TestAtomicTestSummaryJSONRoundTrip(t *testing.T) {
	summary := AtomicTestSummary{
		TotalTests: 10,
		Passed:     6,
		Failed:     2,
		Blocked:    1,
		Skipped:    1,
		Errors:     0,
		PassRate:   0.6,
		BlockRate:  0.1,
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal AtomicTestSummary: %v", err)
	}

	var decoded AtomicTestSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AtomicTestSummary: %v", err)
	}

	if decoded.TotalTests != 10 {
		t.Errorf("TotalTests = %d, want 10", decoded.TotalTests)
	}
	if decoded.PassRate != 0.6 {
		t.Errorf("PassRate = %f, want 0.6", decoded.PassRate)
	}
}
