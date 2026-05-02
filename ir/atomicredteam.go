// Package ir provides the intermediate representation for threat models.
package ir

import (
	"regexp"
	"strings"

	"github.com/invopop/jsonschema"
)

// AtomicTestMapping maps MITRE ATT&CK techniques to Atomic Red Team tests.
// Atomic Red Team provides pre-built tests for adversary emulation.
type AtomicTestMapping struct {
	// TechniqueID is the MITRE ATT&CK technique ID (e.g., "T1059.001").
	TechniqueID string `json:"techniqueId"`

	// AtomicTests lists specific Atomic test IDs (e.g., ["T1059.001-1", "T1059.001-2"]).
	AtomicTests []string `json:"atomicTests,omitempty"`

	// Validated indicates if the tests have been validated in the environment.
	Validated bool `json:"validated,omitempty"`

	// LastRun is the timestamp of the last test execution (ISO 8601).
	LastRun string `json:"lastRun,omitempty"`

	// Result is the outcome of the last test run.
	Result AtomicTestResult `json:"result,omitempty"`

	// Notes provides additional context about the test execution.
	Notes string `json:"notes,omitempty"`

	// Platform specifies the target platform (windows, linux, macos).
	Platform string `json:"platform,omitempty"`

	// ExecutionTime is the time taken to run the tests (in seconds).
	ExecutionTime int `json:"executionTime,omitempty"`
}

// AtomicTestResult represents the outcome of an Atomic Red Team test.
type AtomicTestResult string

const (
	// AtomicTestResultPassed indicates the test executed successfully and the technique was demonstrated.
	AtomicTestResultPassed AtomicTestResult = "passed"

	// AtomicTestResultFailed indicates the test failed to execute or demonstrate the technique.
	AtomicTestResultFailed AtomicTestResult = "failed"

	// AtomicTestResultBlocked indicates the test was blocked by security controls.
	AtomicTestResultBlocked AtomicTestResult = "blocked"

	// AtomicTestResultSkipped indicates the test was skipped (e.g., wrong platform).
	AtomicTestResultSkipped AtomicTestResult = "skipped"

	// AtomicTestResultError indicates an error occurred during test execution.
	AtomicTestResultError AtomicTestResult = "error"
)

// JSONSchema implements jsonschema.JSONSchemaer for AtomicTestResult.
func (AtomicTestResult) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"passed", "failed", "blocked", "skipped", "error"},
	}
}

// ValidateTechniqueID validates a MITRE ATT&CK technique ID format.
// Valid formats: T1234, T1234.001, T1234.001
func ValidateTechniqueID(id string) bool {
	// Pattern: T followed by 4 digits, optionally followed by .XXX
	pattern := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	return pattern.MatchString(id)
}

// ValidateAtomicTestID validates an Atomic Red Team test ID format.
// Valid formats: T1234-1, T1234.001-1, T1234.001-12
func ValidateAtomicTestID(id string) bool {
	// Pattern: Technique ID followed by -N
	pattern := regexp.MustCompile(`^T\d{4}(\.\d{3})?-\d+$`)
	return pattern.MatchString(id)
}

// AtomicTestSummary provides a summary of Atomic Red Team test results.
type AtomicTestSummary struct {
	TotalTests    int `json:"totalTests"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Blocked       int `json:"blocked"`
	Skipped       int `json:"skipped"`
	Errors        int `json:"errors"`
	PassRate      float64 `json:"passRate"`
	BlockRate     float64 `json:"blockRate"`
}

// CalculateSummary calculates test summary statistics from a list of test mappings.
func CalculateAtomicTestSummary(tests []AtomicTestMapping) *AtomicTestSummary {
	summary := &AtomicTestSummary{}

	for _, test := range tests {
		if !test.Validated {
			continue
		}
		summary.TotalTests++
		switch test.Result {
		case AtomicTestResultPassed:
			summary.Passed++
		case AtomicTestResultFailed:
			summary.Failed++
		case AtomicTestResultBlocked:
			summary.Blocked++
		case AtomicTestResultSkipped:
			summary.Skipped++
		case AtomicTestResultError:
			summary.Errors++
		}
	}

	if summary.TotalTests > 0 {
		summary.PassRate = float64(summary.Passed) / float64(summary.TotalTests)
		summary.BlockRate = float64(summary.Blocked) / float64(summary.TotalTests)
	}

	return summary
}

// GetAtomicTestURL returns the GitHub URL for an Atomic Red Team test.
func GetAtomicTestURL(techniqueID string) string {
	// Remove any subtechnique suffix for the main technique folder
	baseTechnique := strings.Split(techniqueID, ".")[0]
	return "https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/" + baseTechnique
}
