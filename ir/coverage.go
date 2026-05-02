// Package ir provides the intermediate representation for threat models.
package ir

import "github.com/invopop/jsonschema"

// DetectionCoverageMatrix represents MITRE ATT&CK detection coverage.
// This enables heatmap visualization and gap analysis.
type DetectionCoverageMatrix struct {
	// Techniques contains coverage data for each technique.
	Techniques []TechniqueCoverage `json:"techniques"`

	// Summary provides aggregate statistics.
	Summary *CoverageSummary `json:"summary,omitempty"`

	// LastUpdated is the timestamp when coverage was last calculated.
	LastUpdated string `json:"lastUpdated,omitempty"`

	// Source identifies where the coverage data came from.
	Source string `json:"source,omitempty"`
}

// TechniqueCoverage represents detection coverage for a single MITRE ATT&CK technique.
type TechniqueCoverage struct {
	// TechniqueID is the MITRE ATT&CK technique ID (e.g., "T1059.001").
	TechniqueID string `json:"techniqueId"`

	// TechniqueName is the human-readable technique name.
	TechniqueName string `json:"techniqueName,omitempty"`

	// Tactic is the MITRE ATT&CK tactic (e.g., "execution").
	Tactic string `json:"tactic,omitempty"`

	// Coverage indicates the level of detection coverage.
	Coverage CoverageLevel `json:"coverage"`

	// DetectionIDs lists the IDs of detection rules covering this technique.
	DetectionIDs []string `json:"detectionIds,omitempty"`

	// DataSources lists the data sources used for detection.
	DataSources []string `json:"dataSources,omitempty"`

	// Notes provides additional context about coverage.
	Notes string `json:"notes,omitempty"`

	// Confidence indicates confidence in the coverage assessment.
	Confidence string `json:"confidence,omitempty"`
}

// CoverageLevel indicates the level of detection coverage for a technique.
type CoverageLevel string

const (
	// CoverageLevelNone indicates no detection coverage.
	CoverageLevelNone CoverageLevel = "none"

	// CoverageLevelMinimal indicates minimal/basic detection coverage.
	CoverageLevelMinimal CoverageLevel = "minimal"

	// CoverageLevelPartial indicates partial detection coverage.
	CoverageLevelPartial CoverageLevel = "partial"

	// CoverageLevelSubstantial indicates substantial detection coverage.
	CoverageLevelSubstantial CoverageLevel = "substantial"

	// CoverageLevelFull indicates full/comprehensive detection coverage.
	CoverageLevelFull CoverageLevel = "full"
)

// JSONSchema implements jsonschema.JSONSchemaer for CoverageLevel.
func (CoverageLevel) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"none", "minimal", "partial", "substantial", "full"},
	}
}

// CoverageSummary provides aggregate statistics for detection coverage.
type CoverageSummary struct {
	// TotalTechniques is the total number of techniques assessed.
	TotalTechniques int `json:"totalTechniques"`

	// CoveredFull is the count of techniques with full coverage.
	CoveredFull int `json:"coveredFull"`

	// CoveredSubstantial is the count with substantial coverage.
	CoveredSubstantial int `json:"coveredSubstantial"`

	// CoveredPartial is the count with partial coverage.
	CoveredPartial int `json:"coveredPartial"`

	// CoveredMinimal is the count with minimal coverage.
	CoveredMinimal int `json:"coveredMinimal"`

	// NotCovered is the count of techniques with no coverage.
	NotCovered int `json:"notCovered"`

	// CoveragePercent is the percentage of techniques with any coverage.
	CoveragePercent float64 `json:"coveragePercent"`

	// EffectiveCoveragePercent weights coverage levels (full=100%, substantial=75%, partial=50%, minimal=25%).
	EffectiveCoveragePercent float64 `json:"effectiveCoveragePercent"`

	// GapsByTactic groups uncovered techniques by MITRE tactic.
	GapsByTactic map[string]int `json:"gapsByTactic,omitempty"`
}

// CalculateCoverage computes coverage summary from technique coverage data.
func CalculateCoverage(techniques []TechniqueCoverage) *CoverageSummary {
	summary := &CoverageSummary{
		GapsByTactic: make(map[string]int),
	}

	var effectiveScore float64

	for _, tc := range techniques {
		summary.TotalTechniques++

		switch tc.Coverage {
		case CoverageLevelFull:
			summary.CoveredFull++
			effectiveScore += 1.0
		case CoverageLevelSubstantial:
			summary.CoveredSubstantial++
			effectiveScore += 0.75
		case CoverageLevelPartial:
			summary.CoveredPartial++
			effectiveScore += 0.5
		case CoverageLevelMinimal:
			summary.CoveredMinimal++
			effectiveScore += 0.25
		case CoverageLevelNone:
			summary.NotCovered++
			if tc.Tactic != "" {
				summary.GapsByTactic[tc.Tactic]++
			}
		}
	}

	if summary.TotalTechniques > 0 {
		covered := summary.CoveredFull + summary.CoveredSubstantial + summary.CoveredPartial + summary.CoveredMinimal
		summary.CoveragePercent = float64(covered) / float64(summary.TotalTechniques) * 100
		summary.EffectiveCoveragePercent = effectiveScore / float64(summary.TotalTechniques) * 100
	}

	return summary
}

// GetGaps returns all techniques with no coverage.
func (m *DetectionCoverageMatrix) GetGaps() []TechniqueCoverage {
	var gaps []TechniqueCoverage
	for _, tc := range m.Techniques {
		if tc.Coverage == CoverageLevelNone {
			gaps = append(gaps, tc)
		}
	}
	return gaps
}

// GetCoverageByTactic returns techniques grouped by tactic.
func (m *DetectionCoverageMatrix) GetCoverageByTactic() map[string][]TechniqueCoverage {
	byTactic := make(map[string][]TechniqueCoverage)
	for _, tc := range m.Techniques {
		if tc.Tactic != "" {
			byTactic[tc.Tactic] = append(byTactic[tc.Tactic], tc)
		}
	}
	return byTactic
}

// GetTechniqueCoverage returns coverage for a specific technique ID.
func (m *DetectionCoverageMatrix) GetTechniqueCoverage(techniqueID string) *TechniqueCoverage {
	for i := range m.Techniques {
		if m.Techniques[i].TechniqueID == techniqueID {
			return &m.Techniques[i]
		}
	}
	return nil
}
