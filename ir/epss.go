// Package ir provides the intermediate representation for threat models.
package ir

// EPSSData represents Exploit Prediction Scoring System (EPSS) data
// from FIRST (Forum of Incident Response and Security Teams).
// EPSS provides a probability score indicating the likelihood that a
// vulnerability will be exploited in the wild within the next 30 days.
type EPSSData struct {
	CVE        string  `json:"cve"`                  // CVE identifier (e.g., "CVE-2024-1234")
	EPSSScore  float64 `json:"epssScore"`            // EPSS probability score (0.0 to 1.0)
	Percentile float64 `json:"percentile"`           // Percentile rank (0.0 to 100.0)
	DateScored string  `json:"dateScored,omitempty"` // Date the score was calculated (ISO 8601)
}

// EPSSRiskLevel represents categorical risk levels derived from EPSS scores.
type EPSSRiskLevel string

const (
	// EPSSRiskCritical indicates very high likelihood of exploitation (> 0.7 / top 1%)
	EPSSRiskCritical EPSSRiskLevel = "critical"
	// EPSSRiskHigh indicates high likelihood of exploitation (0.3 - 0.7 / top 5%)
	EPSSRiskHigh EPSSRiskLevel = "high"
	// EPSSRiskMedium indicates moderate likelihood of exploitation (0.1 - 0.3 / top 20%)
	EPSSRiskMedium EPSSRiskLevel = "medium"
	// EPSSRiskLow indicates lower likelihood of exploitation (< 0.1)
	EPSSRiskLow EPSSRiskLevel = "low"
)

// RiskLevel returns a categorical risk level based on the EPSS score.
// This uses commonly recommended thresholds for prioritization.
func (e *EPSSData) RiskLevel() EPSSRiskLevel {
	switch {
	case e.EPSSScore >= 0.7:
		return EPSSRiskCritical
	case e.EPSSScore >= 0.3:
		return EPSSRiskHigh
	case e.EPSSScore >= 0.1:
		return EPSSRiskMedium
	default:
		return EPSSRiskLow
	}
}

// RiskLevelByPercentile returns a categorical risk level based on percentile.
// This is useful when comparing relative risk across all known CVEs.
func (e *EPSSData) RiskLevelByPercentile() EPSSRiskLevel {
	switch {
	case e.Percentile >= 99.0:
		return EPSSRiskCritical
	case e.Percentile >= 95.0:
		return EPSSRiskHigh
	case e.Percentile >= 80.0:
		return EPSSRiskMedium
	default:
		return EPSSRiskLow
	}
}

// IsPriority returns true if the vulnerability should be prioritized for
// remediation based on EPSS score (commonly used threshold: >= 0.1).
func (e *EPSSData) IsPriority() bool {
	return e.EPSSScore >= 0.1
}

// IsHighPriority returns true if the vulnerability is high priority
// based on EPSS score (threshold: >= 0.3).
func (e *EPSSData) IsHighPriority() bool {
	return e.EPSSScore >= 0.3
}

// EPSSCatalog provides lookup functionality for EPSS scores.
// This can be populated from the FIRST EPSS API or embedded data.
type EPSSCatalog struct {
	Entries     map[string]EPSSData `json:"entries"`               // CVE ID -> EPSS data
	LastUpdated string              `json:"lastUpdated,omitempty"` // Date catalog was last updated
	Source      string              `json:"source,omitempty"`      // Data source (e.g., "FIRST EPSS API")
}

// GetEPSSScore returns EPSS data for a given CVE ID, or nil if not found.
func (c *EPSSCatalog) GetEPSSScore(cveID string) *EPSSData {
	if c == nil || c.Entries == nil {
		return nil
	}
	if entry, ok := c.Entries[cveID]; ok {
		return &entry
	}
	return nil
}

// GetHighPriorityCVEs returns all CVEs with EPSS score >= 0.3.
func (c *EPSSCatalog) GetHighPriorityCVEs() []EPSSData {
	var results []EPSSData
	if c == nil || c.Entries == nil {
		return results
	}
	for _, entry := range c.Entries {
		if entry.IsHighPriority() {
			results = append(results, entry)
		}
	}
	return results
}

// GetPriorityCVEs returns all CVEs with EPSS score >= 0.1.
func (c *EPSSCatalog) GetPriorityCVEs() []EPSSData {
	var results []EPSSData
	if c == nil || c.Entries == nil {
		return results
	}
	for _, entry := range c.Entries {
		if entry.IsPriority() {
			results = append(results, entry)
		}
	}
	return results
}
