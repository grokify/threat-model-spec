package ir

// SBOMFormat represents supported SBOM formats
type SBOMFormat string

const (
	SBOMFormatCycloneDX SBOMFormat = "cyclonedx"
	SBOMFormatSPDX      SBOMFormat = "spdx"
)

// SBOMReference links a threat model to an SBOM document
type SBOMReference struct {
	// Format specifies the SBOM format (cyclonedx, spdx)
	Format SBOMFormat `json:"format,omitempty"`

	// Version of the SBOM specification (e.g., "1.5" for CycloneDX, "2.3" for SPDX)
	Version string `json:"version,omitempty"`

	// URI is the location of the SBOM document
	URI string `json:"uri,omitempty"`

	// SerialNumber is the unique identifier for the SBOM (CycloneDX)
	SerialNumber string `json:"serialNumber,omitempty"`

	// DocumentNamespace is the unique identifier for the SBOM (SPDX)
	DocumentNamespace string `json:"documentNamespace,omitempty"`

	// Components lists the software components referenced in this threat model
	Components []ComponentReference `json:"components,omitempty"`
}

// ComponentReference links a threat or attack to a specific software component
type ComponentReference struct {
	// ID is the component identifier from the SBOM (purl, cpe, or internal ID)
	ID string `json:"id,omitempty"`

	// PURL is the Package URL for the component (e.g., pkg:npm/lodash@4.17.21)
	PURL string `json:"purl,omitempty"`

	// CPE is the Common Platform Enumeration for the component
	CPE string `json:"cpe,omitempty"`

	// Name is the human-readable component name
	Name string `json:"name,omitempty"`

	// Version is the component version
	Version string `json:"version,omitempty"`

	// Supplier is the component supplier/vendor
	Supplier string `json:"supplier,omitempty"`

	// License is the component license (SPDX identifier)
	License string `json:"license,omitempty"`

	// VulnerabilityIDs lists CVE or other vulnerability IDs affecting this component
	VulnerabilityIDs []string `json:"vulnerabilityIds,omitempty"`
}

// DependencyRisk represents risk information for a software dependency
type DependencyRisk struct {
	// ComponentRef references the component in the SBOM
	ComponentRef ComponentReference `json:"componentRef,omitempty"`

	// RiskLevel is the overall risk level (critical, high, medium, low)
	RiskLevel RiskLevel `json:"riskLevel,omitempty"`

	// VulnerabilityCount is the number of known vulnerabilities
	VulnerabilityCount int `json:"vulnerabilityCount,omitempty"`

	// CriticalCount is the number of critical severity vulnerabilities
	CriticalCount int `json:"criticalCount,omitempty"`

	// HighCount is the number of high severity vulnerabilities
	HighCount int `json:"highCount,omitempty"`

	// OutdatedBy indicates how many versions behind the latest
	OutdatedBy int `json:"outdatedBy,omitempty"`

	// LastUpdated is when the component was last updated
	LastUpdated string `json:"lastUpdated,omitempty"`

	// Deprecated indicates if the component is deprecated
	Deprecated bool `json:"deprecated,omitempty"`

	// Unmaintained indicates if the component appears unmaintained
	Unmaintained bool `json:"unmaintained,omitempty"`

	// DirectDependency indicates if this is a direct or transitive dependency
	DirectDependency bool `json:"directDependency,omitempty"`

	// Notes provides additional context about the dependency risk
	Notes string `json:"notes,omitempty"`
}

// CalculateDependencyRiskLevel calculates an overall risk level based on vulnerability counts
func CalculateDependencyRiskLevel(criticalCount, highCount, mediumCount int, deprecated, unmaintained bool) RiskLevel {
	if criticalCount > 0 || (deprecated && highCount > 0) {
		return RiskLevelCritical
	}
	if highCount > 0 || (unmaintained && mediumCount > 0) {
		return RiskLevelHigh
	}
	if mediumCount > 0 || deprecated || unmaintained {
		return RiskLevelMedium
	}
	return RiskLevelLow
}
