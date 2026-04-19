package ir

import "github.com/invopop/jsonschema"

// ComplianceFramework identifies the regulatory or compliance framework.
type ComplianceFramework string

const (
	// ComplianceFrameworkSOC2 is the AICPA SOC 2 framework.
	ComplianceFrameworkSOC2 ComplianceFramework = "soc2"

	// ComplianceFrameworkPCIDSS is the Payment Card Industry Data Security Standard.
	ComplianceFrameworkPCIDSS ComplianceFramework = "pci-dss"

	// ComplianceFrameworkHIPAA is the Health Insurance Portability and Accountability Act.
	ComplianceFrameworkHIPAA ComplianceFramework = "hipaa"

	// ComplianceFrameworkGDPR is the General Data Protection Regulation.
	ComplianceFrameworkGDPR ComplianceFramework = "gdpr"

	// ComplianceFrameworkCCPA is the California Consumer Privacy Act.
	ComplianceFrameworkCCPA ComplianceFramework = "ccpa"

	// ComplianceFrameworkFedRAMP is the Federal Risk and Authorization Management Program.
	ComplianceFrameworkFedRAMP ComplianceFramework = "fedramp"

	// ComplianceFrameworkNISTSP80053 is NIST Special Publication 800-53.
	ComplianceFrameworkNISTSP80053 ComplianceFramework = "nist-sp-800-53"

	// ComplianceFrameworkNISTSP800171 is NIST Special Publication 800-171.
	ComplianceFrameworkNISTSP800171 ComplianceFramework = "nist-sp-800-171"

	// ComplianceFrameworkSOX is the Sarbanes-Oxley Act.
	ComplianceFrameworkSOX ComplianceFramework = "sox"

	// ComplianceFrameworkGLBA is the Gramm-Leach-Bliley Act.
	ComplianceFrameworkGLBA ComplianceFramework = "glba"
)

// JSONSchema implements jsonschema.JSONSchemaer for ComplianceFramework.
func (ComplianceFramework) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"soc2", "pci-dss", "hipaa", "gdpr", "ccpa",
			"fedramp", "nist-sp-800-53", "nist-sp-800-171", "sox", "glba",
		},
	}
}

// ComplianceMapping represents a regulatory or compliance framework reference.
type ComplianceMapping struct {
	// Framework identifies the compliance framework.
	Framework ComplianceFramework `json:"framework"`

	// RequirementID is the specific requirement or control reference.
	// Examples: "CC6.1" (SOC 2), "3.5.1" (PCI-DSS), "164.312(a)(1)" (HIPAA).
	RequirementID string `json:"requirementId"`

	// RequirementName is the human-readable requirement title.
	RequirementName string `json:"requirementName,omitempty"`

	// Category groups related requirements (e.g., "Common Criteria", "Access Control").
	Category string `json:"category,omitempty"`

	// Description explains how this requirement applies to the threat model.
	Description string `json:"description,omitempty"`

	// Status indicates compliance status (compliant, non-compliant, partial, not-assessed).
	Status string `json:"status,omitempty"`

	// Evidence provides references to compliance evidence or documentation.
	Evidence string `json:"evidence,omitempty"`

	// URL is a link to the compliance documentation.
	URL string `json:"url,omitempty"`
}

// SOC2TrustServiceCategory represents the SOC 2 Trust Service Categories.
type SOC2TrustServiceCategory string

const (
	SOC2Security         SOC2TrustServiceCategory = "Security"
	SOC2Availability     SOC2TrustServiceCategory = "Availability"
	SOC2ProcessingIntegrity SOC2TrustServiceCategory = "Processing Integrity"
	SOC2Confidentiality  SOC2TrustServiceCategory = "Confidentiality"
	SOC2Privacy          SOC2TrustServiceCategory = "Privacy"
)

// JSONSchema implements jsonschema.JSONSchemaer for SOC2TrustServiceCategory.
func (SOC2TrustServiceCategory) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"Security", "Availability", "Processing Integrity", "Confidentiality", "Privacy"},
	}
}
