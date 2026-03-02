package ir

import "github.com/invopop/jsonschema"

// Mappings contains references to external security frameworks.
// This allows threat models to be mapped to industry-standard frameworks
// for compliance, reporting, and interoperability.
type Mappings struct {
	// MITREAttack contains MITRE ATT&CK technique mappings.
	MITREAttack []MITREAttackMapping `json:"mitreAttack,omitempty"`

	// MITREATLAS contains MITRE ATLAS (AI-specific) technique mappings.
	MITREATLAS []MITREATLASMapping `json:"mitreAtlas,omitempty"`

	// OWASP contains OWASP Top 10 mappings (API, LLM, Web).
	OWASP []OWASPMapping `json:"owasp,omitempty"`

	// CWE contains Common Weakness Enumeration mappings.
	CWE []CWEMapping `json:"cwe,omitempty"`

	// CVSS contains the CVSS vector string and score.
	CVSS *CVSSMapping `json:"cvss,omitempty"`

	// STRIDE contains STRIDE threat category mappings.
	STRIDE []STRIDEMapping `json:"stride,omitempty"`
}

// MITREAttackMapping represents a MITRE ATT&CK technique reference.
type MITREAttackMapping struct {
	// TacticID is the tactic ID (e.g., "TA0001").
	TacticID string `json:"tacticId"`

	// TacticName is the human-readable tactic name (e.g., "Initial Access").
	TacticName string `json:"tacticName,omitempty"`

	// TechniqueID is the technique ID (e.g., "T1189").
	TechniqueID string `json:"techniqueId"`

	// TechniqueName is the human-readable technique name (e.g., "Drive-by Compromise").
	TechniqueName string `json:"techniqueName,omitempty"`

	// SubTechniqueID is the sub-technique ID (e.g., "T1189.001"), if applicable.
	SubTechniqueID string `json:"subTechniqueId,omitempty"`

	// Description explains how this technique applies to the threat model.
	Description string `json:"description,omitempty"`

	// URL is the link to the ATT&CK page.
	URL string `json:"url,omitempty"`
}

// MITREATLASMapping represents a MITRE ATLAS (AI/ML) technique reference.
type MITREATLASMapping struct {
	// TacticID is the tactic ID (e.g., "AML.TA0002").
	TacticID string `json:"tacticId"`

	// TacticName is the human-readable tactic name.
	TacticName string `json:"tacticName,omitempty"`

	// TechniqueID is the technique ID (e.g., "AML.T0024").
	TechniqueID string `json:"techniqueId"`

	// TechniqueName is the human-readable technique name.
	TechniqueName string `json:"techniqueName,omitempty"`

	// Description explains how this technique applies.
	Description string `json:"description,omitempty"`

	// URL is the link to the ATLAS page.
	URL string `json:"url,omitempty"`
}

// OWASPCategory identifies which OWASP Top 10 list a mapping belongs to.
type OWASPCategory string

const (
	OWASPCategoryAPI OWASPCategory = "api" // API Security Top 10
	OWASPCategoryLLM OWASPCategory = "llm" // LLM Application Top 10
	OWASPCategoryWeb OWASPCategory = "web" // Web Application Top 10
)

// JSONSchema implements jsonschema.JSONSchemaer for OWASPCategory.
func (OWASPCategory) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"api", "llm", "web"},
	}
}

// OWASPMapping represents an OWASP Top 10 reference.
type OWASPMapping struct {
	// Category identifies which OWASP list (api, llm, web).
	Category OWASPCategory `json:"category"`

	// ID is the OWASP ID (e.g., "API2:2023", "LLM06:2025", "A01:2021").
	ID string `json:"id"`

	// Name is the human-readable name (e.g., "Broken Authentication").
	Name string `json:"name,omitempty"`

	// Description explains how this applies to the threat model.
	Description string `json:"description,omitempty"`

	// URL is the link to the OWASP page.
	URL string `json:"url,omitempty"`
}

// CWEMapping represents a Common Weakness Enumeration reference.
type CWEMapping struct {
	// ID is the CWE ID (e.g., "CWE-346").
	ID string `json:"id"`

	// Name is the human-readable name (e.g., "Origin Validation Error").
	Name string `json:"name,omitempty"`

	// Description explains how this weakness applies.
	Description string `json:"description,omitempty"`

	// URL is the link to the CWE page.
	URL string `json:"url,omitempty"`
}

// CVSSMapping represents a CVSS (Common Vulnerability Scoring System) assessment.
type CVSSMapping struct {
	// Version is the CVSS version (e.g., "3.1", "4.0").
	Version string `json:"version"`

	// Vector is the CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N").
	Vector string `json:"vector"`

	// BaseScore is the calculated base score (0.0 - 10.0).
	BaseScore float64 `json:"baseScore"`

	// Severity is the qualitative severity rating.
	Severity CVSSSeverity `json:"severity"`

	// Description provides context for the scoring.
	Description string `json:"description,omitempty"`
}

// CVSSSeverity represents the qualitative severity rating.
type CVSSSeverity string

const (
	CVSSSeverityNone     CVSSSeverity = "None"
	CVSSSeverityLow      CVSSSeverity = "Low"
	CVSSSeverityMedium   CVSSSeverity = "Medium"
	CVSSSeverityHigh     CVSSSeverity = "High"
	CVSSSeverityCritical CVSSSeverity = "Critical"
)

// JSONSchema implements jsonschema.JSONSchemaer for CVSSSeverity.
func (CVSSSeverity) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"None", "Low", "Medium", "High", "Critical"},
	}
}

// STRIDEMapping represents a STRIDE threat category mapping with details.
type STRIDEMapping struct {
	// Category is the STRIDE category (S, T, R, I, D, E).
	Category STRIDEThreat `json:"category"`

	// Name is the full name (e.g., "Spoofing", "Tampering").
	Name string `json:"name,omitempty"`

	// Description explains how this threat applies.
	Description string `json:"description,omitempty"`

	// AffectedComponents lists the component IDs affected by this threat.
	AffectedComponents []string `json:"affectedComponents,omitempty"`
}

// GetSTRIDEName returns the full name for a STRIDE category.
func GetSTRIDEName(s STRIDEThreat) string {
	switch s {
	case STRIDESpoofing:
		return "Spoofing"
	case STRIDETampering:
		return "Tampering"
	case STRIDERepudiation:
		return "Repudiation"
	case STRIDEInformationDisc:
		return "Information Disclosure"
	case STRIDEDenialOfService:
		return "Denial of Service"
	case STRIDEElevationOfPrivilege:
		return "Elevation of Privilege"
	default:
		return string(s)
	}
}
