package ir

import "github.com/invopop/jsonschema"

// LINDDUNThreat identifies a LINDDUN privacy threat category.
// LINDDUN is a privacy threat modeling framework that complements STRIDE.
type LINDDUNThreat string

const (
	// LINDDUNLinkability - Ability to link two or more items of interest.
	LINDDUNLinkability LINDDUNThreat = "L"

	// LINDDUNIdentifiability - Ability to identify a subject from a set of subjects.
	LINDDUNIdentifiability LINDDUNThreat = "I"

	// LINDDUNNonRepudiation - Inability to deny an action or involvement.
	LINDDUNNonRepudiation LINDDUNThreat = "N"

	// LINDDUNDetectability - Ability to detect the existence of an item of interest.
	LINDDUNDetectability LINDDUNThreat = "D"

	// LINDDUNDisclosure - Exposure of information to unauthorized parties.
	LINDDUNDisclosure LINDDUNThreat = "Di"

	// LINDDUNUnawareness - Lack of awareness of data processing activities.
	LINDDUNUnawareness LINDDUNThreat = "U"

	// LINDDUNNonCompliance - Failure to comply with legislation, regulation, or policy.
	LINDDUNNonCompliance LINDDUNThreat = "Nc"
)

// JSONSchema implements jsonschema.JSONSchemaer for LINDDUNThreat.
func (LINDDUNThreat) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"L", "I", "N", "D", "Di", "U", "Nc"},
	}
}

// GetLINDDUNName returns the full name for a LINDDUN category.
func GetLINDDUNName(t LINDDUNThreat) string {
	switch t {
	case LINDDUNLinkability:
		return "Linkability"
	case LINDDUNIdentifiability:
		return "Identifiability"
	case LINDDUNNonRepudiation:
		return "Non-repudiation"
	case LINDDUNDetectability:
		return "Detectability"
	case LINDDUNDisclosure:
		return "Disclosure of Information"
	case LINDDUNUnawareness:
		return "Unawareness"
	case LINDDUNNonCompliance:
		return "Non-compliance"
	default:
		return string(t)
	}
}

// GetLINDDUNDescription returns a description for a LINDDUN category.
func GetLINDDUNDescription(t LINDDUNThreat) string {
	switch t {
	case LINDDUNLinkability:
		return "Ability to link two or more items of interest about a data subject"
	case LINDDUNIdentifiability:
		return "Ability to identify a data subject within a set of subjects"
	case LINDDUNNonRepudiation:
		return "Inability to deny having performed an action or being involved"
	case LINDDUNDetectability:
		return "Ability to detect the existence of an item of interest"
	case LINDDUNDisclosure:
		return "Exposure of personal information to unauthorized parties"
	case LINDDUNUnawareness:
		return "Lack of awareness about what data is collected and how it is processed"
	case LINDDUNNonCompliance:
		return "Failure to comply with privacy legislation, regulation, or policy"
	default:
		return ""
	}
}

// LINDDUNMapping represents a LINDDUN privacy threat mapping with details.
type LINDDUNMapping struct {
	// Category is the LINDDUN category (L, I, N, D, Di, U, Nc).
	Category LINDDUNThreat `json:"category"`

	// Name is the full name (e.g., "Linkability", "Identifiability").
	Name string `json:"name,omitempty"`

	// Description explains how this privacy threat applies.
	Description string `json:"description,omitempty"`

	// AffectedDataTypes lists the types of personal data affected.
	// Examples: "PII", "PHI", "financial", "biometric", "location".
	AffectedDataTypes []string `json:"affectedDataTypes,omitempty"`

	// AffectedComponents lists the component IDs affected by this threat.
	AffectedComponents []string `json:"affectedComponents,omitempty"`

	// DataSubjects identifies the categories of data subjects affected.
	// Examples: "customers", "employees", "patients", "minors".
	DataSubjects []string `json:"dataSubjects,omitempty"`

	// PrivacyPrinciple identifies the privacy principle violated.
	// Examples: "data minimization", "purpose limitation", "consent".
	PrivacyPrinciple string `json:"privacyPrinciple,omitempty"`
}

// DataCategory represents categories of personal or sensitive data.
type DataCategory string

const (
	DataCategoryPII        DataCategory = "pii"        // Personally Identifiable Information
	DataCategoryPHI        DataCategory = "phi"        // Protected Health Information
	DataCategoryFinancial  DataCategory = "financial"  // Financial data
	DataCategoryBiometric  DataCategory = "biometric"  // Biometric data
	DataCategoryLocation   DataCategory = "location"   // Location data
	DataCategoryBehavioral DataCategory = "behavioral" // Behavioral/tracking data
	DataCategoryGenetic    DataCategory = "genetic"    // Genetic data
	DataCategoryMinor      DataCategory = "minor"      // Data about minors
	DataCategorySensitive  DataCategory = "sensitive"  // Other sensitive categories
)

// JSONSchema implements jsonschema.JSONSchemaer for DataCategory.
func (DataCategory) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"pii", "phi", "financial", "biometric", "location",
			"behavioral", "genetic", "minor", "sensitive",
		},
	}
}
