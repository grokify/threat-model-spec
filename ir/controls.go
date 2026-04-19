package ir

import "github.com/invopop/jsonschema"

// NISTCSFFunction represents the five core functions of the NIST Cybersecurity Framework.
type NISTCSFFunction string

const (
	NISTCSFIdentify NISTCSFFunction = "Identify"
	NISTCSFProtect  NISTCSFFunction = "Protect"
	NISTCSFDetect   NISTCSFFunction = "Detect"
	NISTCSFRespond  NISTCSFFunction = "Respond"
	NISTCSFRecover  NISTCSFFunction = "Recover"
)

// JSONSchema implements jsonschema.JSONSchemaer for NISTCSFFunction.
func (NISTCSFFunction) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"Identify", "Protect", "Detect", "Respond", "Recover"},
	}
}

// NISTCSFMapping represents a NIST Cybersecurity Framework control reference.
type NISTCSFMapping struct {
	// Function is the CSF function (Identify, Protect, Detect, Respond, Recover).
	Function NISTCSFFunction `json:"function"`

	// Category is the category ID (e.g., "ID.AM", "PR.AC").
	Category string `json:"category"`

	// CategoryName is the human-readable category name (e.g., "Asset Management").
	CategoryName string `json:"categoryName,omitempty"`

	// Subcategory is the subcategory ID (e.g., "ID.AM-1", "PR.AC-1").
	Subcategory string `json:"subcategory,omitempty"`

	// SubcategoryName is the human-readable subcategory description.
	SubcategoryName string `json:"subcategoryName,omitempty"`

	// Description explains how this control applies to the threat model.
	Description string `json:"description,omitempty"`

	// URL is a link to the NIST CSF documentation.
	URL string `json:"url,omitempty"`
}

// CISControlMapping represents a CIS Critical Security Controls reference.
type CISControlMapping struct {
	// ControlID is the control number (e.g., "1", "2", "16").
	ControlID string `json:"controlId"`

	// ControlName is the control title (e.g., "Inventory and Control of Enterprise Assets").
	ControlName string `json:"controlName,omitempty"`

	// SafeguardID is the specific safeguard ID (e.g., "1.1", "16.4").
	SafeguardID string `json:"safeguardId,omitempty"`

	// SafeguardName is the safeguard description.
	SafeguardName string `json:"safeguardName,omitempty"`

	// ImplementationGroup indicates the implementation group (IG1, IG2, IG3).
	ImplementationGroup string `json:"implementationGroup,omitempty"`

	// AssetType indicates the asset type (Devices, Software, Network, Data, Users).
	AssetType string `json:"assetType,omitempty"`

	// SecurityFunction indicates the security function (Identify, Protect, Detect, Respond, Recover).
	SecurityFunction string `json:"securityFunction,omitempty"`

	// Description explains how this control applies to the threat model.
	Description string `json:"description,omitempty"`

	// URL is a link to the CIS Controls documentation.
	URL string `json:"url,omitempty"`
}

// ISO27001Mapping represents an ISO/IEC 27001 control reference.
type ISO27001Mapping struct {
	// ControlID is the control reference (e.g., "A.5.1", "A.9.2.3").
	ControlID string `json:"controlId"`

	// ControlName is the control title.
	ControlName string `json:"controlName,omitempty"`

	// Domain is the control domain (e.g., "A.5 Information security policies").
	Domain string `json:"domain,omitempty"`

	// Objective is the control objective.
	Objective string `json:"objective,omitempty"`

	// Description explains how this control applies to the threat model.
	Description string `json:"description,omitempty"`

	// URL is a link to the ISO 27001 documentation.
	URL string `json:"url,omitempty"`
}

// ControlFramework identifies which control framework a mapping belongs to.
type ControlFramework string

const (
	ControlFrameworkNISTCSF  ControlFramework = "nist-csf"
	ControlFrameworkCIS      ControlFramework = "cis"
	ControlFrameworkISO27001 ControlFramework = "iso27001"
)

// JSONSchema implements jsonschema.JSONSchemaer for ControlFramework.
func (ControlFramework) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"nist-csf", "cis", "iso27001"},
	}
}

// Controls aggregates control framework mappings.
type Controls struct {
	// NISTCSF contains NIST Cybersecurity Framework mappings.
	NISTCSF []NISTCSFMapping `json:"nistCsf,omitempty"`

	// CIS contains CIS Critical Security Controls mappings.
	CIS []CISControlMapping `json:"cis,omitempty"`

	// ISO27001 contains ISO/IEC 27001 control mappings.
	ISO27001 []ISO27001Mapping `json:"iso27001,omitempty"`
}
