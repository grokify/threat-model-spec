package ir

import (
	"time"
)

// VEXStatus represents the status of a vulnerability in a VEX statement
type VEXStatus string

const (
	VEXStatusNotAffected        VEXStatus = "not_affected"
	VEXStatusAffected           VEXStatus = "affected"
	VEXStatusFixed              VEXStatus = "fixed"
	VEXStatusUnderInvestigation VEXStatus = "under_investigation"
)

// VEXJustification provides the reason for a not_affected status
type VEXJustification string

const (
	// VEXJustificationComponentNotPresent - the vulnerable component is not included
	VEXJustificationComponentNotPresent VEXJustification = "component_not_present"

	// VEXJustificationVulnerableCodeNotPresent - the vulnerable code is not present
	VEXJustificationVulnerableCodeNotPresent VEXJustification = "vulnerable_code_not_present"

	// VEXJustificationVulnerableCodeNotInExecutePath - vulnerable code exists but cannot be executed
	VEXJustificationVulnerableCodeNotInExecutePath VEXJustification = "vulnerable_code_not_in_execute_path"

	// VEXJustificationVulnerableCodeCannotBeControlledByAdversary - input cannot reach vulnerable code
	VEXJustificationVulnerableCodeCannotBeControlledByAdversary VEXJustification = "vulnerable_code_cannot_be_controlled_by_adversary"

	// VEXJustificationInlineMitigationsAlreadyExist - mitigations are in place
	VEXJustificationInlineMitigationsAlreadyExist VEXJustification = "inline_mitigations_already_exist"
)

// VEXStatement represents a Vulnerability Exploitability eXchange statement
type VEXStatement struct {
	// ID is a unique identifier for this VEX statement
	ID string `json:"id,omitempty"`

	// VulnerabilityID is the CVE or other vulnerability identifier
	VulnerabilityID string `json:"vulnerabilityId,omitempty"`

	// Status indicates the exploitability status
	Status VEXStatus `json:"status,omitempty"`

	// Justification explains why status is not_affected (required when status is not_affected)
	Justification VEXJustification `json:"justification,omitempty"`

	// ImpactStatement provides additional context for the status
	ImpactStatement string `json:"impactStatement,omitempty"`

	// ActionStatement describes what action is recommended
	ActionStatement string `json:"actionStatement,omitempty"`

	// Products lists the affected product identifiers (PURLs, CPEs, etc.)
	Products []string `json:"products,omitempty"`

	// Subcomponents lists specific subcomponents if not the entire product
	Subcomponents []string `json:"subcomponents,omitempty"`

	// Supplier is the organization making this statement
	Supplier string `json:"supplier,omitempty"`

	// Timestamp is when this statement was made
	Timestamp time.Time `json:"timestamp,omitempty"`

	// LastUpdated is when this statement was last modified
	LastUpdated time.Time `json:"lastUpdated,omitempty"`

	// Version is the version of this VEX statement
	Version string `json:"version,omitempty"`
}

// VEXDocument represents a collection of VEX statements (OpenVEX format)
type VEXDocument struct {
	// Context is the JSON-LD context (typically "https://openvex.dev/ns/v0.2.0")
	Context string `json:"@context,omitempty"`

	// ID is the document identifier
	ID string `json:"@id,omitempty"`

	// Author is the entity that created this document
	Author string `json:"author,omitempty"`

	// Role is the author's role (e.g., "vendor", "coordinator", "discoverer")
	Role string `json:"role,omitempty"`

	// Timestamp is when this document was created
	Timestamp time.Time `json:"timestamp,omitempty"`

	// Version is the document version
	Version string `json:"version,omitempty"`

	// Tooling describes the tool that generated this document
	Tooling string `json:"tooling,omitempty"`

	// Statements contains the VEX statements
	Statements []VEXStatement `json:"statements,omitempty"`
}

// NewVEXDocument creates a new VEX document with default context
func NewVEXDocument(author string) *VEXDocument {
	return &VEXDocument{
		Context:   "https://openvex.dev/ns/v0.2.0",
		Author:    author,
		Timestamp: time.Now().UTC(),
		Version:   "1",
	}
}

// AddStatement adds a VEX statement to the document
func (d *VEXDocument) AddStatement(stmt VEXStatement) {
	if stmt.Timestamp.IsZero() {
		stmt.Timestamp = time.Now().UTC()
	}
	d.Statements = append(d.Statements, stmt)
}

// NewNotAffectedStatement creates a VEX statement for a not_affected vulnerability
func NewNotAffectedStatement(vulnID string, justification VEXJustification, products []string, impactStatement string) VEXStatement {
	return VEXStatement{
		VulnerabilityID: vulnID,
		Status:          VEXStatusNotAffected,
		Justification:   justification,
		Products:        products,
		ImpactStatement: impactStatement,
		Timestamp:       time.Now().UTC(),
	}
}

// NewAffectedStatement creates a VEX statement for an affected vulnerability
func NewAffectedStatement(vulnID string, products []string, actionStatement string) VEXStatement {
	return VEXStatement{
		VulnerabilityID: vulnID,
		Status:          VEXStatusAffected,
		Products:        products,
		ActionStatement: actionStatement,
		Timestamp:       time.Now().UTC(),
	}
}

// NewFixedStatement creates a VEX statement for a fixed vulnerability
func NewFixedStatement(vulnID string, products []string, impactStatement string) VEXStatement {
	return VEXStatement{
		VulnerabilityID: vulnID,
		Status:          VEXStatusFixed,
		Products:        products,
		ImpactStatement: impactStatement,
		Timestamp:       time.Now().UTC(),
	}
}

// NewUnderInvestigationStatement creates a VEX statement for a vulnerability under investigation
func NewUnderInvestigationStatement(vulnID string, products []string) VEXStatement {
	return VEXStatement{
		VulnerabilityID: vulnID,
		Status:          VEXStatusUnderInvestigation,
		Products:        products,
		Timestamp:       time.Now().UTC(),
	}
}

// IsValid checks if the VEX statement has required fields
func (s *VEXStatement) IsValid() bool {
	if s.VulnerabilityID == "" || s.Status == "" {
		return false
	}
	// Justification is required for not_affected status
	if s.Status == VEXStatusNotAffected && s.Justification == "" {
		return false
	}
	return true
}
