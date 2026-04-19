package ir

import "github.com/invopop/jsonschema"

// MitigationStatus represents the current state of a mitigation.
type MitigationStatus string

const (
	// MitigationStatusPlanned indicates the mitigation is planned but not implemented.
	MitigationStatusPlanned MitigationStatus = "planned"

	// MitigationStatusImplemented indicates the mitigation is fully implemented.
	MitigationStatusImplemented MitigationStatus = "implemented"

	// MitigationStatusPartial indicates the mitigation is partially implemented.
	MitigationStatusPartial MitigationStatus = "partial"

	// MitigationStatusAccepted indicates the risk is accepted without mitigation.
	MitigationStatusAccepted MitigationStatus = "accepted"

	// MitigationStatusTransferred indicates the risk is transferred (e.g., insurance).
	MitigationStatusTransferred MitigationStatus = "transferred"

	// MitigationStatusNotApplicable indicates the mitigation does not apply.
	MitigationStatusNotApplicable MitigationStatus = "not-applicable"
)

// JSONSchema implements jsonschema.JSONSchemaer for MitigationStatus.
func (MitigationStatus) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"planned", "implemented", "partial", "accepted", "transferred", "not-applicable"},
	}
}

// ThreatStatus represents the lifecycle state of an identified threat.
type ThreatStatus string

const (
	// ThreatStatusIdentified indicates the threat has been identified.
	ThreatStatusIdentified ThreatStatus = "identified"

	// ThreatStatusAnalyzing indicates the threat is under analysis.
	ThreatStatusAnalyzing ThreatStatus = "analyzing"

	// ThreatStatusMitigated indicates the threat has been mitigated.
	ThreatStatusMitigated ThreatStatus = "mitigated"

	// ThreatStatusAccepted indicates the threat risk is accepted.
	ThreatStatusAccepted ThreatStatus = "accepted"

	// ThreatStatusTransferred indicates the threat risk is transferred.
	ThreatStatusTransferred ThreatStatus = "transferred"

	// ThreatStatusMonitoring indicates the threat is being monitored.
	ThreatStatusMonitoring ThreatStatus = "monitoring"
)

// JSONSchema implements jsonschema.JSONSchemaer for ThreatStatus.
func (ThreatStatus) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"identified", "analyzing", "mitigated", "accepted", "transferred", "monitoring"},
	}
}

// Mitigation represents a countermeasure or control that addresses one or more threats.
type Mitigation struct {
	// ID is the unique identifier for the mitigation.
	ID string `json:"id"`

	// Title is a brief description of the mitigation.
	Title string `json:"title"`

	// Description provides detailed information about the mitigation.
	Description string `json:"description,omitempty"`

	// ThreatIDs lists the IDs of threats this mitigation addresses.
	// These can reference Attack steps, Flow IDs, or Element IDs.
	ThreatIDs []string `json:"threatIds,omitempty"`

	// STRIDECategories lists the STRIDE categories this mitigation addresses.
	STRIDECategories []STRIDEThreat `json:"strideCategories,omitempty"`

	// ControlID references the security control implementing this mitigation.
	// Can reference NIST CSF, CIS, or ISO 27001 control IDs.
	ControlID string `json:"controlId,omitempty"`

	// Status indicates the current implementation status.
	Status MitigationStatus `json:"status"`

	// Owner is the person or team responsible for the mitigation.
	Owner string `json:"owner,omitempty"`

	// VerifiedDate is when the mitigation was verified as effective (RFC 3339 format).
	VerifiedDate string `json:"verifiedDate,omitempty"`

	// Effectiveness describes how effective the mitigation is (high, medium, low).
	Effectiveness string `json:"effectiveness,omitempty"`

	// Notes provides additional context or implementation details.
	Notes string `json:"notes,omitempty"`
}

// ThreatEntry represents an identified threat with status tracking.
// This can be used to track threats independently of diagram elements.
type ThreatEntry struct {
	// ID is the unique identifier for the threat.
	ID string `json:"id"`

	// Title is a brief description of the threat.
	Title string `json:"title"`

	// Description provides detailed information about the threat.
	Description string `json:"description,omitempty"`

	// STRIDECategory identifies the STRIDE threat category.
	STRIDECategory STRIDEThreat `json:"strideCategory,omitempty"`

	// AffectedElements lists the element IDs affected by this threat.
	AffectedElements []string `json:"affectedElements,omitempty"`

	// Status indicates the current threat lifecycle state.
	Status ThreatStatus `json:"status"`

	// Severity indicates the threat severity (critical, high, medium, low).
	Severity string `json:"severity,omitempty"`

	// Likelihood indicates the probability of exploitation (high, medium, low).
	Likelihood string `json:"likelihood,omitempty"`

	// MitigationIDs lists the IDs of mitigations addressing this threat.
	MitigationIDs []string `json:"mitigationIds,omitempty"`
}
