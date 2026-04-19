package ir

import "github.com/invopop/jsonschema"

// AssumptionType categorizes the type of assumption.
type AssumptionType string

const (
	// AssumptionTypeTrust relates to trust relationships.
	AssumptionTypeTrust AssumptionType = "trust"

	// AssumptionTypeSecurity relates to security controls in place.
	AssumptionTypeSecurity AssumptionType = "security"

	// AssumptionTypeOperational relates to operational procedures.
	AssumptionTypeOperational AssumptionType = "operational"

	// AssumptionTypeEnvironment relates to the deployment environment.
	AssumptionTypeEnvironment AssumptionType = "environment"

	// AssumptionTypeThreat relates to threat actor capabilities.
	AssumptionTypeThreat AssumptionType = "threat"

	// AssumptionTypeCompliance relates to compliance requirements.
	AssumptionTypeCompliance AssumptionType = "compliance"

	// AssumptionTypeDependency relates to external dependencies.
	AssumptionTypeDependency AssumptionType = "dependency"
)

// JSONSchema implements jsonschema.JSONSchemaer for AssumptionType.
func (AssumptionType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"trust", "security", "operational", "environment",
			"threat", "compliance", "dependency",
		},
	}
}

// ValidationStatus indicates whether an assumption has been validated.
type ValidationStatus string

const (
	ValidationStatusNotValidated ValidationStatus = "not-validated"
	ValidationStatusValidated    ValidationStatus = "validated"
	ValidationStatusInvalidated  ValidationStatus = "invalidated"
	ValidationStatusPending      ValidationStatus = "pending"
)

// JSONSchema implements jsonschema.JSONSchemaer for ValidationStatus.
func (ValidationStatus) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"not-validated", "validated", "invalidated", "pending"},
	}
}

// Assumption represents a security assumption that underlies the threat model.
type Assumption struct {
	// ID is the unique identifier for the assumption.
	ID string `json:"id"`

	// Title is a brief statement of the assumption.
	Title string `json:"title"`

	// Description provides detailed context about the assumption.
	Description string `json:"description,omitempty"`

	// Type categorizes the assumption.
	Type AssumptionType `json:"type,omitempty"`

	// Rationale explains why this assumption is made.
	Rationale string `json:"rationale,omitempty"`

	// Impact describes what happens if the assumption is violated.
	Impact string `json:"impact,omitempty"`

	// ImpactSeverity rates the impact severity (critical, high, medium, low).
	ImpactSeverity string `json:"impactSeverity,omitempty"`

	// ValidationStatus indicates whether the assumption has been validated.
	ValidationStatus ValidationStatus `json:"validationStatus,omitempty"`

	// ValidationMethod describes how the assumption can be or was validated.
	ValidationMethod string `json:"validationMethod,omitempty"`

	// ValidatedDate is when the assumption was validated (RFC 3339 format).
	ValidatedDate string `json:"validatedDate,omitempty"`

	// Owner is the person or team responsible for validating this assumption.
	Owner string `json:"owner,omitempty"`

	// RelatedComponentIDs lists components that depend on this assumption.
	RelatedComponentIDs []string `json:"relatedComponentIds,omitempty"`

	// Notes provides additional context or caveats.
	Notes string `json:"notes,omitempty"`
}

// Prerequisite represents a precondition that must be true for the threat model.
type Prerequisite struct {
	// ID is the unique identifier for the prerequisite.
	ID string `json:"id"`

	// Title is a brief description of the prerequisite.
	Title string `json:"title"`

	// Description provides detailed information about the prerequisite.
	Description string `json:"description,omitempty"`

	// Type categorizes the prerequisite.
	Type AssumptionType `json:"type,omitempty"`

	// Required indicates if this prerequisite is mandatory.
	Required bool `json:"required,omitempty"`

	// Status indicates if the prerequisite is met (met, not-met, partial, unknown).
	Status string `json:"status,omitempty"`

	// DependsOn lists other prerequisite IDs that must be met first.
	DependsOn []string `json:"dependsOn,omitempty"`

	// RelatedThreatIDs lists threats that require this prerequisite.
	RelatedThreatIDs []string `json:"relatedThreatIds,omitempty"`

	// Notes provides additional context.
	Notes string `json:"notes,omitempty"`
}
