package ir

import "github.com/invopop/jsonschema"

// ScenarioType categorizes the type of attack scenario.
type ScenarioType string

const (
	// ScenarioTypeExternalAttack represents attacks from external threat actors.
	ScenarioTypeExternalAttack ScenarioType = "external-attack"

	// ScenarioTypeInsiderThreat represents attacks from insiders.
	ScenarioTypeInsiderThreat ScenarioType = "insider-threat"

	// ScenarioTypeSupplyChain represents supply chain compromise scenarios.
	ScenarioTypeSupplyChain ScenarioType = "supply-chain"

	// ScenarioTypeDataBreach represents data breach scenarios.
	ScenarioTypeDataBreach ScenarioType = "data-breach"

	// ScenarioTypePrivacyViolation represents privacy violation scenarios.
	ScenarioTypePrivacyViolation ScenarioType = "privacy-violation"

	// ScenarioTypeDenialOfService represents availability attack scenarios.
	ScenarioTypeDenialOfService ScenarioType = "denial-of-service"

	// ScenarioTypeEscalation represents privilege escalation scenarios.
	ScenarioTypeEscalation ScenarioType = "escalation"
)

// JSONSchema implements jsonschema.JSONSchemaer for ScenarioType.
func (ScenarioType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"external-attack", "insider-threat", "supply-chain", "data-breach", "privacy-violation", "denial-of-service", "escalation"},
	}
}

// Scenario represents a what-if attack scenario for analysis.
// Scenarios help explore potential attack paths during design-time threat modeling.
type Scenario struct {
	// ID is the unique identifier for the scenario.
	ID string `json:"id"`

	// Title is a brief description of the scenario.
	Title string `json:"title"`

	// Description provides the full scenario narrative.
	Description string `json:"description,omitempty"`

	// Type categorizes the scenario.
	Type ScenarioType `json:"type,omitempty"`

	// ThreatActorID links to the threat actor profile executing this scenario.
	ThreatActorID string `json:"threatActorId,omitempty"`

	// Preconditions that must be true for this scenario to be viable.
	// Example: "Attacker has network access to DMZ"
	Preconditions []string `json:"preconditions,omitempty"`

	// AttackPath describes the sequence of attack steps.
	// Can reference element IDs, attack IDs, or free-form descriptions.
	AttackPath []string `json:"attackPath,omitempty"`

	// TargetAssetIDs lists the assets targeted in this scenario.
	TargetAssetIDs []string `json:"targetAssetIds,omitempty"`

	// TargetElementIDs lists the diagram elements targeted.
	TargetElementIDs []string `json:"targetElementIds,omitempty"`

	// ThreatIDs links to ThreatEntry IDs relevant to this scenario.
	ThreatIDs []string `json:"threatIds,omitempty"`

	// Risk assessment for this scenario.
	Risk *RiskAssessment `json:"risk,omitempty"`

	// Outcome describes what happens if the attack succeeds.
	Outcome string `json:"outcome,omitempty"`

	// BusinessImpact describes the business consequences.
	BusinessImpact string `json:"businessImpact,omitempty"`

	// MitigationIDs lists mitigations that would prevent this scenario.
	MitigationIDs []string `json:"mitigationIds,omitempty"`

	// DetectionIDs lists detections that would identify this scenario.
	DetectionIDs []string `json:"detectionIds,omitempty"`

	// Notes provides additional analysis or commentary.
	Notes string `json:"notes,omitempty"`
}
