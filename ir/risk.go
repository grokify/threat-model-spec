package ir

import "github.com/invopop/jsonschema"

// RiskLevel represents the categorical risk level.
type RiskLevel string

const (
	// RiskLevelCritical represents critical risk (score 20-25).
	RiskLevelCritical RiskLevel = "critical"

	// RiskLevelHigh represents high risk (score 15-19).
	RiskLevelHigh RiskLevel = "high"

	// RiskLevelMedium represents medium risk (score 8-14).
	RiskLevelMedium RiskLevel = "medium"

	// RiskLevelLow represents low risk (score 4-7).
	RiskLevelLow RiskLevel = "low"

	// RiskLevelInfo represents informational/minimal risk (score 1-3).
	RiskLevelInfo RiskLevel = "info"
)

// JSONSchema implements jsonschema.JSONSchemaer for RiskLevel.
func (RiskLevel) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"critical", "high", "medium", "low", "info"},
	}
}

// RiskAssessment provides structured risk scoring based on likelihood and impact.
// The score is calculated as Likelihood × Impact (1-25 scale).
type RiskAssessment struct {
	// Likelihood of exploitation (1-5 scale).
	// 1=Rare, 2=Unlikely, 3=Possible, 4=Likely, 5=Almost Certain
	Likelihood int `json:"likelihood"`

	// Impact if exploited (1-5 scale).
	// 1=Negligible, 2=Minor, 3=Moderate, 4=Major, 5=Severe
	Impact int `json:"impact"`

	// Score is Likelihood × Impact (1-25, can be calculated or provided).
	Score int `json:"score,omitempty"`

	// Level is the categorical risk level (can be calculated from score).
	Level RiskLevel `json:"level,omitempty"`

	// LikelihoodRationale explains why this likelihood was chosen.
	LikelihoodRationale string `json:"likelihoodRationale,omitempty"`

	// ImpactRationale explains why this impact was chosen.
	ImpactRationale string `json:"impactRationale,omitempty"`
}

// Calculate computes the Score and Level from Likelihood and Impact.
func (r *RiskAssessment) Calculate() {
	r.Score = r.Likelihood * r.Impact
	r.Level = ScoreToLevel(r.Score)
}

// ScoreToLevel converts a numeric risk score (1-25) to a RiskLevel.
func ScoreToLevel(score int) RiskLevel {
	switch {
	case score >= 20:
		return RiskLevelCritical
	case score >= 15:
		return RiskLevelHigh
	case score >= 8:
		return RiskLevelMedium
	case score >= 4:
		return RiskLevelLow
	default:
		return RiskLevelInfo
	}
}

// IsValid checks if the RiskAssessment has valid values.
func (r *RiskAssessment) IsValid() bool {
	return r.Likelihood >= 1 && r.Likelihood <= 5 &&
		r.Impact >= 1 && r.Impact <= 5
}

// ModelPhase indicates the SDLC phase of the threat model.
type ModelPhase string

const (
	// ModelPhaseDesign indicates pre-implementation threat modeling.
	ModelPhaseDesign ModelPhase = "design"

	// ModelPhaseDevelopment indicates threat modeling during implementation.
	ModelPhaseDevelopment ModelPhase = "development"

	// ModelPhaseReview indicates a security review phase.
	ModelPhaseReview ModelPhase = "review"

	// ModelPhaseProduction indicates threat modeling of a live system.
	ModelPhaseProduction ModelPhase = "production"

	// ModelPhaseIncident indicates post-incident threat analysis.
	ModelPhaseIncident ModelPhase = "incident"
)

// JSONSchema implements jsonschema.JSONSchemaer for ModelPhase.
func (ModelPhase) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"design", "development", "review", "production", "incident"},
	}
}
