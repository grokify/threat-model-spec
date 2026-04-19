package ir

import "github.com/invopop/jsonschema"

// ThreatActorType identifies the category of threat actor.
type ThreatActorType string

const (
	// ThreatActorTypeNationState represents government-sponsored actors.
	ThreatActorTypeNationState ThreatActorType = "nation-state"

	// ThreatActorTypeCriminal represents financially motivated criminal organizations.
	ThreatActorTypeCriminal ThreatActorType = "criminal"

	// ThreatActorTypeHacktivist represents ideologically motivated actors.
	ThreatActorTypeHacktivist ThreatActorType = "hacktivist"

	// ThreatActorTypeInsider represents malicious or negligent insiders.
	ThreatActorTypeInsider ThreatActorType = "insider"

	// ThreatActorTypeCompetitor represents corporate espionage actors.
	ThreatActorTypeCompetitor ThreatActorType = "competitor"

	// ThreatActorTypeTerrorist represents terrorist organizations.
	ThreatActorTypeTerrorist ThreatActorType = "terrorist"

	// ThreatActorTypeScriptKiddie represents low-sophistication opportunistic actors.
	ThreatActorTypeScriptKiddie ThreatActorType = "script-kiddie"

	// ThreatActorTypeResearcher represents security researchers or ethical hackers.
	ThreatActorTypeResearcher ThreatActorType = "researcher"
)

// JSONSchema implements jsonschema.JSONSchemaer for ThreatActorType.
func (ThreatActorType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"nation-state", "criminal", "hacktivist", "insider",
			"competitor", "terrorist", "script-kiddie", "researcher",
		},
	}
}

// Sophistication represents the technical sophistication of a threat actor.
type Sophistication string

const (
	SophisticationNone     Sophistication = "none"
	SophisticationLow      Sophistication = "low"
	SophisticationMedium   Sophistication = "medium"
	SophisticationHigh     Sophistication = "high"
	SophisticationAdvanced Sophistication = "advanced"
)

// JSONSchema implements jsonschema.JSONSchemaer for Sophistication.
func (Sophistication) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"none", "low", "medium", "high", "advanced"},
	}
}

// Motivation identifies the primary motivation of a threat actor.
type Motivation string

const (
	MotivationFinancial    Motivation = "financial"
	MotivationEspionage    Motivation = "espionage"
	MotivationDisruption   Motivation = "disruption"
	MotivationDestruction  Motivation = "destruction"
	MotivationIdeological  Motivation = "ideological"
	MotivationRevenge      Motivation = "revenge"
	MotivationNotoriety    Motivation = "notoriety"
	MotivationCuriosity    Motivation = "curiosity"
	MotivationCompetitive  Motivation = "competitive"
)

// JSONSchema implements jsonschema.JSONSchemaer for Motivation.
func (Motivation) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"financial", "espionage", "disruption", "destruction",
			"ideological", "revenge", "notoriety", "curiosity", "competitive",
		},
	}
}

// ResourceLevel represents the resources available to a threat actor.
type ResourceLevel string

const (
	ResourceLevelMinimal   ResourceLevel = "minimal"
	ResourceLevelLimited   ResourceLevel = "limited"
	ResourceLevelModerate  ResourceLevel = "moderate"
	ResourceLevelExtensive ResourceLevel = "extensive"
	ResourceLevelUnlimited ResourceLevel = "unlimited"
)

// JSONSchema implements jsonschema.JSONSchemaer for ResourceLevel.
func (ResourceLevel) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"minimal", "limited", "moderate", "extensive", "unlimited"},
	}
}

// ThreatActor represents an adversary or threat source profile.
type ThreatActor struct {
	// ID is the unique identifier for the threat actor.
	ID string `json:"id"`

	// Name is the threat actor name or alias.
	Name string `json:"name"`

	// Type categorizes the threat actor.
	Type ThreatActorType `json:"type"`

	// Aliases lists other names this actor is known by.
	Aliases []string `json:"aliases,omitempty"`

	// Description provides context about the threat actor.
	Description string `json:"description,omitempty"`

	// Sophistication indicates the technical capability level.
	Sophistication Sophistication `json:"sophistication,omitempty"`

	// Motivations lists the actor's primary motivations.
	Motivations []Motivation `json:"motivations,omitempty"`

	// Resources indicates the resource level available.
	Resources ResourceLevel `json:"resources,omitempty"`

	// PrimaryGoals describes what the actor is trying to achieve.
	PrimaryGoals []string `json:"primaryGoals,omitempty"`

	// TTPs lists MITRE ATT&CK technique IDs associated with this actor.
	TTPs []string `json:"ttps,omitempty"`

	// TargetedIndustries lists industries this actor targets.
	TargetedIndustries []string `json:"targetedIndustries,omitempty"`

	// TargetedRegions lists geographic regions this actor targets.
	TargetedRegions []string `json:"targetedRegions,omitempty"`

	// KnownCampaigns lists known attack campaigns attributed to this actor.
	KnownCampaigns []string `json:"knownCampaigns,omitempty"`

	// References provides external links about this threat actor.
	References []string `json:"references,omitempty"`
}
