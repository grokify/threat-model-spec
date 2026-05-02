package ir

import "github.com/invopop/jsonschema"

// PlaybookPhase identifies the phase of incident response.
type PlaybookPhase string

const (
	PlaybookPhasePreparation   PlaybookPhase = "preparation"
	PlaybookPhaseIdentification PlaybookPhase = "identification"
	PlaybookPhaseContainment   PlaybookPhase = "containment"
	PlaybookPhaseEradication   PlaybookPhase = "eradication"
	PlaybookPhaseRecovery      PlaybookPhase = "recovery"
	PlaybookPhaseLessonsLearned PlaybookPhase = "lessons-learned"
)

// JSONSchema implements jsonschema.JSONSchemaer for PlaybookPhase.
func (PlaybookPhase) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"preparation", "identification", "containment", "eradication", "recovery", "lessons-learned"},
	}
}

// IncidentPlaybook describes incident response procedures for a threat.
type IncidentPlaybook struct {
	// ID is the unique identifier for this playbook.
	ID string `json:"id"`

	// Name is the playbook name.
	Name string `json:"name"`

	// Description provides an overview of this playbook.
	Description string `json:"description,omitempty"`

	// ThreatType identifies the type of threat this playbook addresses.
	ThreatType string `json:"threatType,omitempty"`

	// Severity indicates the incident severity this playbook handles.
	Severity string `json:"severity,omitempty"`

	// Steps contains the ordered response steps.
	Steps []PlaybookStep `json:"steps,omitempty"`

	// Contacts lists people/teams to contact during the incident.
	Contacts []Contact `json:"contacts,omitempty"`

	// Tools lists tools needed for incident response.
	Tools []string `json:"tools,omitempty"`

	// References lists external resources.
	References []string `json:"references,omitempty"`

	// MITRETechniques lists MITRE ATT&CK techniques this playbook addresses.
	MITRETechniques []string `json:"mitreTechniques,omitempty"`

	// SLAMinutes is the expected response time SLA in minutes.
	SLAMinutes int `json:"slaMinutes,omitempty"`

	// LastReviewed is the date this playbook was last reviewed.
	LastReviewed string `json:"lastReviewed,omitempty"`

	// Owner is the team or person responsible for this playbook.
	Owner string `json:"owner,omitempty"`

	// Tags are metadata tags for categorization.
	Tags []string `json:"tags,omitempty"`
}

// PlaybookStep represents a single step in an incident response playbook.
type PlaybookStep struct {
	// Step is the sequence number (1, 2, 3...).
	Step int `json:"step"`

	// Phase is the incident response phase (identification, containment, etc.).
	Phase PlaybookPhase `json:"phase,omitempty"`

	// Action describes what to do in this step.
	Action string `json:"action"`

	// Description provides detailed instructions.
	Description string `json:"description,omitempty"`

	// Owner is the team or role responsible for this step.
	Owner string `json:"owner,omitempty"`

	// Automated indicates if this step can be automated.
	Automated bool `json:"automated,omitempty"`

	// AutomationScript is the script or tool to run for automated steps.
	AutomationScript string `json:"automationScript,omitempty"`

	// TimeMinutes is the estimated time for this step in minutes.
	TimeMinutes int `json:"timeMinutes,omitempty"`

	// Dependencies lists step numbers that must complete before this one.
	Dependencies []int `json:"dependencies,omitempty"`

	// EscalationTrigger describes when to escalate from this step.
	EscalationTrigger string `json:"escalationTrigger,omitempty"`

	// Notes provides additional context.
	Notes string `json:"notes,omitempty"`

	// Commands lists specific commands to run.
	Commands []string `json:"commands,omitempty"`

	// Checklist provides items to verify during this step.
	Checklist []string `json:"checklist,omitempty"`
}

// Contact represents a person or team to contact during an incident.
type Contact struct {
	// Name is the contact name.
	Name string `json:"name"`

	// Role is the contact's role (e.g., "Security Lead", "On-Call Engineer").
	Role string `json:"role,omitempty"`

	// Email is the contact's email address.
	Email string `json:"email,omitempty"`

	// Phone is the contact's phone number.
	Phone string `json:"phone,omitempty"`

	// Slack is the contact's Slack handle or channel.
	Slack string `json:"slack,omitempty"`

	// PagerDuty is the PagerDuty schedule or escalation policy.
	PagerDuty string `json:"pagerDuty,omitempty"`

	// Availability describes when this contact is available.
	Availability string `json:"availability,omitempty"`

	// Primary indicates if this is the primary contact.
	Primary bool `json:"primary,omitempty"`
}
