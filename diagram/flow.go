package diagram

import (
	"github.com/grokify/threat-model-spec/killchain"
	"github.com/grokify/threat-model-spec/stride"
)

// FlowType represents the type of data flow.
type FlowType string

const (
	// NormalFlow represents legitimate data flow.
	NormalFlow FlowType = "flow-normal"

	// AttackFlow represents malicious traffic.
	AttackFlow FlowType = "flow-attack"

	// ExfilFlow represents data exfiltration.
	ExfilFlow FlowType = "flow-exfil"

	// LateralFlow represents lateral movement.
	LateralFlow FlowType = "flow-lateral"

	// C2Flow represents command and control traffic.
	C2Flow FlowType = "flow-c2"
)

// D2Class returns the D2 style class for this flow type.
func (f FlowType) D2Class() string {
	return string(f)
}

// Flow represents a data flow between elements.
type Flow struct {
	// ID is an optional identifier for this flow.
	ID string `json:"id,omitempty"`

	// From is the source element ID.
	From string `json:"from"`

	// To is the destination element ID.
	To string `json:"to"`

	// Label is the display text for this flow.
	Label string `json:"label,omitempty"`

	// Type is the flow type.
	Type FlowType `json:"type"`

	// Step is the attack step number (if this is an attack flow).
	Step int `json:"step,omitempty"`

	// Threats lists STRIDE threats associated with this flow.
	Threats []stride.Threat `json:"threats,omitempty"`

	// MITRETactic maps to a MITRE ATT&CK tactic.
	MITRETactic killchain.MITRETactic `json:"mitreTactic,omitempty"`

	// MITRETechnique maps to a specific MITRE ATT&CK technique.
	MITRETechnique *killchain.Technique `json:"mitreTechnique,omitempty"`

	// KillChainPhase maps to a Cyber Kill Chain phase.
	KillChainPhase killchain.LockheedPhase `json:"killChainPhase,omitempty"`

	// Style overrides the default style.
	Style *Style `json:"style,omitempty"`

	// Description provides additional context.
	Description string `json:"description,omitempty"`
}

// IsAttack returns true if this is an attack flow.
func (f Flow) IsAttack() bool {
	switch f.Type {
	case AttackFlow, ExfilFlow, LateralFlow, C2Flow:
		return true
	default:
		return false
	}
}

// GetLabel returns the label, optionally prefixed with step number.
func (f Flow) GetLabel() string {
	if f.Step > 0 && f.Label != "" {
		return f.Label // Step is typically included in the label already
	}
	return f.Label
}

// HasSTRIDE returns true if this flow has STRIDE threat annotations.
func (f Flow) HasSTRIDE() bool {
	return len(f.Threats) > 0
}

// HasMITRE returns true if this flow has MITRE ATT&CK mapping.
func (f Flow) HasMITRE() bool {
	return f.MITRETactic != "" || f.MITRETechnique != nil
}
