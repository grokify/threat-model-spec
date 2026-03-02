package killchain

// LockheedPhase represents a phase in the Lockheed Martin Cyber Kill Chain.
type LockheedPhase int

const (
	// Recon is the reconnaissance phase - harvesting email addresses,
	// conference information, etc.
	Recon LockheedPhase = iota + 1

	// Weaponization is coupling exploit with backdoor into deliverable payload.
	Weaponization

	// Delivery is delivering weaponized bundle to the victim via email,
	// web, USB, etc.
	Delivery

	// Exploitation is exploiting a vulnerability to execute code on
	// victim's system.
	Exploitation

	// Installation is installing malware on the asset.
	Installation

	// CommandControl is establishing command channel for remote manipulation.
	CommandControl

	// ActionsOnObjectives is accomplishing the original goals of the intrusion.
	ActionsOnObjectives
)

// String returns the full name of the kill chain phase.
func (p LockheedPhase) String() string {
	switch p {
	case Recon:
		return "Reconnaissance"
	case Weaponization:
		return "Weaponization"
	case Delivery:
		return "Delivery"
	case Exploitation:
		return "Exploitation"
	case Installation:
		return "Installation"
	case CommandControl:
		return "Command & Control"
	case ActionsOnObjectives:
		return "Actions on Objectives"
	default:
		return "Unknown"
	}
}

// ShortName returns a short name for the phase.
func (p LockheedPhase) ShortName() string {
	switch p {
	case Recon:
		return "Recon"
	case Weaponization:
		return "Weaponize"
	case Delivery:
		return "Deliver"
	case Exploitation:
		return "Exploit"
	case Installation:
		return "Install"
	case CommandControl:
		return "C2"
	case ActionsOnObjectives:
		return "Actions"
	default:
		return "Unknown"
	}
}

// D2Class returns the D2 style class name for this phase.
func (p LockheedPhase) D2Class() string {
	switch p {
	case Recon:
		return "killchain-recon"
	case Weaponization:
		return "killchain-weaponize"
	case Delivery:
		return "killchain-deliver"
	case Exploitation:
		return "killchain-exploit"
	case Installation:
		return "killchain-install"
	case CommandControl:
		return "killchain-c2"
	case ActionsOnObjectives:
		return "killchain-actions"
	default:
		return ""
	}
}

// Number returns the phase number (1-7).
func (p LockheedPhase) Number() int {
	return int(p)
}

// AllLockheedPhases returns all Cyber Kill Chain phases in order.
func AllLockheedPhases() []LockheedPhase {
	return []LockheedPhase{
		Recon,
		Weaponization,
		Delivery,
		Exploitation,
		Installation,
		CommandControl,
		ActionsOnObjectives,
	}
}

// KillChainStep represents a step in an attack mapped to the Kill Chain.
type KillChainStep struct {
	// Phase is the Kill Chain phase.
	Phase LockheedPhase `json:"phase"`

	// Description describes what happens in this step.
	Description string `json:"description"`

	// MITRETechnique optionally maps to a MITRE ATT&CK technique.
	MITRETechnique *Technique `json:"mitreTechnique,omitempty"`
}

// Label returns a formatted label for use in diagrams.
func (s KillChainStep) Label() string {
	return s.Phase.ShortName() + ": " + s.Description
}
