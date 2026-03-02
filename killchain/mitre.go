// Package killchain provides types for attack chain frameworks including
// MITRE ATT&CK and Lockheed Martin Cyber Kill Chain.
package killchain

// MITRETactic represents a MITRE ATT&CK tactic (the "why" of an attack).
type MITRETactic string

const (
	// Reconnaissance (TA0043) - Gathering information to plan future operations.
	Reconnaissance MITRETactic = "TA0043"

	// ResourceDevelopment (TA0042) - Establishing resources to support operations.
	ResourceDevelopment MITRETactic = "TA0042"

	// InitialAccess (TA0001) - Trying to get into your network.
	InitialAccess MITRETactic = "TA0001"

	// Execution (TA0002) - Trying to run malicious code.
	Execution MITRETactic = "TA0002"

	// Persistence (TA0003) - Trying to maintain foothold.
	Persistence MITRETactic = "TA0003"

	// PrivilegeEscalation (TA0004) - Trying to gain higher-level permissions.
	PrivilegeEscalation MITRETactic = "TA0004"

	// DefenseEvasion (TA0005) - Trying to avoid being detected.
	DefenseEvasion MITRETactic = "TA0005"

	// CredentialAccess (TA0006) - Trying to steal credentials.
	CredentialAccess MITRETactic = "TA0006"

	// Discovery (TA0007) - Trying to figure out your environment.
	Discovery MITRETactic = "TA0007"

	// LateralMovement (TA0008) - Trying to move through your environment.
	LateralMovement MITRETactic = "TA0008"

	// Collection (TA0009) - Trying to gather data of interest.
	Collection MITRETactic = "TA0009"

	// CommandAndControl (TA0011) - Trying to communicate with compromised systems.
	CommandAndControl MITRETactic = "TA0011"

	// Exfiltration (TA0010) - Trying to steal data.
	Exfiltration MITRETactic = "TA0010"

	// Impact (TA0040) - Trying to manipulate, interrupt, or destroy systems.
	Impact MITRETactic = "TA0040"
)

// String returns the full name of the tactic.
func (t MITRETactic) String() string {
	switch t {
	case Reconnaissance:
		return "Reconnaissance"
	case ResourceDevelopment:
		return "Resource Development"
	case InitialAccess:
		return "Initial Access"
	case Execution:
		return "Execution"
	case Persistence:
		return "Persistence"
	case PrivilegeEscalation:
		return "Privilege Escalation"
	case DefenseEvasion:
		return "Defense Evasion"
	case CredentialAccess:
		return "Credential Access"
	case Discovery:
		return "Discovery"
	case LateralMovement:
		return "Lateral Movement"
	case Collection:
		return "Collection"
	case CommandAndControl:
		return "Command and Control"
	case Exfiltration:
		return "Exfiltration"
	case Impact:
		return "Impact"
	default:
		return string(t)
	}
}

// ID returns the MITRE ATT&CK tactic ID.
func (t MITRETactic) ID() string {
	return string(t)
}

// D2Class returns the D2 style class name for this tactic.
func (t MITRETactic) D2Class() string {
	switch t {
	case InitialAccess:
		return "mitre-initial-access"
	case Execution:
		return "mitre-execution"
	case Persistence:
		return "mitre-persistence"
	case PrivilegeEscalation:
		return "mitre-priv-esc"
	case DefenseEvasion:
		return "mitre-defense-evasion"
	case CredentialAccess:
		return "mitre-cred-access"
	case Discovery:
		return "mitre-discovery"
	case LateralMovement:
		return "mitre-lateral"
	case Collection:
		return "mitre-collection"
	case CommandAndControl:
		return "mitre-c2"
	case Exfiltration:
		return "mitre-exfil"
	case Impact:
		return "mitre-impact"
	default:
		return "mitre-tactic"
	}
}

// URL returns the MITRE ATT&CK URL for this tactic.
func (t MITRETactic) URL() string {
	return "https://attack.mitre.org/tactics/" + string(t) + "/"
}

// AllMITRETactics returns all MITRE ATT&CK tactics in attack order.
func AllMITRETactics() []MITRETactic {
	return []MITRETactic{
		Reconnaissance,
		ResourceDevelopment,
		InitialAccess,
		Execution,
		Persistence,
		PrivilegeEscalation,
		DefenseEvasion,
		CredentialAccess,
		Discovery,
		LateralMovement,
		Collection,
		CommandAndControl,
		Exfiltration,
		Impact,
	}
}

// Technique represents a MITRE ATT&CK technique (the "how" of an attack).
type Technique struct {
	// ID is the technique identifier (e.g., "T1199").
	ID string `json:"id"`

	// Name is the technique name.
	Name string `json:"name"`

	// Tactic is the parent tactic this technique belongs to.
	Tactic MITRETactic `json:"tactic"`

	// Description provides details about the technique.
	Description string `json:"description,omitempty"`

	// SubTechniqueID is the sub-technique ID if applicable (e.g., "T1059.001").
	SubTechniqueID string `json:"subTechniqueId,omitempty"`
}

// URL returns the MITRE ATT&CK URL for this technique.
func (t Technique) URL() string {
	id := t.ID
	if t.SubTechniqueID != "" {
		id = t.SubTechniqueID
	}
	return "https://attack.mitre.org/techniques/" + id + "/"
}

// Label returns a formatted label for use in diagrams.
func (t Technique) Label() string {
	if t.Name != "" {
		return t.Tactic.ID() + " " + t.Tactic.String() + "\n" + t.ID + " " + t.Name
	}
	return t.Tactic.ID() + " " + t.Tactic.String()
}

// CommonTechniques returns commonly referenced techniques for quick access.
var CommonTechniques = map[string]Technique{
	"T1199": {
		ID:     "T1199",
		Name:   "Trusted Relationship",
		Tactic: InitialAccess,
	},
	"T1078": {
		ID:     "T1078",
		Name:   "Valid Accounts",
		Tactic: InitialAccess,
	},
	"T1110": {
		ID:     "T1110",
		Name:   "Brute Force",
		Tactic: CredentialAccess,
	},
	"T1059": {
		ID:     "T1059",
		Name:   "Command and Scripting Interpreter",
		Tactic: Execution,
	},
	"T1041": {
		ID:     "T1041",
		Name:   "Exfiltration Over C2 Channel",
		Tactic: Exfiltration,
	},
	"T1082": {
		ID:     "T1082",
		Name:   "System Information Discovery",
		Tactic: Discovery,
	},
}
