package ir

// DiagramIR is the intermediate representation for all threat modeling diagrams.
// It uses a non-polymorphic structure where the Type field identifies the diagram
// kind, and different fields are used depending on the type.
//
// For DFD: Uses Elements, Boundaries, Flows
// For Attack Chain: Uses Elements, Boundaries, Attacks, Targets
// For Sequence: Uses Actors, Phases, Messages
type DiagramIR struct {
	// Type identifies the diagram type (dfd, attack-chain, sequence).
	Type DiagramType `json:"type"`

	// Title is the diagram title.
	Title string `json:"title"`

	// Description provides additional context about the diagram.
	Description string `json:"description,omitempty"`

	// Direction specifies the layout direction (right, down, etc.).
	Direction Direction `json:"direction,omitempty"`

	// Legend controls whether to show the legend.
	Legend *Legend `json:"legend,omitempty"`

	// Mappings contains references to external security frameworks
	// (MITRE ATT&CK, ATLAS, OWASP, CWE, CVSS, STRIDE).
	Mappings *Mappings `json:"mappings,omitempty"`

	// --- DFD and Attack Chain fields ---

	// Elements are the DFD elements (processes, datastores, external entities).
	Elements []Element `json:"elements,omitempty"`

	// Boundaries are the trust boundaries containing elements.
	Boundaries []Boundary `json:"boundaries,omitempty"`

	// Flows are the data flows between elements (for DFD).
	Flows []Flow `json:"flows,omitempty"`

	// --- Attack Chain specific fields ---

	// Attacks are the attack steps (for attack-chain type).
	Attacks []Attack `json:"attacks,omitempty"`

	// Targets are the high-value assets being targeted.
	Targets []Target `json:"targets,omitempty"`

	// --- Sequence diagram specific fields ---

	// Actors are the lifelines in a sequence diagram.
	Actors []Actor `json:"actors,omitempty"`

	// Phases group messages into logical attack phases.
	Phases []Phase `json:"phases,omitempty"`

	// Messages are the interactions between actors (for sequence type).
	Messages []Message `json:"messages,omitempty"`

	// --- Attack Tree specific fields ---

	// AttackTree contains the attack tree structure (for attack-tree type).
	AttackTree *AttackTree `json:"attackTree,omitempty"`

	// --- Cross-cutting security fields ---

	// Threats contains identified threats with status tracking.
	Threats []ThreatEntry `json:"threats,omitempty"`

	// Mitigations contains countermeasures addressing identified threats.
	Mitigations []Mitigation `json:"mitigations,omitempty"`

	// Detections contains detection capabilities for threats and attacks.
	Detections []Detection `json:"detections,omitempty"`

	// ResponseActions contains incident response actions.
	ResponseActions []ResponseAction `json:"responseActions,omitempty"`
}

// Legend configures the diagram legend.
type Legend struct {
	// Show controls whether the legend is displayed.
	Show bool `json:"show"`

	// ShowSTRIDE includes STRIDE threat legend.
	ShowSTRIDE bool `json:"showStride,omitempty"`

	// ShowLINDDUN includes LINDDUN privacy threat legend.
	ShowLINDDUN bool `json:"showLinddun,omitempty"`

	// ShowMITRE includes MITRE ATT&CK tactic legend.
	ShowMITRE bool `json:"showMitre,omitempty"`

	// ShowAssets includes asset classification legend.
	ShowAssets bool `json:"showAssets,omitempty"`

	// ShowElements includes element type legend.
	ShowElements bool `json:"showElements,omitempty"`

	// ShowBoundaries includes boundary type legend.
	ShowBoundaries bool `json:"showBoundaries,omitempty"`

	// ShowMitigations includes mitigation status legend.
	ShowMitigations bool `json:"showMitigations,omitempty"`
}

// Element represents a DFD element (process, datastore, external entity, etc.).
type Element struct {
	// ID is the unique identifier for the element.
	ID string `json:"id"`

	// Label is the display name.
	Label string `json:"label"`

	// Type identifies the element type.
	Type ElementType `json:"type"`

	// ParentID is the ID of the containing boundary (if any).
	ParentID string `json:"parentId,omitempty"`

	// Classification indicates the asset value/sensitivity.
	Classification AssetClassification `json:"classification,omitempty"`

	// STRIDEThreats lists applicable STRIDE threats.
	STRIDEThreats []STRIDEThreat `json:"strideThreats,omitempty"`

	// Description provides additional context.
	Description string `json:"description,omitempty"`
}

// Boundary represents a trust boundary containing elements.
type Boundary struct {
	// ID is the unique identifier for the boundary.
	ID string `json:"id"`

	// Label is the display name.
	Label string `json:"label"`

	// Type identifies the boundary type.
	Type BoundaryType `json:"type"`

	// ParentID is the ID of a containing boundary (for nested boundaries).
	ParentID string `json:"parentId,omitempty"`

	// Description provides additional context.
	Description string `json:"description,omitempty"`
}

// Flow represents a data flow between elements.
type Flow struct {
	// From is the source element ID.
	From string `json:"from"`

	// To is the destination element ID.
	To string `json:"to"`

	// Label describes the flow.
	Label string `json:"label,omitempty"`

	// Type identifies the flow type (normal, attack, exfil).
	Type FlowType `json:"type,omitempty"`

	// Bidirectional indicates if the flow goes both ways.
	Bidirectional bool `json:"bidirectional,omitempty"`
}

// Attack represents an attack step in an attack chain.
type Attack struct {
	// Step is the sequence number (1, 2, 3...).
	Step int `json:"step"`

	// From is the source element ID.
	From string `json:"from"`

	// To is the destination element ID.
	To string `json:"to"`

	// Label describes the attack step.
	Label string `json:"label"`

	// MITRETactic is the MITRE ATT&CK tactic ID.
	MITRETactic MITRETactic `json:"mitreTactic,omitempty"`

	// MITRETechnique is the MITRE ATT&CK technique ID (e.g., T1110).
	MITRETechnique string `json:"mitreTechnique,omitempty"`

	// STRIDEThreats lists applicable STRIDE threats.
	STRIDEThreats []STRIDEThreat `json:"strideThreats,omitempty"`

	// Description provides additional context.
	Description string `json:"description,omitempty"`
}

// Target represents a high-value asset being targeted.
type Target struct {
	// ElementID references the element that is a target.
	ElementID string `json:"elementId"`

	// Classification indicates the asset value.
	Classification AssetClassification `json:"classification"`

	// STRIDEThreats lists applicable STRIDE threats.
	STRIDEThreats []STRIDEThreat `json:"strideThreats,omitempty"`

	// Impact describes the impact if compromised.
	Impact string `json:"impact,omitempty"`
}

// Actor represents a lifeline in a sequence diagram.
type Actor struct {
	// ID is the unique identifier.
	ID string `json:"id"`

	// Label is the display name.
	Label string `json:"label"`

	// Type identifies the actor type (for styling).
	Type ElementType `json:"type,omitempty"`

	// Malicious indicates if this is an attacker-controlled actor.
	Malicious bool `json:"malicious,omitempty"`
}

// Phase groups messages into a logical attack phase.
type Phase struct {
	// Name is the phase name.
	Name string `json:"name"`

	// MITRETactic is the MITRE ATT&CK tactic for this phase.
	MITRETactic MITRETactic `json:"mitreTactic,omitempty"`

	// Description provides additional context.
	Description string `json:"description,omitempty"`

	// StartMessage is the first message index in this phase.
	StartMessage int `json:"startMessage"`

	// EndMessage is the last message index in this phase.
	EndMessage int `json:"endMessage"`
}

// Message represents an interaction between actors in a sequence diagram.
type Message struct {
	// Seq is the sequence number (1, 2, 3...).
	Seq int `json:"seq"`

	// From is the source actor ID.
	From string `json:"from"`

	// To is the destination actor ID.
	To string `json:"to"`

	// Label describes the message.
	Label string `json:"label"`

	// Type identifies the message type (normal, attack, exfil).
	Type FlowType `json:"type,omitempty"`

	// MITRETechnique is the MITRE ATT&CK technique ID (if applicable).
	MITRETechnique string `json:"mitreTechnique,omitempty"`

	// Note is a self-message note (when From == To).
	Note bool `json:"note,omitempty"`
}
