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

	// Network contains optional network topology details.
	Network *NetworkInfo `json:"network,omitempty"`

	// AssetIDs links this element to Asset definitions.
	AssetIDs []string `json:"assetIds,omitempty"`
}

// NetworkInfo contains network topology details for an element.
// This is useful for mapping DFD elements to actual network infrastructure.
type NetworkInfo struct {
	// Host is the hostname, IP address, or service name.
	Host string `json:"host,omitempty"`

	// Ports lists the ports exposed by this element.
	Ports []int `json:"ports,omitempty"`

	// Protocols lists the protocols used (HTTP, HTTPS, gRPC, TCP, etc.).
	Protocols []string `json:"protocols,omitempty"`

	// Zone indicates the network zone (dmz, internal, cloud, public, etc.).
	Zone string `json:"zone,omitempty"`

	// CIDR is the network CIDR block if applicable.
	CIDR string `json:"cidr,omitempty"`

	// Cloud contains cloud-specific identifiers.
	Cloud *CloudInfo `json:"cloud,omitempty"`
}

// CloudInfo contains cloud provider specific details.
type CloudInfo struct {
	// Provider is the cloud provider (aws, gcp, azure, etc.).
	Provider string `json:"provider,omitempty"`

	// Region is the cloud region.
	Region string `json:"region,omitempty"`

	// VPC is the VPC/VNet identifier.
	VPC string `json:"vpc,omitempty"`

	// Subnet is the subnet identifier.
	Subnet string `json:"subnet,omitempty"`

	// ResourceID is the cloud resource identifier.
	ResourceID string `json:"resourceId,omitempty"`
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

	// Action describes what the attacker does in this step.
	// More specific than Label when both are provided.
	Action string `json:"action,omitempty"`

	// Outcome describes the result of this attack step.
	Outcome string `json:"outcome,omitempty"`

	// MITRETactic is the MITRE ATT&CK tactic ID.
	MITRETactic MITRETactic `json:"mitreTactic,omitempty"`

	// MITRETechnique is the MITRE ATT&CK technique ID (e.g., T1110).
	MITRETechnique string `json:"mitreTechnique,omitempty"`

	// ATLASTechnique is the MITRE ATLAS technique ID for AI/ML-specific attacks.
	ATLASTechnique string `json:"atlasTechnique,omitempty"`

	// OWASPIds lists applicable OWASP categories (e.g., "API01", "LLM01", "A01:2021").
	// Supports multiple IDs as one step may map to several OWASP categories.
	OWASPIds []string `json:"owaspIds,omitempty"`

	// ASIIds lists applicable OWASP Agentic Security categories (e.g., "ASI02:2026", "ASI03:2026").
	// Supports multiple IDs as one step may map to several ASI categories.
	ASIIds []string `json:"asiIds,omitempty"`

	// STRIDEThreats lists applicable STRIDE threats.
	STRIDEThreats []STRIDEThreat `json:"strideThreats,omitempty"`

	// LINDDUNThreats lists applicable LINDDUN privacy threats.
	LINDDUNThreats []LINDDUNThreat `json:"linddunThreats,omitempty"`

	// Description provides additional context.
	Description string `json:"description,omitempty"`

	// --- Role-based notes (v0.7.0) ---

	// RedTeamNotes provides exploitation guidance for this specific step.
	RedTeamNotes string `json:"redTeamNotes,omitempty"`

	// BlueTeamNotes provides detection guidance for this specific step.
	BlueTeamNotes string `json:"blueTeamNotes,omitempty"`

	// RemediationNote provides fix guidance for this specific step.
	RemediationNote string `json:"remediationNote,omitempty"`

	// TestRef links this attack step to an app-test-spec test case.
	TestRef *TestReference `json:"testRef,omitempty"`

	// --- Supply Chain (v0.6.0) ---

	// ComponentRefs links this attack step to vulnerable software components.
	ComponentRefs []ComponentReference `json:"componentRefs,omitempty"`
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
