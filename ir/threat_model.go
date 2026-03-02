package ir

// ThreatModel is the canonical representation of a security threat model.
// It contains shared metadata and framework mappings, with multiple diagram
// views of the same vulnerability or threat scenario.
//
// This is the preferred format for complete threat models. Individual DiagramIR
// files can be used for single-diagram use cases or generated from a ThreatModel.
type ThreatModel struct {
	// ID is a unique identifier for the threat model (e.g., "openclaw-websocket-localhost").
	ID string `json:"id"`

	// Title is the human-readable title of the threat model.
	Title string `json:"title"`

	// Description provides an overview of the vulnerability or threat scenario.
	Description string `json:"description,omitempty"`

	// Version tracks the threat model version (e.g., "1.0.0").
	Version string `json:"version,omitempty"`

	// Authors lists the people who created or contributed to this threat model.
	Authors []Author `json:"authors,omitempty"`

	// References contains external links to related resources.
	References []Reference `json:"references,omitempty"`

	// Mappings contains references to external security frameworks
	// (MITRE ATT&CK, ATLAS, OWASP, CWE, CVSS, STRIDE).
	// These mappings apply to the overall threat model.
	Mappings *Mappings `json:"mappings,omitempty"`

	// Diagrams contains the individual diagram views of the threat model.
	// Each diagram represents a different perspective (DFD, attack chain, sequence).
	Diagrams []DiagramView `json:"diagrams"`
}

// Author represents a contributor to the threat model.
type Author struct {
	// Name is the author's name.
	Name string `json:"name"`

	// Email is the author's email address.
	Email string `json:"email,omitempty"`

	// URL is a link to the author's profile or website.
	URL string `json:"url,omitempty"`
}

// Reference is an external resource related to the threat model.
type Reference struct {
	// Title is the reference title.
	Title string `json:"title"`

	// URL is the link to the resource.
	URL string `json:"url"`

	// Type categorizes the reference (e.g., "advisory", "blog", "paper", "cve").
	Type string `json:"type,omitempty"`
}

// DiagramView represents a single diagram within a ThreatModel.
// It embeds DiagramIR but allows the diagram to inherit or override
// the parent ThreatModel's mappings.
type DiagramView struct {
	// Type identifies the diagram type (dfd, attack-chain, sequence).
	Type DiagramType `json:"type"`

	// Title is the diagram-specific title. If empty, inherits from ThreatModel.
	Title string `json:"title,omitempty"`

	// Description provides diagram-specific context.
	Description string `json:"description,omitempty"`

	// Direction specifies the layout direction (right, down, etc.).
	Direction Direction `json:"direction,omitempty"`

	// Legend controls whether to show the legend.
	Legend *Legend `json:"legend,omitempty"`

	// Mappings contains diagram-specific framework mappings.
	// If nil, the diagram inherits from the parent ThreatModel.
	// If set, these mappings apply only to this diagram view.
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
}

// ToDigramIR converts a DiagramView to a standalone DiagramIR,
// inheriting mappings from the parent ThreatModel if not overridden.
func (dv *DiagramView) ToDiagramIR(parent *ThreatModel) *DiagramIR {
	ir := &DiagramIR{
		Type:        dv.Type,
		Title:       dv.Title,
		Description: dv.Description,
		Direction:   dv.Direction,
		Legend:      dv.Legend,
		Mappings:    dv.Mappings,
		Elements:    dv.Elements,
		Boundaries:  dv.Boundaries,
		Flows:       dv.Flows,
		Attacks:     dv.Attacks,
		Targets:     dv.Targets,
		Actors:      dv.Actors,
		Phases:      dv.Phases,
		Messages:    dv.Messages,
	}

	// Inherit title from parent if not set
	if ir.Title == "" && parent != nil {
		ir.Title = parent.Title
	}

	// Inherit mappings from parent if not set
	if ir.Mappings == nil && parent != nil {
		ir.Mappings = parent.Mappings
	}

	return ir
}

// GetDiagram returns the first diagram of the specified type, or nil if not found.
func (tm *ThreatModel) GetDiagram(dt DiagramType) *DiagramView {
	for i := range tm.Diagrams {
		if tm.Diagrams[i].Type == dt {
			return &tm.Diagrams[i]
		}
	}
	return nil
}

// GetDiagramIR returns a standalone DiagramIR for the specified type,
// with inherited mappings from the ThreatModel.
func (tm *ThreatModel) GetDiagramIR(dt DiagramType) *DiagramIR {
	dv := tm.GetDiagram(dt)
	if dv == nil {
		return nil
	}
	return dv.ToDiagramIR(tm)
}
