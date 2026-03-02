package diagram

import (
	"github.com/grokify/threat-model-spec/stride"
)

// Direction represents the diagram layout direction.
type Direction string

const (
	// DirectionRight flows left to right.
	DirectionRight Direction = "right"

	// DirectionDown flows top to bottom.
	DirectionDown Direction = "down"

	// DirectionLeft flows right to left.
	DirectionLeft Direction = "left"

	// DirectionUp flows bottom to top.
	DirectionUp Direction = "up"
)

// Diagram represents a complete threat model diagram.
type Diagram struct {
	// Title is the diagram title.
	Title string `json:"title,omitempty"`

	// Direction is the layout direction.
	Direction Direction `json:"direction,omitempty"`

	// Boundaries are the trust boundaries in the diagram.
	Boundaries []Boundary `json:"boundaries,omitempty"`

	// Elements are the DFD elements in the diagram.
	Elements []Element `json:"elements,omitempty"`

	// Flows are the data flows between elements.
	Flows []Flow `json:"flows,omitempty"`

	// Threats are standalone threat annotations.
	Threats []stride.Threat `json:"threats,omitempty"`

	// IncludeStyles determines if style classes should be included.
	IncludeStyles bool `json:"includeStyles,omitempty"`

	// StylesPath is the path to the D2TM styles directory.
	StylesPath string `json:"stylesPath,omitempty"`
}

// New creates a new empty diagram.
func New(title string) *Diagram {
	return &Diagram{
		Title:      title,
		Direction:  DirectionRight,
		Boundaries: make([]Boundary, 0),
		Elements:   make([]Element, 0),
		Flows:      make([]Flow, 0),
		Threats:    make([]stride.Threat, 0),
	}
}

// AddBoundary adds a trust boundary to the diagram.
func (d *Diagram) AddBoundary(id, label string, boundaryType BoundaryType) *Boundary {
	b := Boundary{
		ID:    id,
		Label: label,
		Type:  boundaryType,
	}
	d.Boundaries = append(d.Boundaries, b)
	return &d.Boundaries[len(d.Boundaries)-1]
}

// AddNestedBoundary adds a trust boundary nested within another boundary.
func (d *Diagram) AddNestedBoundary(id, label string, boundaryType BoundaryType, parentID string) *Boundary {
	b := Boundary{
		ID:       id,
		Label:    label,
		Type:     boundaryType,
		ParentID: parentID,
	}
	d.Boundaries = append(d.Boundaries, b)
	return &d.Boundaries[len(d.Boundaries)-1]
}

// AddElement adds an element to the diagram.
func (d *Diagram) AddElement(id, label string, elementType ElementType, parentID string) *Element {
	e := Element{
		ID:       id,
		Label:    label,
		Type:     elementType,
		ParentID: parentID,
	}
	d.Elements = append(d.Elements, e)
	return &d.Elements[len(d.Elements)-1]
}

// AddFlow adds a data flow between elements.
func (d *Diagram) AddFlow(from, to, label string, flowType FlowType) *Flow {
	f := Flow{
		From:  from,
		To:    to,
		Label: label,
		Type:  flowType,
	}
	d.Flows = append(d.Flows, f)
	return &d.Flows[len(d.Flows)-1]
}

// AddAttackFlow adds an attack flow with step number.
func (d *Diagram) AddAttackFlow(from, to, label string, step int) *Flow {
	f := Flow{
		From:  from,
		To:    to,
		Label: label,
		Type:  AttackFlow,
		Step:  step,
	}
	d.Flows = append(d.Flows, f)
	return &d.Flows[len(d.Flows)-1]
}

// AddThreat adds a standalone threat annotation.
func (d *Diagram) AddThreat(threat stride.Threat) {
	d.Threats = append(d.Threats, threat)
}

// GetBoundary returns a boundary by ID.
func (d *Diagram) GetBoundary(id string) *Boundary {
	for i := range d.Boundaries {
		if d.Boundaries[i].ID == id {
			return &d.Boundaries[i]
		}
	}
	return nil
}

// GetElement returns an element by ID.
func (d *Diagram) GetElement(id string) *Element {
	for i := range d.Elements {
		if d.Elements[i].ID == id {
			return &d.Elements[i]
		}
	}
	return nil
}

// ElementsInBoundary returns all elements within a boundary.
func (d *Diagram) ElementsInBoundary(boundaryID string) []Element {
	var result []Element
	for _, e := range d.Elements {
		if e.ParentID == boundaryID {
			result = append(result, e)
		}
	}
	return result
}

// AttackFlows returns only attack flows (non-normal flows).
func (d *Diagram) AttackFlows() []Flow {
	var result []Flow
	for _, f := range d.Flows {
		if f.IsAttack() {
			result = append(result, f)
		}
	}
	return result
}

// FlowsWithSTRIDE returns flows that have STRIDE annotations.
func (d *Diagram) FlowsWithSTRIDE() []Flow {
	var result []Flow
	for _, f := range d.Flows {
		if f.HasSTRIDE() {
			result = append(result, f)
		}
	}
	return result
}

// FlowsWithMITRE returns flows that have MITRE ATT&CK mapping.
func (d *Diagram) FlowsWithMITRE() []Flow {
	var result []Flow
	for _, f := range d.Flows {
		if f.HasMITRE() {
			result = append(result, f)
		}
	}
	return result
}

// AllThreats returns all threats from flows and standalone threats.
func (d *Diagram) AllThreats() []stride.Threat {
	threats := make([]stride.Threat, len(d.Threats))
	copy(threats, d.Threats)

	for _, f := range d.Flows {
		threats = append(threats, f.Threats...)
	}
	return threats
}
