package ir

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LoadFromFile loads a DiagramIR from a JSON file.
func LoadFromFile(path string) (*DiagramIR, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	var d DiagramIR
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return &d, nil
}

// LoadThreatModelFromFile loads a ThreatModel from a JSON file.
func LoadThreatModelFromFile(path string) (*ThreatModel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	var tm ThreatModel
	if err := json.Unmarshal(data, &tm); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return &tm, nil
}

// RenderD2 renders the DiagramIR to D2 format.
func (d *DiagramIR) RenderD2() string {
	switch d.Type {
	case DiagramTypeDFD:
		return d.renderDFD()
	case DiagramTypeAttack:
		return d.renderAttackChain()
	case DiagramTypeSequence:
		return d.renderSequence()
	default:
		return d.renderDFD() // Default to DFD
	}
}

// renderDFD renders a Data Flow Diagram.
func (d *DiagramIR) renderDFD() string {
	var sb strings.Builder

	// Header
	fmt.Fprintf(&sb, "# %s\n", d.Title)
	if d.Description != "" {
		fmt.Fprintf(&sb, "# %s\n", d.Description)
	}
	sb.WriteString("\n")

	// Direction
	if d.Direction != "" {
		fmt.Fprintf(&sb, "direction: %s\n\n", d.Direction)
	}

	// Legend
	if d.Legend != nil && d.Legend.Show {
		sb.WriteString(d.renderLegend())
	}

	// Boundaries
	sb.WriteString("# Trust Boundaries\n")
	for _, b := range d.Boundaries {
		if b.ParentID == "" { // Top-level boundaries
			sb.WriteString(d.renderBoundary(b))
		}
	}

	// Standalone elements (no parent)
	for _, e := range d.Elements {
		if e.ParentID == "" {
			sb.WriteString(d.renderElement(e))
		}
	}

	// Flows
	sb.WriteString("\n# Data Flows\n")
	for _, f := range d.Flows {
		sb.WriteString(d.renderFlow(f))
	}

	return sb.String()
}

// renderAttackChain renders an Attack Chain diagram.
func (d *DiagramIR) renderAttackChain() string {
	var sb strings.Builder

	// Header
	fmt.Fprintf(&sb, "# %s\n", d.Title)
	if d.Description != "" {
		fmt.Fprintf(&sb, "# %s\n", d.Description)
	}
	sb.WriteString("\n")

	// Direction
	if d.Direction != "" {
		fmt.Fprintf(&sb, "direction: %s\n\n", d.Direction)
	}

	// Legend
	if d.Legend != nil && d.Legend.Show {
		sb.WriteString(d.renderLegend())
	}

	// Boundaries
	sb.WriteString("# Trust Boundaries\n")
	for _, b := range d.Boundaries {
		if b.ParentID == "" {
			sb.WriteString(d.renderBoundary(b))
		}
	}

	// Standalone elements
	for _, e := range d.Elements {
		if e.ParentID == "" {
			sb.WriteString(d.renderElement(e))
		}
	}

	// Attack flows
	sb.WriteString("\n# Attack Flow\n")
	for _, a := range d.Attacks {
		sb.WriteString(d.renderAttack(a))
	}

	return sb.String()
}

// renderSequence renders a Sequence diagram.
func (d *DiagramIR) renderSequence() string {
	var sb strings.Builder

	// Header
	fmt.Fprintf(&sb, "# %s\n", d.Title)
	if d.Description != "" {
		fmt.Fprintf(&sb, "# %s\n", d.Description)
	}
	sb.WriteString("\n")

	// Sequence diagram shape
	sb.WriteString("shape: sequence_diagram\n\n")

	// Actors
	sb.WriteString("# Actors\n")
	for _, a := range d.Actors {
		sb.WriteString(d.renderActor(a))
	}

	// Messages grouped by phase
	if len(d.Phases) > 0 {
		for _, p := range d.Phases {
			fmt.Fprintf(&sb, "\n# %s", p.Name)
			if p.MITRETactic != "" {
				fmt.Fprintf(&sb, " [%s]", p.MITRETactic)
			}
			sb.WriteString("\n")

			for _, m := range d.Messages {
				if m.Seq >= p.StartMessage && m.Seq <= p.EndMessage {
					sb.WriteString(d.renderMessage(m))
				}
			}
		}
	} else {
		sb.WriteString("\n# Messages\n")
		for _, m := range d.Messages {
			sb.WriteString(d.renderMessage(m))
		}
	}

	return sb.String()
}

// renderLegend renders the legend section.
func (d *DiagramIR) renderLegend() string {
	var sb strings.Builder

	sb.WriteString("legend: Legend {\n")
	sb.WriteString("  style: {\n")
	sb.WriteString("    fill: \"#fafafa\"\n")
	sb.WriteString("    stroke: \"#e0e0e0\"\n")
	sb.WriteString("    border-radius: 8\n")
	sb.WriteString("  }\n")

	if d.Legend.ShowSTRIDE {
		sb.WriteString("\n  stride: STRIDE Threats {\n")
		sb.WriteString("    style.fill: \"#ffffff\"\n")
		sb.WriteString("    s: S - Spoofing { style: { fill: \"#ffebee\"; stroke: \"#c62828\" } }\n")
		sb.WriteString("    t: T - Tampering { style: { fill: \"#fff3e0\"; stroke: \"#ef6c00\" } }\n")
		sb.WriteString("    r: R - Repudiation { style: { fill: \"#fffde7\"; stroke: \"#f9a825\" } }\n")
		sb.WriteString("    i: I - Info Disclosure { style: { fill: \"#e3f2fd\"; stroke: \"#1565c0\" } }\n")
		sb.WriteString("    d: D - Denial of Service { style: { fill: \"#fce4ec\"; stroke: \"#c2185b\" } }\n")
		sb.WriteString("    e: E - Elevation { style: { fill: \"#e8f5e9\"; stroke: \"#2e7d32\" } }\n")
		sb.WriteString("  }\n")
	}

	if d.Legend.ShowMITRE {
		sb.WriteString("\n  mitre: MITRE ATT&CK {\n")
		sb.WriteString("    style.fill: \"#ffffff\"\n")
		sb.WriteString("    ta0001: TA0001 Initial Access { style: { fill: \"#fff3e0\"; stroke: \"#ef6c00\" } }\n")
		sb.WriteString("    ta0006: TA0006 Credential Access { style: { fill: \"#fce4ec\"; stroke: \"#c2185b\" } }\n")
		sb.WriteString("    ta0009: TA0009 Collection { style: { fill: \"#f3e5f5\"; stroke: \"#7b1fa2\" } }\n")
		sb.WriteString("    ta0010: TA0010 Exfiltration { style: { fill: \"#ffcdd2\"; stroke: \"#b71c1c\" } }\n")
		sb.WriteString("  }\n")
	}

	if d.Legend.ShowAssets {
		sb.WriteString("\n  assets: Asset Classification {\n")
		sb.WriteString("    style.fill: \"#ffffff\"\n")
		sb.WriteString("    crown: Crown Jewel { style: { fill: \"#ffcdd2\"; stroke: \"#b71c1c\"; stroke-width: 3 } }\n")
		sb.WriteString("    high: High Value { style: { fill: \"#fff3e0\"; stroke: \"#ef6c00\"; stroke-width: 2 } }\n")
		sb.WriteString("  }\n")
	}

	if d.Legend.ShowElements {
		sb.WriteString("\n  elements: Element Types {\n")
		sb.WriteString("    style.fill: \"#ffffff\"\n")
		sb.WriteString("    process: Process { shape: rectangle; style: { fill: \"#e3f2fd\"; stroke: \"#1976d2\" } }\n")
		sb.WriteString("    datastore: Data Store { shape: cylinder; style: { fill: \"#fce4ec\"; stroke: \"#c2185b\" } }\n")
		sb.WriteString("    external: External Entity { shape: person; style: { fill: \"#e8f5e9\"; stroke: \"#388e3c\" } }\n")
		sb.WriteString("  }\n")
	}

	if d.Legend.ShowBoundaries {
		sb.WriteString("\n  boundaries: Trust Boundaries {\n")
		sb.WriteString("    style.fill: \"#ffffff\"\n")
		sb.WriteString("    browser: Browser { style: { stroke-dash: 5; stroke: \"#1565c0\"; fill: \"#e3f2fd\" } }\n")
		sb.WriteString("    localhost: Localhost { style: { stroke-dash: 5; stroke: \"#7b1fa2\"; fill: \"#f3e5f5\" } }\n")
		sb.WriteString("  }\n")
	}

	sb.WriteString("}\n\n")
	return sb.String()
}

// renderBoundary renders a trust boundary and its nested elements.
func (d *DiagramIR) renderBoundary(b Boundary) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s: %s {\n", b.ID, b.Label)
	sb.WriteString("  style: {\n")
	sb.WriteString("    stroke-dash: 5\n")

	// Style based on boundary type
	switch b.Type {
	case BoundaryTypeBrowser:
		sb.WriteString("    stroke: \"#1565c0\"\n")
		sb.WriteString("    fill: \"#e3f2fd\"\n")
	case BoundaryTypeLocalhost:
		sb.WriteString("    stroke: \"#7b1fa2\"\n")
		sb.WriteString("    fill: \"#f3e5f5\"\n")
	case BoundaryTypeNetwork:
		sb.WriteString("    stroke: \"#00796b\"\n")
		sb.WriteString("    fill: \"#e0f2f1\"\n")
	case BoundaryTypeCloud:
		sb.WriteString("    stroke: \"#0288d1\"\n")
		sb.WriteString("    fill: \"#e1f5fe\"\n")
	case BoundaryTypeBreached:
		sb.WriteString("    stroke: \"#b71c1c\"\n")
		sb.WriteString("    fill: \"#ffebee\"\n")
	default:
		sb.WriteString("    stroke: \"#9e9e9e\"\n")
		sb.WriteString("    fill: \"#f5f5f5\"\n")
	}

	sb.WriteString("    stroke-width: 2\n")
	sb.WriteString("    border-radius: 10\n")
	sb.WriteString("  }\n\n")

	// Nested elements
	for _, e := range d.Elements {
		if e.ParentID == b.ID {
			sb.WriteString(d.renderElementNested(e, "  "))
		}
	}

	// Nested boundaries
	for _, nb := range d.Boundaries {
		if nb.ParentID == b.ID {
			nested := d.renderBoundary(nb)
			// Indent nested content
			for _, line := range strings.Split(nested, "\n") {
				if line != "" {
					fmt.Fprintf(&sb, "  %s\n", line)
				}
			}
		}
	}

	sb.WriteString("}\n\n")
	return sb.String()
}

// renderElement renders a standalone element.
func (d *DiagramIR) renderElement(e Element) string {
	return d.renderElementNested(e, "")
}

// renderElementNested renders an element with indentation.
func (d *DiagramIR) renderElementNested(e Element, indent string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s%s: %s {\n", indent, e.ID, e.Label)

	// Shape based on type
	shape := elementTypeToShape(e.Type)
	fmt.Fprintf(&sb, "%s  shape: %s\n", indent, shape)

	fmt.Fprintf(&sb, "%s  style: {\n", indent)

	// Style based on classification
	switch e.Classification {
	case AssetClassificationCrownJewel:
		fmt.Fprintf(&sb, "%s    fill: \"#ffcdd2\"\n", indent)
		fmt.Fprintf(&sb, "%s    stroke: \"#b71c1c\"\n", indent)
		fmt.Fprintf(&sb, "%s    stroke-width: 3\n", indent)
	case AssetClassificationHigh:
		fmt.Fprintf(&sb, "%s    fill: \"#fff3e0\"\n", indent)
		fmt.Fprintf(&sb, "%s    stroke: \"#ef6c00\"\n", indent)
		fmt.Fprintf(&sb, "%s    stroke-width: 2\n", indent)
	default:
		// Style based on element type
		fill, stroke := elementTypeToColors(e.Type)
		fmt.Fprintf(&sb, "%s    fill: \"%s\"\n", indent, fill)
		fmt.Fprintf(&sb, "%s    stroke: \"%s\"\n", indent, stroke)
		fmt.Fprintf(&sb, "%s    stroke-width: 2\n", indent)
	}

	fmt.Fprintf(&sb, "%s  }\n", indent)
	fmt.Fprintf(&sb, "%s}\n\n", indent)

	return sb.String()
}

// renderFlow renders a data flow.
func (d *DiagramIR) renderFlow(f Flow) string {
	var sb strings.Builder

	arrow := "->"
	if f.Bidirectional {
		arrow = "<->"
	}

	label := f.Label
	if label == "" {
		fmt.Fprintf(&sb, "%s %s %s\n", f.From, arrow, f.To)
	} else {
		fmt.Fprintf(&sb, "%s %s %s: %s {\n", f.From, arrow, f.To, label)

		// Style based on flow type
		switch f.Type {
		case FlowTypeAttack:
			sb.WriteString("  style.stroke: \"#c62828\"\n")
			sb.WriteString("  style.stroke-width: 2\n")
			sb.WriteString("  style.stroke-dash: 3\n")
		case FlowTypeExfil:
			sb.WriteString("  style.stroke: \"#b71c1c\"\n")
			sb.WriteString("  style.stroke-width: 3\n")
			sb.WriteString("  style.stroke-dash: 5\n")
		default:
			sb.WriteString("  style.stroke: \"#616161\"\n")
		}

		sb.WriteString("}\n")
	}

	return sb.String()
}

// renderAttack renders an attack step.
func (d *DiagramIR) renderAttack(a Attack) string {
	var sb strings.Builder

	label := fmt.Sprintf("%d. %s", a.Step, a.Label)
	if a.MITRETechnique != "" {
		label += fmt.Sprintf(" (%s)", a.MITRETechnique)
	}

	fmt.Fprintf(&sb, "%s -> %s: %s {\n", a.From, a.To, label)

	// Color based on MITRE tactic
	switch a.MITRETactic {
	case MITREInitialAccess:
		sb.WriteString("  style.stroke: \"#ef6c00\"\n")
	case MITRECredentialAccess:
		sb.WriteString("  style.stroke: \"#c2185b\"\n")
	case MITRECollection:
		sb.WriteString("  style.stroke: \"#7b1fa2\"\n")
	case MITREExfiltration:
		sb.WriteString("  style.stroke: \"#b71c1c\"\n")
	default:
		sb.WriteString("  style.stroke: \"#c62828\"\n")
	}

	sb.WriteString("  style.stroke-width: 2\n")
	sb.WriteString("  style.stroke-dash: 3\n")
	sb.WriteString("}\n\n")

	return sb.String()
}

// renderActor renders a sequence diagram actor.
func (d *DiagramIR) renderActor(a Actor) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s: %s {\n", a.ID, a.Label)
	sb.WriteString("  style: {\n")

	if a.Malicious {
		sb.WriteString("    fill: \"#ffcdd2\"\n")
		sb.WriteString("    stroke: \"#b71c1c\"\n")
	} else {
		fill, stroke := elementTypeToColors(a.Type)
		fmt.Fprintf(&sb, "    fill: \"%s\"\n", fill)
		fmt.Fprintf(&sb, "    stroke: \"%s\"\n", stroke)
	}

	sb.WriteString("    stroke-width: 2\n")
	sb.WriteString("  }\n")
	sb.WriteString("}\n\n")

	return sb.String()
}

// renderMessage renders a sequence diagram message.
func (d *DiagramIR) renderMessage(m Message) string {
	var sb strings.Builder

	label := fmt.Sprintf("%d. %s", m.Seq, m.Label)

	fmt.Fprintf(&sb, "%s -> %s: %s {\n", m.From, m.To, label)

	switch m.Type {
	case FlowTypeAttack:
		sb.WriteString("  style.stroke: \"#c62828\"\n")
		sb.WriteString("  style.stroke-width: 2\n")
	case FlowTypeExfil:
		sb.WriteString("  style.stroke: \"#b71c1c\"\n")
		sb.WriteString("  style.stroke-width: 3\n")
	default:
		sb.WriteString("  style.stroke: \"#616161\"\n")
	}

	sb.WriteString("}\n\n")

	return sb.String()
}

// Helper functions

func elementTypeToShape(t ElementType) string {
	switch t {
	case ElementTypeProcess:
		return "rectangle"
	case ElementTypeDatastore:
		return "cylinder"
	case ElementTypeExternalEntity:
		return "person"
	case ElementTypeGateway:
		return "hexagon"
	case ElementTypeBrowser:
		return "rectangle"
	case ElementTypeAgent:
		return "rectangle"
	case ElementTypeAPI:
		return "cloud"
	default:
		return "rectangle"
	}
}

func elementTypeToColors(t ElementType) (fill, stroke string) {
	switch t {
	case ElementTypeProcess:
		return "#e3f2fd", "#1976d2"
	case ElementTypeDatastore:
		return "#fce4ec", "#c2185b"
	case ElementTypeExternalEntity:
		return "#e8f5e9", "#388e3c"
	case ElementTypeGateway:
		return "#e0f2f1", "#00796b"
	case ElementTypeBrowser:
		return "#e3f2fd", "#1565c0"
	case ElementTypeAgent:
		return "#e8eaf6", "#3f51b5"
	case ElementTypeAPI:
		return "#fff3e0", "#ef6c00"
	default:
		return "#f5f5f5", "#9e9e9e"
	}
}
