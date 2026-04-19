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
	case DiagramTypeAttackTree:
		return d.renderAttackTree()
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

	// Mitigations
	sb.WriteString(d.renderMitigations())

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

	if d.Legend.ShowLINDDUN {
		sb.WriteString("\n  linddun: LINDDUN Privacy Threats {\n")
		sb.WriteString("    style.fill: \"#ffffff\"\n")
		sb.WriteString("    l: L - Linkability { style: { fill: \"#e8eaf6\"; stroke: \"#3f51b5\" } }\n")
		sb.WriteString("    i: I - Identifiability { style: { fill: \"#e3f2fd\"; stroke: \"#1976d2\" } }\n")
		sb.WriteString("    n: N - Non-repudiation { style: { fill: \"#fff3e0\"; stroke: \"#f57c00\" } }\n")
		sb.WriteString("    d: D - Detectability { style: { fill: \"#fce4ec\"; stroke: \"#c2185b\" } }\n")
		sb.WriteString("    di: Di - Disclosure { style: { fill: \"#ffebee\"; stroke: \"#c62828\" } }\n")
		sb.WriteString("    u: U - Unawareness { style: { fill: \"#f3e5f5\"; stroke: \"#7b1fa2\" } }\n")
		sb.WriteString("    nc: Nc - Non-compliance { style: { fill: \"#efebe9\"; stroke: \"#5d4037\" } }\n")
		sb.WriteString("  }\n")
	}

	if d.Legend.ShowMitigations {
		sb.WriteString("\n  mitigations: Mitigation Status {\n")
		sb.WriteString("    style.fill: \"#ffffff\"\n")
		sb.WriteString("    implemented: Implemented { style: { fill: \"#e8f5e9\"; stroke: \"#2e7d32\" } }\n")
		sb.WriteString("    partial: Partial { style: { fill: \"#fff3e0\"; stroke: \"#f57c00\" } }\n")
		sb.WriteString("    planned: Planned { style: { fill: \"#e3f2fd\"; stroke: \"#1976d2\" } }\n")
		sb.WriteString("    accepted: Accepted { style: { fill: \"#f5f5f5\"; stroke: \"#616161\" } }\n")
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

// renderAttackTree renders an Attack Tree diagram.
func (d *DiagramIR) renderAttackTree() string {
	var sb strings.Builder

	// Header
	fmt.Fprintf(&sb, "# %s\n", d.Title)
	if d.Description != "" {
		fmt.Fprintf(&sb, "# %s\n", d.Description)
	}
	sb.WriteString("\n")

	// Direction (typically top-down for attack trees)
	if d.Direction != "" {
		fmt.Fprintf(&sb, "direction: %s\n\n", d.Direction)
	} else {
		sb.WriteString("direction: down\n\n")
	}

	// Legend
	if d.Legend != nil && d.Legend.Show {
		sb.WriteString(d.renderAttackTreeLegend())
	}

	// Attack tree structure
	if d.AttackTree == nil || len(d.AttackTree.Nodes) == 0 {
		sb.WriteString("# No attack tree nodes defined\n")
		return sb.String()
	}

	// Render all nodes
	sb.WriteString("# Attack Tree Nodes\n")
	for _, node := range d.AttackTree.Nodes {
		sb.WriteString(d.renderAttackTreeNode(node))
	}

	// Render connections
	sb.WriteString("\n# Attack Tree Connections\n")
	for _, node := range d.AttackTree.Nodes {
		for _, childID := range node.Children {
			fmt.Fprintf(&sb, "%s -> %s\n", node.ID, childID)
		}
	}

	return sb.String()
}

// renderAttackTreeLegend renders the legend for attack trees.
func (d *DiagramIR) renderAttackTreeLegend() string {
	var sb strings.Builder

	sb.WriteString("legend: Legend {\n")
	sb.WriteString("  style: {\n")
	sb.WriteString("    fill: \"#fafafa\"\n")
	sb.WriteString("    stroke: \"#e0e0e0\"\n")
	sb.WriteString("    border-radius: 8\n")
	sb.WriteString("  }\n")

	sb.WriteString("\n  gates: Logic Gates {\n")
	sb.WriteString("    style.fill: \"#ffffff\"\n")
	sb.WriteString("    and: AND Gate (∧) { style: { fill: \"#e3f2fd\"; stroke: \"#1976d2\" } }\n")
	sb.WriteString("    or: OR Gate (∨) { style: { fill: \"#fff3e0\"; stroke: \"#ef6c00\" } }\n")
	sb.WriteString("    leaf: Leaf Attack { style: { fill: \"#ffebee\"; stroke: \"#c62828\" } }\n")
	sb.WriteString("  }\n")

	sb.WriteString("\n  status: Attack Status {\n")
	sb.WriteString("    style.fill: \"#ffffff\"\n")
	sb.WriteString("    active: Active Attack { style: { fill: \"#ffebee\"; stroke: \"#c62828\" } }\n")
	sb.WriteString("    mitigated: Mitigated { style: { fill: \"#e8f5e9\"; stroke: \"#2e7d32\" } }\n")
	sb.WriteString("  }\n")

	sb.WriteString("}\n\n")
	return sb.String()
}

// renderAttackTreeNode renders a single attack tree node.
func (d *DiagramIR) renderAttackTreeNode(node AttackTreeNode) string {
	var sb strings.Builder

	// Build label with gate symbol
	label := node.Label
	switch node.NodeType {
	case AttackTreeNodeTypeAND:
		label = fmt.Sprintf("∧ %s", node.Label)
	case AttackTreeNodeTypeOR:
		label = fmt.Sprintf("∨ %s", node.Label)
	}

	// Add MITRE technique if present
	if node.MITRETechnique != "" {
		label = fmt.Sprintf("%s\\n[%s]", label, node.MITRETechnique)
	}

	fmt.Fprintf(&sb, "%s: \"%s\" {\n", node.ID, label)

	// Shape based on node type
	switch node.NodeType {
	case AttackTreeNodeTypeAND:
		sb.WriteString("  shape: diamond\n")
	case AttackTreeNodeTypeOR:
		sb.WriteString("  shape: hexagon\n")
	default:
		sb.WriteString("  shape: rectangle\n")
	}

	sb.WriteString("  style: {\n")

	// Color based on node type and mitigation status
	if node.Mitigated {
		sb.WriteString("    fill: \"#e8f5e9\"\n")
		sb.WriteString("    stroke: \"#2e7d32\"\n")
	} else {
		switch node.NodeType {
		case AttackTreeNodeTypeAND:
			sb.WriteString("    fill: \"#e3f2fd\"\n")
			sb.WriteString("    stroke: \"#1976d2\"\n")
		case AttackTreeNodeTypeOR:
			sb.WriteString("    fill: \"#fff3e0\"\n")
			sb.WriteString("    stroke: \"#ef6c00\"\n")
		default:
			sb.WriteString("    fill: \"#ffebee\"\n")
			sb.WriteString("    stroke: \"#c62828\"\n")
		}
	}

	sb.WriteString("    stroke-width: 2\n")
	sb.WriteString("    border-radius: 8\n")
	sb.WriteString("  }\n")
	sb.WriteString("}\n\n")

	return sb.String()
}

// renderMitigations renders the mitigations section.
func (d *DiagramIR) renderMitigations() string {
	if len(d.Mitigations) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n# Mitigations\n")
	sb.WriteString("mitigations: Mitigations {\n")
	sb.WriteString("  style: {\n")
	sb.WriteString("    fill: \"#f5f5f5\"\n")
	sb.WriteString("    stroke: \"#9e9e9e\"\n")
	sb.WriteString("    border-radius: 10\n")
	sb.WriteString("  }\n\n")

	for _, m := range d.Mitigations {
		sb.WriteString(d.renderMitigation(m))
	}

	sb.WriteString("}\n")
	return sb.String()
}

// renderMitigation renders a single mitigation.
func (d *DiagramIR) renderMitigation(m Mitigation) string {
	var sb strings.Builder

	label := m.Title
	if m.Status != "" {
		label = fmt.Sprintf("%s [%s]", m.Title, m.Status)
	}

	fmt.Fprintf(&sb, "  %s: \"%s\" {\n", m.ID, label)
	sb.WriteString("    shape: rectangle\n")
	sb.WriteString("    style: {\n")

	// Color based on status
	switch m.Status {
	case MitigationStatusImplemented:
		sb.WriteString("      fill: \"#e8f5e9\"\n")
		sb.WriteString("      stroke: \"#2e7d32\"\n")
	case MitigationStatusPartial:
		sb.WriteString("      fill: \"#fff3e0\"\n")
		sb.WriteString("      stroke: \"#f57c00\"\n")
	case MitigationStatusPlanned:
		sb.WriteString("      fill: \"#e3f2fd\"\n")
		sb.WriteString("      stroke: \"#1976d2\"\n")
	case MitigationStatusAccepted:
		sb.WriteString("      fill: \"#f5f5f5\"\n")
		sb.WriteString("      stroke: \"#616161\"\n")
	case MitigationStatusTransferred:
		sb.WriteString("      fill: \"#e1f5fe\"\n")
		sb.WriteString("      stroke: \"#0288d1\"\n")
	default:
		sb.WriteString("      fill: \"#f5f5f5\"\n")
		sb.WriteString("      stroke: \"#9e9e9e\"\n")
	}

	sb.WriteString("      stroke-width: 2\n")
	sb.WriteString("      border-radius: 5\n")
	sb.WriteString("    }\n")
	sb.WriteString("  }\n\n")

	return sb.String()
}

// LINDDUNThreatToColors returns fill and stroke colors for LINDDUN threat types.
// This can be used by external rendering tools.
func LINDDUNThreatToColors(t LINDDUNThreat) (fill, stroke string) {
	switch t {
	case LINDDUNLinkability:
		return "#e8eaf6", "#3f51b5"
	case LINDDUNIdentifiability:
		return "#e3f2fd", "#1976d2"
	case LINDDUNNonRepudiation:
		return "#fff3e0", "#f57c00"
	case LINDDUNDetectability:
		return "#fce4ec", "#c2185b"
	case LINDDUNDisclosure:
		return "#ffebee", "#c62828"
	case LINDDUNUnawareness:
		return "#f3e5f5", "#7b1fa2"
	case LINDDUNNonCompliance:
		return "#efebe9", "#5d4037"
	default:
		return "#f5f5f5", "#9e9e9e"
	}
}
