package ir

import (
	"fmt"
	"strings"
)

// RenderMarkdown renders a FrameworkReport as a templated Markdown document,
// dispatching on Framework. Hand-built via strings.Builder, matching this
// repo's existing D2 rendering style (ir/render.go) rather than pulling in
// a template-engine dependency.
func (r *FrameworkReport) RenderMarkdown() string {
	var sb strings.Builder

	switch r.Framework {
	case FrameworkSTRIDE:
		renderSTRIDEMarkdown(&sb, r)
	case FrameworkLINDDUN:
		renderLINDDUNMarkdown(&sb, r)
	case FrameworkMITREAttack:
		renderMITREAttackMarkdown(&sb, r)
	case FrameworkOWASP:
		renderOWASPMarkdown(&sb, r)
	case FrameworkAttackTree:
		renderAttackTreeMarkdown(&sb, r)
	default:
		fmt.Fprintf(&sb, "# Unknown framework %q\n", r.Framework)
	}

	return sb.String()
}

func renderSTRIDEMarkdown(sb *strings.Builder, r *FrameworkReport) {
	sb.WriteString("# STRIDE Report\n\n")
	if r.STRIDE == nil {
		sb.WriteString("No STRIDE body computed.\n")
		return
	}
	b := r.STRIDE

	sb.WriteString("## Coverage\n\n")
	sb.WriteString("| Category | Name | Mappings |\n|----------|------|----------|\n")
	for _, cat := range allSTRIDECategories() {
		fmt.Fprintf(sb, "| %s | %s | %d |\n", cat, GetSTRIDEName(cat), b.CoverageByCategory[cat])
	}
	sb.WriteString("\n")

	if len(b.CategoriesMissing) > 0 {
		sb.WriteString("## Uncovered Categories\n\n")
		for _, cat := range b.CategoriesMissing {
			fmt.Fprintf(sb, "- %s (%s)\n", GetSTRIDEName(cat), cat)
		}
		sb.WriteString("\n")
	}

	renderSTRIDEMappingsTable(sb, b.Mappings)
}

func renderSTRIDEMappingsTable(sb *strings.Builder, mappings []STRIDEMapping) {
	if len(mappings) == 0 {
		sb.WriteString("No STRIDE mappings on this model.\n")
		return
	}
	sb.WriteString("## Mappings\n\n")
	sb.WriteString("| Category | Name | Affected Components |\n|----------|------|----------------------|\n")
	for _, m := range mappings {
		fmt.Fprintf(sb, "| %s | %s | %s |\n", m.Category, m.Name, strings.Join(m.AffectedComponents, ", "))
	}
}

func renderLINDDUNMarkdown(sb *strings.Builder, r *FrameworkReport) {
	sb.WriteString("# LINDDUN Report\n\n")
	if r.LINDDUN == nil {
		sb.WriteString("No LINDDUN body computed.\n")
		return
	}
	b := r.LINDDUN

	sb.WriteString("## Coverage\n\n")
	sb.WriteString("| Category | Name | Mappings |\n|----------|------|----------|\n")
	for _, cat := range allLINDDUNCategories() {
		fmt.Fprintf(sb, "| %s | %s | %d |\n", cat, GetLINDDUNName(cat), b.CoverageByCategory[cat])
	}
	sb.WriteString("\n")

	if len(b.CategoriesMissing) > 0 {
		sb.WriteString("## Uncovered Categories\n\n")
		for _, cat := range b.CategoriesMissing {
			fmt.Fprintf(sb, "- %s (%s)\n", GetLINDDUNName(cat), cat)
		}
		sb.WriteString("\n")
	}

	if len(b.Mappings) == 0 {
		sb.WriteString("No LINDDUN mappings on this model.\n")
		return
	}
	sb.WriteString("## Mappings\n\n")
	sb.WriteString("| Category | Name | Affected Data Types | Affected Components |\n|----------|------|----------------------|----------------------|\n")
	for _, m := range b.Mappings {
		fmt.Fprintf(sb, "| %s | %s | %s | %s |\n", m.Category, m.Name, strings.Join(m.AffectedDataTypes, ", "), strings.Join(m.AffectedComponents, ", "))
	}
}

func renderMITREAttackMarkdown(sb *strings.Builder, r *FrameworkReport) {
	sb.WriteString("# MITRE ATT&CK Report\n\n")
	if r.MITREAttack == nil {
		sb.WriteString("No MITRE ATT&CK body computed.\n")
		return
	}
	b := r.MITREAttack

	if len(b.Mappings) == 0 {
		sb.WriteString("No MITRE ATT&CK mappings on this model.\n")
	} else {
		sb.WriteString("## Mappings\n\n")
		sb.WriteString("| Tactic | Technique | Description |\n|--------|-----------|-------------|\n")
		for _, m := range b.Mappings {
			technique := m.TechniqueID
			if m.TechniqueName != "" {
				technique = fmt.Sprintf("%s (%s)", m.TechniqueID, m.TechniqueName)
			}
			tactic := m.TacticID
			if m.TacticName != "" {
				tactic = fmt.Sprintf("%s (%s)", m.TacticID, m.TacticName)
			}
			fmt.Fprintf(sb, "| %s | %s | %s |\n", tactic, technique, m.Description)
		}
		sb.WriteString("\n")
	}

	if b.DetectionCoverage == nil {
		sb.WriteString("## Detection Coverage\n\nNo detection coverage matrix on this model.\n")
	} else if b.DetectionCoverage.Summary != nil {
		s := b.DetectionCoverage.Summary
		sb.WriteString("## Detection Coverage\n\n")
		fmt.Fprintf(sb, "%d technique(s) assessed, %.0f%% with any coverage, %.0f%% effective coverage.\n\n",
			s.TotalTechniques, s.CoveragePercent, s.EffectiveCoveragePercent)
	}

	if len(b.MappedTechniquesWithoutCoverage) > 0 {
		sb.WriteString("## Mapped Techniques Without Detection Coverage\n\n")
		for _, id := range b.MappedTechniquesWithoutCoverage {
			fmt.Fprintf(sb, "- %s\n", id)
		}
	}
}

func renderOWASPMarkdown(sb *strings.Builder, r *FrameworkReport) {
	sb.WriteString("# OWASP Report\n\n")
	if r.OWASP == nil {
		sb.WriteString("No OWASP body computed.\n")
		return
	}
	b := r.OWASP

	sb.WriteString("## Coverage by List\n\n")
	sb.WriteString("| List | Mappings |\n|------|----------|\n")
	for _, cat := range []OWASPCategory{OWASPCategoryAPI, OWASPCategoryLLM, OWASPCategoryWeb, OWASPCategoryAgentic} {
		fmt.Fprintf(sb, "| %s | %d |\n", cat, b.CoverageByList[cat])
	}
	sb.WriteString("\n")

	if len(b.Mappings) == 0 {
		sb.WriteString("No OWASP mappings on this model.\n")
		return
	}
	sb.WriteString("## Mappings\n\n")
	sb.WriteString("| List | ID | Name |\n|------|----|----- |\n")
	for _, m := range b.Mappings {
		fmt.Fprintf(sb, "| %s | %s | %s |\n", m.Category, m.ID, m.Name)
	}
}

func renderAttackTreeMarkdown(sb *strings.Builder, r *FrameworkReport) {
	sb.WriteString("# Attack Tree / Path Analysis Report\n\n")
	if r.AttackTree == nil {
		sb.WriteString("No attack-tree body computed.\n")
		return
	}
	b := r.AttackTree

	fmt.Fprintf(sb, "Source diagram: `%s`\n\n", b.SourceDiagramType)
	if b.EntryPointHeuristic != "" {
		fmt.Fprintf(sb, "> %s\n\n", b.EntryPointHeuristic)
	}

	if b.Tree != nil {
		sb.WriteString("## Attack Tree\n\n")
		renderAttackTreeNodeMarkdown(sb, b.Tree, b.Tree.RootID, 0)
		sb.WriteString("\n")
	}

	if b.PathAnalysis == nil {
		sb.WriteString("No path analysis computed.\n")
		return
	}
	p := b.PathAnalysis

	sb.WriteString("## Path Analysis\n\n")
	fmt.Fprintf(sb, "- Reachable nodes: %d\n", len(p.ReachableNodes))
	fmt.Fprintf(sb, "- Unreachable targets: %d\n", len(p.UnreachableTargets))
	if p.ShortestPath != nil {
		fmt.Fprintf(sb, "- Shortest path: %s (%d hop(s))\n", strings.Join(p.ShortestPath.Nodes, " -> "), p.ShortestPath.Length)
	}
	sb.WriteString("\n")

	if len(p.CriticalPaths) > 0 {
		sb.WriteString("### Critical Paths\n\n")
		for _, path := range p.CriticalPaths {
			fmt.Fprintf(sb, "- %s (risk: %.2f)\n", strings.Join(path.Nodes, " -> "), path.RiskScore)
		}
		sb.WriteString("\n")
	}

	if len(p.UnreachableTargets) > 0 {
		sb.WriteString("### Unreachable Targets\n\n")
		for _, t := range p.UnreachableTargets {
			fmt.Fprintf(sb, "- %s\n", t)
		}
	}
}

func renderAttackTreeNodeMarkdown(sb *strings.Builder, tree *AttackTree, nodeID string, depth int) {
	node := tree.GetNode(nodeID)
	if node == nil {
		return
	}
	fmt.Fprintf(sb, "%s- %s (%s)\n", strings.Repeat("  ", depth), node.Label, node.NodeType)
	for _, childID := range node.Children {
		renderAttackTreeNodeMarkdown(sb, tree, childID, depth+1)
	}
}
