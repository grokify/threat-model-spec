package ir

import "fmt"

// ComputeFrameworkReport derives a FrameworkReport for the given framework
// from the canonical model. It reads model data only — it never mutates tm
// and never appends to tm.FrameworkReports; the caller decides whether to
// materialize the result.
func ComputeFrameworkReport(tm *ThreatModel, framework FrameworkID) (*FrameworkReport, error) {
	if tm == nil {
		return nil, fmt.Errorf("cannot compute a framework report from a nil ThreatModel")
	}

	switch framework {
	case FrameworkSTRIDE:
		return computeSTRIDEReport(tm), nil
	case FrameworkLINDDUN:
		return computeLINDDUNReport(tm), nil
	case FrameworkMITREAttack:
		return computeMITREAttackReport(tm), nil
	case FrameworkOWASP:
		return computeOWASPReport(tm), nil
	case FrameworkAttackTree:
		return computeAttackTreeReport(tm)
	default:
		return nil, fmt.Errorf("unknown framework %q", framework)
	}
}

// allSTRIDECategories lists the six STRIDE categories in their canonical order.
func allSTRIDECategories() []STRIDEThreat {
	return []STRIDEThreat{
		STRIDESpoofing, STRIDETampering, STRIDERepudiation,
		STRIDEInformationDisc, STRIDEDenialOfService, STRIDEElevationOfPrivilege,
	}
}

func computeSTRIDEReport(tm *ThreatModel) *FrameworkReport {
	var mappings []STRIDEMapping
	if tm.Mappings != nil {
		mappings = tm.Mappings.STRIDE
	}

	coverage := make(map[STRIDEThreat]int)
	for _, m := range mappings {
		coverage[m.Category]++
	}

	var covered, missing []STRIDEThreat
	for _, cat := range allSTRIDECategories() {
		if coverage[cat] > 0 {
			covered = append(covered, cat)
		} else {
			missing = append(missing, cat)
		}
	}

	return &FrameworkReport{
		ID:        "framework-report-stride",
		Framework: FrameworkSTRIDE,
		STRIDE: &STRIDEReportBody{
			Mappings:           mappings,
			CoverageByCategory: coverage,
			CategoriesCovered:  covered,
			CategoriesMissing:  missing,
		},
	}
}

// allLINDDUNCategories lists the seven LINDDUN categories in their canonical order.
func allLINDDUNCategories() []LINDDUNThreat {
	return []LINDDUNThreat{
		LINDDUNLinkability, LINDDUNIdentifiability, LINDDUNNonRepudiation,
		LINDDUNDetectability, LINDDUNDisclosure, LINDDUNUnawareness, LINDDUNNonCompliance,
	}
}

func computeLINDDUNReport(tm *ThreatModel) *FrameworkReport {
	var mappings []LINDDUNMapping
	if tm.Mappings != nil {
		mappings = tm.Mappings.LINDDUN
	}

	coverage := make(map[LINDDUNThreat]int)
	for _, m := range mappings {
		coverage[m.Category]++
	}

	var covered, missing []LINDDUNThreat
	for _, cat := range allLINDDUNCategories() {
		if coverage[cat] > 0 {
			covered = append(covered, cat)
		} else {
			missing = append(missing, cat)
		}
	}

	return &FrameworkReport{
		ID:        "framework-report-linddun",
		Framework: FrameworkLINDDUN,
		LINDDUN: &LINDDUNReportBody{
			Mappings:           mappings,
			CoverageByCategory: coverage,
			CategoriesCovered:  covered,
			CategoriesMissing:  missing,
		},
	}
}

func computeMITREAttackReport(tm *ThreatModel) *FrameworkReport {
	var mappings []MITREAttackMapping
	if tm.Mappings != nil {
		mappings = tm.Mappings.MITREAttack
	}

	var withoutCoverage []string
	if tm.DetectionCoverage != nil {
		for _, m := range mappings {
			if tm.DetectionCoverage.GetTechniqueCoverage(m.TechniqueID) == nil {
				withoutCoverage = append(withoutCoverage, m.TechniqueID)
			}
		}
	} else {
		// No coverage matrix at all: every mapped technique is, by
		// definition, without recorded coverage.
		for _, m := range mappings {
			withoutCoverage = append(withoutCoverage, m.TechniqueID)
		}
	}

	return &FrameworkReport{
		ID:        "framework-report-mitre-attack",
		Framework: FrameworkMITREAttack,
		MITREAttack: &MITREAttackReportBody{
			Mappings:                        mappings,
			DetectionCoverage:               tm.DetectionCoverage,
			MappedTechniquesWithoutCoverage: withoutCoverage,
		},
	}
}

func computeOWASPReport(tm *ThreatModel) *FrameworkReport {
	var mappings []OWASPMapping
	if tm.Mappings != nil {
		mappings = tm.Mappings.OWASP
	}

	coverage := make(map[OWASPCategory]int)
	for _, m := range mappings {
		coverage[m.Category]++
	}

	return &FrameworkReport{
		ID:        "framework-report-owasp",
		Framework: FrameworkOWASP,
		OWASP: &OWASPReportBody{
			Mappings:       mappings,
			CoverageByList: coverage,
		},
	}
}

// entryPointHeuristicNote documents, for the report body, the rule
// computeAttackTreeReport applies to infer EntryPoints/Targets — diagrams
// don't author these explicitly today (see AttackGraph.EntryPoints/Targets).
const entryPointHeuristicNote = "entry points inferred as external-entity elements; targets inferred as datastore elements (diagrams do not author these explicitly)"

func computeAttackTreeReport(tm *ThreatModel) (*FrameworkReport, error) {
	if len(tm.Diagrams) == 0 {
		return nil, fmt.Errorf("cannot compute an attack-tree report: model has no diagrams")
	}

	body := &AttackTreeReportBody{EntryPointHeuristic: entryPointHeuristicNote}

	// Prefer a literal attack-tree diagram's authored structure.
	if dv := tm.GetDiagram(DiagramTypeAttackTree); dv != nil && dv.AttackTree != nil {
		body.SourceDiagramType = DiagramTypeAttackTree
		body.Tree = dv.AttackTree
	}

	// Always also compute a graph path analysis, preferring an
	// attack-chain diagram (built for this purpose), then falling back to
	// the model's first diagram of any type.
	source := tm.GetDiagram(DiagramTypeAttack)
	if source == nil {
		source = &tm.Diagrams[0]
	}
	if body.SourceDiagramType == "" {
		body.SourceDiagramType = source.Type
	}

	diagramIR := source.ToDiagramIR(tm)
	graph := BuildAttackGraphFromDiagram(diagramIR)
	if graph != nil {
		for _, n := range graph.Nodes {
			switch n.Type {
			case GraphNodeTypeActor:
				graph.EntryPoints = append(graph.EntryPoints, n.ID)
			case GraphNodeTypeAsset:
				graph.Targets = append(graph.Targets, n.ID)
			}
		}
		body.PathAnalysis = graph.AnalyzePaths()
	}

	return &FrameworkReport{
		ID:         "framework-report-attack-tree",
		Framework:  FrameworkAttackTree,
		AttackTree: body,
	}, nil
}
