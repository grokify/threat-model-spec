package ir

import "testing"

func minimalThreatModelForFrameworkReport() *ThreatModel {
	return &ThreatModel{
		ID:    "fr-test-model",
		Title: "Framework Report Test Model",
		Diagrams: []DiagramView{
			{
				Type:  DiagramTypeDFD,
				Title: "Test DFD",
				Elements: []Element{
					{ID: "user", Label: "User", Type: ElementTypeExternalEntity},
					{ID: "app", Label: "App", Type: ElementTypeProcess},
					{ID: "db", Label: "Database", Type: ElementTypeDatastore},
				},
				Flows: []Flow{
					{From: "user", To: "app", Label: "request"},
					{From: "app", To: "db", Label: "query"},
				},
			},
		},
	}
}

func TestComputeFrameworkReport_NilModel(t *testing.T) {
	if _, err := ComputeFrameworkReport(nil, FrameworkSTRIDE); err == nil {
		t.Fatal("expected an error for a nil ThreatModel")
	}
}

func TestComputeFrameworkReport_UnknownFramework(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	if _, err := ComputeFrameworkReport(tm, FrameworkID("not-a-real-framework")); err == nil {
		t.Fatal("expected an error for an unknown framework")
	}
}

func TestComputeSTRIDEReport(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Mappings = &Mappings{
		STRIDE: []STRIDEMapping{
			{Category: STRIDESpoofing, Name: "Spoofing", AffectedComponents: []string{"app"}},
			{Category: STRIDESpoofing, Name: "Spoofing again", AffectedComponents: []string{"db"}},
			{Category: STRIDETampering, Name: "Tampering", AffectedComponents: []string{"db"}},
		},
	}

	report, err := ComputeFrameworkReport(tm, FrameworkSTRIDE)
	if err != nil {
		t.Fatalf("ComputeFrameworkReport: %v", err)
	}
	if report.Framework != FrameworkSTRIDE {
		t.Errorf("Framework = %q, want %q", report.Framework, FrameworkSTRIDE)
	}
	if report.STRIDE == nil {
		t.Fatal("STRIDE body is nil")
	}
	if len(report.STRIDE.Mappings) != 3 {
		t.Errorf("len(Mappings) = %d, want 3", len(report.STRIDE.Mappings))
	}
	if report.STRIDE.CoverageByCategory[STRIDESpoofing] != 2 {
		t.Errorf("CoverageByCategory[Spoofing] = %d, want 2", report.STRIDE.CoverageByCategory[STRIDESpoofing])
	}
	if report.STRIDE.CoverageByCategory[STRIDETampering] != 1 {
		t.Errorf("CoverageByCategory[Tampering] = %d, want 1", report.STRIDE.CoverageByCategory[STRIDETampering])
	}
	if len(report.STRIDE.CategoriesCovered) != 2 {
		t.Errorf("len(CategoriesCovered) = %d, want 2", len(report.STRIDE.CategoriesCovered))
	}
	if len(report.STRIDE.CategoriesMissing) != 4 {
		t.Errorf("len(CategoriesMissing) = %d, want 4", len(report.STRIDE.CategoriesMissing))
	}
}

func TestComputeSTRIDEReport_NoMappings(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()

	report, err := ComputeFrameworkReport(tm, FrameworkSTRIDE)
	if err != nil {
		t.Fatalf("ComputeFrameworkReport: %v", err)
	}
	if len(report.STRIDE.Mappings) != 0 {
		t.Errorf("len(Mappings) = %d, want 0", len(report.STRIDE.Mappings))
	}
	if len(report.STRIDE.CategoriesCovered) != 0 {
		t.Errorf("len(CategoriesCovered) = %d, want 0", len(report.STRIDE.CategoriesCovered))
	}
	if len(report.STRIDE.CategoriesMissing) != 6 {
		t.Errorf("len(CategoriesMissing) = %d, want 6", len(report.STRIDE.CategoriesMissing))
	}
}

func TestComputeLINDDUNReport(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Mappings = &Mappings{
		LINDDUN: []LINDDUNMapping{
			{Category: LINDDUNLinkability},
			{Category: LINDDUNDisclosure},
			{Category: LINDDUNDisclosure},
		},
	}

	report, err := ComputeFrameworkReport(tm, FrameworkLINDDUN)
	if err != nil {
		t.Fatalf("ComputeFrameworkReport: %v", err)
	}
	if report.LINDDUN.CoverageByCategory[LINDDUNDisclosure] != 2 {
		t.Errorf("CoverageByCategory[Disclosure] = %d, want 2", report.LINDDUN.CoverageByCategory[LINDDUNDisclosure])
	}
	if len(report.LINDDUN.CategoriesCovered) != 2 {
		t.Errorf("len(CategoriesCovered) = %d, want 2", len(report.LINDDUN.CategoriesCovered))
	}
	if len(report.LINDDUN.CategoriesMissing) != 5 {
		t.Errorf("len(CategoriesMissing) = %d, want 5", len(report.LINDDUN.CategoriesMissing))
	}
}

func TestComputeMITREAttackReport_JoinsCoverage(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Mappings = &Mappings{
		MITREAttack: []MITREAttackMapping{
			{TechniqueID: "T1059", TacticID: "TA0002"},
			{TechniqueID: "T1078", TacticID: "TA0001"},
		},
	}
	tm.DetectionCoverage = &DetectionCoverageMatrix{
		Techniques: []TechniqueCoverage{
			{TechniqueID: "T1059", Coverage: CoverageLevelFull},
		},
	}

	report, err := ComputeFrameworkReport(tm, FrameworkMITREAttack)
	if err != nil {
		t.Fatalf("ComputeFrameworkReport: %v", err)
	}
	if report.MITREAttack.DetectionCoverage == nil {
		t.Fatal("DetectionCoverage is nil")
	}
	if len(report.MITREAttack.MappedTechniquesWithoutCoverage) != 1 || report.MITREAttack.MappedTechniquesWithoutCoverage[0] != "T1078" {
		t.Errorf("MappedTechniquesWithoutCoverage = %v, want [T1078]", report.MITREAttack.MappedTechniquesWithoutCoverage)
	}
}

func TestComputeMITREAttackReport_NoCoverageMatrixAtAll(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Mappings = &Mappings{
		MITREAttack: []MITREAttackMapping{
			{TechniqueID: "T1059"},
			{TechniqueID: "T1078"},
		},
	}

	report, err := ComputeFrameworkReport(tm, FrameworkMITREAttack)
	if err != nil {
		t.Fatalf("ComputeFrameworkReport: %v", err)
	}
	if report.MITREAttack.DetectionCoverage != nil {
		t.Error("DetectionCoverage should be nil when the model has none")
	}
	if len(report.MITREAttack.MappedTechniquesWithoutCoverage) != 2 {
		t.Errorf("len(MappedTechniquesWithoutCoverage) = %d, want 2 (every mapped technique, no matrix at all)", len(report.MITREAttack.MappedTechniquesWithoutCoverage))
	}
}

func TestComputeOWASPReport(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Mappings = &Mappings{
		OWASP: []OWASPMapping{
			{Category: OWASPCategoryAPI, ID: "API2:2023"},
			{Category: OWASPCategoryLLM, ID: "LLM06:2025"},
			{Category: OWASPCategoryLLM, ID: "LLM01:2025"},
		},
	}

	report, err := ComputeFrameworkReport(tm, FrameworkOWASP)
	if err != nil {
		t.Fatalf("ComputeFrameworkReport: %v", err)
	}
	if report.OWASP.CoverageByList[OWASPCategoryLLM] != 2 {
		t.Errorf("CoverageByList[LLM] = %d, want 2", report.OWASP.CoverageByList[OWASPCategoryLLM])
	}
	if report.OWASP.CoverageByList[OWASPCategoryAPI] != 1 {
		t.Errorf("CoverageByList[API] = %d, want 1", report.OWASP.CoverageByList[OWASPCategoryAPI])
	}
}

func TestComputeAttackTreeReport_NoDiagrams(t *testing.T) {
	tm := &ThreatModel{ID: "empty", Title: "Empty"}
	if _, err := ComputeFrameworkReport(tm, FrameworkAttackTree); err == nil {
		t.Fatal("expected an error for a model with no diagrams")
	}
}

func TestComputeAttackTreeReport_UsesAttackTreeDiagramWhenPresent(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Diagrams = append(tm.Diagrams, DiagramView{
		Type:  DiagramTypeAttackTree,
		Title: "Attack Tree",
		AttackTree: &AttackTree{
			RootID: "goal",
			Nodes: []AttackTreeNode{
				{ID: "goal", Label: "Compromise DB", NodeType: AttackTreeNodeTypeOR, Children: []string{"leaf1"}},
				{ID: "leaf1", Label: "Steal credentials", NodeType: AttackTreeNodeTypeLeaf},
			},
		},
	})

	report, err := ComputeFrameworkReport(tm, FrameworkAttackTree)
	if err != nil {
		t.Fatalf("ComputeFrameworkReport: %v", err)
	}
	if report.AttackTree.SourceDiagramType != DiagramTypeAttackTree {
		t.Errorf("SourceDiagramType = %q, want %q", report.AttackTree.SourceDiagramType, DiagramTypeAttackTree)
	}
	if report.AttackTree.Tree == nil || report.AttackTree.Tree.RootID != "goal" {
		t.Fatal("expected the literal AttackTree to be carried through")
	}
	if report.AttackTree.PathAnalysis == nil {
		t.Error("expected PathAnalysis to still be computed even when a literal tree is present")
	}
}

func TestComputeAttackTreeReport_PrefersAttackChainOverDFD(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Diagrams = append(tm.Diagrams, DiagramView{
		Type:  DiagramTypeAttack,
		Title: "Attack Chain",
		Elements: []Element{
			{ID: "attacker", Label: "Attacker", Type: ElementTypeExternalEntity},
			{ID: "target", Label: "Target DB", Type: ElementTypeDatastore},
		},
		Attacks: []Attack{
			{Step: 1, From: "attacker", To: "target", Label: "Exfiltrate"},
		},
	})

	report, err := ComputeFrameworkReport(tm, FrameworkAttackTree)
	if err != nil {
		t.Fatalf("ComputeFrameworkReport: %v", err)
	}
	if report.AttackTree.SourceDiagramType != DiagramTypeAttack {
		t.Errorf("SourceDiagramType = %q, want %q", report.AttackTree.SourceDiagramType, DiagramTypeAttack)
	}
	if report.AttackTree.Tree != nil {
		t.Error("Tree should be nil when no attack-tree-type diagram exists")
	}
	if report.AttackTree.PathAnalysis == nil {
		t.Fatal("expected PathAnalysis to be computed")
	}
	found := false
	for _, n := range report.AttackTree.PathAnalysis.ReachableNodes {
		if n == "target" {
			found = true
		}
	}
	if !found {
		t.Errorf("ReachableNodes = %v, want it to include the inferred target %q", report.AttackTree.PathAnalysis.ReachableNodes, "target")
	}
}

func TestComputeAttackTreeReport_FallsBackToFirstDiagram(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport() // only a DFD, no attack-chain or attack-tree diagram

	report, err := ComputeFrameworkReport(tm, FrameworkAttackTree)
	if err != nil {
		t.Fatalf("ComputeFrameworkReport: %v", err)
	}
	if report.AttackTree.SourceDiagramType != DiagramTypeDFD {
		t.Errorf("SourceDiagramType = %q, want %q", report.AttackTree.SourceDiagramType, DiagramTypeDFD)
	}
	if report.AttackTree.EntryPointHeuristic == "" {
		t.Error("EntryPointHeuristic should document the inference rule")
	}
}

func TestFrameworkReportDigest_DeterministicForSameInput(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Mappings = &Mappings{STRIDE: []STRIDEMapping{{Category: STRIDESpoofing}}}

	d1, err := FrameworkReportDigest(tm, FrameworkSTRIDE)
	if err != nil {
		t.Fatalf("FrameworkReportDigest: %v", err)
	}
	d2, err := FrameworkReportDigest(tm, FrameworkSTRIDE)
	if err != nil {
		t.Fatalf("FrameworkReportDigest: %v", err)
	}
	if d1 != d2 {
		t.Errorf("digest not deterministic: %q != %q", d1, d2)
	}
}

func TestFrameworkReportDigest_ChangesWithModelContent(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	tm.Mappings = &Mappings{STRIDE: []STRIDEMapping{{Category: STRIDESpoofing}}}
	before, err := FrameworkReportDigest(tm, FrameworkSTRIDE)
	if err != nil {
		t.Fatalf("FrameworkReportDigest: %v", err)
	}

	tm.Mappings.STRIDE = append(tm.Mappings.STRIDE, STRIDEMapping{Category: STRIDETampering})
	after, err := FrameworkReportDigest(tm, FrameworkSTRIDE)
	if err != nil {
		t.Fatalf("FrameworkReportDigest: %v", err)
	}

	if before == after {
		t.Error("digest did not change after adding a new STRIDE mapping")
	}
}

func TestFrameworkReportDigest_UnknownFramework(t *testing.T) {
	tm := minimalThreatModelForFrameworkReport()
	if _, err := FrameworkReportDigest(tm, FrameworkID("not-a-real-framework")); err == nil {
		t.Fatal("expected an error for an unknown framework")
	}
}

// TestComputeFrameworkReport_RealExamples smoke-tests every framework
// against the repo's real example models, catching panics or nil-pointer
// issues that a synthetic fixture might not exercise (e.g. a Mappings
// field with fewer sub-fields populated than the fixtures use).
func TestComputeFrameworkReport_RealExamples(t *testing.T) {
	paths := []string{
		"../examples/openclaw-websocket-takeover.json",
		"../examples/design-phase-payment-checkout.json",
		"../examples/supply-chain-vulnerable-dependency.json",
		"../examples/threat-model-spec-self-assessment.json",
	}
	frameworks := []FrameworkID{FrameworkSTRIDE, FrameworkLINDDUN, FrameworkMITREAttack, FrameworkOWASP, FrameworkAttackTree}

	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			tm, err := LoadThreatModelFromFile(path)
			if err != nil {
				t.Fatalf("loading %s: %v", path, err)
			}
			for _, fw := range frameworks {
				fw := fw
				t.Run(string(fw), func(t *testing.T) {
					if _, err := ComputeFrameworkReport(tm, fw); err != nil {
						t.Errorf("ComputeFrameworkReport(%s, %s): %v", path, fw, err)
					}
				})
			}
		})
	}
}
