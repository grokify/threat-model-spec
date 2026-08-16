package ir_test

// Cross-repo conformance test (PRD FR1.4, TRD "Stage conformance test").
//
// threat-model-spec is the one repo in the PDLC ecosystem that can safely
// import both github.com/ProductBuildersHQ/pdlc and
// github.com/ProductBuildersHQ/visionspec directly: visionspec sits
// upstream of pdlc in the visionstudio -> visionspec dependency chain, and
// pdlc itself depends on visionspec, so visionspec cannot import pdlc
// without closing a cycle. visionspec's PDLCStage is therefore a set of
// string constants that must match pdlc's Stage* values *by convention*,
// not by a Go import. This test is the drift guard for that convention.

import (
	"testing"

	"github.com/ProductBuildersHQ/pdlc"
	"github.com/ProductBuildersHQ/visionspec/pkg/spectype"

	"github.com/grokify/threat-model-spec/ir"
)

func TestIRStageMatchesPDLC(t *testing.T) {
	pdlcStages, err := pdlc.Stages()
	if err != nil {
		t.Fatalf("pdlc.Stages() error: %v", err)
	}

	pdlcIDs := make(map[string]bool, len(pdlcStages))
	for _, s := range pdlcStages {
		pdlcIDs[s.ID] = true
	}

	for _, s := range ir.AllStages() {
		if !pdlcIDs[string(s)] {
			t.Errorf("ir.Stage %q has no matching pdlc stage ID", s)
		}
	}
	if len(ir.AllStages()) != len(pdlcStages) {
		t.Errorf("ir.AllStages() has %d stages, pdlc.Stages() has %d", len(ir.AllStages()), len(pdlcStages))
	}
}

func TestSpecTypePDLCStageResolvesAgainstPDLC(t *testing.T) {
	// Every visionspec PDLCStage constant actually in use on a core spec
	// type must resolve to a real pdlc stage — this is the concrete drift
	// check: if pdlc ever renames/removes a stage ID without visionspec's
	// string constants being updated to match, this test fails here (the
	// one place that can see both sides).
	seen := map[spectype.PDLCStage]bool{}
	for _, st := range spectype.CoreSpecTypes() {
		if st.PDLCStage == "" {
			continue // execution-tracking spec types (plan, roadmap) carry none
		}
		seen[st.PDLCStage] = true
	}
	if len(seen) == 0 {
		t.Fatal("no spec types carry a PDLCStage — registry or categorization regressed")
	}
	for stage := range seen {
		if _, ok := pdlc.StageByID(string(stage)); !ok {
			t.Errorf("visionspec PDLCStage %q does not resolve to a pdlc stage", stage)
		}
	}
}

func TestSpecTypePDLCStageConstantsMatchIRStage(t *testing.T) {
	// Belt-and-suspenders: the two constant sets, defined independently in
	// two repos, must use identical string values for the stages they
	// share (only the two spec-driven stages appear in visionspec).
	pairs := map[spectype.PDLCStage]ir.Stage{
		spectype.PDLCStageProductDefinition: ir.StageProductDefinition,
		spectype.PDLCStageBuilderDefinition: ir.StageBuilderDefinition,
	}
	for specStage, irStage := range pairs {
		if string(specStage) != string(irStage) {
			t.Errorf("spectype.PDLCStage %q != ir.Stage %q", specStage, irStage)
		}
	}
}
