package evaluation

import (
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

func allCoveragePassing(stage ir.Stage) CoverageCheckResults {
	profile, err := ir.StageReportProfileByStage(stage)
	if err != nil {
		panic(err)
	}
	results := make(CoverageCheckResults, len(profile.CoverageChecks))
	for _, id := range profile.CoverageChecks {
		results[id] = true
	}
	return results
}

func TestEvaluateStageGate_AllPassing(t *testing.T) {
	evalResult := &EvaluationResult{
		Categories: []CategoryResult{
			{Category: "asset_coverage", Score: "pass"},
			{Category: "invariant_completeness", Score: "pass"},
			{Category: "threat_actor_realism", Score: "pass"},
			{Category: "abuse_case_grounding", Score: "pass"},
		},
	}

	_, gate, err := EvaluateStageGate("test-project", ir.StageProductDefinition, allCoveragePassing(ir.StageProductDefinition), evalResult, nil)
	if err != nil {
		t.Fatalf("EvaluateStageGate() error: %v", err)
	}
	if gate.Result != ir.GateResultPassed {
		t.Errorf("Result = %q, want %q", gate.Result, ir.GateResultPassed)
	}
	if gate.Stage != ir.StageProductDefinition {
		t.Errorf("Stage = %q, want %q", gate.Stage, ir.StageProductDefinition)
	}
	if len(gate.Criteria) == 0 {
		t.Error("expected non-empty Criteria")
	}
}

func TestEvaluateStageGate_RubricFailureBlocksGate(t *testing.T) {
	// Reuse the seeded-defect calibration fixture: coverage all passes,
	// but the rubric itself fails a required category.
	fixture := stageCalibrationFixtures[ir.StageBuilderDefinition]

	_, gate, err := EvaluateStageGate("test-project", ir.StageBuilderDefinition, allCoveragePassing(ir.StageBuilderDefinition), &fixture, nil)
	if err != nil {
		t.Fatalf("EvaluateStageGate() error: %v", err)
	}
	if gate.Result != ir.GateResultFailed {
		t.Errorf("Result = %q, want %q (a required category scored fail)", gate.Result, ir.GateResultFailed)
	}
}

func TestEvaluateStageGate_CoverageFailureBlocksGate(t *testing.T) {
	profile, err := ir.StageReportProfileByStage(ir.StageImplementation)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	coverage := make(CoverageCheckResults, len(profile.CoverageChecks))
	for i, id := range profile.CoverageChecks {
		coverage[id] = i != 0 // first check fails
	}

	_, gate, err := EvaluateStageGate("test-project", ir.StageImplementation, coverage, nil, nil)
	if err != nil {
		t.Fatalf("EvaluateStageGate() error: %v", err)
	}
	if gate.Result != ir.GateResultFailed {
		t.Errorf("Result = %q, want %q (a coverage check failed)", gate.Result, ir.GateResultFailed)
	}
}

func TestEvaluateStageGate_NoDataIsPending(t *testing.T) {
	// No coverage results supplied and no rubric result: nothing was
	// actually evaluated, so the gate must not read as "passed".
	_, gate, err := EvaluateStageGate("test-project", ir.StageProductOperations, CoverageCheckResults{}, nil, nil)
	if err != nil {
		t.Fatalf("EvaluateStageGate() error: %v", err)
	}
	if gate.Result != ir.GateResultPending {
		t.Errorf("Result = %q, want %q", gate.Result, ir.GateResultPending)
	}
}

func TestEvaluateStageGate_UnevaluatedCheckIsNotTreatedAsFailed(t *testing.T) {
	// A coverage check absent from the map (not yet run) must not sink the
	// gate the same way an explicit false (actually failed) does — only
	// checks that were run and failed should block. Here one check passes
	// explicitly and the rest are simply absent (unevaluated).
	profile, err := ir.StageReportProfileByStage(ir.StageProductDefinition)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(profile.CoverageChecks) < 2 {
		t.Fatal("fixture assumption broken: expected at least 2 coverage checks")
	}
	coverage := CoverageCheckResults{profile.CoverageChecks[0]: true}

	_, gate, err := EvaluateStageGate("test-project", ir.StageProductDefinition, coverage, nil, nil)
	if err != nil {
		t.Fatalf("EvaluateStageGate() error: %v", err)
	}
	if gate.Result == ir.GateResultFailed {
		t.Error("unevaluated checks should not fail the gate — only explicitly failed ones should")
	}
}

func TestEvaluateStageGate_EvidenceIDsCarried(t *testing.T) {
	_, gate, err := EvaluateStageGate("test-project", ir.StageDeployment, allCoveragePassing(ir.StageDeployment), nil, []string{"evidence-1", "evidence-2"})
	if err != nil {
		t.Fatalf("EvaluateStageGate() error: %v", err)
	}
	if len(gate.EvidenceIDs) != 2 {
		t.Errorf("EvidenceIDs = %v, want 2 entries", gate.EvidenceIDs)
	}
}

func TestEvaluateStageGate_UnknownStage(t *testing.T) {
	_, _, err := EvaluateStageGate("test-project", "not-a-real-stage", nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown stage")
	}
}

func TestEvaluateStageGate_ResultIsValidIRGateResult(t *testing.T) {
	// The gate produced must be insertable into a ThreatModel that passes
	// validateLifecycle() — a real integration check, not just a value
	// comparison.
	_, gate, err := EvaluateStageGate("test-project", ir.StageProductDefinition, allCoveragePassing(ir.StageProductDefinition), nil, nil)
	if err != nil {
		t.Fatalf("EvaluateStageGate() error: %v", err)
	}

	tm := ir.ThreatModel{
		ID:    "test-model",
		Title: "Test Model",
		Diagrams: []ir.DiagramView{
			{Type: ir.DiagramTypeDFD, Title: "Test", Elements: []ir.Element{{ID: "e1", Label: "E1", Type: ir.ElementTypeProcess}}},
		},
		Gates: []ir.Gate{gate},
	}
	if err := tm.Validate(); err != nil {
		t.Errorf("ThreatModel with the produced Gate failed validation: %v", err)
	}
}
