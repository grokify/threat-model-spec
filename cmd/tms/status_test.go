package main

import (
	"encoding/json"
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

func resetStatusFlags() {
	statusJSON = false
	statusCI = false
}

func modelForStatusTest() *ir.ThreatModel {
	tm := &ir.ThreatModel{
		ID:    "status-test",
		Title: "Status Test Model",
		Diagrams: []ir.DiagramView{
			{Type: ir.DiagramTypeDFD, Title: "Test", Elements: []ir.Element{{ID: "a", Label: "A", Type: ir.ElementTypeProcess}}},
		},
		Lifecycle: &ir.Lifecycle{CurrentStage: ir.StageImplementation},
		AnalysisRuns: []ir.AnalysisRun{
			{ID: "run-1", Stage: ir.StageProductDefinition, Status: ir.AnalysisRunStatusCompleted},
			{ID: "run-2", Stage: ir.StageImplementation, Status: ir.AnalysisRunStatusInProgress},
			{ID: "run-3", Stage: ir.StageImplementation, Status: ir.AnalysisRunStatusCompleted},
		},
		Gates: []ir.Gate{
			{ID: "gate-1", Stage: ir.StageProductDefinition, Result: ir.GateResultPassed},
			{ID: "gate-2", Stage: ir.StageImplementation, Result: ir.GateResultFailed},
		},
		Findings: []ir.Finding{
			{ID: "f-1", Type: ir.FindingTypeObservation, Status: ir.FindingStatusValidated},
			{ID: "f-2", Type: ir.FindingTypeVulnerability, Status: ir.FindingStatusCandidate},
			{ID: "f-3", Type: ir.FindingTypeWeakness, Status: ir.FindingStatusRejected},
		},
	}
	return tm
}

func TestBuildStatusReport(t *testing.T) {
	report := buildStatusReport(modelForStatusTest())

	if report.CurrentStage != ir.StageImplementation {
		t.Errorf("CurrentStage = %q, want %q", report.CurrentStage, ir.StageImplementation)
	}
	if len(report.Stages) != 6 {
		t.Fatalf("len(Stages) = %d, want 6", len(report.Stages))
	}

	var productDef, impl stageStatus
	for _, s := range report.Stages {
		switch s.Stage {
		case ir.StageProductDefinition:
			productDef = s
		case ir.StageImplementation:
			impl = s
		}
	}

	if productDef.Runs != 1 || productDef.GateResult != ir.GateResultPassed {
		t.Errorf("product-definition status = %+v, want 1 run, gate passed", productDef)
	}
	// run-3 (completed) is recorded after run-2 (in-progress) in
	// AnalysisRuns, so the latest-run-status should reflect run-3.
	if impl.Runs != 2 || impl.LatestRunStatus != ir.AnalysisRunStatusCompleted || impl.GateResult != ir.GateResultFailed {
		t.Errorf("implementation status = %+v, want 2 runs, latest completed, gate failed", impl)
	}

	if report.Findings.Total != 3 || report.Findings.Validated != 1 || report.Findings.Candidate != 1 || report.Findings.Rejected != 1 {
		t.Errorf("Findings = %+v, want total=3 validated=1 candidate=1 rejected=1", report.Findings)
	}
}

func TestStatusReport_HasFailedGate(t *testing.T) {
	report := buildStatusReport(modelForStatusTest())
	if !report.hasFailedGate() {
		t.Error("hasFailedGate() = false, want true (implementation gate failed)")
	}

	clean := buildStatusReport(&ir.ThreatModel{
		ID: "clean", Title: "Clean",
		Diagrams: []ir.DiagramView{{Type: ir.DiagramTypeDFD, Title: "T"}},
		Gates:    []ir.Gate{{ID: "g", Stage: ir.StageImplementation, Result: ir.GateResultPassed}},
	})
	if clean.hasFailedGate() {
		t.Error("hasFailedGate() = true for an all-passed model, want false")
	}
}

func TestStatus_HumanOutput(t *testing.T) {
	resetFlags()
	resetStatusFlags()

	rootCmd.SetArgs([]string{"status", goldenExample})
	out := captureStdout(t, func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("status: %v", err)
		}
	})
	if out == "" {
		t.Error("status produced no output")
	}
}

func TestStatus_JSONOutput(t *testing.T) {
	resetFlags()
	resetStatusFlags()

	rootCmd.SetArgs([]string{"status", goldenExample, "--json"})
	out := captureStdout(t, func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("status --json: %v", err)
		}
	})

	var report statusReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("unmarshaling status JSON: %v\noutput: %s", err, out)
	}
	if len(report.Stages) != 6 {
		t.Errorf("len(Stages) = %d, want 6", len(report.Stages))
	}
}
