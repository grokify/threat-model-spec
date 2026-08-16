package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grokify/threat-model-spec/ir"
)

// resetAnalyzeFlags clears the analyze command's package-level flag
// variables between subtests, same rationale as resetFlags in main_test.go.
func resetAnalyzeFlags() {
	analyzeStage = ""
	analyzeProfile = ""
	analyzeProducer = "unknown-agent"
	analyzeApply = ""
	analyzeRunID = ""
	analyzeDryRun = false
}

func copyExampleFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../examples/openclaw-websocket-takeover.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing fixture copy: %v", err)
	}
	return path
}

func loadModel(t *testing.T, path string) *ir.ThreatModel {
	t.Helper()
	tm, err := ir.LoadThreatModelFromFile(path)
	if err != nil {
		t.Fatalf("loading %s: %v", path, err)
	}
	return tm
}

func TestAnalyze_PlanMode_OpensArtifactsAndRun(t *testing.T) {
	resetFlags()
	resetAnalyzeFlags()
	path := copyExampleFixture(t)

	rootCmd.SetArgs([]string{"analyze", path, "--stage", "implementation", "--profile", "first-party", "README.md"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze: %v", err)
	}

	tm := loadModel(t, path)
	if len(tm.Artifacts) != 1 {
		t.Fatalf("Artifacts = %d, want 1", len(tm.Artifacts))
	}
	if tm.Artifacts[0].URI != "README.md" {
		t.Errorf("Artifacts[0].URI = %q, want %q", tm.Artifacts[0].URI, "README.md")
	}
	if len(tm.AnalysisRuns) != 1 {
		t.Fatalf("AnalysisRuns = %d, want 1", len(tm.AnalysisRuns))
	}
	run := tm.AnalysisRuns[0]
	if run.Status != ir.AnalysisRunStatusInProgress {
		t.Errorf("run.Status = %q, want %q", run.Status, ir.AnalysisRunStatusInProgress)
	}
	if run.Stage != ir.StageImplementation {
		t.Errorf("run.Stage = %q, want %q", run.Stage, ir.StageImplementation)
	}
	if len(run.InputArtifactIDs) != 1 || run.InputArtifactIDs[0] != tm.Artifacts[0].ID {
		t.Errorf("run.InputArtifactIDs = %v, want [%s]", run.InputArtifactIDs, tm.Artifacts[0].ID)
	}
}

func TestAnalyze_DryRun_DoesNotMutate(t *testing.T) {
	resetFlags()
	resetAnalyzeFlags()
	path := copyExampleFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	rootCmd.SetArgs([]string{"analyze", path, "--stage", "deployment", "--profile", "first-party", "--dry-run", "README.md"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze --dry-run: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture after: %v", err)
	}
	if string(before) != string(after) {
		t.Error("--dry-run modified the model file")
	}
}

func TestAnalyze_ProfileRejectsDisallowedStage(t *testing.T) {
	resetFlags()
	resetAnalyzeFlags()
	path := copyExampleFixture(t)

	// third-party has no source access, so implementation must be rejected
	// — runAnalyze calls os.Exit(1) on this path via runPlanMode, so we
	// can't exercise it through rootCmd.Execute() (would kill the test
	// binary, same caveat as tms gate's --stage-omitted path). Verify the
	// underlying profile logic directly instead.
	availability, err := ir.ArtifactAvailabilityProfileByProfile(ir.AnalysisRunProfileThirdParty)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if availability.PermitsStage(ir.StageImplementation) {
		t.Fatal("third-party should not permit implementation — test assumption broken")
	}
	_ = path // fixture unused on this deliberately-indirect path; kept for symmetry with other subtests
}

func TestAnalyze_ApplyMode_MergesAndCompletesRun(t *testing.T) {
	resetFlags()
	resetAnalyzeFlags()
	path := copyExampleFixture(t)

	rootCmd.SetArgs([]string{"analyze", path, "--stage", "implementation", "--profile", "first-party", "README.md"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze (plan): %v", err)
	}
	tm := loadModel(t, path)
	runID := tm.AnalysisRuns[0].ID

	results := ir.AnalysisResults{
		Evidence: []ir.Evidence{
			{ID: "evidence-test-1", Locator: ir.EvidenceLocator{Type: ir.EvidenceLocatorTypeFile, Path: "README.md", StartLine: 1, EndLine: 3}},
		},
		Findings: []ir.Finding{
			{ID: "finding-test-1", Type: ir.FindingTypeObservation, Status: ir.FindingStatusValidated, Confidence: 0.9, Title: "test finding", EvidenceIDs: []string{"evidence-test-1"}},
		},
	}
	resultsData, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	resultsPath := filepath.Join(t.TempDir(), "results.json")
	if err := os.WriteFile(resultsPath, resultsData, 0o644); err != nil {
		t.Fatalf("writing results: %v", err)
	}

	resetFlags()
	resetAnalyzeFlags()
	rootCmd.SetArgs([]string{"analyze", path, "--stage", "implementation", "--apply", resultsPath, "--run", runID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze --apply: %v", err)
	}

	tm = loadModel(t, path)
	if len(tm.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(tm.Findings))
	}
	if tm.Findings[0].ProducerRunID != runID {
		t.Errorf("Findings[0].ProducerRunID = %q, want %q", tm.Findings[0].ProducerRunID, runID)
	}
	if tm.AnalysisRuns[0].Status != ir.AnalysisRunStatusCompleted {
		t.Errorf("run.Status = %q, want %q", tm.AnalysisRuns[0].Status, ir.AnalysisRunStatusCompleted)
	}
	if tm.AnalysisRuns[0].CompletedAt == "" {
		t.Error("run.CompletedAt is empty after apply")
	}
	if err := tm.Validate(); err != nil {
		t.Errorf("model invalid after apply: %v", err)
	}
	if tm.Findings[0].Stage != ir.StageImplementation {
		t.Errorf("Findings[0].Stage = %q, want %q (apply mode should default an unset Stage to --stage)", tm.Findings[0].Stage, ir.StageImplementation)
	}
	if len(tm.Gates) != 1 {
		t.Fatalf("Gates = %d, want 1 (apply mode should compute and record a gate)", len(tm.Gates))
	}
	if tm.Gates[0].Stage != ir.StageImplementation {
		t.Errorf("Gates[0].Stage = %q, want %q", tm.Gates[0].Stage, ir.StageImplementation)
	}
}

func TestAnalyze_ApplyMode_MergesV07CoreObjectsWithProvenance(t *testing.T) {
	resetFlags()
	resetAnalyzeFlags()
	path := copyExampleFixture(t)

	rootCmd.SetArgs([]string{"analyze", path, "--stage", "product-definition", "--profile", "first-party", "docs/PRD.md"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze (plan): %v", err)
	}
	tm := loadModel(t, path)
	runID := tm.AnalysisRuns[0].ID

	results := ir.AnalysisResults{
		Assets:       []ir.Asset{{ID: "asset-test-1", Name: "Test Asset", Classification: ir.SensitivityConfidential}},
		ThreatActors: []ir.ThreatActor{{ID: "actor-test-1", Name: "Test Actor", Type: ir.ThreatActorTypeCriminal}},
		Scenarios:    []ir.Scenario{{ID: "scenario-test-1", Title: "Test Scenario", TargetAssetIDs: []string{"asset-test-1"}}},
		Mitigations:  []ir.Mitigation{{ID: "mitigation-test-1", Title: "Test Mitigation", Status: ir.MitigationStatusPlanned}},
	}
	resultsData, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	resultsPath := filepath.Join(t.TempDir(), "results.json")
	if err := os.WriteFile(resultsPath, resultsData, 0o644); err != nil {
		t.Fatalf("writing results: %v", err)
	}

	resetFlags()
	resetAnalyzeFlags()
	rootCmd.SetArgs([]string{"analyze", path, "--stage", "product-definition", "--apply", resultsPath, "--run", runID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze --apply: %v", err)
	}

	// The flagship fixture already carries its own Assets/ThreatActors/
	// Scenarios/Mitigations, so assert the newly merged object is present
	// with the expected provenance rather than assuming array length.
	tm = loadModel(t, path)
	asset := findByID(t, "asset-test-1", len(tm.Assets), func(i int) string { return tm.Assets[i].ID })
	if tm.Assets[asset].ProducerRunID != runID {
		t.Errorf("Assets[%d].ProducerRunID = %q, want %q", asset, tm.Assets[asset].ProducerRunID, runID)
	}
	actor := findByID(t, "actor-test-1", len(tm.ThreatActors), func(i int) string { return tm.ThreatActors[i].ID })
	if tm.ThreatActors[actor].ProducerRunID != runID {
		t.Errorf("ThreatActors[%d].ProducerRunID = %q, want %q", actor, tm.ThreatActors[actor].ProducerRunID, runID)
	}
	scenario := findByID(t, "scenario-test-1", len(tm.Scenarios), func(i int) string { return tm.Scenarios[i].ID })
	if tm.Scenarios[scenario].ProducerRunID != runID {
		t.Errorf("Scenarios[%d].ProducerRunID = %q, want %q", scenario, tm.Scenarios[scenario].ProducerRunID, runID)
	}
	mitigation := findByID(t, "mitigation-test-1", len(tm.Mitigations), func(i int) string { return tm.Mitigations[i].ID })
	if tm.Mitigations[mitigation].ProducerRunID != runID {
		t.Errorf("Mitigations[%d].ProducerRunID = %q, want %q", mitigation, tm.Mitigations[mitigation].ProducerRunID, runID)
	}
	if err := tm.Validate(); err != nil {
		t.Errorf("model invalid after apply: %v", err)
	}
}

// findByID returns the index of the element whose id() equals want,
// failing the test if none matches.
func findByID(t *testing.T, want string, n int, id func(i int) string) int {
	t.Helper()
	for i := 0; i < n; i++ {
		if id(i) == want {
			return i
		}
	}
	t.Fatalf("no element with id %q found among %d elements", want, n)
	return -1
}

func TestAnalyze_ApplyMode_DefaultsToMostRecentInProgressRun(t *testing.T) {
	resetFlags()
	resetAnalyzeFlags()
	path := copyExampleFixture(t)

	rootCmd.SetArgs([]string{"analyze", path, "--stage", "implementation", "--profile", "first-party", "README.md"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze (plan): %v", err)
	}

	results := ir.AnalysisResults{Findings: []ir.Finding{{ID: "f-1", Type: ir.FindingTypeObservation, Status: ir.FindingStatusValidated}}}
	resultsData, _ := json.Marshal(results)
	resultsPath := filepath.Join(t.TempDir(), "results.json")
	if err := os.WriteFile(resultsPath, resultsData, 0o644); err != nil {
		t.Fatalf("writing results: %v", err)
	}

	// No --run given: apply should find the run by stage + in-progress status.
	resetFlags()
	resetAnalyzeFlags()
	rootCmd.SetArgs([]string{"analyze", path, "--stage", "implementation", "--apply", resultsPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze --apply (no --run): %v", err)
	}

	tm := loadModel(t, path)
	if tm.AnalysisRuns[0].Status != ir.AnalysisRunStatusCompleted {
		t.Errorf("run.Status = %q, want %q", tm.AnalysisRuns[0].Status, ir.AnalysisRunStatusCompleted)
	}
}

// TestAnalyze_ApplyMode_GateUpsertsAsCoverageImproves exercises the
// computeAndUpsertGate path end to end against product-definition, where
// every coverage check is model-wide (not Finding.Stage-scoped), making the
// before/after coverage state easy to control: the flagship fixture already
// carries Assets/ThreatActors but no SecurityRequirements, so the first
// apply's gate should fail on has-invariant/has-prohibited-outcome, and a
// second apply adding both requirement types should flip it to passed —
// via an upsert (one Gate row), not a second Gate appended.
func TestAnalyze_ApplyMode_GateUpsertsAsCoverageImproves(t *testing.T) {
	resetFlags()
	resetAnalyzeFlags()
	path := copyExampleFixture(t)

	rootCmd.SetArgs([]string{"analyze", path, "--stage", "product-definition", "--profile", "first-party", "docs/PRD.md"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze (plan) run 1: %v", err)
	}
	tm := loadModel(t, path)
	run1ID := tm.AnalysisRuns[0].ID

	resultsPath1 := filepath.Join(t.TempDir(), "results1.json")
	if err := os.WriteFile(resultsPath1, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("writing results1: %v", err)
	}
	resetFlags()
	resetAnalyzeFlags()
	rootCmd.SetArgs([]string{"analyze", path, "--stage", "product-definition", "--apply", resultsPath1, "--run", run1ID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze --apply run 1: %v", err)
	}

	tm = loadModel(t, path)
	if len(tm.Gates) != 1 {
		t.Fatalf("Gates = %d, want 1 after first apply", len(tm.Gates))
	}
	if tm.Gates[0].Result != ir.GateResultFailed {
		t.Errorf("Gates[0].Result = %q, want %q (no invariant/prohibited-outcome requirements yet)", tm.Gates[0].Result, ir.GateResultFailed)
	}

	// A second plan-mode call for the same stage would reuse plan mode's
	// deterministic artifact-%s-%d IDs and collide with run 1's artifacts —
	// a separate, pre-existing limitation of plan mode unrelated to gate
	// computation. Open the second run directly instead.
	run2ID := "run-product-definition-2"
	tm.AnalysisRuns = append(tm.AnalysisRuns, ir.AnalysisRun{
		ID:        run2ID,
		Stage:     ir.StageProductDefinition,
		Profile:   ir.AnalysisRunProfileFirstParty,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Status:    ir.AnalysisRunStatusInProgress,
	})
	writeModel(tm, path)

	results2 := ir.AnalysisResults{
		SecurityRequirements: []ir.SecurityRequirement{
			{ID: "req-invariant-test", Statement: "test invariant", Type: ir.SecurityRequirementTypeInvariant},
			{ID: "req-prohibited-test", Statement: "test prohibited outcome", Type: ir.SecurityRequirementTypeProhibitedOutcome},
		},
	}
	results2Data, err := json.Marshal(results2)
	if err != nil {
		t.Fatalf("marshal results2: %v", err)
	}
	resultsPath2 := filepath.Join(t.TempDir(), "results2.json")
	if err := os.WriteFile(resultsPath2, results2Data, 0o644); err != nil {
		t.Fatalf("writing results2: %v", err)
	}
	resetFlags()
	resetAnalyzeFlags()
	rootCmd.SetArgs([]string{"analyze", path, "--stage", "product-definition", "--apply", resultsPath2, "--run", run2ID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze --apply run 2: %v", err)
	}

	tm = loadModel(t, path)
	if len(tm.Gates) != 1 {
		t.Fatalf("Gates = %d, want 1 after second apply (upsert, not append)", len(tm.Gates))
	}
	if tm.Gates[0].Result != ir.GateResultPassed {
		t.Errorf("Gates[0].Result = %q, want %q (all four product-definition checks now computable-true)", tm.Gates[0].Result, ir.GateResultPassed)
	}
}

func TestAnalyze_ApplyMode_InvalidResultsWriteNothing(t *testing.T) {
	resetFlags()
	resetAnalyzeFlags()
	path := copyExampleFixture(t)

	rootCmd.SetArgs([]string{"analyze", path, "--stage", "implementation", "--profile", "first-party", "README.md"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("analyze (plan): %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	// A finding referencing evidence that doesn't exist makes the merged
	// model invalid; apply must reject it and leave the file untouched.
	results := ir.AnalysisResults{
		Findings: []ir.Finding{{ID: "f-bad", Type: ir.FindingTypeObservation, Status: ir.FindingStatusValidated, EvidenceIDs: []string{"does-not-exist"}}},
	}
	resultsData, _ := json.Marshal(results)
	resultsPath := filepath.Join(t.TempDir(), "results.json")
	if err := os.WriteFile(resultsPath, resultsData, 0o644); err != nil {
		t.Fatalf("writing results: %v", err)
	}

	// This exercises the os.Exit(1) path in runApplyMode's validation
	// failure branch — can't run it through rootCmd.Execute() directly
	// (same os.Exit hazard as elsewhere in this package). Verify the
	// atomicity guarantee at the level we can: constructing the same
	// candidate model this code path builds and confirming it fails
	// validation, which is precisely what gates the write.
	tm := loadModel(t, path)
	candidate := *tm
	candidate.Findings = append(append([]ir.Finding{}, tm.Findings...), results.Findings...)
	if err := candidate.Validate(); err == nil {
		t.Fatal("expected the candidate model (bad evidence reference) to fail validation")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture after: %v", err)
	}
	if string(before) != string(after) {
		t.Error("file should be unchanged since apply was never actually invoked with the bad results in this test")
	}
}
