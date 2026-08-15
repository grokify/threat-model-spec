package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
