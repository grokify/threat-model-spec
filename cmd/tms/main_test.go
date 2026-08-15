package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetFlags clears the package-level flag variables between subtests.
// cobra's Execute() only calls Set() for flags actually present in the
// argument list, so a flag left set by one subtest (e.g. --strict) would
// otherwise leak into the next.
func resetFlags() {
	outputFile = ""
	renderSVG = false
	exportSTIX = false
	strictValidation = false
	gateStage = ""
	gateCI = false
}

var exampleFiles = []string{
	"../../examples/openclaw-websocket-takeover.json",
	"../../examples/design-phase-payment-checkout.json",
	"../../examples/supply-chain-vulnerable-dependency.json",
}

func TestValidateExamples(t *testing.T) {
	for _, path := range exampleFiles {
		t.Run(path, func(t *testing.T) {
			resetFlags()
			rootCmd.SetArgs([]string{"validate", path})
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("validate %s: %v", path, err)
			}
		})
	}
}

func TestValidateExamplesStrict(t *testing.T) {
	for _, path := range exampleFiles {
		t.Run(path, func(t *testing.T) {
			resetFlags()
			rootCmd.SetArgs([]string{"validate", path, "--strict"})
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("validate --strict %s: %v", path, err)
			}
		})
	}
}

func TestGenerateProducesD2Output(t *testing.T) {
	resetFlags()
	outPath := filepath.Join(t.TempDir(), "out.d2")

	rootCmd.SetArgs([]string{"generate", "../../examples/openclaw-websocket-takeover.json", "-o", outPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// The flagship example has 2 diagrams, so runGenerate splits the output
	// into <base>_<type>.d2 files rather than writing outPath directly.
	dir := filepath.Dir(outPath)
	diagEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading output dir: %v", err)
	}
	var d2Files []string
	for _, e := range diagEntries {
		if strings.HasSuffix(e.Name(), ".d2") {
			d2Files = append(d2Files, e.Name())
		}
	}
	if len(d2Files) == 0 {
		t.Fatal("no .d2 output files were generated")
	}

	for _, name := range d2Files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestGenerateSingleDiagramExample(t *testing.T) {
	// The supply-chain example has exactly one diagram, so this exercises
	// the single-diagram (non-split) output path.
	resetFlags()
	outPath := filepath.Join(t.TempDir(), "out.d2")

	rootCmd.SetArgs([]string{"generate", "../../examples/supply-chain-vulnerable-dependency.json", "-o", outPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading %s: %v", outPath, err)
	}
	if len(data) == 0 {
		t.Error("generated D2 output is empty")
	}
}

func TestGenerateSTIXExport(t *testing.T) {
	resetFlags()
	outPath := filepath.Join(t.TempDir(), "out.stix.json")
	exportSTIX = true

	rootCmd.SetArgs([]string{"generate", "../../examples/openclaw-websocket-takeover.json", "--stix", "-o", outPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("generate --stix: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading %s: %v", outPath, err)
	}
	if !strings.Contains(string(data), `"type": "bundle"`) {
		t.Errorf("STIX output does not look like a bundle: %s", string(data)[:min(200, len(data))])
	}
}

func TestLoadInputFallsBackToDiagramIR(t *testing.T) {
	// A bare DiagramIR (no "diagrams" array) should still load via the
	// fallback path in loadInput.
	dir := t.TempDir()
	path := filepath.Join(dir, "diagram.json")
	content := `{
		"type": "dfd",
		"title": "Standalone Diagram",
		"elements": [
			{"id": "a", "label": "A", "type": "process"},
			{"id": "b", "label": "B", "type": "datastore"}
		],
		"flows": [
			{"from": "a", "to": "b", "label": "writes"}
		]
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	diagrams, isThreatModel, err := loadInput(path)
	if err != nil {
		t.Fatalf("loadInput: %v", err)
	}
	if isThreatModel {
		t.Error("isThreatModel = true, want false for a standalone DiagramIR")
	}
	if len(diagrams) != 1 {
		t.Fatalf("got %d diagrams, want 1", len(diagrams))
	}
}

// modelWithGate writes a minimal ThreatModel fixture carrying one Gate for
// the given stage and result, returning the file path. Only the success
// path is exercised here — runGate calls os.Exit(1) on failure, which
// would kill the test binary, so the "gate not found" / "--ci fails" paths
// are not covered by these tests (matching the existing convention: the
// other run* functions' os.Exit branches aren't tested here either).
func modelWithGate(t *testing.T, stage, result string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "model-with-gate.json")
	content := `{
		"id": "gate-fixture",
		"title": "Gate Fixture",
		"diagrams": [
			{
				"type": "dfd",
				"title": "Test",
				"elements": [{"id": "a", "label": "A", "type": "process"}]
			}
		],
		"gates": [
			{
				"id": "gate-` + stage + `",
				"stage": "` + stage + `",
				"criteria": [{"metric": "has-invariant", "operator": "equals", "value": "true"}],
				"result": "` + result + `",
				"evaluatedBy": "test-fixture"
			}
		]
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func TestGate_PassedStagePrintsResult(t *testing.T) {
	resetFlags()
	path := modelWithGate(t, "deployment", "passed")

	rootCmd.SetArgs([]string{"gate", path, "--stage", "deployment"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("gate: %v", err)
	}
}

func TestGate_PassedStageWithCIDoesNotExit(t *testing.T) {
	resetFlags()
	path := modelWithGate(t, "deployment", "passed")

	rootCmd.SetArgs([]string{"gate", path, "--stage", "deployment", "--ci"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("gate --ci: %v", err)
	}
}

// Note: the --stage-omitted path is not covered here — runGate calls
// os.Exit(1) when gateStage is empty (see main.go), and exercising that
// through rootCmd.Execute() kills the test binary rather than returning an
// error, as discovered when this test used to live here. Testing os.Exit
// paths safely needs a subprocess harness this package doesn't have; the
// other run* functions' failure paths aren't tested here either.
