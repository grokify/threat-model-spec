package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

// resetReportFlags clears the report command's package-level flag
// variables between subtests.
func resetReportFlags() {
	reportFramework = ""
	reportFormat = "json"
	reportOutputFile = ""
}

const goldenExample = "../../examples/openclaw-websocket-takeover.json"

// updateGolden regenerates golden files instead of comparing against them,
// when RUN with UPDATE_GOLDEN=1 in the environment — the standard Go
// golden-file idiom, without adding a flag dependency to this package.
var updateGolden = os.Getenv("UPDATE_GOLDEN") == "1"

func compareOrUpdateGolden(t *testing.T, goldenPath string, got string) {
	t.Helper()
	if updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("creating golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("writing golden file: %v", err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file %s (run with UPDATE_GOLDEN=1 to create it): %v", goldenPath, err)
	}
	if got != string(want) {
		t.Errorf("output does not match golden file %s (run with UPDATE_GOLDEN=1 to update it)\n--- got ---\n%s\n--- want ---\n%s", goldenPath, got, string(want))
	}
}

var allFrameworks = []string{"stride", "linddun", "mitre-attack", "owasp", "attack-tree"}

func TestReport_JSONGoldenFiles(t *testing.T) {
	for _, fw := range allFrameworks {
		fw := fw
		t.Run(fw, func(t *testing.T) {
			resetFlags()
			resetReportFlags()
			outPath := filepath.Join(t.TempDir(), "out.json")

			rootCmd.SetArgs([]string{"report", goldenExample, "--framework", fw, "-o", outPath})
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("report --framework %s: %v", fw, err)
			}
			got, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("reading output: %v", err)
			}

			compareOrUpdateGolden(t, filepath.Join("testdata", "framework-reports", fw+".golden.json"), string(got))
		})
	}
}

func TestReport_MarkdownGoldenFiles(t *testing.T) {
	for _, fw := range allFrameworks {
		fw := fw
		t.Run(fw, func(t *testing.T) {
			resetFlags()
			resetReportFlags()
			outPath := filepath.Join(t.TempDir(), "out.md")

			rootCmd.SetArgs([]string{"report", goldenExample, "--framework", fw, "--format", "markdown", "-o", outPath})
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("report --framework %s --format markdown: %v", fw, err)
			}
			got, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("reading output: %v", err)
			}

			compareOrUpdateGolden(t, filepath.Join("testdata", "framework-reports", fw+".golden.md"), string(got))
		})
	}
}

func TestReport_DefaultsToJSON(t *testing.T) {
	resetFlags()
	resetReportFlags()
	outPath := filepath.Join(t.TempDir(), "out")

	rootCmd.SetArgs([]string{"report", goldenExample, "--framework", "stride", "-o", outPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("report: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if data[0] != '{' {
		t.Errorf("default output does not look like JSON: %s", data[:min(50, len(data))])
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// whatever was written to it. runReport/warnStaleFrameworkReports print
// warnings and errors to os.Stderr directly (not through cobra), so this
// is the only way to assert on that output without a subprocess harness.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stderr: %v", err)
	}
	return string(out)
}

// Note: runReport itself calls os.Exit(1) on an unknown --format, which
// this package's existing convention avoids testing directly (would kill
// the test binary). Confirmed manually: `tms report model.json --framework
// stride --format bogus` exits 1 with "unknown --format" on stderr.

func TestWarnStaleFrameworkReports_NoReports(t *testing.T) {
	tm, err := ir.LoadThreatModelFromFile(goldenExample)
	if err != nil {
		t.Fatalf("loading example: %v", err)
	}

	out := captureStderr(t, func() { warnStaleFrameworkReports(tm) })
	if out != "" {
		t.Errorf("expected no warning for a model with no FrameworkReports, got: %q", out)
	}
}

func TestWarnStaleFrameworkReports_NoSourceRevisionIsNotWarned(t *testing.T) {
	tm, err := ir.LoadThreatModelFromFile(goldenExample)
	if err != nil {
		t.Fatalf("loading example: %v", err)
	}
	tm.FrameworkReports = []ir.FrameworkReport{{ID: "fr-1", Framework: ir.FrameworkSTRIDE}}

	out := captureStderr(t, func() { warnStaleFrameworkReports(tm) })
	if out != "" {
		t.Errorf("expected no warning for a report with no SourceRevision (never digested), got: %q", out)
	}
}

func TestWarnStaleFrameworkReports_StaleIsWarned(t *testing.T) {
	tm, err := ir.LoadThreatModelFromFile(goldenExample)
	if err != nil {
		t.Fatalf("loading example: %v", err)
	}
	tm.FrameworkReports = []ir.FrameworkReport{{ID: "fr-1", Framework: ir.FrameworkSTRIDE, SourceRevision: "not-a-real-digest"}}

	out := captureStderr(t, func() { warnStaleFrameworkReports(tm) })
	if !strings.Contains(out, "fr-1") || !strings.Contains(out, "stale") {
		t.Errorf("expected a stale warning mentioning fr-1, got: %q", out)
	}
}

func TestWarnStaleFrameworkReports_FreshIsNotWarned(t *testing.T) {
	tm, err := ir.LoadThreatModelFromFile(goldenExample)
	if err != nil {
		t.Fatalf("loading example: %v", err)
	}
	digest, err := ir.FrameworkReportDigest(tm, ir.FrameworkSTRIDE)
	if err != nil {
		t.Fatalf("FrameworkReportDigest: %v", err)
	}
	tm.FrameworkReports = []ir.FrameworkReport{{ID: "fr-1", Framework: ir.FrameworkSTRIDE, SourceRevision: digest}}

	out := captureStderr(t, func() { warnStaleFrameworkReports(tm) })
	if out != "" {
		t.Errorf("expected no warning for a fresh digest, got: %q", out)
	}
}
