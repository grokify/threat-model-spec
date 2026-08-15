package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/grokify/threat-model-spec/ir"
)

// tms report is a pure read command: it derives a FrameworkReport fresh
// from the canonical model every time and never mutates it (tms analyze
// remains the single writing verb). Materializing a report into the
// model's frameworkReports array — for an audit snapshot — is a capability
// of the data format itself, not something this command does; tms
// validate warns if a materialized report has drifted from a fresh
// computation.
var reportCmd = &cobra.Command{
	Use:   "report <input.json>",
	Short: "Derive a framework-specific report from the canonical model",
	Long: `Compute a FrameworkReport (STRIDE, LINDDUN, MITRE ATT&CK, OWASP, or
attack-tree) from the canonical model. Always computed fresh from the
model's current state — tms report never writes to the model.`,
	Args: cobra.ExactArgs(1),
	Run:  runReport,
	Example: `  tms report threat-model.json --framework stride
  tms report threat-model.json --framework attack-tree --format markdown
  tms report threat-model.json --framework mitre-attack -o report.json`,
}

var (
	reportFramework  string
	reportFormat     string
	reportOutputFile string
)

func init() {
	reportCmd.Flags().StringVar(&reportFramework, "framework", "", "Framework to report on: stride, linddun, mitre-attack, owasp, attack-tree (required)")
	reportCmd.Flags().StringVar(&reportFormat, "format", "json", "Output format: json or markdown")
	reportCmd.Flags().StringVarP(&reportOutputFile, "output", "o", "", "Output file (default: stdout)")
	_ = reportCmd.MarkFlagRequired("framework")

	rootCmd.AddCommand(reportCmd)
}

// warnStaleFrameworkReports prints a warning (not a validation failure) for
// every materialized FrameworkReport whose SourceRevision no longer
// matches a fresh computation. A report with no SourceRevision was never
// digested and is silently skipped — there's nothing to compare against.
func warnStaleFrameworkReports(tm *ir.ThreatModel) {
	for _, fr := range tm.FrameworkReports {
		if fr.SourceRevision == "" {
			continue
		}
		current, err := ir.FrameworkReportDigest(tm, fr.Framework)
		if err != nil {
			continue
		}
		if current != fr.SourceRevision {
			fmt.Fprintf(os.Stderr, "Warning: framework report %q (%s) is stale relative to the current model\n", fr.ID, fr.Framework)
		}
	}
}

func runReport(_ *cobra.Command, args []string) {
	inputPath := args[0]

	if reportFramework == "" {
		fmt.Fprintln(os.Stderr, "Error: --framework is required")
		os.Exit(1)
	}

	tm, err := ir.LoadThreatModelFromFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	report, err := ir.ComputeFrameworkReport(tm, ir.FrameworkID(reportFramework))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error computing report: %v\n", err)
		os.Exit(1)
	}

	var out string
	switch reportFormat {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding report: %v\n", err)
			os.Exit(1)
		}
		out = string(data)
	case "markdown", "md":
		out = report.RenderMarkdown()
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown --format %q (want json or markdown)\n", reportFormat)
		os.Exit(1)
	}

	if reportOutputFile == "" {
		fmt.Println(out)
		return
	}
	if err := os.WriteFile(reportOutputFile, []byte(out), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", reportOutputFile, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Report written: %s\n", reportOutputFile)
}
