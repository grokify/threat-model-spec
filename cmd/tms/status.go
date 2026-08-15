package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/grokify/threat-model-spec/ir"
)

// tms status is a pure read command summarizing a model's PDLC lifecycle
// state: which stages have been analyzed, their latest run status and
// recorded gate result, and a findings breakdown by adjudication status.
var statusCmd = &cobra.Command{
	Use:   "status <input.json>",
	Short: "Summarize a model's PDLC lifecycle state",
	Long: `Print a summary of a model's PDLC lifecycle state: which stages have
recorded AnalysisRuns, their latest run status, each stage's recorded
Gate result, and a Finding breakdown by adjudication status.`,
	Args: cobra.ExactArgs(1),
	Run:  runStatus,
	Example: `  tms status threat-model.json
  tms status threat-model.json --json
  tms status threat-model.json --ci`,
}

var (
	statusJSON bool
	statusCI   bool
)

func init() {
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output as JSON")
	statusCmd.Flags().BoolVar(&statusCI, "ci", false, "Exit non-zero if any recorded gate has failed")

	rootCmd.AddCommand(statusCmd)
}

// stageStatus summarizes one PDLC stage's recorded activity.
type stageStatus struct {
	Stage           ir.Stage             `json:"stage"`
	Runs            int                  `json:"runs"`
	LatestRunStatus ir.AnalysisRunStatus `json:"latestRunStatus,omitempty"`
	GateResult      ir.GateResult        `json:"gateResult,omitempty"`
}

// findingsSummary counts Findings by adjudication status.
type findingsSummary struct {
	Total                int `json:"total"`
	Candidate            int `json:"candidate"`
	Validated            int `json:"validated"`
	Rejected             int `json:"rejected"`
	InsufficientEvidence int `json:"insufficientEvidence"`
}

// statusReport is the tms status command's output shape — a computed CLI
// view, not a canonical IR type: nothing here is persisted to the model.
type statusReport struct {
	ModelID      string          `json:"modelId"`
	Title        string          `json:"title"`
	CurrentStage ir.Stage        `json:"currentStage,omitempty"`
	Stages       []stageStatus   `json:"stages"`
	Findings     findingsSummary `json:"findings"`
}

func buildStatusReport(tm *ir.ThreatModel) statusReport {
	report := statusReport{ModelID: tm.ID, Title: tm.Title}
	if tm.Lifecycle != nil {
		report.CurrentStage = tm.Lifecycle.CurrentStage
	}

	for _, stage := range ir.AllStages() {
		ss := stageStatus{Stage: stage}
		for _, run := range tm.AnalysisRuns {
			if run.Stage != stage {
				continue
			}
			ss.Runs++
			ss.LatestRunStatus = run.Status
		}
		for _, gate := range tm.Gates {
			if gate.Stage == stage {
				ss.GateResult = gate.Result
			}
		}
		report.Stages = append(report.Stages, ss)
	}

	for _, f := range tm.Findings {
		report.Findings.Total++
		switch f.Status {
		case ir.FindingStatusCandidate:
			report.Findings.Candidate++
		case ir.FindingStatusValidated:
			report.Findings.Validated++
		case ir.FindingStatusRejected:
			report.Findings.Rejected++
		case ir.FindingStatusInsufficientEvidence:
			report.Findings.InsufficientEvidence++
		}
	}

	return report
}

func (r statusReport) hasFailedGate() bool {
	for _, s := range r.Stages {
		if s.GateResult == ir.GateResultFailed {
			return true
		}
	}
	return false
}

func runStatus(_ *cobra.Command, args []string) {
	inputPath := args[0]

	tm, err := ir.LoadThreatModelFromFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", inputPath, err)
		os.Exit(1)
	}

	report := buildStatusReport(tm)

	if statusJSON {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding status: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("%s (%s)\n", report.Title, report.ModelID)
		if report.CurrentStage != "" {
			fmt.Printf("Current stage: %s\n", report.CurrentStage)
		}
		fmt.Println()
		fmt.Printf("%-22s %6s  %-16s  %s\n", "STAGE", "RUNS", "LATEST STATUS", "GATE")
		for _, s := range report.Stages {
			latest := "-"
			if s.LatestRunStatus != "" {
				latest = string(s.LatestRunStatus)
			}
			gate := "-"
			if s.GateResult != "" {
				gate = string(s.GateResult)
			}
			fmt.Printf("%-22s %6d  %-16s  %s\n", s.Stage, s.Runs, latest, gate)
		}
		fmt.Println()
		fmt.Printf("Findings: %d total (%d candidate, %d validated, %d rejected, %d insufficient-evidence)\n",
			report.Findings.Total, report.Findings.Candidate, report.Findings.Validated, report.Findings.Rejected, report.Findings.InsufficientEvidence)
	}

	if statusCI && report.hasFailedGate() {
		os.Exit(1)
	}
}
