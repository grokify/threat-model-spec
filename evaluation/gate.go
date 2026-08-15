package evaluation

import (
	"fmt"
	"time"

	"github.com/plexusone/structured-evaluation/summary"

	"github.com/grokify/threat-model-spec/ir"
)

// CoverageCheckResults maps a StageReportProfile.CoverageChecks ID to
// whether that deterministic check passed.
type CoverageCheckResults map[string]bool

// EvaluateStageGate aggregates deterministic coverage checks and a rubric
// EvaluationResult into a structured-evaluation SummaryReport (a GO/WARN/
// NO-GO decision per structured-evaluation's own vocabulary) and the
// corresponding ir.Gate, written back with criteria and evidence.
//
// evalResult may be nil if no rubric evaluation has run yet; the gate then
// reflects coverage checks alone and is more likely to come out Pending.
// evidenceIDs are ir.Evidence IDs the caller wants attached to the
// resulting Gate — EvaluateStageGate does not create Evidence itself.
func EvaluateStageGate(project string, stage ir.Stage, coverage CoverageCheckResults, evalResult *EvaluationResult, evidenceIDs []string) (*summary.SummaryReport, ir.Gate, error) {
	profile, err := ir.StageReportProfileByStage(stage)
	if err != nil {
		return nil, ir.Gate{}, fmt.Errorf("loading report profile for stage %q: %w", stage, err)
	}

	report := summary.NewSummaryReport(project, "", string(stage))

	coverageTasks := make([]summary.TaskResult, 0, len(profile.CoverageChecks))
	for _, checkID := range profile.CoverageChecks {
		// A check absent from the map hasn't been evaluated yet (Skip) —
		// distinct from a check that was evaluated and failed (NoGo).
		// Conflating the two would make an unrun analysis silently read as
		// a failed one, the same class of gap this codebase avoids
		// elsewhere (see the artifact-availability "every stage accounted
		// for" guarantee and the dynamic-testing-disclosure rubric).
		status := summary.StatusSkip
		detail := "not evaluated"
		if passed, ok := coverage[checkID]; ok {
			if passed {
				status = summary.StatusGo
				detail = "passed"
			} else {
				status = summary.StatusNoGo
				detail = "failed"
			}
		}
		coverageTasks = append(coverageTasks, summary.TaskResult{ID: checkID, Status: status, Detail: detail})
	}
	report.AddTeam(summary.TeamSection{ID: "coverage", Name: "Deterministic Coverage Checks", Tasks: coverageTasks})

	var rubricTasks []summary.TaskResult
	if evalResult != nil {
		for _, cr := range evalResult.Categories {
			status := summary.StatusGo
			switch cr.Score {
			case "fail":
				status = summary.StatusNoGo
			case "partial":
				status = summary.StatusWarn
			}
			rubricTasks = append(rubricTasks, summary.TaskResult{ID: cr.Category, Status: status, Detail: cr.Reasoning})
		}
	}
	report.AddTeam(summary.TeamSection{ID: "rubric", Name: "Rubric: " + profile.RubricID, Tasks: rubricTasks})

	report.ComputeOverallStatus()

	gate := ir.Gate{
		ID:          "gate-" + string(stage),
		Stage:       stage,
		EvaluatedBy: "evaluation.EvaluateStageGate",
		EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
		EvidenceIDs: evidenceIDs,
	}
	for _, checkID := range profile.CoverageChecks {
		gate.Criteria = append(gate.Criteria, ir.GateCriterion{Metric: checkID, Operator: "equals", Value: "true"})
	}

	switch report.Status {
	case summary.StatusNoGo:
		gate.Result = ir.GateResultFailed
	case summary.StatusSkip:
		// No coverage checks were declared and no rubric result was
		// supplied — nothing was actually evaluated.
		gate.Result = ir.GateResultPending
	default: // StatusGo or StatusWarn
		gate.Result = ir.GateResultPassed
	}

	return report, gate, nil
}
