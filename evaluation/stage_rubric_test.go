package evaluation

import (
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

func TestStageRubric_UnknownStage(t *testing.T) {
	if _, err := StageRubric("not-a-real-stage"); err == nil {
		t.Fatal("expected error for unknown stage")
	}
}

func TestStageRubrics_AllSixLoad(t *testing.T) {
	rubrics, err := StageRubrics()
	if err != nil {
		t.Fatalf("StageRubrics() error: %v", err)
	}
	if len(rubrics) != 6 {
		t.Fatalf("len(StageRubrics()) = %d, want 6", len(rubrics))
	}
	for i, stage := range ir.AllStages() {
		if rubrics[i].ID != string(stage)+"-v1" {
			t.Errorf("rubrics[%d].ID = %q, want %q", i, rubrics[i].ID, string(stage)+"-v1")
		}
	}
}

func TestStageRubric_ReviewTypeConventionIsAvailable(t *testing.T) {
	// StageReviewType (RMI-105) is the convention for setting ReviewType on
	// a report envelope; confirm it produces a value that matches the
	// stage rubric's own naming so the two conventions stay consistent.
	for _, stage := range ir.AllStages() {
		rubric, err := StageRubric(stage)
		if err != nil {
			t.Fatalf("StageRubric(%q) error: %v", stage, err)
		}
		reviewType := StageReviewType(stage)
		if reviewType != string(stage) {
			t.Errorf("StageReviewType(%q) = %q, want %q", stage, reviewType, string(stage))
		}
		if rubric.ID != reviewType+"-v1" {
			t.Errorf("stage %q: rubric ID %q doesn't correspond to ReviewType %q", stage, rubric.ID, reviewType)
		}
	}
}
