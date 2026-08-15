package ir

import (
	"encoding/json"
	"testing"
)

func TestArtifactType_JSONSchema(t *testing.T) {
	schema := ArtifactType("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 12 {
		t.Errorf("expected 12 enum values, got %d", len(schema.Enum))
	}
}

func TestAnalysisRunStatus_JSONSchema(t *testing.T) {
	schema := AnalysisRunStatus("").JSONSchema()
	if len(schema.Enum) != 3 {
		t.Errorf("expected 3 enum values, got %d", len(schema.Enum))
	}
}

func TestAnalysisRunProfile_JSONSchema(t *testing.T) {
	schema := AnalysisRunProfile("").JSONSchema()
	if len(schema.Enum) != 3 {
		t.Errorf("expected 3 enum values, got %d", len(schema.Enum))
	}
}

func TestGateResult_JSONSchema(t *testing.T) {
	schema := GateResult("").JSONSchema()
	if len(schema.Enum) != 3 {
		t.Errorf("expected 3 enum values, got %d", len(schema.Enum))
	}
}

func TestArtifact_JSON(t *testing.T) {
	a := Artifact{
		ID:         "artifact-prd-1",
		Type:       ArtifactTypeProductSpec,
		URI:        "repo://docs/product.md",
		Revision:   "sha256:abc",
		Stage:      StageProductDefinition,
		ObservedAt: "2026-08-12T18:00:00Z",
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded Artifact
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded != a {
		t.Errorf("round-trip mismatch: got %+v, want %+v", decoded, a)
	}
}

func TestAnalysisRun_JSON(t *testing.T) {
	r := AnalysisRun{
		ID:      "run-sast-104",
		Stage:   StageImplementation,
		Method:  "sast",
		Profile: AnalysisRunProfileFirstParty,
		Producer: AnalysisProducer{
			Type:    "agent",
			Name:    "code-security-agent",
			Version: "2.3",
		},
		InputArtifactIDs: []string{"artifact-code-1"},
		StartedAt:        "2026-08-12T18:00:00Z",
		Status:           AnalysisRunStatusCompleted,
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded AnalysisRun
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Producer.Name != "code-security-agent" {
		t.Errorf("Producer.Name = %q, want %q", decoded.Producer.Name, "code-security-agent")
	}
	if len(decoded.InputArtifactIDs) != 1 || decoded.InputArtifactIDs[0] != "artifact-code-1" {
		t.Errorf("InputArtifactIDs = %v, want [artifact-code-1]", decoded.InputArtifactIDs)
	}
}

func TestGate_JSON(t *testing.T) {
	g := Gate{
		ID:    "gate-production-release",
		Stage: StageDeployment,
		Criteria: []GateCriterion{
			{Metric: "unaccepted-critical-findings", Operator: "equals", Value: "0"},
		},
		Result:      GateResultFailed,
		EvaluatedBy: "policy-engine",
	}

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded Gate
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.Criteria) != 1 || decoded.Criteria[0].Metric != "unaccepted-critical-findings" {
		t.Errorf("Criteria mismatch: %+v", decoded.Criteria)
	}
	if decoded.Result != GateResultFailed {
		t.Errorf("Result = %q, want %q", decoded.Result, GateResultFailed)
	}
}

func TestLifecycle_JSON(t *testing.T) {
	l := Lifecycle{CurrentStage: StageBuilderDefinition}

	data, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded Lifecycle
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.CurrentStage != StageBuilderDefinition {
		t.Errorf("CurrentStage = %q, want %q", decoded.CurrentStage, StageBuilderDefinition)
	}
}
