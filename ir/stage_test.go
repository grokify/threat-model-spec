package ir

import "testing"

func TestAllStagesOrderAndCount(t *testing.T) {
	stages := AllStages()
	if len(stages) != 6 {
		t.Fatalf("len(AllStages()) = %d, want 6", len(stages))
	}
	want := []Stage{
		StageProductDefinition,
		StageBuilderDefinition,
		StageImplementation,
		StageDeployment,
		StageBuilderOperations,
		StageProductOperations,
	}
	for i, s := range stages {
		if s != want[i] {
			t.Errorf("AllStages()[%d] = %q, want %q", i, s, want[i])
		}
	}
}

func TestStageIsBuilderStage(t *testing.T) {
	tests := []struct {
		stage Stage
		want  bool
	}{
		{StageProductDefinition, false},
		{StageBuilderDefinition, true},
		{StageImplementation, true},
		{StageDeployment, true},
		{StageBuilderOperations, true},
		{StageProductOperations, false},
	}
	for _, tt := range tests {
		if got := tt.stage.IsBuilderStage(); got != tt.want {
			t.Errorf("%q.IsBuilderStage() = %v, want %v", tt.stage, got, tt.want)
		}
	}
}

func TestStageJSONSchema(t *testing.T) {
	schema := Stage("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Type = %q, want %q", schema.Type, "string")
	}
	if len(schema.Enum) != 6 {
		t.Errorf("len(Enum) = %d, want 6", len(schema.Enum))
	}
}
