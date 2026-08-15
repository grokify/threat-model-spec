package ir

import "testing"

func TestStageInputMode_JSONSchema(t *testing.T) {
	schema := StageInputMode("").JSONSchema()
	if len(schema.Enum) != 2 {
		t.Errorf("expected 2 enum values, got %d", len(schema.Enum))
	}
}

func TestStageReportProfiles_AllSixPresent(t *testing.T) {
	profiles, err := StageReportProfiles()
	if err != nil {
		t.Fatalf("StageReportProfiles() error: %v", err)
	}
	if len(profiles) != 6 {
		t.Fatalf("len(StageReportProfiles()) = %d, want 6", len(profiles))
	}
	for i, want := range AllStages() {
		if profiles[i].Stage != want {
			t.Errorf("profiles[%d].Stage = %q, want %q", i, profiles[i].Stage, want)
		}
	}
}

func TestStageReportProfileByStage_UnknownStage(t *testing.T) {
	if _, err := StageReportProfileByStage("not-a-real-stage"); err == nil {
		t.Fatal("expected error for unknown stage")
	}
}

func TestStageReportProfiles_InputModeMatchesStageRole(t *testing.T) {
	// The two spec-driven stages use workflow-specs; the four builder-side
	// stages use artifact-types (see PRD FR3.7 / TRD "InputMode").
	want := map[Stage]StageInputMode{
		StageProductDefinition: StageInputModeWorkflowSpecs,
		StageBuilderDefinition: StageInputModeWorkflowSpecs,
		StageImplementation:    StageInputModeArtifactTypes,
		StageDeployment:        StageInputModeArtifactTypes,
		StageBuilderOperations: StageInputModeArtifactTypes,
		StageProductOperations: StageInputModeArtifactTypes,
	}
	for _, p := range MustStageReportProfiles() {
		if p.InputMode != want[p.Stage] {
			t.Errorf("stage %q InputMode = %q, want %q", p.Stage, p.InputMode, want[p.Stage])
		}
	}
}

func TestStageReportProfiles_WorkflowSpecStagesDeclareNoArtifactTypes(t *testing.T) {
	for _, p := range MustStageReportProfiles() {
		if p.InputMode == StageInputModeWorkflowSpecs && len(p.ArtifactTypes) != 0 {
			t.Errorf("stage %q uses workflow-specs but declares ArtifactTypes %v", p.Stage, p.ArtifactTypes)
		}
	}
}

func TestStageReportProfiles_ArtifactTypesAreValidEnumValues(t *testing.T) {
	validTypes := map[ArtifactType]bool{}
	for _, v := range []any{
		ArtifactTypeProductSpec, ArtifactTypeTechnicalSpec, ArtifactTypeArchitectureDiagram,
		ArtifactTypeAPISpec, ArtifactTypeSourceTree, ArtifactTypeDependencyManifest,
		ArtifactTypeSBOM, ArtifactTypeIaC, ArtifactTypeDeploymentManifest,
		ArtifactTypeRuntimeEndpoint, ArtifactTypeTelemetry, ArtifactTypeIncident,
	} {
		validTypes[v.(ArtifactType)] = true
	}
	for _, p := range MustStageReportProfiles() {
		for _, at := range p.ArtifactTypes {
			if !validTypes[at] {
				t.Errorf("stage %q declares unknown ArtifactType %q", p.Stage, at)
			}
		}
	}
}

func TestStageReportProfiles_ASPMDomainIDsMatchOverlay(t *testing.T) {
	// Every ASPMDomainID a profile declares must (a) be a real domain and
	// (b) have that domain's PrimaryStage equal to the profile's own
	// stage — the report profile and the ASPM registry must agree on the
	// mapping.
	for _, p := range MustStageReportProfiles() {
		for _, id := range p.ASPMDomainIDs {
			domain, ok := ASPMDomainByID(id)
			if !ok {
				t.Errorf("stage %q declares unknown ASPM domain %q", p.Stage, id)
				continue
			}
			if domain.PrimaryStage != p.Stage {
				t.Errorf("stage %q declares ASPM domain %q whose PrimaryStage is %q", p.Stage, id, domain.PrimaryStage)
			}
		}
	}

	// And the reverse: every ASPM domain's PrimaryStage profile must
	// declare that domain, so the mapping is complete in both directions.
	byStage := map[Stage][]ASPMDomainID{}
	for _, p := range MustStageReportProfiles() {
		byStage[p.Stage] = p.ASPMDomainIDs
	}
	for _, d := range ASPMDomains() {
		found := false
		for _, id := range byStage[d.PrimaryStage] {
			if id == d.ID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ASPM domain %q (primary stage %q) is not declared by that stage's report profile", d.ID, d.PrimaryStage)
		}
	}
}

func TestStageReportProfiles_HaveRubricIDAndOutputObjects(t *testing.T) {
	for _, p := range MustStageReportProfiles() {
		if p.RubricID == "" {
			t.Errorf("stage %q has no RubricID", p.Stage)
		}
		if p.RubricID != string(p.Stage) {
			t.Errorf("stage %q RubricID = %q, want it to match the stage id", p.Stage, p.RubricID)
		}
		if len(p.OutputObjects) == 0 {
			t.Errorf("stage %q has no OutputObjects", p.Stage)
		}
		if len(p.CoverageChecks) == 0 {
			t.Errorf("stage %q has no CoverageChecks", p.Stage)
		}
	}
}
