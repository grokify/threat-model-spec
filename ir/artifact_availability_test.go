package ir

import "testing"

func TestArtifactAvailabilityProfiles_AllThreePresent(t *testing.T) {
	profiles, err := ArtifactAvailabilityProfiles()
	if err != nil {
		t.Fatalf("ArtifactAvailabilityProfiles() error: %v", err)
	}
	if len(profiles) != 3 {
		t.Fatalf("len(ArtifactAvailabilityProfiles()) = %d, want 3", len(profiles))
	}
	want := []AnalysisRunProfile{AnalysisRunProfileFirstParty, AnalysisRunProfileThirdParty, AnalysisRunProfileOpenSource}
	for i, p := range profiles {
		if p.Profile != want[i] {
			t.Errorf("profiles[%d].Profile = %q, want %q", i, p.Profile, want[i])
		}
	}
}

func TestArtifactAvailabilityProfileByProfile_UnknownProfile(t *testing.T) {
	if _, err := ArtifactAvailabilityProfileByProfile("not-a-real-profile"); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestArtifactAvailabilityProfiles_FirstPartyPermitsAllStages(t *testing.T) {
	p, err := ArtifactAvailabilityProfileByProfile(AnalysisRunProfileFirstParty)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(p.PermittedStages) != 6 {
		t.Errorf("first-party PermittedStages = %d, want 6", len(p.PermittedStages))
	}
	for _, s := range AllStages() {
		if !p.PermitsStage(s) {
			t.Errorf("first-party should permit stage %q", s)
		}
	}
	if len(p.NotAnalyzableStages) != 0 {
		t.Errorf("first-party should have no NotAnalyzableStages, got %v", p.NotAnalyzableStages)
	}
}

func TestArtifactAvailabilityProfiles_EveryStageAccountedFor(t *testing.T) {
	// For every profile, each of the six stages must be either permitted
	// or explicitly listed as not-analyzable with a reason — no silent
	// gaps where a stage is simply missing from both lists.
	for _, p := range MustArtifactAvailabilityProfiles() {
		notAnalyzable := make(map[Stage]bool, len(p.NotAnalyzableStages))
		for _, n := range p.NotAnalyzableStages {
			if n.Reason == "" {
				t.Errorf("profile %q: NotAnalyzableStages entry for %q has no reason", p.Profile, n.Stage)
			}
			notAnalyzable[n.Stage] = true
		}
		for _, s := range AllStages() {
			permitted := p.PermitsStage(s)
			excluded := notAnalyzable[s]
			if permitted == excluded {
				t.Errorf("profile %q stage %q: permitted=%v excluded=%v, want exactly one to be true", p.Profile, s, permitted, excluded)
			}
		}
	}
}

func TestArtifactAvailabilityProfiles_ThirdPartyExcludesImplementation(t *testing.T) {
	p, err := ArtifactAvailabilityProfileByProfile(AnalysisRunProfileThirdParty)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if p.PermitsStage(StageImplementation) {
		t.Error("third-party should not permit implementation (no source access)")
	}
	if !p.PermitsStage(StageProductDefinition) {
		t.Error("third-party should permit product-definition (public docs)")
	}
}

func TestArtifactAvailabilityProfiles_OpenSourceExcludesDeploymentAndOperations(t *testing.T) {
	p, err := ArtifactAvailabilityProfileByProfile(AnalysisRunProfileOpenSource)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	for _, s := range []Stage{StageDeployment, StageBuilderOperations, StageProductOperations} {
		if p.PermitsStage(s) {
			t.Errorf("open-source should not permit %q (no deployment/operations visibility)", s)
		}
	}
	if !p.PermitsStage(StageImplementation) {
		t.Error("open-source should permit implementation (source access)")
	}
}

func TestArtifactAvailabilityProfiles_ArtifactTypesAreValid(t *testing.T) {
	validTypes := map[ArtifactType]bool{
		ArtifactTypeProductSpec: true, ArtifactTypeTechnicalSpec: true, ArtifactTypeArchitectureDiagram: true,
		ArtifactTypeAPISpec: true, ArtifactTypeSourceTree: true, ArtifactTypeDependencyManifest: true,
		ArtifactTypeSBOM: true, ArtifactTypeIaC: true, ArtifactTypeDeploymentManifest: true,
		ArtifactTypeRuntimeEndpoint: true, ArtifactTypeTelemetry: true, ArtifactTypeIncident: true,
	}
	for _, p := range MustArtifactAvailabilityProfiles() {
		for _, at := range p.AvailableArtifactTypes {
			if !validTypes[at] {
				t.Errorf("profile %q declares unknown ArtifactType %q", p.Profile, at)
			}
		}
	}
}

func TestArtifactAvailabilityProfile_PermitsStage(t *testing.T) {
	p := ArtifactAvailabilityProfile{PermittedStages: []Stage{StageProductDefinition, StageImplementation}}
	if !p.PermitsStage(StageProductDefinition) {
		t.Error("expected PermitsStage(product-definition) = true")
	}
	if p.PermitsStage(StageDeployment) {
		t.Error("expected PermitsStage(deployment) = false")
	}
}
