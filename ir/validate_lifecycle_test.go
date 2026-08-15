package ir

import "testing"

func minimalValidThreatModel() ThreatModel {
	return ThreatModel{
		ID:    "test-model",
		Title: "Test Model",
		Diagrams: []DiagramView{
			{
				Type:  DiagramTypeDFD,
				Title: "Test DFD",
				Elements: []Element{
					{ID: "e1", Label: "Element 1", Type: ElementTypeProcess},
				},
			},
		},
	}
}

func TestValidateLifecycle_ValidModel(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Artifacts = []Artifact{{ID: "artifact-1", Type: ArtifactTypeSourceTree}}
	tm.AnalysisRuns = []AnalysisRun{{
		ID: "run-1", Stage: StageImplementation, Status: AnalysisRunStatusCompleted,
		Producer:         AnalysisProducer{Type: "agent", Name: "test-agent"},
		InputArtifactIDs: []string{"artifact-1"},
	}}
	tm.Evidence = []Evidence{{ID: "evidence-1", ArtifactID: "artifact-1", Locator: EvidenceLocator{Type: EvidenceLocatorTypeFile, Path: "main.go"}}}
	tm.Gates = []Gate{{ID: "gate-1", Stage: StageImplementation, Result: GateResultPassed, EvidenceIDs: []string{"evidence-1"}}}
	tm.SecurityRequirements = []SecurityRequirement{{
		ID: "req-1", Statement: "test", Type: SecurityRequirementTypeInvariant,
		OriginArtifactID: "artifact-1", VerificationIDs: []string{"run-1", "gate-1"},
	}}
	tm.ArchitectureAssertions = []ArchitectureAssertion{{
		ID: "assert-1", SubjectID: "e1", Predicate: "network-exposure", Expected: "private",
		ExpectedEvidenceIDs: []string{"evidence-1"}, Status: ArchitectureAssertionStatusUnverified,
	}}
	tm.Findings = []Finding{{
		ID: "finding-1", Type: FindingTypeVulnerability, Status: FindingStatusCandidate,
		EvidenceIDs: []string{"evidence-1"}, ProducerRunID: "run-1", ASPMDomainID: ASPMDomainCodeSecurity,
	}}
	tm.Assets = []Asset{{ID: "asset-1", Name: "Test Asset", Classification: SensitivityConfidential, ProducerRunID: "run-1"}}
	tm.ThreatActors = []ThreatActor{{ID: "actor-1", Name: "Test Actor", Type: ThreatActorTypeCriminal, ProducerRunID: "run-1"}}
	tm.Scenarios = []Scenario{{ID: "scenario-1", Title: "Test Scenario", ProducerRunID: "run-1"}}
	tm.Mitigations = []Mitigation{{ID: "mitigation-1", Title: "Test Mitigation", Status: MitigationStatusPlanned, ProducerRunID: "run-1"}}

	if err := tm.Validate(); err != nil {
		t.Fatalf("expected valid model, got error: %v", err)
	}
}

func TestValidateLifecycle_DuplicateIDs(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Artifacts = []Artifact{
		{ID: "artifact-1", Type: ArtifactTypeSourceTree},
		{ID: "artifact-1", Type: ArtifactTypeSBOM},
	}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for duplicate artifact id")
	}
}

func TestValidateLifecycle_UnknownArtifactReference(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Evidence = []Evidence{{ID: "evidence-1", ArtifactID: "does-not-exist", Locator: EvidenceLocator{Type: EvidenceLocatorTypeFile}}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for evidence referencing unknown artifact")
	}
}

func TestValidateLifecycle_UnknownEvidenceReference(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Findings = []Finding{{ID: "finding-1", Type: FindingTypeVulnerability, Status: FindingStatusCandidate, EvidenceIDs: []string{"does-not-exist"}}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for finding referencing unknown evidence")
	}
}

func TestValidateLifecycle_UnknownProducerRun(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Findings = []Finding{{ID: "finding-1", Type: FindingTypeVulnerability, Status: FindingStatusCandidate, ProducerRunID: "does-not-exist"}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for finding referencing unknown analysisRun")
	}
}

func TestValidateLifecycle_UnknownAssetProducerRun(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Assets = []Asset{{ID: "asset-1", Name: "Test Asset", Classification: SensitivityConfidential, ProducerRunID: "does-not-exist"}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for asset referencing unknown analysisRun")
	}
}

func TestValidateLifecycle_UnknownThreatActorProducerRun(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.ThreatActors = []ThreatActor{{ID: "actor-1", Name: "Test Actor", Type: ThreatActorTypeCriminal, ProducerRunID: "does-not-exist"}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for threatActor referencing unknown analysisRun")
	}
}

func TestValidateLifecycle_UnknownScenarioProducerRun(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Scenarios = []Scenario{{ID: "scenario-1", Title: "Test Scenario", ProducerRunID: "does-not-exist"}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for scenario referencing unknown analysisRun")
	}
}

func TestValidateLifecycle_UnknownMitigationProducerRun(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Mitigations = []Mitigation{{ID: "mitigation-1", Title: "Test Mitigation", Status: MitigationStatusPlanned, ProducerRunID: "does-not-exist"}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for mitigation referencing unknown analysisRun")
	}
}

func TestValidateLifecycle_UnknownASPMDomain(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Findings = []Finding{{ID: "finding-1", Type: FindingTypeVulnerability, Status: FindingStatusCandidate, ASPMDomainID: "not-a-real-domain"}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for finding referencing unknown ASPM domain")
	}
}

func TestValidateLifecycle_UnknownGateEvidence(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.Gates = []Gate{{ID: "gate-1", Stage: StageImplementation, Result: GateResultPassed, EvidenceIDs: []string{"does-not-exist"}}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for gate referencing unknown evidence")
	}
}

func TestValidateLifecycle_UnknownVerificationReference(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.SecurityRequirements = []SecurityRequirement{{
		ID: "req-1", Statement: "test", Type: SecurityRequirementTypeInvariant,
		VerificationIDs: []string{"does-not-exist"},
	}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for securityRequirement referencing unknown run/gate")
	}
}

func TestValidateLifecycle_UnknownAssertionEvidence(t *testing.T) {
	tm := minimalValidThreatModel()
	tm.ArchitectureAssertions = []ArchitectureAssertion{{
		ID: "assert-1", SubjectID: "e1", Predicate: "network-exposure", Expected: "private",
		ObservedEvidenceIDs: []string{"does-not-exist"}, Status: ArchitectureAssertionStatusContradicted,
	}}
	err := tm.Validate()
	if err == nil {
		t.Fatal("expected validation error for architectureAssertion referencing unknown evidence")
	}
}

func TestValidateLifecycle_EmptyLifecycleObjectsIsValid(t *testing.T) {
	// Backward compatibility: a model with none of the new lifecycle fields
	// populated must still validate cleanly.
	tm := minimalValidThreatModel()
	if err := tm.Validate(); err != nil {
		t.Fatalf("expected valid model with no lifecycle objects, got error: %v", err)
	}
}
