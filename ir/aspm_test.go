package ir

import "testing"

func TestASPMDomainID_JSONSchema(t *testing.T) {
	schema := ASPMDomainID("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 10 {
		t.Errorf("expected 10 enum values, got %d", len(schema.Enum))
	}
}

func TestASPMDomains_AllTenPresent(t *testing.T) {
	domains := ASPMDomains()
	if len(domains) != 10 {
		t.Fatalf("ASPMDomains() returned %d domains, want 10", len(domains))
	}

	seen := make(map[ASPMDomainID]bool)
	for _, d := range domains {
		if d.ID == "" {
			t.Error("domain has empty ID")
		}
		if seen[d.ID] {
			t.Errorf("duplicate domain ID %q", d.ID)
		}
		seen[d.ID] = true
		if d.Name == "" {
			t.Errorf("domain %q missing Name", d.ID)
		}
	}
}

func TestASPMDomains_PrimaryStageMapping(t *testing.T) {
	want := map[ASPMDomainID]Stage{
		ASPMDomainGitPosture:         StageImplementation,
		ASPMDomainCodeSecurity:       StageImplementation,
		ASPMDomainSecretPIIScan:      StageImplementation,
		ASPMDomainOpenSourceSecurity: StageImplementation,
		ASPMDomainSBOM:               StageImplementation,
		ASPMDomainIaCScan:            StageDeployment,
		ASPMDomainCICDPosture:        StageDeployment,
		ASPMDomainContainerSecurity:  StageDeployment,
		ASPMDomainArtifactSecurity:   StageDeployment,
		ASPMDomainCloudContext:       StageBuilderOperations,
	}
	for _, d := range ASPMDomains() {
		wantStage, ok := want[d.ID]
		if !ok {
			t.Errorf("unexpected domain ID %q not in expected mapping", d.ID)
			continue
		}
		if d.PrimaryStage != wantStage {
			t.Errorf("domain %q PrimaryStage = %q, want %q", d.ID, d.PrimaryStage, wantStage)
		}
		if !d.PrimaryStage.IsBuilderStage() {
			t.Errorf("domain %q PrimaryStage %q is not a builder stage", d.ID, d.PrimaryStage)
		}
	}
}

func TestASPMDomains_ImplementationCount(t *testing.T) {
	counts := map[Stage]int{}
	for _, d := range ASPMDomains() {
		counts[d.PrimaryStage]++
	}
	if counts[StageImplementation] != 5 {
		t.Errorf("Implementation domain count = %d, want 5", counts[StageImplementation])
	}
	if counts[StageDeployment] != 4 {
		t.Errorf("Deployment domain count = %d, want 4", counts[StageDeployment])
	}
	if counts[StageBuilderOperations] != 1 {
		t.Errorf("BuilderOperations domain count = %d, want 1", counts[StageBuilderOperations])
	}
}

func TestASPMDomainByID(t *testing.T) {
	d, ok := ASPMDomainByID(ASPMDomainSBOM)
	if !ok {
		t.Fatal("ASPMDomainByID(ASPMDomainSBOM) not found")
	}
	if d.Name != "SBOM" {
		t.Errorf("Name = %q, want %q", d.Name, "SBOM")
	}

	if _, ok := ASPMDomainByID("not-a-real-domain"); ok {
		t.Error("ASPMDomainByID(\"not-a-real-domain\") should not be found")
	}
}
