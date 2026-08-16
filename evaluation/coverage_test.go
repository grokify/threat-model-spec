package evaluation

import (
	"testing"

	"github.com/grokify/threat-model-spec/ir"
)

func TestComputeCoverageChecks_HasSTRIDEMapping(t *testing.T) {
	tests := []struct {
		name     string
		findings []ir.Finding
		want     bool
	}{
		{
			name:     "no threat-candidate findings at stage: not covered",
			findings: nil,
			want:     false,
		},
		{
			name: "threat-candidate finding with STRIDE: covered",
			findings: []ir.Finding{
				{ID: "f1", Stage: ir.StageBuilderDefinition, Type: ir.FindingTypeThreatCandidate, STRIDEThreats: []ir.STRIDEThreat{ir.STRIDESpoofing}},
			},
			want: true,
		},
		{
			name: "threat-candidate finding without STRIDE: not covered",
			findings: []ir.Finding{
				{ID: "f1", Stage: ir.StageBuilderDefinition, Type: ir.FindingTypeThreatCandidate},
			},
			want: false,
		},
		{
			name: "one mapped, one unmapped threat-candidate: not covered",
			findings: []ir.Finding{
				{ID: "f1", Stage: ir.StageBuilderDefinition, Type: ir.FindingTypeThreatCandidate, STRIDEThreats: []ir.STRIDEThreat{ir.STRIDESpoofing}},
				{ID: "f2", Stage: ir.StageBuilderDefinition, Type: ir.FindingTypeThreatCandidate},
			},
			want: false,
		},
		{
			name: "unmapped finding at a different stage is ignored",
			findings: []ir.Finding{
				{ID: "f1", Stage: ir.StageBuilderDefinition, Type: ir.FindingTypeThreatCandidate, STRIDEThreats: []ir.STRIDEThreat{ir.STRIDESpoofing}},
				{ID: "f2", Stage: ir.StageImplementation, Type: ir.FindingTypeThreatCandidate},
			},
			want: true,
		},
		{
			name: "unmapped observation-type finding is ignored (not a threat-candidate)",
			findings: []ir.Finding{
				{ID: "f1", Stage: ir.StageBuilderDefinition, Type: ir.FindingTypeThreatCandidate, STRIDEThreats: []ir.STRIDEThreat{ir.STRIDESpoofing}},
				{ID: "f2", Stage: ir.StageBuilderDefinition, Type: ir.FindingTypeObservation},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &ir.ThreatModel{Findings: tt.findings}
			results, uncomputed, err := ComputeCoverageChecks(model, ir.StageBuilderDefinition)
			if err != nil {
				t.Fatalf("ComputeCoverageChecks() error: %v", err)
			}
			if got, ok := results["has-stride-mapping"]; !ok || got != tt.want {
				t.Errorf("has-stride-mapping = %v (ok=%v), want %v", got, ok, tt.want)
			}
			for _, id := range uncomputed {
				if id == "has-stride-mapping" {
					t.Error("has-stride-mapping should not appear in uncomputed")
				}
			}
		})
	}
}

func TestComputeCoverageChecks_ProductDefinition(t *testing.T) {
	model := &ir.ThreatModel{
		Assets:       []ir.Asset{{ID: "asset-1"}},
		ThreatActors: []ir.ThreatActor{{ID: "actor-1"}},
		SecurityRequirements: []ir.SecurityRequirement{
			{ID: "req-1", Type: ir.SecurityRequirementTypeInvariant},
		},
	}

	results, uncomputed, err := ComputeCoverageChecks(model, ir.StageProductDefinition)
	if err != nil {
		t.Fatalf("ComputeCoverageChecks() error: %v", err)
	}

	want := CoverageCheckResults{
		"has-assets":             true,
		"has-invariant":          true,
		"has-threat-actor":       true,
		"has-prohibited-outcome": false,
	}
	for id, wantVal := range want {
		if got, ok := results[id]; !ok || got != wantVal {
			t.Errorf("%s = %v (ok=%v), want %v", id, got, ok, wantVal)
		}
	}
	if len(uncomputed) != 0 {
		t.Errorf("uncomputed = %v, want none — every product-definition check is computable", uncomputed)
	}
}

func TestComputeCoverageChecks_HasEvidencePerFinding(t *testing.T) {
	tests := []struct {
		name     string
		evidence []ir.Evidence
		findings []ir.Finding
		want     bool
	}{
		{
			name:     "no findings at stage: not covered",
			findings: nil,
			want:     false,
		},
		{
			name:     "finding with resolvable evidence: covered",
			evidence: []ir.Evidence{{ID: "ev-1"}},
			findings: []ir.Finding{{ID: "f1", Stage: ir.StageImplementation, EvidenceIDs: []string{"ev-1"}}},
			want:     true,
		},
		{
			name:     "finding with no evidence: not covered",
			findings: []ir.Finding{{ID: "f1", Stage: ir.StageImplementation}},
			want:     false,
		},
		{
			name:     "finding with dangling evidence reference: not covered",
			findings: []ir.Finding{{ID: "f1", Stage: ir.StageImplementation, EvidenceIDs: []string{"ev-missing"}}},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &ir.ThreatModel{Evidence: tt.evidence, Findings: tt.findings}
			results, _, err := ComputeCoverageChecks(model, ir.StageImplementation)
			if err != nil {
				t.Fatalf("ComputeCoverageChecks() error: %v", err)
			}
			if got, ok := results["has-evidence-per-finding"]; !ok || got != tt.want {
				t.Errorf("has-evidence-per-finding = %v (ok=%v), want %v", got, ok, tt.want)
			}
		})
	}
}

func TestComputeCoverageChecks_UncomputedChecksReturned(t *testing.T) {
	model := &ir.ThreatModel{}
	results, uncomputed, err := ComputeCoverageChecks(model, ir.StageBuilderDefinition)
	if err != nil {
		t.Fatalf("ComputeCoverageChecks() error: %v", err)
	}

	wantUncomputed := map[string]bool{
		"has-trust-boundaries":         true,
		"has-required-controls":        true,
		"has-api-contract-drift-check": true,
	}
	if len(uncomputed) != len(wantUncomputed) {
		t.Errorf("uncomputed = %v, want %d entries", uncomputed, len(wantUncomputed))
	}
	for _, id := range uncomputed {
		if !wantUncomputed[id] {
			t.Errorf("unexpected uncomputed check %q", id)
		}
	}
	if _, ok := results["has-trust-boundaries"]; ok {
		t.Error("has-trust-boundaries should not appear in results — it is uncomputed")
	}
}

func TestComputeCoverageChecks_UnknownStage(t *testing.T) {
	_, _, err := ComputeCoverageChecks(&ir.ThreatModel{}, ir.Stage("not-a-stage"))
	if err == nil {
		t.Fatal("expected an error for an unknown stage")
	}
}
