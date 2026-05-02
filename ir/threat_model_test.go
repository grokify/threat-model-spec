package ir

import (
	"encoding/json"
	"testing"
)

func TestThreatModelValidate(t *testing.T) {
	tests := []struct {
		name    string
		tm      ThreatModel
		wantErr bool
	}{
		{
			name: "valid minimal threat model",
			tm: ThreatModel{
				ID:    "test-model",
				Title: "Test Threat Model",
				Diagrams: []DiagramView{
					{
						Type:  DiagramTypeDFD,
						Title: "Test DFD",
						Elements: []Element{
							{ID: "e1", Label: "Element 1", Type: ElementTypeProcess},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			tm: ThreatModel{
				Title: "Test Threat Model",
				Diagrams: []DiagramView{
					{Type: DiagramTypeDFD, Title: "Test"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing title",
			tm: ThreatModel{
				ID: "test-model",
				Diagrams: []DiagramView{
					{Type: DiagramTypeDFD, Title: "Test"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing diagrams",
			tm: ThreatModel{
				ID:       "test-model",
				Title:    "Test Threat Model",
				Diagrams: []DiagramView{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tm.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestThreatModelIsValid(t *testing.T) {
	validTM := ThreatModel{
		ID:    "test-model",
		Title: "Test Threat Model",
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

	if !validTM.IsValid() {
		t.Error("IsValid() = false, want true for valid threat model")
	}

	invalidTM := ThreatModel{
		Title: "Missing ID",
	}

	if invalidTM.IsValid() {
		t.Error("IsValid() = true, want false for invalid threat model")
	}
}

func TestThreatModelGetDiagram(t *testing.T) {
	tm := ThreatModel{
		ID:    "test-model",
		Title: "Test Threat Model",
		Diagrams: []DiagramView{
			{Type: DiagramTypeDFD, Title: "DFD Diagram"},
			{Type: DiagramTypeAttack, Title: "Attack Chain"},
			{Type: DiagramTypeSequence, Title: "Sequence Diagram"},
		},
	}

	// Test finding existing diagram types
	dfd := tm.GetDiagram(DiagramTypeDFD)
	if dfd == nil {
		t.Fatal("GetDiagram(DFD) returned nil")
	}
	if dfd.Title != "DFD Diagram" {
		t.Errorf("GetDiagram(DFD).Title = %s, want DFD Diagram", dfd.Title)
	}

	attackChain := tm.GetDiagram(DiagramTypeAttack)
	if attackChain == nil {
		t.Fatal("GetDiagram(AttackChain) returned nil")
	}
	if attackChain.Title != "Attack Chain" {
		t.Errorf("GetDiagram(AttackChain).Title = %s, want Attack Chain", attackChain.Title)
	}

	// Test non-existing diagram type
	attackTree := tm.GetDiagram(DiagramTypeAttackTree)
	if attackTree != nil {
		t.Error("GetDiagram(AttackTree) should return nil for non-existing type")
	}
}

func TestThreatModelGetDiagramIR(t *testing.T) {
	tm := ThreatModel{
		ID:    "test-model",
		Title: "Test Threat Model",
		Mappings: &Mappings{
			STRIDE: []STRIDEMapping{
				{Category: "S", Description: "Spoofing"},
			},
		},
		Diagrams: []DiagramView{
			{
				Type: DiagramTypeDFD,
				// Title intentionally empty to test inheritance
				Elements: []Element{
					{ID: "e1", Label: "Element 1", Type: ElementTypeProcess},
				},
			},
		},
	}

	// Test getting DiagramIR
	dir := tm.GetDiagramIR(DiagramTypeDFD)
	if dir == nil {
		t.Fatal("GetDiagramIR(DFD) returned nil")
	}

	// Test title inheritance
	if dir.Title != "Test Threat Model" {
		t.Errorf("DiagramIR.Title = %s, want Test Threat Model (inherited)", dir.Title)
	}

	// Test mappings inheritance
	if dir.Mappings == nil {
		t.Fatal("DiagramIR.Mappings should be inherited from parent")
	}
	if len(dir.Mappings.STRIDE) != 1 {
		t.Errorf("DiagramIR.Mappings.STRIDE length = %d, want 1", len(dir.Mappings.STRIDE))
	}

	// Test non-existing diagram type
	nilDir := tm.GetDiagramIR(DiagramTypeAttackTree)
	if nilDir != nil {
		t.Error("GetDiagramIR(AttackTree) should return nil for non-existing type")
	}
}

func TestDiagramViewToDiagramIR(t *testing.T) {
	parent := &ThreatModel{
		ID:    "parent-model",
		Title: "Parent Title",
		Mappings: &Mappings{
			STRIDE: []STRIDEMapping{
				{Category: "S", Description: "Spoofing"},
			},
		},
		Mitigations: []Mitigation{
			{ID: "m1", Title: "Mitigation 1"},
		},
	}

	tests := []struct {
		name           string
		dv             DiagramView
		parent         *ThreatModel
		wantTitle      string
		wantMappings   bool
		wantMitigations int
	}{
		{
			name: "inherits title from parent",
			dv: DiagramView{
				Type: DiagramTypeDFD,
				// Title empty
			},
			parent:         parent,
			wantTitle:      "Parent Title",
			wantMappings:   true,
			wantMitigations: 1,
		},
		{
			name: "uses own title",
			dv: DiagramView{
				Type:  DiagramTypeDFD,
				Title: "Own Title",
			},
			parent:         parent,
			wantTitle:      "Own Title",
			wantMappings:   true,
			wantMitigations: 1,
		},
		{
			name: "uses own mappings",
			dv: DiagramView{
				Type:  DiagramTypeDFD,
				Title: "With Mappings",
				Mappings: &Mappings{
					STRIDE: []STRIDEMapping{
						{Category: "T", Description: "Tampering"},
					},
				},
			},
			parent:       parent,
			wantTitle:    "With Mappings",
			wantMappings: true,
		},
		{
			name: "nil parent",
			dv: DiagramView{
				Type:  DiagramTypeDFD,
				Title: "Standalone",
			},
			parent:    nil,
			wantTitle: "Standalone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.dv.ToDiagramIR(tt.parent)

			if dir.Title != tt.wantTitle {
				t.Errorf("Title = %s, want %s", dir.Title, tt.wantTitle)
			}

			if tt.wantMappings && dir.Mappings == nil {
				t.Error("Mappings should not be nil")
			}

			if tt.wantMitigations > 0 && len(dir.Mitigations) != tt.wantMitigations {
				t.Errorf("Mitigations length = %d, want %d", len(dir.Mitigations), tt.wantMitigations)
			}
		})
	}
}

func TestThreatModelJSONRoundTrip(t *testing.T) {
	tm := ThreatModel{
		ID:          "test-model",
		Title:       "Test Threat Model",
		Description: "A test threat model for unit testing",
		Version:     "1.0.0",
		Phase:       ModelPhaseProduction,
		Authors: []Author{
			{Name: "Test Author", Email: "test@example.com"},
		},
		References: []Reference{
			{Title: "Test Reference", URL: "https://example.com", Type: "advisory"},
		},
		Mappings: &Mappings{
			STRIDE: []STRIDEMapping{
				{Category: "S", Description: "Spoofing test"},
			},
		},
		Diagrams: []DiagramView{
			{
				Type:  DiagramTypeDFD,
				Title: "Test DFD",
				Elements: []Element{
					{ID: "e1", Label: "Element 1", Type: ElementTypeProcess},
				},
			},
		},
		ThreatActors: []ThreatActor{
			{ID: "ta1", Name: "Test Actor"},
		},
		Assets: []Asset{
			{ID: "a1", Name: "Test Asset"},
		},
	}

	data, err := json.MarshalIndent(tm, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal ThreatModel: %v", err)
	}

	var decoded ThreatModel
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ThreatModel: %v", err)
	}

	if decoded.ID != tm.ID {
		t.Errorf("ID = %s, want %s", decoded.ID, tm.ID)
	}
	if decoded.Title != tm.Title {
		t.Errorf("Title = %s, want %s", decoded.Title, tm.Title)
	}
	if decoded.Phase != tm.Phase {
		t.Errorf("Phase = %s, want %s", decoded.Phase, tm.Phase)
	}
	if len(decoded.Authors) != 1 {
		t.Errorf("Authors length = %d, want 1", len(decoded.Authors))
	}
	if len(decoded.Diagrams) != 1 {
		t.Errorf("Diagrams length = %d, want 1", len(decoded.Diagrams))
	}
}

func TestThreatModelWithV060Features(t *testing.T) {
	// Test ThreatModel with all v0.6.0 features
	tm := ThreatModel{
		ID:    "v060-test",
		Title: "v0.6.0 Feature Test",
		Diagrams: []DiagramView{
			{Type: DiagramTypeDFD, Title: "Test"},
		},
		// Role-based security guidance
		RedTeam: &ExploitationGuidance{
			Prerequisites: []string{"Test prerequisite"},
		},
		BlueTeam: &DefenseGuidance{
			MonitoringRecommendations: []string{"Test monitoring"},
		},
		Remediation: &RemediationGuidance{
			ReviewChecklist: []ChecklistItem{{Item: "Test item"}},
		},
		Playbooks: []IncidentPlaybook{
			{ID: "pb1", Name: "Test Playbook"},
		},
		// Risk quantification
		RiskAssessment: &FAIRAssessment{
			ThreatEventFrequency: &FrequencyEstimate{
				Min: 1, Max: 10, MostLikely: 5,
			},
			RiskScore: 7.5,
		},
		BusinessImpact: &BusinessImpact{
			CustomerImpact: "Low impact",
			Criticality:    CriticalityHigh,
		},
		EPSSData: []EPSSData{
			{CVE: "CVE-2026-12345", EPSSScore: 0.5, Percentile: 85.0},
		},
		// Purple team
		AtomicTests: []AtomicTestMapping{
			{TechniqueID: "T1059", Validated: true, Result: AtomicTestResultPassed},
		},
		DetectionCoverage: &DetectionCoverageMatrix{
			Techniques: []TechniqueCoverage{
				{TechniqueID: "T1059", Coverage: CoverageLevelFull},
			},
		},
		// Security metrics
		Metrics: &SecurityMetrics{
			MTTD:          &MetricDuration{Value: 4, Unit: MetricTimeUnitHours},
			DetectionRate: 0.85,
		},
	}

	// Verify JSON round-trip
	data, err := json.MarshalIndent(tm, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal ThreatModel with v0.6.0 features: %v", err)
	}

	var decoded ThreatModel
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ThreatModel with v0.6.0 features: %v", err)
	}

	// Verify v0.6.0 features
	if decoded.RedTeam == nil {
		t.Error("RedTeam should not be nil")
	}
	if decoded.BlueTeam == nil {
		t.Error("BlueTeam should not be nil")
	}
	if decoded.Remediation == nil {
		t.Error("Remediation should not be nil")
	}
	if len(decoded.Playbooks) != 1 {
		t.Errorf("Playbooks length = %d, want 1", len(decoded.Playbooks))
	}
	if decoded.RiskAssessment == nil {
		t.Error("RiskAssessment should not be nil")
	}
	if decoded.RiskAssessment.RiskScore != 7.5 {
		t.Errorf("RiskScore = %f, want 7.5", decoded.RiskAssessment.RiskScore)
	}
	if decoded.BusinessImpact == nil {
		t.Error("BusinessImpact should not be nil")
	}
	if len(decoded.EPSSData) != 1 {
		t.Errorf("EPSSData length = %d, want 1", len(decoded.EPSSData))
	}
	if len(decoded.AtomicTests) != 1 {
		t.Errorf("AtomicTests length = %d, want 1", len(decoded.AtomicTests))
	}
	if decoded.DetectionCoverage == nil {
		t.Error("DetectionCoverage should not be nil")
	}
	if decoded.Metrics == nil {
		t.Error("Metrics should not be nil")
	}
	if decoded.Metrics.DetectionRate != 0.85 {
		t.Errorf("DetectionRate = %f, want 0.85", decoded.Metrics.DetectionRate)
	}
}

func TestThreatModelValidateWithInvalidDiagram(t *testing.T) {
	tm := ThreatModel{
		ID:    "test-model",
		Title: "Test Threat Model",
		Diagrams: []DiagramView{
			{
				Type: DiagramTypeDFD,
				// Invalid: DFD with attacks instead of elements
				Attacks: []Attack{
					{Step: 1, Label: "Attack 1"},
				},
			},
		},
	}

	err := tm.Validate()
	if err == nil {
		t.Error("Validate() should return error for invalid diagram")
	}
}
