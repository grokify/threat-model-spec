package ir

import (
	"testing"
)

func TestValidate_Mitigations(t *testing.T) {
	tests := []struct {
		name      string
		diagram   DiagramIR
		wantError bool
		errField  string
	}{
		{
			name: "valid mitigations",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Threats: []ThreatEntry{
					{ID: "threat-1", Title: "Threat", Status: ThreatStatusIdentified},
				},
				Mitigations: []Mitigation{
					{ID: "mit-1", Title: "Mitigation", Status: MitigationStatusImplemented, ThreatIDs: []string{"threat-1"}},
				},
			},
			wantError: false,
		},
		{
			name: "mitigation missing id",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Mitigations: []Mitigation{
					{Title: "Mitigation", Status: MitigationStatusImplemented},
				},
			},
			wantError: true,
			errField:  "mitigations",
		},
		{
			name: "mitigation missing title",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Mitigations: []Mitigation{
					{ID: "mit-1", Status: MitigationStatusImplemented},
				},
			},
			wantError: true,
			errField:  "mitigations",
		},
		{
			name: "mitigation missing status",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Mitigations: []Mitigation{
					{ID: "mit-1", Title: "Mitigation"},
				},
			},
			wantError: true,
			errField:  "mitigations",
		},
		{
			name: "duplicate mitigation id",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Mitigations: []Mitigation{
					{ID: "mit-1", Title: "Mitigation 1", Status: MitigationStatusImplemented},
					{ID: "mit-1", Title: "Mitigation 2", Status: MitigationStatusPlanned},
				},
			},
			wantError: true,
			errField:  "mitigations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.diagram.Validate()
			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				} else if verrs, ok := err.(ValidationErrors); ok {
					found := false
					for _, e := range verrs {
						if e.Field == tt.errField {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected error in field %q, got %v", tt.errField, err)
					}
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_Threats(t *testing.T) {
	tests := []struct {
		name      string
		diagram   DiagramIR
		wantError bool
		errField  string
	}{
		{
			name: "valid threats",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Threats: []ThreatEntry{
					{ID: "threat-1", Title: "Threat", Status: ThreatStatusIdentified, AffectedElements: []string{"elem-1"}},
				},
			},
			wantError: false,
		},
		{
			name: "threat missing id",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Threats: []ThreatEntry{
					{Title: "Threat", Status: ThreatStatusIdentified},
				},
			},
			wantError: true,
			errField:  "threats",
		},
		{
			name: "threat missing title",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Threats: []ThreatEntry{
					{ID: "threat-1", Status: ThreatStatusIdentified},
				},
			},
			wantError: true,
			errField:  "threats",
		},
		{
			name: "threat references unknown element",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Threats: []ThreatEntry{
					{ID: "threat-1", Title: "Threat", Status: ThreatStatusIdentified, AffectedElements: []string{"unknown"}},
				},
			},
			wantError: true,
			errField:  "threats",
		},
		{
			name: "threat references unknown mitigation",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Threats: []ThreatEntry{
					{ID: "threat-1", Title: "Threat", Status: ThreatStatusIdentified, MitigationIDs: []string{"unknown"}},
				},
			},
			wantError: true,
			errField:  "threats",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.diagram.Validate()
			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				} else if verrs, ok := err.(ValidationErrors); ok {
					found := false
					for _, e := range verrs {
						if e.Field == tt.errField {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected error in field %q, got %v", tt.errField, err)
					}
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_Detections(t *testing.T) {
	tests := []struct {
		name      string
		diagram   DiagramIR
		wantError bool
		errField  string
	}{
		{
			name: "valid detections",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Threats: []ThreatEntry{
					{ID: "threat-1", Title: "Threat", Status: ThreatStatusIdentified},
				},
				Detections: []Detection{
					{ID: "det-1", Title: "Detection", Coverage: DetectionCoverageFull, ThreatIDs: []string{"threat-1"}},
				},
			},
			wantError: false,
		},
		{
			name: "detection missing id",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Detections: []Detection{
					{Title: "Detection", Coverage: DetectionCoverageFull},
				},
			},
			wantError: true,
			errField:  "detections",
		},
		{
			name: "detection missing coverage",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Detections: []Detection{
					{ID: "det-1", Title: "Detection"},
				},
			},
			wantError: true,
			errField:  "detections",
		},
		{
			name: "detection references unknown threat",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Detections: []Detection{
					{ID: "det-1", Title: "Detection", Coverage: DetectionCoverageFull, ThreatIDs: []string{"unknown"}},
				},
			},
			wantError: true,
			errField:  "detections",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.diagram.Validate()
			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				} else if verrs, ok := err.(ValidationErrors); ok {
					found := false
					for _, e := range verrs {
						if e.Field == tt.errField {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected error in field %q, got %v", tt.errField, err)
					}
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_ResponseActions(t *testing.T) {
	tests := []struct {
		name      string
		diagram   DiagramIR
		wantError bool
		errField  string
	}{
		{
			name: "valid response actions",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				Detections: []Detection{
					{ID: "det-1", Title: "Detection", Coverage: DetectionCoverageFull},
				},
				ResponseActions: []ResponseAction{
					{ID: "resp-1", Title: "Response", TriggerDetectionIDs: []string{"det-1"}},
				},
			},
			wantError: false,
		},
		{
			name: "response action missing id",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				ResponseActions: []ResponseAction{
					{Title: "Response"},
				},
			},
			wantError: true,
			errField:  "responseActions",
		},
		{
			name: "response action references unknown detection",
			diagram: DiagramIR{
				Type:  DiagramTypeDFD,
				Title: "Test",
				Elements: []Element{
					{ID: "elem-1", Label: "Process", Type: ElementTypeProcess},
				},
				ResponseActions: []ResponseAction{
					{ID: "resp-1", Title: "Response", TriggerDetectionIDs: []string{"unknown"}},
				},
			},
			wantError: true,
			errField:  "responseActions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.diagram.Validate()
			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				} else if verrs, ok := err.(ValidationErrors); ok {
					found := false
					for _, e := range verrs {
						if e.Field == tt.errField {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected error in field %q, got %v", tt.errField, err)
					}
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateStrict_SecurityFields(t *testing.T) {
	diagram := DiagramIR{
		Type:      DiagramTypeDFD,
		Title:     "Test",
		Direction: DirectionRight,
		Elements: []Element{
			{ID: "elem-1", Label: "Process", Type: ElementTypeProcess, ParentID: "bound-1"},
		},
		Boundaries: []Boundary{
			{ID: "bound-1", Label: "Trust Boundary", Type: BoundaryTypeNetwork},
		},
		Flows: []Flow{
			{From: "elem-1", To: "elem-1", Label: "Self"},
		},
		Threats: []ThreatEntry{
			{ID: "threat-1", Title: "Threat", Status: ThreatStatusIdentified}, // missing severity
		},
		Mitigations: []Mitigation{
			{ID: "mit-1", Title: "Mitigation", Status: MitigationStatusImplemented}, // missing owner
		},
		Detections: []Detection{
			{ID: "det-1", Title: "Detection", Coverage: DetectionCoverageFull}, // missing dataSources
		},
	}

	err := diagram.ValidateStrict()
	if err == nil {
		t.Error("expected strict validation errors for missing recommended fields")
	}

	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}

	// Should have warnings for missing owner, severity, and dataSources
	foundMitigationOwner := false
	foundThreatSeverity := false
	foundDetectionDataSources := false

	for _, e := range verrs {
		if e.Field == "mitigations" && contains(e.Message, "owner") {
			foundMitigationOwner = true
		}
		if e.Field == "threats" && contains(e.Message, "severity") {
			foundThreatSeverity = true
		}
		if e.Field == "detections" && contains(e.Message, "dataSources") {
			foundDetectionDataSources = true
		}
	}

	if !foundMitigationOwner {
		t.Error("expected strict validation warning for missing mitigation owner")
	}
	if !foundThreatSeverity {
		t.Error("expected strict validation warning for missing threat severity")
	}
	if !foundDetectionDataSources {
		t.Error("expected strict validation warning for missing detection dataSources")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
