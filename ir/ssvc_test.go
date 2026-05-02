package ir

import (
	"encoding/json"
	"testing"
)

func TestSSVCAssessmentJSONRoundTrip(t *testing.T) {
	assessment := SSVCAssessment{
		VulnerabilityID:   "CVE-2024-12345",
		Exploitation:      SSVCExploitationActive,
		Automatable:       SSVCAutomatableYes,
		TechnicalImpact:   SSVCTechnicalImpactTotal,
		MissionPrevalence: SSVCMissionPrevalenceEssential,
		PublicWellBeing:   SSVCPublicWellBeingMaterial,
		Decision:          SSVCDecisionAct,
		Notes:             "Critical vulnerability in production system",
		AssessedAt:        "2024-01-15T10:30:00Z",
		AssessedBy:        "security-team",
	}

	data, err := json.MarshalIndent(assessment, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal SSVCAssessment: %v", err)
	}

	var decoded SSVCAssessment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal SSVCAssessment: %v", err)
	}

	if decoded.VulnerabilityID != "CVE-2024-12345" {
		t.Errorf("VulnerabilityID = %s, want CVE-2024-12345", decoded.VulnerabilityID)
	}
	if decoded.Exploitation != SSVCExploitationActive {
		t.Errorf("Exploitation = %s, want active", decoded.Exploitation)
	}
	if decoded.Decision != SSVCDecisionAct {
		t.Errorf("Decision = %s, want act", decoded.Decision)
	}
}

func TestCalculateSSVCDecision(t *testing.T) {
	tests := []struct {
		name              string
		exploitation      SSVCExploitation
		automatable       SSVCAutomatable
		technicalImpact   SSVCTechnicalImpact
		missionPrevalence SSVCMissionPrevalence
		publicWellBeing   SSVCPublicWellBeing
		want              SSVCDecision
	}{
		// Active exploitation scenarios
		{
			name:              "active exploitation with total impact",
			exploitation:      SSVCExploitationActive,
			automatable:       SSVCAutomatableYes,
			technicalImpact:   SSVCTechnicalImpactTotal,
			missionPrevalence: SSVCMissionPrevalenceMinimal,
			publicWellBeing:   SSVCPublicWellBeingMinimal,
			want:              SSVCDecisionAct,
		},
		{
			name:              "active exploitation with essential mission",
			exploitation:      SSVCExploitationActive,
			automatable:       SSVCAutomatableNo,
			technicalImpact:   SSVCTechnicalImpactPartial,
			missionPrevalence: SSVCMissionPrevalenceEssential,
			publicWellBeing:   SSVCPublicWellBeingMinimal,
			want:              SSVCDecisionAct,
		},
		{
			name:              "active exploitation with irreversible public impact",
			exploitation:      SSVCExploitationActive,
			automatable:       SSVCAutomatableNo,
			technicalImpact:   SSVCTechnicalImpactPartial,
			missionPrevalence: SSVCMissionPrevalenceMinimal,
			publicWellBeing:   SSVCPublicWellBeingIrreversible,
			want:              SSVCDecisionAct,
		},
		{
			name:              "active exploitation with partial impact and minimal context",
			exploitation:      SSVCExploitationActive,
			automatable:       SSVCAutomatableNo,
			technicalImpact:   SSVCTechnicalImpactPartial,
			missionPrevalence: SSVCMissionPrevalenceMinimal,
			publicWellBeing:   SSVCPublicWellBeingMinimal,
			want:              SSVCDecisionAttend,
		},

		// POC exploitation scenarios
		{
			name:              "POC automatable with total impact",
			exploitation:      SSVCExploitationPOC,
			automatable:       SSVCAutomatableYes,
			technicalImpact:   SSVCTechnicalImpactTotal,
			missionPrevalence: SSVCMissionPrevalenceMinimal,
			publicWellBeing:   SSVCPublicWellBeingMinimal,
			want:              SSVCDecisionAttend,
		},
		{
			name:              "POC automatable with essential mission",
			exploitation:      SSVCExploitationPOC,
			automatable:       SSVCAutomatableYes,
			technicalImpact:   SSVCTechnicalImpactPartial,
			missionPrevalence: SSVCMissionPrevalenceEssential,
			publicWellBeing:   SSVCPublicWellBeingMinimal,
			want:              SSVCDecisionAttend,
		},
		{
			name:              "POC automatable with irreversible public impact",
			exploitation:      SSVCExploitationPOC,
			automatable:       SSVCAutomatableYes,
			technicalImpact:   SSVCTechnicalImpactPartial,
			missionPrevalence: SSVCMissionPrevalenceMinimal,
			publicWellBeing:   SSVCPublicWellBeingIrreversible,
			want:              SSVCDecisionAttend,
		},
		{
			name:              "POC automatable with partial impact",
			exploitation:      SSVCExploitationPOC,
			automatable:       SSVCAutomatableYes,
			technicalImpact:   SSVCTechnicalImpactPartial,
			missionPrevalence: SSVCMissionPrevalenceSupport,
			publicWellBeing:   SSVCPublicWellBeingMaterial,
			want:              SSVCDecisionTrackStar,
		},
		{
			name:              "POC not automatable with essential mission and total impact",
			exploitation:      SSVCExploitationPOC,
			automatable:       SSVCAutomatableNo,
			technicalImpact:   SSVCTechnicalImpactTotal,
			missionPrevalence: SSVCMissionPrevalenceEssential,
			publicWellBeing:   SSVCPublicWellBeingMinimal,
			want:              SSVCDecisionTrackStar,
		},
		{
			name:              "POC not automatable low impact",
			exploitation:      SSVCExploitationPOC,
			automatable:       SSVCAutomatableNo,
			technicalImpact:   SSVCTechnicalImpactPartial,
			missionPrevalence: SSVCMissionPrevalenceMinimal,
			publicWellBeing:   SSVCPublicWellBeingMinimal,
			want:              SSVCDecisionTrack,
		},

		// No exploitation scenarios
		{
			name:              "no exploitation - high potential",
			exploitation:      SSVCExploitationNone,
			automatable:       SSVCAutomatableYes,
			technicalImpact:   SSVCTechnicalImpactTotal,
			missionPrevalence: SSVCMissionPrevalenceEssential,
			publicWellBeing:   SSVCPublicWellBeingMinimal,
			want:              SSVCDecisionTrackStar,
		},
		{
			name:              "no exploitation - low risk",
			exploitation:      SSVCExploitationNone,
			automatable:       SSVCAutomatableNo,
			technicalImpact:   SSVCTechnicalImpactPartial,
			missionPrevalence: SSVCMissionPrevalenceMinimal,
			publicWellBeing:   SSVCPublicWellBeingMinimal,
			want:              SSVCDecisionTrack,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateSSVCDecision(
				tt.exploitation,
				tt.automatable,
				tt.technicalImpact,
				tt.missionPrevalence,
				tt.publicWellBeing,
			)
			if got != tt.want {
				t.Errorf("CalculateSSVCDecision() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSSVCAssessmentCalculate(t *testing.T) {
	assessment := &SSVCAssessment{
		VulnerabilityID:   "CVE-2024-99999",
		Exploitation:      SSVCExploitationActive,
		Automatable:       SSVCAutomatableYes,
		TechnicalImpact:   SSVCTechnicalImpactTotal,
		MissionPrevalence: SSVCMissionPrevalenceEssential,
		PublicWellBeing:   SSVCPublicWellBeingIrreversible,
	}

	assessment.Calculate()

	if assessment.Decision != SSVCDecisionAct {
		t.Errorf("Calculate() set Decision = %s, want act", assessment.Decision)
	}
}

func TestNewSSVCAssessment(t *testing.T) {
	assessment := NewSSVCAssessment(
		"CVE-2024-12345",
		SSVCExploitationPOC,
		SSVCAutomatableYes,
		SSVCTechnicalImpactTotal,
		SSVCMissionPrevalenceSupport,
		SSVCPublicWellBeingMinimal,
	)

	if assessment.VulnerabilityID != "CVE-2024-12345" {
		t.Errorf("VulnerabilityID = %s, want CVE-2024-12345", assessment.VulnerabilityID)
	}
	if assessment.Decision != SSVCDecisionAttend {
		t.Errorf("Decision = %s, want attend", assessment.Decision)
	}
}

func TestSSVCAssessmentIsHighPriority(t *testing.T) {
	tests := []struct {
		decision SSVCDecision
		want     bool
	}{
		{SSVCDecisionTrack, false},
		{SSVCDecisionTrackStar, false},
		{SSVCDecisionAttend, true},
		{SSVCDecisionAct, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			a := &SSVCAssessment{Decision: tt.decision}
			got := a.IsHighPriority()
			if got != tt.want {
				t.Errorf("IsHighPriority() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSVCAssessmentRequiresImmediateAction(t *testing.T) {
	tests := []struct {
		decision SSVCDecision
		want     bool
	}{
		{SSVCDecisionTrack, false},
		{SSVCDecisionTrackStar, false},
		{SSVCDecisionAttend, false},
		{SSVCDecisionAct, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			a := &SSVCAssessment{Decision: tt.decision}
			got := a.RequiresImmediateAction()
			if got != tt.want {
				t.Errorf("RequiresImmediateAction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSVCEnumConstants(t *testing.T) {
	// Verify exploitation constants
	if SSVCExploitationNone != "none" {
		t.Errorf("SSVCExploitationNone = %s, want none", SSVCExploitationNone)
	}
	if SSVCExploitationPOC != "poc" {
		t.Errorf("SSVCExploitationPOC = %s, want poc", SSVCExploitationPOC)
	}
	if SSVCExploitationActive != "active" {
		t.Errorf("SSVCExploitationActive = %s, want active", SSVCExploitationActive)
	}

	// Verify automatable constants
	if SSVCAutomatableNo != "no" {
		t.Errorf("SSVCAutomatableNo = %s, want no", SSVCAutomatableNo)
	}
	if SSVCAutomatableYes != "yes" {
		t.Errorf("SSVCAutomatableYes = %s, want yes", SSVCAutomatableYes)
	}

	// Verify technical impact constants
	if SSVCTechnicalImpactPartial != "partial" {
		t.Errorf("SSVCTechnicalImpactPartial = %s, want partial", SSVCTechnicalImpactPartial)
	}
	if SSVCTechnicalImpactTotal != "total" {
		t.Errorf("SSVCTechnicalImpactTotal = %s, want total", SSVCTechnicalImpactTotal)
	}

	// Verify decision constants
	if SSVCDecisionTrack != "track" {
		t.Errorf("SSVCDecisionTrack = %s, want track", SSVCDecisionTrack)
	}
	if SSVCDecisionTrackStar != "track*" {
		t.Errorf("SSVCDecisionTrackStar = %s, want track*", SSVCDecisionTrackStar)
	}
	if SSVCDecisionAttend != "attend" {
		t.Errorf("SSVCDecisionAttend = %s, want attend", SSVCDecisionAttend)
	}
	if SSVCDecisionAct != "act" {
		t.Errorf("SSVCDecisionAct = %s, want act", SSVCDecisionAct)
	}
}
