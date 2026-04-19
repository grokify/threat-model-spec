package ir

import "testing"

func TestRiskAssessment_Calculate(t *testing.T) {
	tests := []struct {
		name       string
		likelihood int
		impact     int
		wantScore  int
		wantLevel  RiskLevel
	}{
		{"Critical risk", 5, 5, 25, RiskLevelCritical},
		{"Critical risk lower", 5, 4, 20, RiskLevelCritical},
		{"High risk", 5, 3, 15, RiskLevelHigh},
		{"High risk alt", 4, 4, 16, RiskLevelHigh},
		{"Medium risk", 3, 3, 9, RiskLevelMedium},
		{"Medium risk lower", 2, 4, 8, RiskLevelMedium},
		{"Low risk", 2, 2, 4, RiskLevelLow},
		{"Low risk alt", 1, 5, 5, RiskLevelLow},
		{"Info risk", 1, 2, 2, RiskLevelInfo},
		{"Info risk lowest", 1, 1, 1, RiskLevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RiskAssessment{
				Likelihood: tt.likelihood,
				Impact:     tt.impact,
			}
			r.Calculate()

			if r.Score != tt.wantScore {
				t.Errorf("Score = %d, want %d", r.Score, tt.wantScore)
			}
			if r.Level != tt.wantLevel {
				t.Errorf("Level = %s, want %s", r.Level, tt.wantLevel)
			}
		})
	}
}

func TestRiskAssessment_IsValid(t *testing.T) {
	tests := []struct {
		name       string
		likelihood int
		impact     int
		want       bool
	}{
		{"Valid 1,1", 1, 1, true},
		{"Valid 5,5", 5, 5, true},
		{"Valid 3,4", 3, 4, true},
		{"Invalid likelihood 0", 0, 3, false},
		{"Invalid likelihood 6", 6, 3, false},
		{"Invalid impact 0", 3, 0, false},
		{"Invalid impact 6", 3, 6, false},
		{"Invalid both", 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RiskAssessment{
				Likelihood: tt.likelihood,
				Impact:     tt.impact,
			}
			if got := r.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScoreToLevel(t *testing.T) {
	tests := []struct {
		score int
		want  RiskLevel
	}{
		{25, RiskLevelCritical},
		{20, RiskLevelCritical},
		{19, RiskLevelHigh},
		{15, RiskLevelHigh},
		{14, RiskLevelMedium},
		{8, RiskLevelMedium},
		{7, RiskLevelLow},
		{4, RiskLevelLow},
		{3, RiskLevelInfo},
		{1, RiskLevelInfo},
		{0, RiskLevelInfo},
	}

	for _, tt := range tests {
		t.Run(string(tt.want), func(t *testing.T) {
			if got := ScoreToLevel(tt.score); got != tt.want {
				t.Errorf("ScoreToLevel(%d) = %s, want %s", tt.score, got, tt.want)
			}
		})
	}
}

func TestModelPhase_Values(t *testing.T) {
	phases := []ModelPhase{
		ModelPhaseDesign,
		ModelPhaseDevelopment,
		ModelPhaseReview,
		ModelPhaseProduction,
		ModelPhaseIncident,
	}

	expected := []string{"design", "development", "review", "production", "incident"}

	for i, phase := range phases {
		if string(phase) != expected[i] {
			t.Errorf("ModelPhase %d = %s, want %s", i, phase, expected[i])
		}
	}
}
