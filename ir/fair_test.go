package ir

import (
	"encoding/json"
	"math"
	"testing"
)

func TestFAIRAssessmentJSONRoundTrip(t *testing.T) {
	assessment := FAIRAssessment{
		ThreatEventFrequency: &FrequencyEstimate{
			Min:        1.0,
			Max:        10.0,
			MostLikely: 5.0,
			Confidence: ConfidenceMedium,
		},
		Vulnerability: &Percentage{
			Min:        0.1,
			Max:        0.5,
			MostLikely: 0.3,
			Confidence: ConfidenceHigh,
		},
		PrimaryLoss: &LossEstimate{
			Min:        10000,
			Max:        100000,
			MostLikely: 50000,
			Currency:   Currency{Code: "USD"},
		},
		SecondaryLoss: &LossEstimate{
			Min:        5000,
			Max:        50000,
			MostLikely: 20000,
			Currency:   Currency{Code: "USD"},
		},
		AssessmentDate: "2026-04-28",
		Assessor:       "Security Team",
		Notes:          "Initial risk assessment",
	}

	data, err := json.MarshalIndent(assessment, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal FAIRAssessment: %v", err)
	}

	var decoded FAIRAssessment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal FAIRAssessment: %v", err)
	}

	if decoded.ThreatEventFrequency.MostLikely != 5.0 {
		t.Errorf("TEF MostLikely = %f, want 5.0", decoded.ThreatEventFrequency.MostLikely)
	}
	if decoded.Vulnerability.Confidence != ConfidenceHigh {
		t.Errorf("Vulnerability Confidence = %s, want high", decoded.Vulnerability.Confidence)
	}
	if decoded.PrimaryLoss.Currency.Code != "USD" {
		t.Errorf("PrimaryLoss Currency = %s, want USD", decoded.PrimaryLoss.Currency.Code)
	}
	if decoded.Assessor != "Security Team" {
		t.Errorf("Assessor = %s, want Security Team", decoded.Assessor)
	}
}

func TestCalculateALE(t *testing.T) {
	tests := []struct {
		name       string
		assessment FAIRAssessment
		wantALE    float64
		wantNil    bool
	}{
		{
			name: "basic calculation",
			assessment: FAIRAssessment{
				ThreatEventFrequency: &FrequencyEstimate{
					Min:        1.0,
					Max:        10.0,
					MostLikely: 5.0, // 5 events per year
				},
				Vulnerability: &Percentage{
					Min:        0.1,
					Max:        0.5,
					MostLikely: 0.4, // 40% probability of loss
				},
				PrimaryLoss: &LossEstimate{
					Min:        10000,
					Max:        100000,
					MostLikely: 50000, // $50k per incident
				},
			},
			wantALE: 100000, // 5 × 0.4 × 50000 = 100,000
			wantNil: false,
		},
		{
			name: "with secondary loss",
			assessment: FAIRAssessment{
				ThreatEventFrequency: &FrequencyEstimate{
					MostLikely: 2.0, // 2 events per year
				},
				Vulnerability: &Percentage{
					MostLikely: 0.5, // 50% probability
				},
				PrimaryLoss: &LossEstimate{
					MostLikely: 100000, // $100k primary
				},
				SecondaryLoss: &LossEstimate{
					MostLikely: 50000, // $50k secondary
				},
			},
			wantALE: 150000, // 2 × 0.5 × (100000 + 50000) = 150,000
			wantNil: false,
		},
		{
			name: "missing TEF",
			assessment: FAIRAssessment{
				Vulnerability: &Percentage{MostLikely: 0.5},
				PrimaryLoss:   &LossEstimate{MostLikely: 100000},
			},
			wantNil: true,
		},
		{
			name: "missing vulnerability",
			assessment: FAIRAssessment{
				ThreatEventFrequency: &FrequencyEstimate{MostLikely: 5.0},
				PrimaryLoss:          &LossEstimate{MostLikely: 100000},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ale := tt.assessment.CalculateALE()
			if tt.wantNil {
				if ale != nil {
					t.Errorf("CalculateALE() = %v, want nil", ale)
				}
				return
			}
			if ale == nil {
				t.Fatal("CalculateALE() = nil, want non-nil")
			}
			if math.Abs(ale.Amount-tt.wantALE) > 0.01 {
				t.Errorf("CalculateALE().Amount = %f, want %f", ale.Amount, tt.wantALE)
			}
		})
	}
}

func TestCalculateALERange(t *testing.T) {
	assessment := FAIRAssessment{
		ThreatEventFrequency: &FrequencyEstimate{
			Min:        1.0,
			Max:        10.0,
			MostLikely: 5.0,
		},
		Vulnerability: &Percentage{
			Min:        0.1,
			Max:        0.5,
			MostLikely: 0.3,
		},
		PrimaryLoss: &LossEstimate{
			Min:        10000,
			Max:        100000,
			MostLikely: 50000,
			Currency:   Currency{Code: "EUR"},
		},
	}

	minALE, maxALE := assessment.CalculateALERange()
	if minALE == nil || maxALE == nil {
		t.Fatal("CalculateALERange() returned nil")
	}

	// Min ALE = 1 × 0.1 × 10000 = 1,000
	expectedMin := 1000.0
	if math.Abs(minALE.Amount-expectedMin) > 0.01 {
		t.Errorf("minALE.Amount = %f, want %f", minALE.Amount, expectedMin)
	}

	// Max ALE = 10 × 0.5 × 100000 = 500,000
	expectedMax := 500000.0
	if math.Abs(maxALE.Amount-expectedMax) > 0.01 {
		t.Errorf("maxALE.Amount = %f, want %f", maxALE.Amount, expectedMax)
	}

	// Currency should be preserved
	if minALE.Code != "EUR" {
		t.Errorf("minALE.Code = %s, want EUR", minALE.Code)
	}
}

func TestBusinessImpactJSONRoundTrip(t *testing.T) {
	impact := BusinessImpact{
		RevenueImpact: &LossEstimate{
			Min:        100000,
			Max:        1000000,
			MostLikely: 500000,
			Currency:   Currency{Code: "USD", Symbol: "$"},
		},
		CustomerImpact:    "Potential loss of 10,000 active users",
		RegulatoryImpact:  "GDPR notification requirements, potential fine up to 4% revenue",
		ReputationImpact:  "High - media coverage expected",
		OperationalImpact: "Service degradation for 24-48 hours",
		LegalImpact:       "Class action lawsuit possible",
		Criticality:       CriticalityCritical,
		RecoveryTimeEstimate: &Duration{
			Value: 72,
			Unit:  DurationUnitHours,
		},
	}

	data, err := json.MarshalIndent(impact, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal BusinessImpact: %v", err)
	}

	var decoded BusinessImpact
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal BusinessImpact: %v", err)
	}

	if decoded.Criticality != CriticalityCritical {
		t.Errorf("Criticality = %s, want critical", decoded.Criticality)
	}
	if decoded.RecoveryTimeEstimate.Value != 72 {
		t.Errorf("RecoveryTime Value = %d, want 72", decoded.RecoveryTimeEstimate.Value)
	}
	if decoded.RecoveryTimeEstimate.Unit != DurationUnitHours {
		t.Errorf("RecoveryTime Unit = %s, want hours", decoded.RecoveryTimeEstimate.Unit)
	}
}

func TestConfidenceValues(t *testing.T) {
	validConfidences := []Confidence{
		ConfidenceVeryLow,
		ConfidenceLow,
		ConfidenceMedium,
		ConfidenceHigh,
		ConfidenceVeryHigh,
	}

	for _, c := range validConfidences {
		freq := FrequencyEstimate{
			Min:        1.0,
			Max:        10.0,
			MostLikely: 5.0,
			Confidence: c,
		}

		data, err := json.Marshal(freq)
		if err != nil {
			t.Errorf("Failed to marshal FrequencyEstimate with confidence %s: %v", c, err)
		}

		var decoded FrequencyEstimate
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("Failed to unmarshal FrequencyEstimate with confidence %s: %v", c, err)
		}

		if decoded.Confidence != c {
			t.Errorf("Confidence = %s, want %s", decoded.Confidence, c)
		}
	}
}

func TestCriticalityValues(t *testing.T) {
	validCriticalities := []Criticality{
		CriticalityCritical,
		CriticalityHigh,
		CriticalityMedium,
		CriticalityLow,
	}

	for _, c := range validCriticalities {
		impact := BusinessImpact{
			Criticality: c,
		}

		data, err := json.Marshal(impact)
		if err != nil {
			t.Errorf("Failed to marshal BusinessImpact with criticality %s: %v", c, err)
		}

		var decoded BusinessImpact
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("Failed to unmarshal BusinessImpact with criticality %s: %v", c, err)
		}

		if decoded.Criticality != c {
			t.Errorf("Criticality = %s, want %s", decoded.Criticality, c)
		}
	}
}

func TestDurationUnits(t *testing.T) {
	validUnits := []DurationUnit{
		DurationUnitSeconds,
		DurationUnitMinutes,
		DurationUnitHours,
		DurationUnitDays,
		DurationUnitWeeks,
	}

	for _, u := range validUnits {
		dur := Duration{
			Value: 10,
			Unit:  u,
		}

		data, err := json.Marshal(dur)
		if err != nil {
			t.Errorf("Failed to marshal Duration with unit %s: %v", u, err)
		}

		var decoded Duration
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("Failed to unmarshal Duration with unit %s: %v", u, err)
		}

		if decoded.Unit != u {
			t.Errorf("Unit = %s, want %s", decoded.Unit, u)
		}
	}
}
