package ir

import (
	"encoding/json"
	"math"
	"testing"
)

func TestSecurityMetricsJSONRoundTrip(t *testing.T) {
	metrics := SecurityMetrics{
		MTTD: &MetricDuration{
			Value:  4.5,
			Unit:   MetricTimeUnitHours,
			Source: "SIEM",
		},
		MTTR: &MetricDuration{
			Value: 30,
			Unit:  MetricTimeUnitMinutes,
		},
		MTTC: &MetricDuration{
			Value: 2,
			Unit:  MetricTimeUnitHours,
		},
		DetectionRate:     0.85,
		FalsePositiveRate: 0.15,
		TruePositiveRate:  0.80,
		IncidentCount:     12,
		AlertVolume:       500,
		MeasuredAt:        "2026-04-28",
		MeasurementPeriod: "Q1 2026",
	}

	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal SecurityMetrics: %v", err)
	}

	var decoded SecurityMetrics
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal SecurityMetrics: %v", err)
	}

	if decoded.MTTD.Value != 4.5 {
		t.Errorf("MTTD.Value = %f, want 4.5", decoded.MTTD.Value)
	}
	if decoded.MTTD.Unit != MetricTimeUnitHours {
		t.Errorf("MTTD.Unit = %s, want hours", decoded.MTTD.Unit)
	}
	if decoded.DetectionRate != 0.85 {
		t.Errorf("DetectionRate = %f, want 0.85", decoded.DetectionRate)
	}
	if decoded.IncidentCount != 12 {
		t.Errorf("IncidentCount = %d, want 12", decoded.IncidentCount)
	}
}

func TestMetricDurationToMinutes(t *testing.T) {
	tests := []struct {
		duration *MetricDuration
		want     float64
	}{
		{&MetricDuration{Value: 120, Unit: MetricTimeUnitSeconds}, 2.0},
		{&MetricDuration{Value: 30, Unit: MetricTimeUnitMinutes}, 30.0},
		{&MetricDuration{Value: 2, Unit: MetricTimeUnitHours}, 120.0},
		{&MetricDuration{Value: 1, Unit: MetricTimeUnitDays}, 1440.0},
		{&MetricDuration{Value: 1, Unit: MetricTimeUnitWeeks}, 10080.0},
		{nil, 0.0},
	}

	for _, tt := range tests {
		got := tt.duration.ToMinutes()
		if math.Abs(got-tt.want) > 0.01 {
			if tt.duration != nil {
				t.Errorf("ToMinutes() for %f %s = %f, want %f", tt.duration.Value, tt.duration.Unit, got, tt.want)
			} else {
				t.Errorf("ToMinutes() for nil = %f, want %f", got, tt.want)
			}
		}
	}
}

func TestMetricDurationToHours(t *testing.T) {
	duration := &MetricDuration{Value: 120, Unit: MetricTimeUnitMinutes}
	got := duration.ToHours()
	want := 2.0

	if math.Abs(got-want) > 0.01 {
		t.Errorf("ToHours() = %f, want %f", got, want)
	}
}

func TestMetricTimeUnits(t *testing.T) {
	validUnits := []MetricTimeUnit{
		MetricTimeUnitSeconds,
		MetricTimeUnitMinutes,
		MetricTimeUnitHours,
		MetricTimeUnitDays,
		MetricTimeUnitWeeks,
	}

	for _, unit := range validUnits {
		dur := MetricDuration{Value: 10, Unit: unit}

		data, err := json.Marshal(dur)
		if err != nil {
			t.Errorf("Failed to marshal MetricDuration with unit %s: %v", unit, err)
		}

		var decoded MetricDuration
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("Failed to unmarshal MetricDuration with unit %s: %v", unit, err)
		}

		if decoded.Unit != unit {
			t.Errorf("Unit = %s, want %s", decoded.Unit, unit)
		}
	}
}

func TestCompareToIndustry(t *testing.T) {
	metrics := SecurityMetrics{
		MTTD: &MetricDuration{Value: 2, Unit: MetricTimeUnitHours},
		MTTR: &MetricDuration{Value: 1, Unit: MetricTimeUnitHours},
	}

	benchmark := MetricsBenchmark{
		Category:    "Technology",
		AverageMTTD: &MetricDuration{Value: 4, Unit: MetricTimeUnitHours},
		AverageMTTR: &MetricDuration{Value: 2, Unit: MetricTimeUnitHours},
		Source:      "Industry Report 2026",
		Year:        2026,
	}

	comparison := metrics.CompareToIndustry(&benchmark)

	// MTTD: 2 hours vs 4 hours benchmark = -2 hours delta (better)
	if comparison.MTTDDelta != -2.0 {
		t.Errorf("MTTDDelta = %f, want -2.0", comparison.MTTDDelta)
	}
	if !comparison.MTTDBetterThanAverage {
		t.Error("MTTDBetterThanAverage should be true")
	}

	// MTTR: 1 hour vs 2 hours benchmark = -1 hour delta (better)
	if comparison.MTTRDelta != -1.0 {
		t.Errorf("MTTRDelta = %f, want -1.0", comparison.MTTRDelta)
	}
	if !comparison.MTTRBetterThanAverage {
		t.Error("MTTRBetterThanAverage should be true")
	}
}

func TestCompareToIndustryWorse(t *testing.T) {
	metrics := SecurityMetrics{
		MTTD: &MetricDuration{Value: 8, Unit: MetricTimeUnitHours},
	}

	benchmark := MetricsBenchmark{
		AverageMTTD: &MetricDuration{Value: 4, Unit: MetricTimeUnitHours},
	}

	comparison := metrics.CompareToIndustry(&benchmark)

	// MTTD: 8 hours vs 4 hours benchmark = +4 hours delta (worse)
	if comparison.MTTDDelta != 4.0 {
		t.Errorf("MTTDDelta = %f, want 4.0", comparison.MTTDDelta)
	}
	if comparison.MTTDBetterThanAverage {
		t.Error("MTTDBetterThanAverage should be false")
	}
}

func TestCalculateEfficiency(t *testing.T) {
	metrics := SecurityMetrics{
		DetectionRate:     0.9,  // 90% recall
		FalsePositiveRate: 0.1,  // 10% false positives
		TruePositiveRate:  0.9,  // 90% true positives
		IncidentCount:     10,
		AlertVolume:       500,
	}

	efficiency := metrics.CalculateEfficiency()

	// AlertsPerIncident = 500 / 10 = 50
	if efficiency.AlertsPerIncident != 50.0 {
		t.Errorf("AlertsPerIncident = %f, want 50.0", efficiency.AlertsPerIncident)
	}

	// Precision = 0.9 / (0.9 + 0.1) = 0.9
	if math.Abs(efficiency.Precision-0.9) > 0.01 {
		t.Errorf("Precision = %f, want 0.9", efficiency.Precision)
	}

	// Recall = DetectionRate = 0.9
	if efficiency.Recall != 0.9 {
		t.Errorf("Recall = %f, want 0.9", efficiency.Recall)
	}

	// F1 = 2 * (0.9 * 0.9) / (0.9 + 0.9) = 0.9
	if math.Abs(efficiency.F1Score-0.9) > 0.01 {
		t.Errorf("F1Score = %f, want 0.9", efficiency.F1Score)
	}
}

func TestCalculateEfficiencyZero(t *testing.T) {
	metrics := SecurityMetrics{}

	efficiency := metrics.CalculateEfficiency()

	if efficiency.F1Score != 0 {
		t.Errorf("F1Score = %f, want 0", efficiency.F1Score)
	}
}

func TestMetricsBenchmarkJSONRoundTrip(t *testing.T) {
	benchmark := MetricsBenchmark{
		Category:    "Financial Services",
		AverageMTTD: &MetricDuration{Value: 6, Unit: MetricTimeUnitHours},
		AverageMTTR: &MetricDuration{Value: 45, Unit: MetricTimeUnitMinutes},
		Source:      "Verizon DBIR 2026",
		Year:        2026,
	}

	data, err := json.MarshalIndent(benchmark, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal MetricsBenchmark: %v", err)
	}

	var decoded MetricsBenchmark
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal MetricsBenchmark: %v", err)
	}

	if decoded.Category != "Financial Services" {
		t.Errorf("Category = %s, want Financial Services", decoded.Category)
	}
	if decoded.Year != 2026 {
		t.Errorf("Year = %d, want 2026", decoded.Year)
	}
}

func TestDetectionEfficiencyJSONRoundTrip(t *testing.T) {
	efficiency := DetectionEfficiency{
		AlertsPerIncident: 50.0,
		Precision:         0.85,
		Recall:            0.90,
		F1Score:           0.87,
	}

	data, err := json.MarshalIndent(efficiency, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal DetectionEfficiency: %v", err)
	}

	var decoded DetectionEfficiency
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal DetectionEfficiency: %v", err)
	}

	if decoded.Precision != 0.85 {
		t.Errorf("Precision = %f, want 0.85", decoded.Precision)
	}
	if decoded.F1Score != 0.87 {
		t.Errorf("F1Score = %f, want 0.87", decoded.F1Score)
	}
}
