// Package ir provides the intermediate representation for threat models.
package ir

import "github.com/invopop/jsonschema"

// SecurityMetrics contains key security metrics for a threat model.
// These metrics help track detection and response effectiveness.
type SecurityMetrics struct {
	// MTTD is the Mean Time to Detect (how long to identify threats).
	MTTD *MetricDuration `json:"mttd,omitempty"`

	// MTTR is the Mean Time to Respond (how long to begin response).
	MTTR *MetricDuration `json:"mttr,omitempty"`

	// MTTC is the Mean Time to Contain (how long to contain threats).
	MTTC *MetricDuration `json:"mttc,omitempty"`

	// MTTRE is the Mean Time to Remediate/Eradicate.
	MTTRE *MetricDuration `json:"mttre,omitempty"`

	// DetectionRate is the percentage of threats detected (0.0 - 1.0).
	DetectionRate float64 `json:"detectionRate,omitempty"`

	// FalsePositiveRate is the percentage of false positive alerts (0.0 - 1.0).
	FalsePositiveRate float64 `json:"falsePositiveRate,omitempty"`

	// TruePositiveRate is the percentage of true positive detections (0.0 - 1.0).
	TruePositiveRate float64 `json:"truePositiveRate,omitempty"`

	// EscalationRate is the percentage of alerts that require escalation (0.0 - 1.0).
	EscalationRate float64 `json:"escalationRate,omitempty"`

	// IncidentCount is the number of security incidents in the measurement period.
	IncidentCount int `json:"incidentCount,omitempty"`

	// AlertVolume is the total number of alerts in the measurement period.
	AlertVolume int `json:"alertVolume,omitempty"`

	// MeasuredAt is the timestamp when metrics were collected.
	MeasuredAt string `json:"measuredAt,omitempty"`

	// MeasurementPeriod describes the time period for these metrics.
	MeasurementPeriod string `json:"measurementPeriod,omitempty"`

	// Notes provides additional context about the metrics.
	Notes string `json:"notes,omitempty"`
}

// MetricDuration represents a time duration for security metrics.
type MetricDuration struct {
	// Value is the numeric duration value.
	Value float64 `json:"value"`

	// Unit is the time unit.
	Unit MetricTimeUnit `json:"unit"`

	// Source describes where this measurement came from.
	Source string `json:"source,omitempty"`

	// Confidence indicates confidence in the measurement.
	Confidence string `json:"confidence,omitempty"`
}

// MetricTimeUnit represents time units for metrics.
type MetricTimeUnit string

const (
	MetricTimeUnitSeconds MetricTimeUnit = "seconds"
	MetricTimeUnitMinutes MetricTimeUnit = "minutes"
	MetricTimeUnitHours   MetricTimeUnit = "hours"
	MetricTimeUnitDays    MetricTimeUnit = "days"
	MetricTimeUnitWeeks   MetricTimeUnit = "weeks"
)

// JSONSchema implements jsonschema.JSONSchemaer for MetricTimeUnit.
func (MetricTimeUnit) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"seconds", "minutes", "hours", "days", "weeks"},
	}
}

// ToMinutes converts the duration to minutes for comparison.
func (d *MetricDuration) ToMinutes() float64 {
	if d == nil {
		return 0
	}
	switch d.Unit {
	case MetricTimeUnitSeconds:
		return d.Value / 60
	case MetricTimeUnitMinutes:
		return d.Value
	case MetricTimeUnitHours:
		return d.Value * 60
	case MetricTimeUnitDays:
		return d.Value * 60 * 24
	case MetricTimeUnitWeeks:
		return d.Value * 60 * 24 * 7
	default:
		return d.Value
	}
}

// ToHours converts the duration to hours for comparison.
func (d *MetricDuration) ToHours() float64 {
	return d.ToMinutes() / 60
}

// MetricsBenchmark provides industry benchmark comparisons for security metrics.
type MetricsBenchmark struct {
	// Category describes the industry/organization type.
	Category string `json:"category"`

	// AverageMTTD is the industry average MTTD.
	AverageMTTD *MetricDuration `json:"averageMttd,omitempty"`

	// AverageMTTR is the industry average MTTR.
	AverageMTTR *MetricDuration `json:"averageMttr,omitempty"`

	// Source is the source of benchmark data.
	Source string `json:"source,omitempty"`

	// Year is the year of the benchmark data.
	Year int `json:"year,omitempty"`
}

// CompareToIndustry compares current metrics to industry benchmarks.
func (m *SecurityMetrics) CompareToIndustry(benchmark *MetricsBenchmark) *MetricsComparison {
	comp := &MetricsComparison{}

	if m.MTTD != nil && benchmark.AverageMTTD != nil {
		currentMTTD := m.MTTD.ToHours()
		benchmarkMTTD := benchmark.AverageMTTD.ToHours()
		comp.MTTDDelta = currentMTTD - benchmarkMTTD
		comp.MTTDBetterThanAverage = currentMTTD < benchmarkMTTD
	}

	if m.MTTR != nil && benchmark.AverageMTTR != nil {
		currentMTTR := m.MTTR.ToHours()
		benchmarkMTTR := benchmark.AverageMTTR.ToHours()
		comp.MTTRDelta = currentMTTR - benchmarkMTTR
		comp.MTTRBetterThanAverage = currentMTTR < benchmarkMTTR
	}

	return comp
}

// MetricsComparison holds the results of comparing metrics to benchmarks.
type MetricsComparison struct {
	// MTTDDelta is the difference from benchmark (negative = better).
	MTTDDelta float64 `json:"mttdDelta,omitempty"`

	// MTTDBetterThanAverage indicates if MTTD is better than benchmark.
	MTTDBetterThanAverage bool `json:"mttdBetterThanAverage,omitempty"`

	// MTTRDelta is the difference from benchmark (negative = better).
	MTTRDelta float64 `json:"mttrDelta,omitempty"`

	// MTTRBetterThanAverage indicates if MTTR is better than benchmark.
	MTTRBetterThanAverage bool `json:"mttrBetterThanAverage,omitempty"`
}

// CalculateEfficiency calculates detection efficiency metrics.
func (m *SecurityMetrics) CalculateEfficiency() *DetectionEfficiency {
	eff := &DetectionEfficiency{}

	if m.AlertVolume > 0 {
		eff.AlertsPerIncident = float64(m.AlertVolume) / float64(max(m.IncidentCount, 1))
	}

	if m.FalsePositiveRate > 0 || m.TruePositiveRate > 0 {
		// Precision = TP / (TP + FP)
		if m.TruePositiveRate > 0 {
			eff.Precision = m.TruePositiveRate / (m.TruePositiveRate + m.FalsePositiveRate)
		}
	}

	if m.DetectionRate > 0 {
		eff.Recall = m.DetectionRate
	}

	// F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
	if eff.Precision > 0 && eff.Recall > 0 {
		eff.F1Score = 2 * (eff.Precision * eff.Recall) / (eff.Precision + eff.Recall)
	}

	return eff
}

// DetectionEfficiency provides derived efficiency metrics.
type DetectionEfficiency struct {
	// AlertsPerIncident is the average number of alerts per incident.
	AlertsPerIncident float64 `json:"alertsPerIncident,omitempty"`

	// Precision is the ratio of true positives to all positive predictions.
	Precision float64 `json:"precision,omitempty"`

	// Recall is the ratio of true positives to all actual positives (same as DetectionRate).
	Recall float64 `json:"recall,omitempty"`

	// F1Score is the harmonic mean of precision and recall.
	F1Score float64 `json:"f1Score,omitempty"`
}
