// Package ir provides the intermediate representation for threat models.
package ir

// FAIRAssessment represents a Factor Analysis of Information Risk (FAIR)
// assessment for quantifying risk in monetary or probabilistic terms.
type FAIRAssessment struct {
	// Loss Event Frequency (LEF) components
	ThreatEventFrequency *FrequencyEstimate `json:"threatEventFrequency,omitempty"`
	Vulnerability        *Percentage        `json:"vulnerability,omitempty"`

	// Loss Magnitude (LM) components
	PrimaryLoss   *LossEstimate `json:"primaryLoss,omitempty"`
	SecondaryLoss *LossEstimate `json:"secondaryLoss,omitempty"`

	// Derived values (can be calculated or provided)
	AnnualizedLossExpectancy *Currency `json:"annualizedLossExpectancy,omitempty"`
	RiskScore                float64   `json:"riskScore,omitempty"`

	// Metadata
	AssessmentDate string `json:"assessmentDate,omitempty"`
	Assessor       string `json:"assessor,omitempty"`
	Notes          string `json:"notes,omitempty"`
}

// FrequencyEstimate represents a probabilistic estimate for event frequency.
// Used for Threat Event Frequency (TEF) and other frequency components.
type FrequencyEstimate struct {
	Min        float64    `json:"min"`                  // Minimum expected occurrences per year
	Max        float64    `json:"max"`                  // Maximum expected occurrences per year
	MostLikely float64    `json:"mostLikely"`           // Most likely occurrences per year
	Confidence Confidence `json:"confidence,omitempty"` // Confidence level in the estimate
}

// LossEstimate represents a monetary loss estimate with uncertainty bounds.
// Used for Primary Loss Magnitude (PLM) and Secondary Loss Magnitude (SLM).
type LossEstimate struct {
	Min        float64  `json:"min"`                // Minimum expected loss
	Max        float64  `json:"max"`                // Maximum expected loss
	MostLikely float64  `json:"mostLikely"`         // Most likely loss
	Currency   Currency `json:"currency,omitempty"` // Currency for loss values (defaults to USD)
}

// Percentage represents a probability or percentage value (0.0 to 1.0).
// Used for Vulnerability (probability of loss event given threat event).
type Percentage struct {
	Min        float64    `json:"min"`                  // Minimum probability (0.0 to 1.0)
	Max        float64    `json:"max"`                  // Maximum probability (0.0 to 1.0)
	MostLikely float64    `json:"mostLikely"`           // Most likely probability (0.0 to 1.0)
	Confidence Confidence `json:"confidence,omitempty"` // Confidence level in the estimate
}

// Currency represents a monetary value with its currency code.
type Currency struct {
	Amount float64 `json:"amount"`           // Monetary amount
	Code   string  `json:"code,omitempty"`   // ISO 4217 currency code (default: USD)
	Symbol string  `json:"symbol,omitempty"` // Currency symbol for display (e.g., "$")
}

// Confidence represents confidence level in an estimate.
type Confidence string

const (
	ConfidenceVeryLow  Confidence = "very-low"  // < 20% confidence
	ConfidenceLow      Confidence = "low"       // 20-40% confidence
	ConfidenceMedium   Confidence = "medium"    // 40-60% confidence
	ConfidenceHigh     Confidence = "high"      // 60-80% confidence
	ConfidenceVeryHigh Confidence = "very-high" // > 80% confidence
)

// BusinessImpact represents the broader business impact of a threat,
// beyond direct monetary loss.
type BusinessImpact struct {
	// Financial impacts
	RevenueImpact *LossEstimate `json:"revenueImpact,omitempty"` // Direct revenue loss

	// Non-financial impacts (descriptive)
	CustomerImpact    string `json:"customerImpact,omitempty"`    // Impact on customers
	RegulatoryImpact  string `json:"regulatoryImpact,omitempty"`  // Regulatory/compliance impact
	ReputationImpact  string `json:"reputationImpact,omitempty"`  // Brand/reputation impact
	OperationalImpact string `json:"operationalImpact,omitempty"` // Business operations impact
	LegalImpact       string `json:"legalImpact,omitempty"`       // Legal liability impact

	// Severity classification
	Criticality Criticality `json:"criticality,omitempty"` // Overall criticality level

	// Recovery estimates
	RecoveryTimeEstimate *Duration `json:"recoveryTimeEstimate,omitempty"` // Estimated time to recover
}

// Criticality represents business criticality level.
type Criticality string

const (
	CriticalityCritical Criticality = "critical" // Business-threatening impact
	CriticalityHigh     Criticality = "high"     // Significant business impact
	CriticalityMedium   Criticality = "medium"   // Moderate business impact
	CriticalityLow      Criticality = "low"      // Minor business impact
)

// Duration represents a time duration with unit.
type Duration struct {
	Value int          `json:"value"` // Numeric value
	Unit  DurationUnit `json:"unit"`  // Time unit
}

// DurationUnit represents time measurement units.
type DurationUnit string

const (
	DurationUnitSeconds DurationUnit = "seconds"
	DurationUnitMinutes DurationUnit = "minutes"
	DurationUnitHours   DurationUnit = "hours"
	DurationUnitDays    DurationUnit = "days"
	DurationUnitWeeks   DurationUnit = "weeks"
)

// CalculateALE calculates the Annualized Loss Expectancy from FAIR components.
// ALE = TEF × Vulnerability × (Primary LM + Secondary LM)
// This uses the "most likely" values for a simple point estimate.
// For Monte Carlo simulation, use the full distributions.
func (f *FAIRAssessment) CalculateALE() *Currency {
	if f.ThreatEventFrequency == nil || f.Vulnerability == nil {
		return nil
	}

	// Loss Event Frequency = TEF × Vulnerability
	lef := f.ThreatEventFrequency.MostLikely * f.Vulnerability.MostLikely

	// Loss Magnitude = Primary + Secondary
	var lm float64
	currencyCode := "USD"

	if f.PrimaryLoss != nil {
		lm += f.PrimaryLoss.MostLikely
		if f.PrimaryLoss.Currency.Code != "" {
			currencyCode = f.PrimaryLoss.Currency.Code
		}
	}
	if f.SecondaryLoss != nil {
		lm += f.SecondaryLoss.MostLikely
	}

	// ALE = LEF × LM
	ale := lef * lm

	return &Currency{
		Amount: ale,
		Code:   currencyCode,
	}
}

// CalculateALERange calculates the min/max range for ALE.
// Returns (min ALE, max ALE).
func (f *FAIRAssessment) CalculateALERange() (*Currency, *Currency) {
	if f.ThreatEventFrequency == nil || f.Vulnerability == nil {
		return nil, nil
	}

	currencyCode := "USD"
	if f.PrimaryLoss != nil && f.PrimaryLoss.Currency.Code != "" {
		currencyCode = f.PrimaryLoss.Currency.Code
	}

	// Min ALE = Min TEF × Min Vuln × Min LM
	minLEF := f.ThreatEventFrequency.Min * f.Vulnerability.Min
	var minLM float64
	if f.PrimaryLoss != nil {
		minLM += f.PrimaryLoss.Min
	}
	if f.SecondaryLoss != nil {
		minLM += f.SecondaryLoss.Min
	}
	minALE := minLEF * minLM

	// Max ALE = Max TEF × Max Vuln × Max LM
	maxLEF := f.ThreatEventFrequency.Max * f.Vulnerability.Max
	var maxLM float64
	if f.PrimaryLoss != nil {
		maxLM += f.PrimaryLoss.Max
	}
	if f.SecondaryLoss != nil {
		maxLM += f.SecondaryLoss.Max
	}
	maxALE := maxLEF * maxLM

	return &Currency{Amount: minALE, Code: currencyCode}, &Currency{Amount: maxALE, Code: currencyCode}
}
