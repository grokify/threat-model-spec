package ir

import "github.com/invopop/jsonschema"

// DetectionFormat identifies the format of a detection rule.
type DetectionFormat string

const (
	DetectionFormatSigma    DetectionFormat = "sigma"
	DetectionFormatYara     DetectionFormat = "yara"
	DetectionFormatSplunk   DetectionFormat = "splunk"
	DetectionFormatElastic  DetectionFormat = "elastic"
	DetectionFormatKQL      DetectionFormat = "kql"
	DetectionFormatSnort    DetectionFormat = "snort"
	DetectionFormatSuricata DetectionFormat = "suricata"
	DetectionFormatCustom   DetectionFormat = "custom"
)

// JSONSchema implements jsonschema.JSONSchemaer for DetectionFormat.
func (DetectionFormat) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"sigma", "yara", "splunk", "elastic", "kql", "snort", "suricata", "custom"},
	}
}

// IOCType identifies the type of Indicator of Compromise.
type IOCType string

const (
	IOCTypeIP       IOCType = "ip"
	IOCTypeDomain   IOCType = "domain"
	IOCTypeURL      IOCType = "url"
	IOCTypeHash     IOCType = "hash"
	IOCTypeFilepath IOCType = "filepath"
	IOCTypeEmail    IOCType = "email"
	IOCTypeRegistry IOCType = "registry"
	IOCTypeProcess  IOCType = "process"
	IOCTypeCert     IOCType = "certificate"
	IOCTypePattern  IOCType = "pattern"
)

// JSONSchema implements jsonschema.JSONSchemaer for IOCType.
func (IOCType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"ip", "domain", "url", "hash", "filepath", "email", "registry", "process", "certificate", "pattern"},
	}
}

// DefenseGuidance provides blue team/defensive security guidance
// for detecting and hunting for threats.
type DefenseGuidance struct {
	// DetectionRules contains detection rules in various formats.
	DetectionRules []DetectionRule `json:"detectionRules,omitempty"`

	// IOCs contains Indicators of Compromise.
	IOCs []IOC `json:"iocs,omitempty"`

	// LogSources lists log sources useful for detection.
	LogSources []LogSource `json:"logSources,omitempty"`

	// HuntingQueries provides proactive threat hunting queries.
	HuntingQueries []HuntingQuery `json:"huntingQueries,omitempty"`

	// MonitoringRecommendations provides general monitoring guidance.
	MonitoringRecommendations []string `json:"monitoringRecommendations,omitempty"`

	// AlertThresholds describes when to trigger alerts.
	AlertThresholds []AlertThreshold `json:"alertThresholds,omitempty"`

	// Notes provides additional guidance for SOC analysts.
	Notes string `json:"notes,omitempty"`
}

// DetectionRule represents a detection rule for SIEM/EDR/IDS.
type DetectionRule struct {
	// ID is the unique identifier for this rule.
	ID string `json:"id"`

	// Name is the rule name.
	Name string `json:"name"`

	// Format identifies the rule format (sigma, yara, splunk, etc.).
	Format DetectionFormat `json:"format"`

	// Rule is the actual detection rule content.
	Rule string `json:"rule"`

	// Description explains what this rule detects.
	Description string `json:"description,omitempty"`

	// Severity indicates the alert severity (informational, low, medium, high, critical).
	Severity string `json:"severity,omitempty"`

	// FalsePositives lists known false positive scenarios.
	FalsePositives []string `json:"falsePositives,omitempty"`

	// References lists external resources about this detection.
	References []string `json:"references,omitempty"`

	// MITRETechniques lists MITRE ATT&CK techniques this rule detects.
	MITRETechniques []string `json:"mitreTechniques,omitempty"`

	// Tags are metadata tags for categorization.
	Tags []string `json:"tags,omitempty"`

	// Status indicates the rule status (experimental, testing, stable, deprecated).
	Status string `json:"status,omitempty"`

	// Author is the rule author.
	Author string `json:"author,omitempty"`

	// Date is the rule creation or update date.
	Date string `json:"date,omitempty"`

	// TestRefs links to app-test-spec tests that validate this detection.
	TestRefs []TestReference `json:"testRefs,omitempty"`
}

// IOC represents an Indicator of Compromise.
type IOC struct {
	// Type identifies the IOC type (ip, domain, hash, etc.).
	Type IOCType `json:"type"`

	// Value is the IOC value.
	Value string `json:"value"`

	// Description explains what this IOC indicates.
	Description string `json:"description,omitempty"`

	// Confidence indicates the confidence level (high, medium, low).
	Confidence string `json:"confidence,omitempty"`

	// ValidUntil is the expiration date for this IOC (ISO 8601 format).
	ValidUntil string `json:"validUntil,omitempty"`

	// Source identifies where this IOC came from.
	Source string `json:"source,omitempty"`

	// MalwareFamily identifies the associated malware family (if any).
	MalwareFamily string `json:"malwareFamily,omitempty"`

	// ThreatActor identifies the associated threat actor (if any).
	ThreatActor string `json:"threatActor,omitempty"`

	// Tags are metadata tags for categorization.
	Tags []string `json:"tags,omitempty"`
}

// LogSource describes a log source useful for detection.
type LogSource struct {
	// Name is the log source name.
	Name string `json:"name"`

	// Description explains what this log source contains.
	Description string `json:"description,omitempty"`

	// EventIDs lists relevant event IDs (e.g., Windows Event IDs).
	EventIDs []string `json:"eventIds,omitempty"`

	// Fields lists important fields to examine in logs.
	Fields []string `json:"fields,omitempty"`

	// Category categorizes the log source (e.g., "webserver", "authentication", "process").
	Category string `json:"category,omitempty"`

	// Platform indicates the platform (e.g., "windows", "linux", "cloud").
	Platform string `json:"platform,omitempty"`

	// RetentionDays is the recommended log retention period.
	RetentionDays int `json:"retentionDays,omitempty"`
}

// HuntingQuery provides a proactive threat hunting query.
type HuntingQuery struct {
	// Name is the query name.
	Name string `json:"name"`

	// Description explains what this query hunts for.
	Description string `json:"description,omitempty"`

	// Platform identifies the query platform (splunk, elastic, kql, etc.).
	Platform DetectionFormat `json:"platform"`

	// Query is the actual query string.
	Query string `json:"query"`

	// Hypothesis describes the threat hypothesis being tested.
	Hypothesis string `json:"hypothesis,omitempty"`

	// DataSources lists required data sources.
	DataSources []string `json:"dataSources,omitempty"`

	// MITRETechniques lists related MITRE ATT&CK techniques.
	MITRETechniques []string `json:"mitreTechniques,omitempty"`

	// ExpectedResults describes what results indicate a positive finding.
	ExpectedResults string `json:"expectedResults,omitempty"`

	// Author is the query author.
	Author string `json:"author,omitempty"`
}

// AlertThreshold defines when to trigger an alert.
type AlertThreshold struct {
	// Metric is the metric being monitored.
	Metric string `json:"metric"`

	// Threshold is the threshold value.
	Threshold string `json:"threshold"`

	// Window is the time window for evaluation (e.g., "5m", "1h").
	Window string `json:"window,omitempty"`

	// Severity is the alert severity when threshold is exceeded.
	Severity string `json:"severity,omitempty"`

	// Description explains this threshold.
	Description string `json:"description,omitempty"`
}
