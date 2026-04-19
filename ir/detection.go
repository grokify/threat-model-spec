package ir

import "github.com/invopop/jsonschema"

// DetectionCoverage indicates the level of detection coverage.
type DetectionCoverage string

const (
	DetectionCoverageNone    DetectionCoverage = "none"
	DetectionCoveragePartial DetectionCoverage = "partial"
	DetectionCoverageFull    DetectionCoverage = "full"
)

// JSONSchema implements jsonschema.JSONSchemaer for DetectionCoverage.
func (DetectionCoverage) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"none", "partial", "full"},
	}
}

// DataSourceType identifies the type of data source for detection.
type DataSourceType string

const (
	DataSourceTypeLogs           DataSourceType = "logs"
	DataSourceTypeSIEM           DataSourceType = "siem"
	DataSourceTypeEDR            DataSourceType = "edr"
	DataSourceTypeNDR            DataSourceType = "ndr"
	DataSourceTypeIDS            DataSourceType = "ids"
	DataSourceTypeWAF            DataSourceType = "waf"
	DataSourceTypeCloudTrail     DataSourceType = "cloudtrail"
	DataSourceTypeAPIGateway     DataSourceType = "api-gateway"
	DataSourceTypeNetworkCapture DataSourceType = "network-capture"
	DataSourceTypeUserBehavior   DataSourceType = "user-behavior"
	DataSourceTypeAuditLog       DataSourceType = "audit-log"
)

// JSONSchema implements jsonschema.JSONSchemaer for DataSourceType.
func (DataSourceType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"logs", "siem", "edr", "ndr", "ids", "waf",
			"cloudtrail", "api-gateway", "network-capture", "user-behavior", "audit-log",
		},
	}
}

// Detection represents detection capabilities for a threat or attack.
type Detection struct {
	// ID is the unique identifier for the detection.
	ID string `json:"id"`

	// Title is a brief description of what is detected.
	Title string `json:"title"`

	// Description provides detailed information about the detection.
	Description string `json:"description,omitempty"`

	// ThreatIDs lists the IDs of threats this detection covers.
	ThreatIDs []string `json:"threatIds,omitempty"`

	// AttackSteps lists the attack step numbers this detection covers.
	AttackSteps []int `json:"attackSteps,omitempty"`

	// MITRETechniques lists MITRE ATT&CK techniques this detection covers.
	MITRETechniques []string `json:"mitreTechniques,omitempty"`

	// Method describes how the threat is detected.
	Method string `json:"method,omitempty"`

	// DataSources lists the data sources used for detection.
	DataSources []DataSourceType `json:"dataSources,omitempty"`

	// Coverage indicates the detection coverage level.
	Coverage DetectionCoverage `json:"coverage"`

	// LatencySeconds is the typical time to detect (in seconds).
	LatencySeconds int `json:"latencySeconds,omitempty"`

	// FalsePositiveRate describes the expected false positive rate (high, medium, low).
	FalsePositiveRate string `json:"falsePositiveRate,omitempty"`

	// DetectionLogic contains the query, rule, or signature logic.
	DetectionLogic string `json:"detectionLogic,omitempty"`

	// Tool identifies the detection tool or platform.
	Tool string `json:"tool,omitempty"`

	// PlaybookID references a response playbook for this detection.
	PlaybookID string `json:"playbookId,omitempty"`

	// AlertSeverity indicates the alert severity when triggered.
	AlertSeverity string `json:"alertSeverity,omitempty"`

	// Enabled indicates if this detection is currently active.
	Enabled bool `json:"enabled,omitempty"`
}

// ResponseAction represents an incident response action.
type ResponseAction struct {
	// ID is the unique identifier for the response action.
	ID string `json:"id"`

	// Title is a brief description of the response action.
	Title string `json:"title"`

	// Description provides detailed information about the response.
	Description string `json:"description,omitempty"`

	// TriggerDetectionIDs lists detection IDs that trigger this response.
	TriggerDetectionIDs []string `json:"triggerDetectionIds,omitempty"`

	// ActionType categorizes the response (isolate, block, alert, investigate, contain).
	ActionType string `json:"actionType,omitempty"`

	// Automated indicates if the response is automated.
	Automated bool `json:"automated,omitempty"`

	// PlaybookURL links to the response playbook.
	PlaybookURL string `json:"playbookUrl,omitempty"`

	// Owner is the team or person responsible for the response.
	Owner string `json:"owner,omitempty"`

	// EscalationPath describes the escalation procedure.
	EscalationPath string `json:"escalationPath,omitempty"`

	// SLAMinutes is the expected response time SLA in minutes.
	SLAMinutes int `json:"slaMinutes,omitempty"`
}
