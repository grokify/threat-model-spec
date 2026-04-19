package ir

import "github.com/invopop/jsonschema"

// SensitivityLevel indicates the sensitivity level of an asset.
type SensitivityLevel string

const (
	// SensitivityPublic indicates publicly available data.
	SensitivityPublic SensitivityLevel = "public"

	// SensitivityInternal indicates internal/employee-only data.
	SensitivityInternal SensitivityLevel = "internal"

	// SensitivityConfidential indicates confidential business data.
	SensitivityConfidential SensitivityLevel = "confidential"

	// SensitivityRestricted indicates highly restricted data (PII, financial).
	SensitivityRestricted SensitivityLevel = "restricted"

	// SensitivitySecret indicates secret/classified data.
	SensitivitySecret SensitivityLevel = "secret"
)

// JSONSchema implements jsonschema.JSONSchemaer for SensitivityLevel.
func (SensitivityLevel) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"public", "internal", "confidential", "restricted", "secret"},
	}
}

// AssetType categorizes the type of asset.
type AssetType string

const (
	// AssetTypeData represents data assets (databases, files, secrets).
	AssetTypeData AssetType = "data"

	// AssetTypeService represents service assets (APIs, microservices).
	AssetTypeService AssetType = "service"

	// AssetTypeInfrastructure represents infrastructure assets (servers, networks).
	AssetTypeInfrastructure AssetType = "infrastructure"

	// AssetTypeCredential represents credential assets (keys, tokens, passwords).
	AssetTypeCredential AssetType = "credential"

	// AssetTypeIdentity represents identity assets (user accounts, service accounts).
	AssetTypeIdentity AssetType = "identity"

	// AssetTypeIntellectualProperty represents IP assets (source code, algorithms).
	AssetTypeIntellectualProperty AssetType = "intellectual-property"
)

// JSONSchema implements jsonschema.JSONSchemaer for AssetType.
func (AssetType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"data", "service", "infrastructure", "credential", "identity", "intellectual-property"},
	}
}

// Asset represents a valuable resource that needs protection.
type Asset struct {
	// ID is the unique identifier for the asset.
	ID string `json:"id"`

	// Name is the human-readable asset name.
	Name string `json:"name"`

	// Description provides details about the asset.
	Description string `json:"description,omitempty"`

	// Type categorizes the asset.
	Type AssetType `json:"type,omitempty"`

	// Classification indicates the sensitivity level.
	Classification SensitivityLevel `json:"classification"`

	// Owner is the person or team responsible for the asset.
	Owner string `json:"owner,omitempty"`

	// ElementIDs links the asset to diagram elements that contain or process it.
	ElementIDs []string `json:"elementIds,omitempty"`

	// DataTypes describes what kind of data this asset contains.
	// Examples: "PII", "PHI", "financial", "credentials", "source-code"
	DataTypes []string `json:"dataTypes,omitempty"`

	// ComplianceFrameworks lists regulations that govern this asset.
	// Examples: "GDPR", "HIPAA", "PCI-DSS", "SOC2"
	ComplianceFrameworks []string `json:"complianceFrameworks,omitempty"`

	// Value describes the business value or impact if compromised.
	Value string `json:"value,omitempty"`

	// RetentionPeriod indicates how long the asset is retained.
	RetentionPeriod string `json:"retentionPeriod,omitempty"`
}
