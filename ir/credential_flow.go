package ir

import "github.com/invopop/jsonschema"

// CredentialFlowStage represents a stage in the credential lifecycle.
type CredentialFlowStage string

const (
	// CredentialStageCreated indicates the credential was created/issued.
	CredentialStageCreated CredentialFlowStage = "created"

	// CredentialStageStored indicates the credential was stored.
	CredentialStageStored CredentialFlowStage = "stored"

	// CredentialStageTransmitted indicates the credential was transmitted.
	CredentialStageTransmitted CredentialFlowStage = "transmitted"

	// CredentialStageExfiltrated indicates the credential was exfiltrated by an attacker.
	CredentialStageExfiltrated CredentialFlowStage = "exfiltrated"

	// CredentialStageReused indicates the credential was reused/replayed by an attacker.
	CredentialStageReused CredentialFlowStage = "reused"

	// CredentialStageRevoked indicates the credential was revoked.
	CredentialStageRevoked CredentialFlowStage = "revoked"

	// CredentialStageExpired indicates the credential expired.
	CredentialStageExpired CredentialFlowStage = "expired"
)

// JSONSchema implements jsonschema.JSONSchemaer for CredentialFlowStage.
func (CredentialFlowStage) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"created", "stored", "transmitted", "exfiltrated", "reused", "revoked", "expired"},
	}
}

// CredentialType categorizes the type of credential.
type CredentialType string

const (
	// CredentialTypeAPIKey represents an API key.
	CredentialTypeAPIKey CredentialType = "api-key"

	// CredentialTypeBearerToken represents a bearer/access token.
	CredentialTypeBearerToken CredentialType = "bearer-token"

	// CredentialTypeRefreshToken represents a refresh token.
	CredentialTypeRefreshToken CredentialType = "refresh-token"

	// CredentialTypeJWT represents a JSON Web Token.
	CredentialTypeJWT CredentialType = "jwt"

	// CredentialTypeSessionToken represents a session token/cookie.
	CredentialTypeSessionToken CredentialType = "session-token"

	// CredentialTypePassword represents a password.
	CredentialTypePassword CredentialType = "password"

	// CredentialTypePrivateKey represents a private key.
	CredentialTypePrivateKey CredentialType = "private-key"

	// CredentialTypeCertificate represents an X.509 certificate.
	CredentialTypeCertificate CredentialType = "certificate"

	// CredentialTypeOAuth represents OAuth credentials.
	CredentialTypeOAuth CredentialType = "oauth"

	// CredentialTypeWebSocketToken represents a WebSocket authentication token.
	CredentialTypeWebSocketToken CredentialType = "websocket-token"
)

// JSONSchema implements jsonschema.JSONSchemaer for CredentialType.
func (CredentialType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"api-key", "bearer-token", "refresh-token", "jwt", "session-token",
			"password", "private-key", "certificate", "oauth", "websocket-token",
		},
	}
}

// CredentialFlow tracks the lifecycle of a credential through the system,
// including both legitimate usage and attack paths where it may be exfiltrated.
type CredentialFlow struct {
	// ID is the unique identifier for this credential flow.
	ID string `json:"id"`

	// Name is a human-readable name for the credential.
	Name string `json:"name"`

	// Description provides details about the credential.
	Description string `json:"description,omitempty"`

	// Type categorizes the credential.
	Type CredentialType `json:"type"`

	// AssetID links to the Asset definition for this credential.
	AssetID string `json:"assetId,omitempty"`

	// Stages tracks the credential through its lifecycle.
	Stages []CredentialFlowEvent `json:"stages,omitempty"`

	// ExpirationDuration is how long the credential is valid (e.g., "24h", "7d").
	ExpirationDuration string `json:"expirationDuration,omitempty"`

	// Revocable indicates whether the credential can be revoked.
	Revocable bool `json:"revocable,omitempty"`

	// RotationPolicy describes how often credentials are rotated.
	RotationPolicy string `json:"rotationPolicy,omitempty"`

	// Scope describes what the credential grants access to.
	Scope []string `json:"scope,omitempty"`

	// RiskLevel indicates the risk if this credential is compromised.
	RiskLevel RiskLevel `json:"riskLevel,omitempty"`
}

// CredentialFlowEvent represents a single event in the credential lifecycle.
type CredentialFlowEvent struct {
	// Stage identifies the lifecycle stage.
	Stage CredentialFlowStage `json:"stage"`

	// ElementID is the diagram element where this event occurs.
	ElementID string `json:"elementId,omitempty"`

	// Description provides context about this event.
	Description string `json:"description,omitempty"`

	// TransportProtocol describes how the credential is transmitted (if applicable).
	// Examples: "https", "wss", "ws", "http"
	TransportProtocol string `json:"transportProtocol,omitempty"`

	// TransportMechanism describes the transport mechanism.
	// Examples: "header", "cookie", "query-param", "body", "websocket-message"
	TransportMechanism string `json:"transportMechanism,omitempty"`

	// Encrypted indicates whether the credential is encrypted at this stage.
	Encrypted bool `json:"encrypted,omitempty"`

	// AttackStep links to an attack step if this is part of an attack chain.
	AttackStep int `json:"attackStep,omitempty"`

	// Vulnerability describes any vulnerability associated with this event.
	Vulnerability string `json:"vulnerability,omitempty"`

	// CWEIDs lists applicable CWE identifiers for vulnerabilities.
	CWEIDs []string `json:"cweIds,omitempty"`
}

// GetExfiltrationPath returns the credential flow events from creation to exfiltration.
// Returns nil if no exfiltration is recorded.
func (cf *CredentialFlow) GetExfiltrationPath() []CredentialFlowEvent {
	var path []CredentialFlowEvent
	for _, event := range cf.Stages {
		path = append(path, event)
		if event.Stage == CredentialStageExfiltrated {
			return path
		}
	}
	return nil
}

// IsExfiltrated returns true if the credential has an exfiltration event.
func (cf *CredentialFlow) IsExfiltrated() bool {
	for _, event := range cf.Stages {
		if event.Stage == CredentialStageExfiltrated {
			return true
		}
	}
	return false
}

// IsReused returns true if the credential has a reuse event (indicating replay attack).
func (cf *CredentialFlow) IsReused() bool {
	for _, event := range cf.Stages {
		if event.Stage == CredentialStageReused {
			return true
		}
	}
	return false
}

// GetVulnerableTransmissions returns transmission events with security issues.
func (cf *CredentialFlow) GetVulnerableTransmissions() []CredentialFlowEvent {
	var vulns []CredentialFlowEvent
	for _, event := range cf.Stages {
		if event.Stage == CredentialStageTransmitted {
			// Check for unencrypted transmission
			if !event.Encrypted && (event.TransportProtocol == "http" || event.TransportProtocol == "ws") {
				vulns = append(vulns, event)
			}
			// Check for credential in query parameter
			if event.TransportMechanism == "query-param" {
				vulns = append(vulns, event)
			}
		}
	}
	return vulns
}
