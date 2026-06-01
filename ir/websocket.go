package ir

import "github.com/invopop/jsonschema"

// WebSocketProtocol identifies the WebSocket protocol type.
type WebSocketProtocol string

const (
	// WebSocketProtocolWS represents unencrypted WebSocket (ws://).
	WebSocketProtocolWS WebSocketProtocol = "ws"

	// WebSocketProtocolWSS represents encrypted WebSocket (wss://).
	WebSocketProtocolWSS WebSocketProtocol = "wss"
)

// JSONSchema implements jsonschema.JSONSchemaer for WebSocketProtocol.
func (WebSocketProtocol) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"ws", "wss"},
	}
}

// WebSocketConfig contains WebSocket-specific security configuration.
// This is used to model WebSocket endpoints and their security posture.
type WebSocketConfig struct {
	// Protocol specifies the WebSocket protocol (ws or wss).
	Protocol WebSocketProtocol `json:"protocol,omitempty"`

	// Endpoint is the WebSocket endpoint path (e.g., "/ws", "/socket.io").
	Endpoint string `json:"endpoint,omitempty"`

	// AllowedOrigins lists origins permitted to connect.
	// An empty list indicates no origin validation (vulnerable).
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`

	// OriginValidation indicates whether origin validation is enforced.
	// When false, the endpoint is vulnerable to Cross-Site WebSocket Hijacking.
	OriginValidation bool `json:"originValidation,omitempty"`

	// CSRFProtection indicates whether CSRF tokens are required for WebSocket upgrade.
	CSRFProtection bool `json:"csrfProtection,omitempty"`

	// AuthenticationRequired indicates whether authentication is required to connect.
	AuthenticationRequired bool `json:"authenticationRequired,omitempty"`

	// AuthenticationMethod describes how authentication is performed.
	// Examples: "bearer-token", "cookie", "query-param", "first-message"
	AuthenticationMethod string `json:"authenticationMethod,omitempty"`

	// RateLimitRPS is the rate limit in requests per second (0 = no limit).
	RateLimitRPS int `json:"rateLimitRps,omitempty"`

	// RateLimitConnections is the max concurrent connections (0 = no limit).
	RateLimitConnections int `json:"rateLimitConnections,omitempty"`

	// MessageSizeLimit is the maximum message size in bytes (0 = no limit).
	MessageSizeLimit int `json:"messageSizeLimit,omitempty"`

	// SubProtocols lists supported WebSocket sub-protocols.
	SubProtocols []string `json:"subProtocols,omitempty"`

	// Vulnerabilities lists known security issues with this WebSocket configuration.
	Vulnerabilities []WebSocketVulnerability `json:"vulnerabilities,omitempty"`
}

// WebSocketVulnerability describes a security issue with a WebSocket endpoint.
type WebSocketVulnerability struct {
	// Type categorizes the vulnerability.
	Type WebSocketVulnType `json:"type"`

	// Description provides details about the vulnerability.
	Description string `json:"description,omitempty"`

	// CWEIDs lists applicable CWE identifiers.
	CWEIDs []string `json:"cweIds,omitempty"`

	// Severity indicates the vulnerability severity.
	Severity string `json:"severity,omitempty"`

	// Exploitable indicates whether this has been verified as exploitable.
	Exploitable bool `json:"exploitable,omitempty"`
}

// WebSocketVulnType categorizes WebSocket-specific vulnerabilities.
type WebSocketVulnType string

const (
	// WebSocketVulnCSWSH represents Cross-Site WebSocket Hijacking.
	WebSocketVulnCSWSH WebSocketVulnType = "cswsh"

	// WebSocketVulnNoOriginValidation represents missing origin header validation.
	WebSocketVulnNoOriginValidation WebSocketVulnType = "no-origin-validation"

	// WebSocketVulnNoRateLimit represents missing rate limiting.
	WebSocketVulnNoRateLimit WebSocketVulnType = "no-rate-limit"

	// WebSocketVulnNoAuth represents missing authentication.
	WebSocketVulnNoAuth WebSocketVulnType = "no-authentication"

	// WebSocketVulnWeakAuth represents weak authentication (e.g., query param token).
	WebSocketVulnWeakAuth WebSocketVulnType = "weak-authentication"

	// WebSocketVulnNoEncryption represents unencrypted WebSocket (ws:// instead of wss://).
	WebSocketVulnNoEncryption WebSocketVulnType = "no-encryption"

	// WebSocketVulnMessageInjection represents message injection vulnerability.
	WebSocketVulnMessageInjection WebSocketVulnType = "message-injection"

	// WebSocketVulnDenialOfService represents DoS through resource exhaustion.
	WebSocketVulnDenialOfService WebSocketVulnType = "denial-of-service"
)

// JSONSchema implements jsonschema.JSONSchemaer for WebSocketVulnType.
func (WebSocketVulnType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"cswsh", "no-origin-validation", "no-rate-limit", "no-authentication",
			"weak-authentication", "no-encryption", "message-injection", "denial-of-service",
		},
	}
}

// IsVulnerableToCSWSH returns true if the WebSocket configuration is vulnerable
// to Cross-Site WebSocket Hijacking.
func (wsc *WebSocketConfig) IsVulnerableToCSWSH() bool {
	// Vulnerable if origin validation is disabled or no allowed origins specified
	if !wsc.OriginValidation {
		return true
	}
	if len(wsc.AllowedOrigins) == 0 {
		return true
	}
	// Check for wildcard origins
	for _, origin := range wsc.AllowedOrigins {
		if origin == "*" || origin == "null" {
			return true
		}
	}
	return false
}

// GetVulnerabilities analyzes the WebSocket configuration and returns identified vulnerabilities.
func (wsc *WebSocketConfig) GetVulnerabilities() []WebSocketVulnerability {
	var vulns []WebSocketVulnerability

	// Check for CSWSH vulnerability
	if wsc.IsVulnerableToCSWSH() {
		vulns = append(vulns, WebSocketVulnerability{
			Type:        WebSocketVulnCSWSH,
			Description: "WebSocket endpoint does not validate Origin header, enabling Cross-Site WebSocket Hijacking",
			CWEIDs:      []string{"CWE-346", "CWE-352"},
			Severity:    "high",
			Exploitable: true,
		})
	}

	// Check for missing encryption
	if wsc.Protocol == WebSocketProtocolWS {
		vulns = append(vulns, WebSocketVulnerability{
			Type:        WebSocketVulnNoEncryption,
			Description: "WebSocket connection is unencrypted (ws://), credentials may be intercepted",
			CWEIDs:      []string{"CWE-319"},
			Severity:    "medium",
			Exploitable: true,
		})
	}

	// Check for missing authentication
	if !wsc.AuthenticationRequired {
		vulns = append(vulns, WebSocketVulnerability{
			Type:        WebSocketVulnNoAuth,
			Description: "WebSocket endpoint does not require authentication",
			CWEIDs:      []string{"CWE-306"},
			Severity:    "high",
			Exploitable: true,
		})
	}

	// Check for weak authentication
	if wsc.AuthenticationMethod == "query-param" {
		vulns = append(vulns, WebSocketVulnerability{
			Type:        WebSocketVulnWeakAuth,
			Description: "Authentication token passed in query parameter may be logged or leaked via Referer",
			CWEIDs:      []string{"CWE-598"},
			Severity:    "medium",
			Exploitable: true,
		})
	}

	// Check for missing rate limiting
	if wsc.RateLimitRPS == 0 && wsc.RateLimitConnections == 0 {
		vulns = append(vulns, WebSocketVulnerability{
			Type:        WebSocketVulnNoRateLimit,
			Description: "WebSocket endpoint has no rate limiting, vulnerable to abuse",
			CWEIDs:      []string{"CWE-770"},
			Severity:    "low",
			Exploitable: true,
		})
	}

	return vulns
}
