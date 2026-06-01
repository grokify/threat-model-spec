package ir

import (
	"testing"
)

func TestWebSocketConfig_IsVulnerableToCSWSH(t *testing.T) {
	tests := []struct {
		name     string
		config   WebSocketConfig
		expected bool
	}{
		{
			name:     "no origin validation",
			config:   WebSocketConfig{OriginValidation: false},
			expected: true,
		},
		{
			name:     "origin validation enabled but no allowed origins",
			config:   WebSocketConfig{OriginValidation: true, AllowedOrigins: []string{}},
			expected: true,
		},
		{
			name:     "wildcard origin",
			config:   WebSocketConfig{OriginValidation: true, AllowedOrigins: []string{"*"}},
			expected: true,
		},
		{
			name:     "null origin",
			config:   WebSocketConfig{OriginValidation: true, AllowedOrigins: []string{"null"}},
			expected: true,
		},
		{
			name:     "properly configured",
			config:   WebSocketConfig{OriginValidation: true, AllowedOrigins: []string{"https://example.com"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsVulnerableToCSWSH(); got != tt.expected {
				t.Errorf("IsVulnerableToCSWSH() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWebSocketConfig_GetVulnerabilities(t *testing.T) {
	// Test a fully vulnerable configuration
	config := WebSocketConfig{
		Protocol:               WebSocketProtocolWS,
		OriginValidation:       false,
		AuthenticationRequired: false,
		AuthenticationMethod:   "query-param",
		RateLimitRPS:           0,
		RateLimitConnections:   0,
	}

	vulns := config.GetVulnerabilities()

	// Should detect multiple vulnerabilities
	if len(vulns) < 3 {
		t.Errorf("Expected at least 3 vulnerabilities, got %d", len(vulns))
	}

	// Check for specific vulnerability types
	hasCSWSH := false
	hasNoEncryption := false
	hasNoAuth := false

	for _, v := range vulns {
		switch v.Type {
		case WebSocketVulnCSWSH:
			hasCSWSH = true
		case WebSocketVulnNoEncryption:
			hasNoEncryption = true
		case WebSocketVulnNoAuth:
			hasNoAuth = true
		}
	}

	if !hasCSWSH {
		t.Error("Expected CSWSH vulnerability to be detected")
	}
	if !hasNoEncryption {
		t.Error("Expected no-encryption vulnerability to be detected")
	}
	if !hasNoAuth {
		t.Error("Expected no-authentication vulnerability to be detected")
	}
}

func TestWebSocketProtocol_JSONSchema(t *testing.T) {
	schema := WebSocketProtocolWS.JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Expected type 'string', got %s", schema.Type)
	}
	if len(schema.Enum) != 2 {
		t.Errorf("Expected 2 enum values, got %d", len(schema.Enum))
	}
}

func TestWebSocketVulnType_JSONSchema(t *testing.T) {
	schema := WebSocketVulnCSWSH.JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Expected type 'string', got %s", schema.Type)
	}
	// Should have all vulnerability types
	if len(schema.Enum) < 8 {
		t.Errorf("Expected at least 8 enum values, got %d", len(schema.Enum))
	}
}
