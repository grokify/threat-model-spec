package ir

import (
	"testing"
)

func TestAgentCapabilities_GetHighRiskTools(t *testing.T) {
	caps := AgentCapabilities{
		Tools: []AgentTool{
			{Name: "file.read", RiskLevel: RiskLevelLow},
			{Name: "system.run", RiskLevel: RiskLevelCritical},
			{Name: "web.browse", RiskLevel: RiskLevelMedium},
			{Name: "database.query", RiskLevel: RiskLevelHigh},
		},
	}

	highRisk := caps.GetHighRiskTools()

	if len(highRisk) != 2 {
		t.Errorf("Expected 2 high-risk tools, got %d", len(highRisk))
	}

	names := make(map[string]bool)
	for _, tool := range highRisk {
		names[tool.Name] = true
	}

	if !names["system.run"] || !names["database.query"] {
		t.Error("Expected system.run and database.query to be identified as high-risk")
	}
}

func TestAgentCapabilities_GetToolsWithoutApproval(t *testing.T) {
	caps := AgentCapabilities{
		Tools: []AgentTool{
			{Name: "file.read", Enabled: true, RequiresApproval: false},
			{Name: "system.run", Enabled: true, RequiresApproval: true},
			{Name: "web.browse", Enabled: false, RequiresApproval: false},
			{Name: "database.query", Enabled: true, RequiresApproval: false},
		},
	}

	noApproval := caps.GetToolsWithoutApproval()

	// Should get file.read and database.query (enabled, no approval)
	// web.browse is disabled, system.run requires approval
	if len(noApproval) != 2 {
		t.Errorf("Expected 2 tools without approval, got %d", len(noApproval))
	}
}

func TestAgentCapabilities_CanExecuteCode(t *testing.T) {
	tests := []struct {
		name     string
		caps     AgentCapabilities
		expected bool
	}{
		{
			name: "has code execution",
			caps: AgentCapabilities{
				Tools: []AgentTool{
					{Name: "exec", Enabled: true, CapabilityType: AgentCapabilityCodeExecution},
				},
			},
			expected: true,
		},
		{
			name: "has shell access",
			caps: AgentCapabilities{
				Tools: []AgentTool{
					{Name: "bash", Enabled: true, CapabilityType: AgentCapabilityShellAccess},
				},
			},
			expected: true,
		},
		{
			name: "no code execution",
			caps: AgentCapabilities{
				Tools: []AgentTool{
					{Name: "read", Enabled: true, CapabilityType: AgentCapabilityFileAccess},
				},
			},
			expected: false,
		},
		{
			name: "code execution disabled",
			caps: AgentCapabilities{
				Tools: []AgentTool{
					{Name: "exec", Enabled: false, CapabilityType: AgentCapabilityCodeExecution},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.caps.CanExecuteCode(); got != tt.expected {
				t.Errorf("CanExecuteCode() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAgentCapabilities_HasUnrestrictedNetworkAccess(t *testing.T) {
	tests := []struct {
		name     string
		caps     AgentCapabilities
		expected bool
	}{
		{
			name:     "no restrictions defined",
			caps:     AgentCapabilities{},
			expected: true,
		},
		{
			name: "internet access with no allowlist",
			caps: AgentCapabilities{
				NetworkRestrictions: &AgentNetworkRestrictions{
					InternetAccess: true,
					AllowedHosts:   []string{},
				},
			},
			expected: true,
		},
		{
			name: "internet access with allowlist",
			caps: AgentCapabilities{
				NetworkRestrictions: &AgentNetworkRestrictions{
					InternetAccess: true,
					AllowedHosts:   []string{"api.example.com"},
				},
			},
			expected: false,
		},
		{
			name: "no internet access",
			caps: AgentCapabilities{
				NetworkRestrictions: &AgentNetworkRestrictions{
					InternetAccess: false,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.caps.HasUnrestrictedNetworkAccess(); got != tt.expected {
				t.Errorf("HasUnrestrictedNetworkAccess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAgentCapabilityType_JSONSchema(t *testing.T) {
	schema := AgentCapabilityCodeExecution.JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Expected type 'string', got %s", schema.Type)
	}
	if len(schema.Enum) != 10 {
		t.Errorf("Expected 10 enum values, got %d", len(schema.Enum))
	}
}

func TestAgentSandboxLevel_JSONSchema(t *testing.T) {
	schema := AgentSandboxNone.JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Expected type 'string', got %s", schema.Type)
	}
	if len(schema.Enum) != 5 {
		t.Errorf("Expected 5 enum values, got %d", len(schema.Enum))
	}
}
