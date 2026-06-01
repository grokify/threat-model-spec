package ir

import (
	"testing"
)

func TestExecutionContext_IsSandboxed(t *testing.T) {
	tests := []struct {
		name     string
		ctx      ExecutionContext
		expected bool
	}{
		{
			name:     "host environment - not sandboxed",
			ctx:      ExecutionContext{EnvironmentType: EnvTypeHost},
			expected: false,
		},
		{
			name:     "container - sandboxed",
			ctx:      ExecutionContext{EnvironmentType: EnvTypeContainer},
			expected: true,
		},
		{
			name:     "VM - sandboxed",
			ctx:      ExecutionContext{EnvironmentType: EnvTypeVM},
			expected: true,
		},
		{
			name:     "browser - sandboxed",
			ctx:      ExecutionContext{EnvironmentType: EnvTypeBrowser},
			expected: true,
		},
		{
			name:     "sandbox - sandboxed",
			ctx:      ExecutionContext{EnvironmentType: EnvTypeSandbox},
			expected: true,
		},
		{
			name:     "serverless - sandboxed",
			ctx:      ExecutionContext{EnvironmentType: EnvTypeServerless},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ctx.IsSandboxed(); got != tt.expected {
				t.Errorf("IsSandboxed() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionContext_IsPrivileged(t *testing.T) {
	tests := []struct {
		name     string
		ctx      ExecutionContext
		expected bool
	}{
		{
			name:     "root",
			ctx:      ExecutionContext{PrivilegeLevel: PrivilegeLevelRoot},
			expected: true,
		},
		{
			name:     "admin",
			ctx:      ExecutionContext{PrivilegeLevel: PrivilegeLevelAdmin},
			expected: true,
		},
		{
			name:     "user",
			ctx:      ExecutionContext{PrivilegeLevel: PrivilegeLevelUser},
			expected: false,
		},
		{
			name:     "service",
			ctx:      ExecutionContext{PrivilegeLevel: PrivilegeLevelService},
			expected: false,
		},
		{
			name:     "restricted",
			ctx:      ExecutionContext{PrivilegeLevel: PrivilegeLevelRestricted},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ctx.IsPrivileged(); got != tt.expected {
				t.Errorf("IsPrivileged() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionContext_CanEscapeToHost(t *testing.T) {
	tests := []struct {
		name     string
		ctx      ExecutionContext
		expected bool
	}{
		{
			name: "has escape vector to host",
			ctx: ExecutionContext{
				EnvironmentType: EnvTypeContainer,
				EscapeVectors: []EscapeVector{
					{TargetContext: EnvTypeHost},
				},
			},
			expected: true,
		},
		{
			name: "no escape vectors",
			ctx: ExecutionContext{
				EnvironmentType: EnvTypeContainer,
				EscapeVectors:   []EscapeVector{},
			},
			expected: false,
		},
		{
			name: "escape vector to different target",
			ctx: ExecutionContext{
				EnvironmentType: EnvTypeContainer,
				EscapeVectors: []EscapeVector{
					{TargetContext: EnvTypeVM},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ctx.CanEscapeToHost(); got != tt.expected {
				t.Errorf("CanEscapeToHost() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionContext_GetPrivilegeEscalationPaths(t *testing.T) {
	ctx := ExecutionContext{
		PrivilegeLevel: PrivilegeLevelUser,
		EscapeVectors: []EscapeVector{
			{Name: "docker-escape", TargetPrivilegeLevel: PrivilegeLevelRoot},
			{Name: "container-breakout", TargetPrivilegeLevel: PrivilegeLevelUser},
			{Name: "local-priv-esc", TargetPrivilegeLevel: PrivilegeLevelAdmin},
		},
	}

	escalations := ctx.GetPrivilegeEscalationPaths()

	// Should find docker-escape (root > user) and local-priv-esc (admin > user)
	if len(escalations) != 2 {
		t.Errorf("Expected 2 privilege escalation paths, got %d", len(escalations))
	}
}

func TestIsHigherPrivilege(t *testing.T) {
	tests := []struct {
		name     string
		current  ExecutionPrivilegeLevel
		target   ExecutionPrivilegeLevel
		expected bool
	}{
		{"root higher than user", PrivilegeLevelUser, PrivilegeLevelRoot, true},
		{"admin higher than user", PrivilegeLevelUser, PrivilegeLevelAdmin, true},
		{"user not higher than root", PrivilegeLevelRoot, PrivilegeLevelUser, false},
		{"same level", PrivilegeLevelUser, PrivilegeLevelUser, false},
		{"restricted lower than service", PrivilegeLevelRestricted, PrivilegeLevelService, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHigherPrivilege(tt.current, tt.target); got != tt.expected {
				t.Errorf("isHigherPrivilege(%v, %v) = %v, want %v", tt.current, tt.target, got, tt.expected)
			}
		})
	}
}

func TestExecutionPrivilegeLevel_JSONSchema(t *testing.T) {
	schema := PrivilegeLevelRoot.JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Expected type 'string', got %s", schema.Type)
	}
	if len(schema.Enum) != 6 {
		t.Errorf("Expected 6 enum values, got %d", len(schema.Enum))
	}
}

func TestExecutionEnvironmentType_JSONSchema(t *testing.T) {
	schema := EnvTypeHost.JSONSchema()
	if schema.Type != "string" {
		t.Errorf("Expected type 'string', got %s", schema.Type)
	}
	if len(schema.Enum) != 6 {
		t.Errorf("Expected 6 enum values, got %d", len(schema.Enum))
	}
}
