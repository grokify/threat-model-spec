package ir

import "github.com/invopop/jsonschema"

// AgentCapabilityType categorizes the types of capabilities an agent may have.
type AgentCapabilityType string

const (
	// AgentCapabilityCodeExecution allows the agent to execute code.
	AgentCapabilityCodeExecution AgentCapabilityType = "code-execution"

	// AgentCapabilityFileAccess allows the agent to read/write files.
	AgentCapabilityFileAccess AgentCapabilityType = "file-access"

	// AgentCapabilityNetworkAccess allows the agent to make network requests.
	AgentCapabilityNetworkAccess AgentCapabilityType = "network-access"

	// AgentCapabilityShellAccess allows the agent to execute shell commands.
	AgentCapabilityShellAccess AgentCapabilityType = "shell-access"

	// AgentCapabilityDatabaseAccess allows the agent to query databases.
	AgentCapabilityDatabaseAccess AgentCapabilityType = "database-access"

	// AgentCapabilityAPIAccess allows the agent to call external APIs.
	AgentCapabilityAPIAccess AgentCapabilityType = "api-access"

	// AgentCapabilityBrowserControl allows the agent to control a browser.
	AgentCapabilityBrowserControl AgentCapabilityType = "browser-control"

	// AgentCapabilityMessaging allows the agent to send messages (email, Slack, etc.).
	AgentCapabilityMessaging AgentCapabilityType = "messaging"

	// AgentCapabilityMemoryAccess allows the agent to access persistent memory.
	AgentCapabilityMemoryAccess AgentCapabilityType = "memory-access"

	// AgentCapabilityToolInvocation allows the agent to invoke other tools/agents.
	AgentCapabilityToolInvocation AgentCapabilityType = "tool-invocation"
)

// JSONSchema implements jsonschema.JSONSchemaer for AgentCapabilityType.
func (AgentCapabilityType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"code-execution", "file-access", "network-access", "shell-access",
			"database-access", "api-access", "browser-control", "messaging",
			"memory-access", "tool-invocation",
		},
	}
}

// AgentSandboxLevel indicates the isolation level of an agent's execution environment.
type AgentSandboxLevel string

const (
	// AgentSandboxNone indicates no sandboxing (full host access).
	AgentSandboxNone AgentSandboxLevel = "none"

	// AgentSandboxProcess indicates process-level isolation.
	AgentSandboxProcess AgentSandboxLevel = "process"

	// AgentSandboxContainer indicates container-level isolation.
	AgentSandboxContainer AgentSandboxLevel = "container"

	// AgentSandboxVM indicates VM-level isolation.
	AgentSandboxVM AgentSandboxLevel = "vm"

	// AgentSandboxRemote indicates execution on a remote/isolated system.
	AgentSandboxRemote AgentSandboxLevel = "remote"
)

// JSONSchema implements jsonschema.JSONSchemaer for AgentSandboxLevel.
func (AgentSandboxLevel) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"none", "process", "container", "vm", "remote"},
	}
}

// AgentCapabilities describes the capabilities and permissions of an AI agent.
// This is essential for threat modeling agentic systems to understand
// what an attacker could do if they compromise or manipulate the agent.
type AgentCapabilities struct {
	// Tools lists the tools available to the agent.
	Tools []AgentTool `json:"tools,omitempty"`

	// Permissions lists the permissions granted to the agent.
	Permissions []AgentPermission `json:"permissions,omitempty"`

	// SandboxLevel indicates the agent's isolation level.
	SandboxLevel AgentSandboxLevel `json:"sandboxLevel,omitempty"`

	// RequiresApproval indicates which actions require human approval.
	RequiresApproval []string `json:"requiresApproval,omitempty"`

	// ApprovalBypassable indicates whether approval requirements can be bypassed.
	// This is a critical security control for agentic systems.
	ApprovalBypassable bool `json:"approvalBypassable,omitempty"`

	// MaxExecutionTime is the maximum execution time per action (e.g., "30s", "5m").
	MaxExecutionTime string `json:"maxExecutionTime,omitempty"`

	// ResourceLimits describes resource constraints.
	ResourceLimits *AgentResourceLimits `json:"resourceLimits,omitempty"`

	// NetworkRestrictions describes network access limitations.
	NetworkRestrictions *AgentNetworkRestrictions `json:"networkRestrictions,omitempty"`

	// IntegratedServices lists external services the agent can access.
	IntegratedServices []AgentIntegration `json:"integratedServices,omitempty"`

	// EscalationPaths describes how the agent's capabilities could be escalated.
	EscalationPaths []AgentEscalationPath `json:"escalationPaths,omitempty"`
}

// AgentTool describes a tool available to the agent.
type AgentTool struct {
	// Name is the tool name (e.g., "system.run", "file.read", "web.browse").
	Name string `json:"name"`

	// Description describes what the tool does.
	Description string `json:"description,omitempty"`

	// CapabilityType categorizes the tool's capability.
	CapabilityType AgentCapabilityType `json:"capabilityType"`

	// Enabled indicates whether the tool is currently enabled.
	Enabled bool `json:"enabled,omitempty"`

	// RequiresApproval indicates whether using this tool requires human approval.
	RequiresApproval bool `json:"requiresApproval,omitempty"`

	// RiskLevel indicates the risk associated with this tool.
	RiskLevel RiskLevel `json:"riskLevel,omitempty"`

	// Parameters describes the tool's parameters.
	Parameters []AgentToolParameter `json:"parameters,omitempty"`

	// ASIIds lists applicable OWASP Agentic Security categories.
	ASIIds []string `json:"asiIds,omitempty"`
}

// AgentToolParameter describes a parameter for an agent tool.
type AgentToolParameter struct {
	// Name is the parameter name.
	Name string `json:"name"`

	// Type is the parameter type (e.g., "string", "file-path", "url").
	Type string `json:"type,omitempty"`

	// Required indicates whether the parameter is required.
	Required bool `json:"required,omitempty"`

	// Validation describes validation rules applied to this parameter.
	Validation string `json:"validation,omitempty"`

	// SensitiveData indicates whether this parameter may contain sensitive data.
	SensitiveData bool `json:"sensitiveData,omitempty"`
}

// AgentPermission describes a permission granted to the agent.
type AgentPermission struct {
	// Resource is the resource being accessed (e.g., "filesystem", "network", "api:slack").
	Resource string `json:"resource"`

	// Actions lists the permitted actions (e.g., "read", "write", "execute").
	Actions []string `json:"actions,omitempty"`

	// Scope limits the permission scope (e.g., "/home/user/workspace/*").
	Scope string `json:"scope,omitempty"`

	// Conditions describes conditions that must be met.
	Conditions string `json:"conditions,omitempty"`
}

// AgentResourceLimits describes resource constraints for the agent.
type AgentResourceLimits struct {
	// MaxMemoryMB is the maximum memory in megabytes.
	MaxMemoryMB int `json:"maxMemoryMb,omitempty"`

	// MaxCPUPercent is the maximum CPU percentage.
	MaxCPUPercent int `json:"maxCpuPercent,omitempty"`

	// MaxDiskMB is the maximum disk space in megabytes.
	MaxDiskMB int `json:"maxDiskMb,omitempty"`

	// MaxOpenFiles is the maximum number of open file descriptors.
	MaxOpenFiles int `json:"maxOpenFiles,omitempty"`

	// MaxProcesses is the maximum number of spawned processes.
	MaxProcesses int `json:"maxProcesses,omitempty"`
}

// AgentNetworkRestrictions describes network access limitations.
type AgentNetworkRestrictions struct {
	// AllowedHosts lists hosts the agent can connect to.
	// Empty list with InternetAccess=true means unrestricted.
	AllowedHosts []string `json:"allowedHosts,omitempty"`

	// BlockedHosts lists hosts the agent cannot connect to.
	BlockedHosts []string `json:"blockedHosts,omitempty"`

	// AllowedPorts lists ports the agent can connect to.
	AllowedPorts []int `json:"allowedPorts,omitempty"`

	// InternetAccess indicates whether the agent can access the internet.
	InternetAccess bool `json:"internetAccess,omitempty"`

	// LocalhostAccess indicates whether the agent can access localhost.
	LocalhostAccess bool `json:"localhostAccess,omitempty"`

	// InternalNetworkAccess indicates whether the agent can access internal networks.
	InternalNetworkAccess bool `json:"internalNetworkAccess,omitempty"`
}

// AgentIntegration describes an external service integration.
type AgentIntegration struct {
	// Service is the service name (e.g., "slack", "github", "jira").
	Service string `json:"service"`

	// Permissions lists the permissions granted for this integration.
	Permissions []string `json:"permissions,omitempty"`

	// CredentialID links to the credential used for this integration.
	CredentialID string `json:"credentialId,omitempty"`

	// Scopes lists the OAuth scopes or API permissions.
	Scopes []string `json:"scopes,omitempty"`
}

// AgentEscalationPath describes how an agent's capabilities could be escalated.
type AgentEscalationPath struct {
	// Name is a short name for this escalation path.
	Name string `json:"name"`

	// Description describes how escalation could occur.
	Description string `json:"description,omitempty"`

	// SourceCapability is the starting capability.
	SourceCapability AgentCapabilityType `json:"sourceCapability"`

	// TargetCapability is the escalated capability.
	TargetCapability AgentCapabilityType `json:"targetCapability"`

	// Mechanism describes the escalation mechanism.
	Mechanism string `json:"mechanism,omitempty"`

	// Mitigations lists controls that prevent this escalation.
	Mitigations []string `json:"mitigations,omitempty"`

	// ASIIds lists applicable OWASP Agentic Security categories.
	ASIIds []string `json:"asiIds,omitempty"`
}

// GetHighRiskTools returns tools with risk level high or critical.
func (ac *AgentCapabilities) GetHighRiskTools() []AgentTool {
	var highRisk []AgentTool
	for _, tool := range ac.Tools {
		if tool.RiskLevel == RiskLevelHigh || tool.RiskLevel == RiskLevelCritical {
			highRisk = append(highRisk, tool)
		}
	}
	return highRisk
}

// GetToolsWithoutApproval returns enabled tools that don't require approval.
func (ac *AgentCapabilities) GetToolsWithoutApproval() []AgentTool {
	var noApproval []AgentTool
	for _, tool := range ac.Tools {
		if tool.Enabled && !tool.RequiresApproval {
			noApproval = append(noApproval, tool)
		}
	}
	return noApproval
}

// CanExecuteCode returns true if the agent has code execution capabilities.
func (ac *AgentCapabilities) CanExecuteCode() bool {
	for _, tool := range ac.Tools {
		if tool.Enabled && (tool.CapabilityType == AgentCapabilityCodeExecution ||
			tool.CapabilityType == AgentCapabilityShellAccess) {
			return true
		}
	}
	return false
}

// HasUnrestrictedNetworkAccess returns true if the agent has unrestricted network access.
func (ac *AgentCapabilities) HasUnrestrictedNetworkAccess() bool {
	if ac.NetworkRestrictions == nil {
		return true // No restrictions defined
	}
	if ac.NetworkRestrictions.InternetAccess && len(ac.NetworkRestrictions.AllowedHosts) == 0 {
		return true
	}
	return false
}
