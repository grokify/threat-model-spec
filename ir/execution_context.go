package ir

import "github.com/invopop/jsonschema"

// ExecutionPrivilegeLevel indicates the privilege level of code execution.
type ExecutionPrivilegeLevel string

const (
	// PrivilegeLevelRoot indicates root/administrator privileges.
	PrivilegeLevelRoot ExecutionPrivilegeLevel = "root"

	// PrivilegeLevelAdmin indicates administrator privileges (non-root).
	PrivilegeLevelAdmin ExecutionPrivilegeLevel = "admin"

	// PrivilegeLevelUser indicates standard user privileges.
	PrivilegeLevelUser ExecutionPrivilegeLevel = "user"

	// PrivilegeLevelService indicates service account privileges.
	PrivilegeLevelService ExecutionPrivilegeLevel = "service"

	// PrivilegeLevelRestricted indicates restricted/sandboxed privileges.
	PrivilegeLevelRestricted ExecutionPrivilegeLevel = "restricted"

	// PrivilegeLevelNone indicates no code execution capability.
	PrivilegeLevelNone ExecutionPrivilegeLevel = "none"
)

// JSONSchema implements jsonschema.JSONSchemaer for ExecutionPrivilegeLevel.
func (ExecutionPrivilegeLevel) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"root", "admin", "user", "service", "restricted", "none"},
	}
}

// ExecutionEnvironmentType indicates the type of execution environment.
type ExecutionEnvironmentType string

const (
	// EnvTypeHost indicates execution directly on the host OS.
	EnvTypeHost ExecutionEnvironmentType = "host"

	// EnvTypeContainer indicates execution within a container.
	EnvTypeContainer ExecutionEnvironmentType = "container"

	// EnvTypeVM indicates execution within a virtual machine.
	EnvTypeVM ExecutionEnvironmentType = "vm"

	// EnvTypeBrowser indicates execution within a browser context.
	EnvTypeBrowser ExecutionEnvironmentType = "browser"

	// EnvTypeServerless indicates execution in a serverless environment.
	EnvTypeServerless ExecutionEnvironmentType = "serverless"

	// EnvTypeSandbox indicates execution in an application sandbox.
	EnvTypeSandbox ExecutionEnvironmentType = "sandbox"
)

// JSONSchema implements jsonschema.JSONSchemaer for ExecutionEnvironmentType.
func (ExecutionEnvironmentType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"host", "container", "vm", "browser", "serverless", "sandbox"},
	}
}

// ExecutionContext describes the context in which code is executed,
// which is critical for understanding the impact of RCE vulnerabilities.
type ExecutionContext struct {
	// EnvironmentType indicates where the code executes.
	EnvironmentType ExecutionEnvironmentType `json:"environmentType"`

	// PrivilegeLevel indicates the execution privileges.
	PrivilegeLevel ExecutionPrivilegeLevel `json:"privilegeLevel"`

	// User is the user account under which code executes.
	User string `json:"user,omitempty"`

	// Groups lists the groups the execution context belongs to.
	Groups []string `json:"groups,omitempty"`

	// ProcessName is the name of the executing process.
	ProcessName string `json:"processName,omitempty"`

	// WorkingDirectory is the working directory for execution.
	WorkingDirectory string `json:"workingDirectory,omitempty"`

	// EnvironmentVariables lists environment variables available.
	EnvironmentVariables []string `json:"environmentVariables,omitempty"`

	// Capabilities lists Linux capabilities (if applicable).
	Capabilities []string `json:"capabilities,omitempty"`

	// SELinuxContext is the SELinux context (if applicable).
	SELinuxContext string `json:"selinuxContext,omitempty"`

	// AppArmorProfile is the AppArmor profile (if applicable).
	AppArmorProfile string `json:"appArmorProfile,omitempty"`

	// SeccompProfile indicates the seccomp profile (if applicable).
	SeccompProfile string `json:"seccompProfile,omitempty"`

	// ContainerInfo contains container-specific details.
	ContainerInfo *ContainerExecutionInfo `json:"containerInfo,omitempty"`

	// BrowserInfo contains browser-specific details.
	BrowserInfo *BrowserExecutionInfo `json:"browserInfo,omitempty"`

	// NetworkAccess describes network access from this context.
	NetworkAccess *ExecutionNetworkAccess `json:"networkAccess,omitempty"`

	// FilesystemAccess describes filesystem access from this context.
	FilesystemAccess *ExecutionFilesystemAccess `json:"filesystemAccess,omitempty"`

	// EscapeVectors describes potential escape paths from this context.
	EscapeVectors []EscapeVector `json:"escapeVectors,omitempty"`
}

// ContainerExecutionInfo contains container-specific execution details.
type ContainerExecutionInfo struct {
	// Runtime is the container runtime (docker, containerd, podman, etc.).
	Runtime string `json:"runtime,omitempty"`

	// Image is the container image.
	Image string `json:"image,omitempty"`

	// Privileged indicates whether the container runs in privileged mode.
	Privileged bool `json:"privileged,omitempty"`

	// HostPID indicates whether the container shares the host PID namespace.
	HostPID bool `json:"hostPid,omitempty"`

	// HostNetwork indicates whether the container shares the host network.
	HostNetwork bool `json:"hostNetwork,omitempty"`

	// Volumes lists mounted volumes.
	Volumes []string `json:"volumes,omitempty"`

	// ReadOnlyRootFS indicates whether the root filesystem is read-only.
	ReadOnlyRootFS bool `json:"readOnlyRootFs,omitempty"`

	// DropCapabilities lists dropped Linux capabilities.
	DropCapabilities []string `json:"dropCapabilities,omitempty"`
}

// BrowserExecutionInfo contains browser-specific execution details.
type BrowserExecutionInfo struct {
	// Origin is the JavaScript origin (e.g., "https://example.com").
	Origin string `json:"origin,omitempty"`

	// SameSite indicates the SameSite cookie attribute.
	SameSite string `json:"sameSite,omitempty"`

	// CrossOriginIsolated indicates whether the context is cross-origin isolated.
	CrossOriginIsolated bool `json:"crossOriginIsolated,omitempty"`

	// ServiceWorker indicates whether this is a service worker context.
	ServiceWorker bool `json:"serviceWorker,omitempty"`

	// WebWorker indicates whether this is a web worker context.
	WebWorker bool `json:"webWorker,omitempty"`

	// LocalStorageAccess indicates whether local storage is accessible.
	LocalStorageAccess bool `json:"localStorageAccess,omitempty"`

	// CookieAccess indicates whether cookies are accessible.
	CookieAccess bool `json:"cookieAccess,omitempty"`

	// LocalhostAccess indicates whether localhost can be accessed.
	// This is relevant for Cross-Site WebSocket Hijacking attacks.
	LocalhostAccess bool `json:"localhostAccess,omitempty"`
}

// ExecutionNetworkAccess describes network capabilities from an execution context.
type ExecutionNetworkAccess struct {
	// CanAccessInternet indicates whether the context can reach the internet.
	CanAccessInternet bool `json:"canAccessInternet,omitempty"`

	// CanAccessLocalhost indicates whether the context can access localhost.
	CanAccessLocalhost bool `json:"canAccessLocalhost,omitempty"`

	// CanAccessInternalNetwork indicates whether internal networks are reachable.
	CanAccessInternalNetwork bool `json:"canAccessInternalNetwork,omitempty"`

	// AllowedPorts lists ports that can be accessed.
	AllowedPorts []int `json:"allowedPorts,omitempty"`

	// BlockedPorts lists ports that are blocked.
	BlockedPorts []int `json:"blockedPorts,omitempty"`

	// DNSAccess indicates whether DNS resolution is available.
	DNSAccess bool `json:"dnsAccess,omitempty"`
}

// ExecutionFilesystemAccess describes filesystem capabilities.
type ExecutionFilesystemAccess struct {
	// ReadPaths lists paths with read access.
	ReadPaths []string `json:"readPaths,omitempty"`

	// WritePaths lists paths with write access.
	WritePaths []string `json:"writePaths,omitempty"`

	// ExecutePaths lists paths with execute access.
	ExecutePaths []string `json:"executePaths,omitempty"`

	// MountPoints lists accessible mount points.
	MountPoints []string `json:"mountPoints,omitempty"`

	// TempDirectory is the temporary directory path.
	TempDirectory string `json:"tempDirectory,omitempty"`
}

// EscapeVector describes a potential escape path from a sandboxed context.
type EscapeVector struct {
	// Name is a short name for this escape vector.
	Name string `json:"name"`

	// Description describes how the escape could occur.
	Description string `json:"description,omitempty"`

	// SourceContext is the starting execution context type.
	SourceContext ExecutionEnvironmentType `json:"sourceContext"`

	// TargetContext is the escaped-to execution context type.
	TargetContext ExecutionEnvironmentType `json:"targetContext"`

	// TargetPrivilegeLevel is the privilege level after escape.
	TargetPrivilegeLevel ExecutionPrivilegeLevel `json:"targetPrivilegeLevel,omitempty"`

	// Mechanism describes the technical mechanism of escape.
	Mechanism string `json:"mechanism,omitempty"`

	// Prerequisites lists conditions required for the escape.
	Prerequisites []string `json:"prerequisites,omitempty"`

	// CWEIDs lists applicable CWE identifiers.
	CWEIDs []string `json:"cweIds,omitempty"`

	// MITRETechnique is the MITRE ATT&CK technique ID.
	MITRETechnique string `json:"mitreTechnique,omitempty"`

	// Mitigations lists controls that prevent this escape.
	Mitigations []string `json:"mitigations,omitempty"`
}

// IsSandboxed returns true if the execution context has some form of sandboxing.
func (ec *ExecutionContext) IsSandboxed() bool {
	switch ec.EnvironmentType {
	case EnvTypeContainer, EnvTypeVM, EnvTypeSandbox, EnvTypeServerless:
		return true
	case EnvTypeBrowser:
		return true // Browser is a form of sandbox
	default:
		return false
	}
}

// IsPrivileged returns true if the execution context has elevated privileges.
func (ec *ExecutionContext) IsPrivileged() bool {
	return ec.PrivilegeLevel == PrivilegeLevelRoot || ec.PrivilegeLevel == PrivilegeLevelAdmin
}

// CanEscapeToHost returns true if there's a known escape vector to host context.
func (ec *ExecutionContext) CanEscapeToHost() bool {
	for _, ev := range ec.EscapeVectors {
		if ev.TargetContext == EnvTypeHost {
			return true
		}
	}
	return false
}

// GetPrivilegeEscalationPaths returns escape vectors that result in higher privileges.
func (ec *ExecutionContext) GetPrivilegeEscalationPaths() []EscapeVector {
	var escalations []EscapeVector
	currentLevel := ec.PrivilegeLevel

	for _, ev := range ec.EscapeVectors {
		if isHigherPrivilege(currentLevel, ev.TargetPrivilegeLevel) {
			escalations = append(escalations, ev)
		}
	}
	return escalations
}

// isHigherPrivilege returns true if target is a higher privilege than current.
func isHigherPrivilege(current, target ExecutionPrivilegeLevel) bool {
	levels := map[ExecutionPrivilegeLevel]int{
		PrivilegeLevelNone:       0,
		PrivilegeLevelRestricted: 1,
		PrivilegeLevelService:    2,
		PrivilegeLevelUser:       3,
		PrivilegeLevelAdmin:      4,
		PrivilegeLevelRoot:       5,
	}
	return levels[target] > levels[current]
}
