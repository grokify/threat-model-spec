package ir

import "github.com/invopop/jsonschema"

// AttackPatternType categorizes the type of attack pattern.
type AttackPatternType string

const (
	// AttackPatternCSWSH represents Cross-Site WebSocket Hijacking.
	AttackPatternCSWSH AttackPatternType = "cswsh"

	// AttackPatternTokenExfiltration represents credential/token exfiltration.
	AttackPatternTokenExfiltration AttackPatternType = "token-exfiltration"

	// AttackPatternSandboxEscape represents sandbox/container escape.
	AttackPatternSandboxEscape AttackPatternType = "sandbox-escape"

	// AttackPatternLocalPrivEsc represents local privilege escalation.
	AttackPatternLocalPrivEsc AttackPatternType = "local-priv-esc"

	// AttackPatternAgentManipulation represents AI agent manipulation.
	AttackPatternAgentManipulation AttackPatternType = "agent-manipulation"

	// AttackPatternSSRF represents Server-Side Request Forgery.
	AttackPatternSSRF AttackPatternType = "ssrf"

	// AttackPatternPromptInjection represents prompt injection attacks.
	AttackPatternPromptInjection AttackPatternType = "prompt-injection"

	// AttackPatternToolAbuse represents abuse of agent tools.
	AttackPatternToolAbuse AttackPatternType = "tool-abuse"

	// AttackPatternSessionHijacking represents session hijacking.
	AttackPatternSessionHijacking AttackPatternType = "session-hijacking"

	// AttackPatternURLParameterInjection represents URL parameter injection.
	AttackPatternURLParameterInjection AttackPatternType = "url-param-injection"
)

// JSONSchema implements jsonschema.JSONSchemaer for AttackPatternType.
func (AttackPatternType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"cswsh", "token-exfiltration", "sandbox-escape", "local-priv-esc",
			"agent-manipulation", "ssrf", "prompt-injection", "tool-abuse",
			"session-hijacking", "url-param-injection",
		},
	}
}

// AttackPattern represents a reusable attack pattern template.
// These patterns can be instantiated for specific vulnerabilities.
type AttackPattern struct {
	// ID is the unique identifier for this pattern.
	ID string `json:"id"`

	// Name is the human-readable pattern name.
	Name string `json:"name"`

	// Type categorizes the attack pattern.
	Type AttackPatternType `json:"type"`

	// Description provides an overview of the attack pattern.
	Description string `json:"description,omitempty"`

	// Prerequisites lists conditions required for this attack.
	Prerequisites []string `json:"prerequisites,omitempty"`

	// AttackSteps provides the template attack chain.
	AttackSteps []AttackPatternStep `json:"attackSteps,omitempty"`

	// VulnerablePatterns contains code patterns that are vulnerable.
	VulnerablePatterns []PatternCodeExample `json:"vulnerablePatterns,omitempty"`

	// SecurePatterns contains secure code patterns.
	SecurePatterns []PatternCodeExample `json:"securePatterns,omitempty"`

	// DetectionPatterns contains patterns for detecting this attack.
	DetectionPatterns []PatternDetection `json:"detectionPatterns,omitempty"`

	// CWEIDs lists applicable CWE identifiers.
	CWEIDs []string `json:"cweIds,omitempty"`

	// MITRETechniques lists applicable MITRE ATT&CK techniques.
	MITRETechniques []string `json:"mitreTechniques,omitempty"`

	// OWASPIds lists applicable OWASP categories.
	OWASPIds []string `json:"owaspIds,omitempty"`

	// ASIIds lists applicable OWASP Agentic Security categories.
	ASIIds []string `json:"asiIds,omitempty"`

	// References contains links to additional information.
	References []Reference `json:"references,omitempty"`
}

// AttackPatternStep represents a step in an attack pattern template.
type AttackPatternStep struct {
	// Step is the sequence number.
	Step int `json:"step"`

	// Name is a short name for this step.
	Name string `json:"name"`

	// Description describes what happens in this step.
	Description string `json:"description,omitempty"`

	// Action is the specific action taken.
	Action string `json:"action,omitempty"`

	// Outcome is the expected result.
	Outcome string `json:"outcome,omitempty"`

	// MITRETactic is the MITRE ATT&CK tactic.
	MITRETactic MITRETactic `json:"mitreTactic,omitempty"`

	// MITRETechnique is the MITRE ATT&CK technique ID.
	MITRETechnique string `json:"mitreTechnique,omitempty"`

	// CWEIDs lists applicable CWE identifiers.
	CWEIDs []string `json:"cweIds,omitempty"`
}

// PatternCodeExample contains a code example for an attack pattern.
type PatternCodeExample struct {
	// Language is the programming language.
	Language string `json:"language"`

	// Framework is the framework (if applicable).
	Framework string `json:"framework,omitempty"`

	// Description describes the code example.
	Description string `json:"description,omitempty"`

	// Code is the example code.
	Code string `json:"code"`

	// Explanation provides detailed explanation.
	Explanation string `json:"explanation,omitempty"`
}

// PatternDetection contains a detection pattern.
type PatternDetection struct {
	// Name is the detection rule name.
	Name string `json:"name"`

	// Format is the detection format (sigma, yara, etc.).
	Format DetectionFormat `json:"format,omitempty"`

	// Rule is the detection rule.
	Rule string `json:"rule,omitempty"`

	// Description describes what this detects.
	Description string `json:"description,omitempty"`

	// FalsePositives lists known false positive scenarios.
	FalsePositives []string `json:"falsePositives,omitempty"`
}

// BuiltinAttackPatterns returns the built-in attack pattern library.
func BuiltinAttackPatterns() []AttackPattern {
	return []AttackPattern{
		CSWSHPattern(),
		TokenExfiltrationPattern(),
		SandboxEscapePattern(),
		AgentToolAbusePattern(),
		URLParameterInjectionPattern(),
	}
}

// CSWSHPattern returns the Cross-Site WebSocket Hijacking attack pattern.
func CSWSHPattern() AttackPattern {
	return AttackPattern{
		ID:          "pattern-cswsh",
		Name:        "Cross-Site WebSocket Hijacking (CSWSH)",
		Type:        AttackPatternCSWSH,
		Description: "Attacker tricks victim's browser into initiating a WebSocket connection to a target server, bypassing same-origin policy because WebSocket connections don't validate Origin header by default.",
		Prerequisites: []string{
			"Target WebSocket server does not validate Origin header",
			"Victim has access to target WebSocket endpoint (e.g., localhost)",
			"Attacker can serve a malicious webpage to victim",
		},
		AttackSteps: []AttackPatternStep{
			{
				Step:           1,
				Name:           "Serve malicious page",
				Description:    "Attacker hosts or injects a malicious webpage that the victim visits",
				Action:         "Deliver HTML page containing WebSocket attack payload",
				Outcome:        "Victim's browser loads attacker's JavaScript",
				MITRETactic:    MITREInitialAccess,
				MITRETechnique: "T1189",
			},
			{
				Step:           2,
				Name:           "Initiate WebSocket connection",
				Description:    "JavaScript initiates WebSocket connection to target server from victim's browser context",
				Action:         "new WebSocket('ws://target:port')",
				Outcome:        "WebSocket connection established (Origin header not validated)",
				MITRETactic:    MITRECommandAndControl,
				MITRETechnique: "T1071",
				CWEIDs:         []string{"CWE-346", "CWE-352"},
			},
			{
				Step:        3,
				Name:        "Send authenticated commands",
				Description: "Attacker uses established connection to send commands authenticated by victim's session",
				Action:      "ws.send(JSON.stringify({cmd: 'privileged_action'}))",
				Outcome:     "Commands executed with victim's permissions",
				MITRETactic: MITREExecution,
			},
		},
		VulnerablePatterns: []PatternCodeExample{
			{
				Language:    "javascript",
				Framework:   "ws",
				Description: "WebSocket server without origin validation",
				Code: `const wss = new WebSocket.Server({ port: 8080 });
wss.on('connection', (ws, req) => {
  // VULNERABLE: No origin header validation
  ws.on('message', handleMessage);
});`,
				Explanation: "The server accepts connections from any origin, enabling CSWSH attacks",
			},
			{
				Language:    "go",
				Framework:   "gorilla/websocket",
				Description: "Gorilla WebSocket without origin check",
				Code: `var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true // VULNERABLE: Accepts all origins
    },
}`,
				Explanation: "CheckOrigin returning true for all requests disables origin validation",
			},
		},
		SecurePatterns: []PatternCodeExample{
			{
				Language:    "javascript",
				Framework:   "ws",
				Description: "WebSocket server with origin validation",
				Code: `const ALLOWED_ORIGINS = ['https://trusted.example.com'];

wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    ws.close(1008, 'Unauthorized origin');
    return;
  }
  ws.on('message', handleMessage);
});`,
				Explanation: "Only connections from explicitly allowed origins are accepted",
			},
			{
				Language:    "go",
				Framework:   "gorilla/websocket",
				Description: "Gorilla WebSocket with strict origin check",
				Code: `var allowedOrigins = []string{"https://trusted.example.com"}

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        origin := r.Header.Get("Origin")
        for _, allowed := range allowedOrigins {
            if origin == allowed {
                return true
            }
        }
        return false
    },
}`,
				Explanation: "Origin is validated against an allowlist before accepting the connection",
			},
		},
		DetectionPatterns: []PatternDetection{
			{
				Name:        "Cross-Origin WebSocket Connection",
				Format:      DetectionFormatSigma,
				Description: "Detect WebSocket connections from unexpected origins",
				Rule: `title: Cross-Origin WebSocket Connection
status: experimental
logsource:
  category: webserver
detection:
  selection:
    method: GET
    request_uri|contains: '/ws'
  filter:
    http_origin|startswith:
      - 'https://trusted'
      - 'http://localhost'
  condition: selection and not filter
level: high`,
				FalsePositives: []string{"Legitimate cross-origin integrations", "Browser extensions"},
			},
		},
		CWEIDs:          []string{"CWE-346", "CWE-352", "CWE-1385"},
		MITRETechniques: []string{"T1189", "T1071"},
		OWASPIds:        []string{"API2:2023"},
		References: []Reference{
			{Title: "OWASP Testing WebSockets", URL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets"},
			{Title: "Cross-Site WebSocket Hijacking", URL: "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking"},
		},
	}
}

// TokenExfiltrationPattern returns the token exfiltration attack pattern.
func TokenExfiltrationPattern() AttackPattern {
	return AttackPattern{
		ID:          "pattern-token-exfil",
		Name:        "Authentication Token Exfiltration",
		Type:        AttackPatternTokenExfiltration,
		Description: "Attacker extracts authentication tokens through various means (URL parameters, unencrypted channels, storage) and replays them to gain unauthorized access.",
		Prerequisites: []string{
			"Application transmits or stores tokens insecurely",
			"Attacker can intercept or access token storage",
		},
		AttackSteps: []AttackPatternStep{
			{
				Step:           1,
				Name:           "Token exposure",
				Description:    "Token is exposed through URL parameters, logs, or unencrypted transmission",
				MITRETactic:    MITRECredentialAccess,
				MITRETechnique: "T1528",
				CWEIDs:         []string{"CWE-598", "CWE-319"},
			},
			{
				Step:           2,
				Name:           "Token capture",
				Description:    "Attacker captures the exposed token",
				MITRETactic:    MITRECollection,
				MITRETechnique: "T1056",
			},
			{
				Step:           3,
				Name:           "Token replay",
				Description:    "Attacker uses captured token to authenticate as victim",
				MITRETactic:    MITREPrivilegeEsc,
				MITRETechnique: "T1134",
			},
		},
		CWEIDs:          []string{"CWE-598", "CWE-319", "CWE-522", "CWE-287"},
		MITRETechniques: []string{"T1528", "T1056", "T1134"},
		OWASPIds:        []string{"API2:2023", "A07:2021"},
	}
}

// SandboxEscapePattern returns the sandbox escape attack pattern.
func SandboxEscapePattern() AttackPattern {
	return AttackPattern{
		ID:          "pattern-sandbox-escape",
		Name:        "Sandbox/Container Escape",
		Type:        AttackPatternSandboxEscape,
		Description: "Attacker escapes from a sandboxed or containerized environment to gain access to the host system or other containers.",
		Prerequisites: []string{
			"Attacker has code execution within sandbox/container",
			"Sandbox has exploitable misconfigurations or vulnerabilities",
		},
		AttackSteps: []AttackPatternStep{
			{
				Step:           1,
				Name:           "Identify escape vector",
				Description:    "Attacker identifies misconfiguration or vulnerability enabling escape",
				MITRETactic:    MITREDiscovery,
				MITRETechnique: "T1613",
			},
			{
				Step:           2,
				Name:           "Exploit escape vector",
				Description:    "Attacker exploits the identified vulnerability to escape",
				MITRETactic:    MITREPrivilegeEsc,
				MITRETechnique: "T1611",
			},
			{
				Step:           3,
				Name:           "Access host resources",
				Description:    "Attacker accesses host filesystem, network, or other resources",
				MITRETactic:    MITREExecution,
				MITRETechnique: "T1059",
			},
		},
		CWEIDs:          []string{"CWE-693", "CWE-269"},
		MITRETechniques: []string{"T1611", "T1613"},
		OWASPIds:        []string{"A05:2021"},
	}
}

// AgentToolAbusePattern returns the agent tool abuse attack pattern.
func AgentToolAbusePattern() AttackPattern {
	return AttackPattern{
		ID:          "pattern-agent-tool-abuse",
		Name:        "AI Agent Tool Abuse",
		Type:        AttackPatternToolAbuse,
		Description: "Attacker manipulates an AI agent into misusing its available tools to perform unauthorized actions, bypass security controls, or access restricted resources.",
		Prerequisites: []string{
			"AI agent has access to powerful tools (code execution, file access, etc.)",
			"Attacker can influence agent input or instructions",
			"Tool usage lacks proper authorization controls",
		},
		AttackSteps: []AttackPatternStep{
			{
				Step:        1,
				Name:        "Bypass approval mechanism",
				Description: "Attacker disables or bypasses user approval requirements",
				Action:      "Modify agent configuration to disable approval prompts",
				MITRETactic: MITREDefenseEvasion,
				CWEIDs:      []string{"CWE-284"},
			},
			{
				Step:        2,
				Name:        "Disable security controls",
				Description: "Attacker disables sandboxing or other security controls",
				Action:      "Change execution context from sandbox to host",
				MITRETactic: MITREPrivilegeEsc,
			},
			{
				Step:        3,
				Name:        "Invoke dangerous tools",
				Description: "Attacker triggers execution of privileged agent tools",
				Action:      "Invoke system.run or code execution tools",
				MITRETactic: MITREExecution,
				CWEIDs:      []string{"CWE-78"},
			},
		},
		CWEIDs:          []string{"CWE-284", "CWE-78", "CWE-269"},
		MITRETechniques: []string{"T1059", "T1548"},
		ASIIds:          []string{"ASI05:2026", "ASI02:2026"},
	}
}

// URLParameterInjectionPattern returns the URL parameter injection attack pattern.
func URLParameterInjectionPattern() AttackPattern {
	return AttackPattern{
		ID:          "pattern-url-param-injection",
		Name:        "URL Parameter Injection",
		Type:        AttackPatternURLParameterInjection,
		Description: "Attacker crafts URLs with malicious parameters that modify application behavior when clicked by a victim. Common in OAuth flows, redirect URLs, and configuration injection.",
		Prerequisites: []string{
			"Application processes URL parameters without validation",
			"Parameters influence security-sensitive behavior",
			"Victim clicks attacker-crafted URL",
		},
		AttackSteps: []AttackPatternStep{
			{
				Step:           1,
				Name:           "Craft malicious URL",
				Description:    "Attacker creates URL with malicious parameter values",
				Action:         "Create URL like: https://app.com?redirect=https://evil.com or ?config=evil-value",
				MITRETactic:    MITREInitialAccess,
				MITRETechnique: "T1566.002",
			},
			{
				Step:        2,
				Name:        "Deliver to victim",
				Description: "Attacker delivers crafted URL to victim via phishing, social media, etc.",
				MITRETactic: MITREInitialAccess,
			},
			{
				Step:        3,
				Name:        "Victim triggers action",
				Description: "Victim clicks link, application processes malicious parameters",
				Outcome:     "Application behavior modified according to attacker's parameters",
				CWEIDs:      []string{"CWE-601", "CWE-20"},
			},
		},
		CWEIDs:          []string{"CWE-601", "CWE-20", "CWE-668"},
		MITRETechniques: []string{"T1566.002"},
		OWASPIds:        []string{"A01:2021", "A03:2021"},
	}
}

// GetAttackPattern returns a built-in attack pattern by ID.
func GetAttackPattern(id string) *AttackPattern {
	patterns := BuiltinAttackPatterns()
	for i := range patterns {
		if patterns[i].ID == id {
			return &patterns[i]
		}
	}
	return nil
}

// GetAttackPatternByType returns all patterns of a given type.
func GetAttackPatternsByType(patternType AttackPatternType) []AttackPattern {
	var matches []AttackPattern
	patterns := BuiltinAttackPatterns()
	for _, p := range patterns {
		if p.Type == patternType {
			matches = append(matches, p)
		}
	}
	return matches
}
