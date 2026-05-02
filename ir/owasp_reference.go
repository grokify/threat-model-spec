package ir

// OWASPEntry contains reference data for an OWASP Top 10 entry.
type OWASPEntry struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Category    OWASPCategory `json:"category"`
	URL         string        `json:"url"`
}

// OWASP API Security Top 10 (2023)
// https://owasp.org/API-Security/editions/2023/en/0x11-t10/
var OWASPAPITop10 = map[string]OWASPEntry{
	"API1:2023": {
		ID:          "API1:2023",
		Name:        "Broken Object Level Authorization",
		Description: "APIs expose endpoints that handle object identifiers, creating a wide attack surface for object level access control issues.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
	},
	"API2:2023": {
		ID:          "API2:2023",
		Name:        "Broken Authentication",
		Description: "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
	},
	"API3:2023": {
		ID:          "API3:2023",
		Name:        "Broken Object Property Level Authorization",
		Description: "APIs expose endpoints that return or accept data objects with properties that require different levels of authorization.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
	},
	"API4:2023": {
		ID:          "API4:2023",
		Name:        "Unrestricted Resource Consumption",
		Description: "APIs do not restrict the size or number of resources that can be requested by the client/user.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
	},
	"API5:2023": {
		ID:          "API5:2023",
		Name:        "Broken Function Level Authorization",
		Description: "Complex access control policies with different hierarchies, groups, and roles lead to authorization flaws.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
	},
	"API6:2023": {
		ID:          "API6:2023",
		Name:        "Unrestricted Access to Sensitive Business Flows",
		Description: "APIs expose business flows that can be exploited when accessed without restrictions.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
	},
	"API7:2023": {
		ID:          "API7:2023",
		Name:        "Server Side Request Forgery",
		Description: "SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
	},
	"API8:2023": {
		ID:          "API8:2023",
		Name:        "Security Misconfiguration",
		Description: "APIs and supporting systems typically contain complex configurations that can be misconfigured.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
	},
	"API9:2023": {
		ID:          "API9:2023",
		Name:        "Improper Inventory Management",
		Description: "APIs expose more endpoints than traditional web applications, making proper documentation and inventory management crucial.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
	},
	"API10:2023": {
		ID:          "API10:2023",
		Name:        "Unsafe Consumption of APIs",
		Description: "Developers trust data from third-party APIs more than user input, often adopting weaker security standards.",
		Category:    OWASPCategoryAPI,
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
	},
}

// OWASP LLM Top 10 (2025)
// https://genai.owasp.org/llm-top-10/
var OWASPLLMTop10 = map[string]OWASPEntry{
	"LLM01:2025": {
		ID:          "LLM01:2025",
		Name:        "Prompt Injection",
		Description: "Manipulating LLMs via crafted inputs can lead to unauthorized access, data breaches, and compromised decision-making.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
	},
	"LLM02:2025": {
		ID:          "LLM02:2025",
		Name:        "Sensitive Information Disclosure",
		Description: "LLMs may inadvertently reveal confidential data in their responses, leading to privacy violations and security breaches.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
	},
	"LLM03:2025": {
		ID:          "LLM03:2025",
		Name:        "Supply Chain Vulnerabilities",
		Description: "Dependencies and external components in LLM systems can introduce vulnerabilities affecting integrity and security.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm03-supply-chain/",
	},
	"LLM04:2025": {
		ID:          "LLM04:2025",
		Name:        "Data and Model Poisoning",
		Description: "Corrupted training data or fine-tuning processes can impair LLM security, accuracy, and ethical behavior.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
	},
	"LLM05:2025": {
		ID:          "LLM05:2025",
		Name:        "Improper Output Handling",
		Description: "Insufficient validation of LLM outputs can lead to XSS, CSRF, SSRF, and other injection attacks in downstream systems.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
	},
	"LLM06:2025": {
		ID:          "LLM06:2025",
		Name:        "Excessive Agency",
		Description: "LLMs with excessive autonomy or capability may perform harmful actions due to unexpected or ambiguous outputs.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
	},
	"LLM07:2025": {
		ID:          "LLM07:2025",
		Name:        "System Prompt Leakage",
		Description: "System prompts or instructions may be inadvertently exposed through model outputs or side channels.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
	},
	"LLM08:2025": {
		ID:          "LLM08:2025",
		Name:        "Vector and Embedding Weaknesses",
		Description: "Vulnerabilities in vector databases and embeddings can be exploited to manipulate RAG systems.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
	},
	"LLM09:2025": {
		ID:          "LLM09:2025",
		Name:        "Misinformation",
		Description: "LLMs can generate false or misleading information, causing reputational damage and legal liability.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm09-misinformation/",
	},
	"LLM10:2025": {
		ID:          "LLM10:2025",
		Name:        "Unbounded Consumption",
		Description: "LLMs can be exploited to consume excessive resources, leading to denial of service and financial impact.",
		Category:    OWASPCategoryLLM,
		URL:         "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
	},
}

// OWASP Web Application Top 10 (2021)
// https://owasp.org/Top10/
var OWASPWebTop10 = map[string]OWASPEntry{
	"A01:2021": {
		ID:          "A01:2021",
		Name:        "Broken Access Control",
		Description: "Access control enforces policy such that users cannot act outside of their intended permissions.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
	},
	"A02:2021": {
		ID:          "A02:2021",
		Name:        "Cryptographic Failures",
		Description: "Failures related to cryptography which often lead to exposure of sensitive data.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
	},
	"A03:2021": {
		ID:          "A03:2021",
		Name:        "Injection",
		Description: "User-supplied data is not validated, filtered, or sanitized by the application.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A03_2021-Injection/",
	},
	"A04:2021": {
		ID:          "A04:2021",
		Name:        "Insecure Design",
		Description: "Missing or ineffective control design; different from implementation bugs.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A04_2021-Insecure_Design/",
	},
	"A05:2021": {
		ID:          "A05:2021",
		Name:        "Security Misconfiguration",
		Description: "Missing security hardening, improperly configured permissions, unnecessary features enabled.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
	},
	"A06:2021": {
		ID:          "A06:2021",
		Name:        "Vulnerable and Outdated Components",
		Description: "Using components with known vulnerabilities or failing to update them timely.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
	},
	"A07:2021": {
		ID:          "A07:2021",
		Name:        "Identification and Authentication Failures",
		Description: "Confirmation of the user's identity, authentication, and session management failures.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
	},
	"A08:2021": {
		ID:          "A08:2021",
		Name:        "Software and Data Integrity Failures",
		Description: "Code and infrastructure that does not protect against integrity violations.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
	},
	"A09:2021": {
		ID:          "A09:2021",
		Name:        "Security Logging and Monitoring Failures",
		Description: "Without logging and monitoring, breaches cannot be detected.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
	},
	"A10:2021": {
		ID:          "A10:2021",
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL.",
		Category:    OWASPCategoryWeb,
		URL:         "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
	},
}

// OWASP Agentic Applications Top 10 (ASI 2026)
// https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
var OWASPAgenticTop10 = map[string]OWASPEntry{
	"ASI01:2026": {
		ID:          "ASI01:2026",
		Name:        "Agentic Prompt Injection",
		Description: "Malicious instructions are injected into an agent's context through various input channels, causing unintended actions.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
	"ASI02:2026": {
		ID:          "ASI02:2026",
		Name:        "Tool Misuse & Exploitation",
		Description: "Attackers exploit an agent's access to tools (file systems, APIs, databases) to perform unauthorized actions.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
	"ASI03:2026": {
		ID:          "ASI03:2026",
		Name:        "Agent Identity & Privilege Abuse",
		Description: "Attackers assume or inherit an agent's identity and elevated privileges to perform unauthorized operations.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
	"ASI04:2026": {
		ID:          "ASI04:2026",
		Name:        "Agentic Supply Chain Compromise",
		Description: "Compromised dependencies, plugins, or integrations in the agentic system introduce vulnerabilities.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
	"ASI05:2026": {
		ID:          "ASI05:2026",
		Name:        "Unexpected Code Execution",
		Description: "Agents execute unintended code through sandbox escapes, container breakouts, or code injection.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
	"ASI06:2026": {
		ID:          "ASI06:2026",
		Name:        "Guardrail Bypass",
		Description: "Safety mechanisms and guardrails are bypassed through adversarial techniques or edge cases.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
	"ASI07:2026": {
		ID:          "ASI07:2026",
		Name:        "Agentic Memory & Context Manipulation",
		Description: "An agent's memory, context, or state is manipulated to influence future decisions.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
	"ASI08:2026": {
		ID:          "ASI08:2026",
		Name:        "Cascading Agent Failures",
		Description: "Failures in one agent propagate through interconnected agents or systems, amplifying impact.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
	"ASI09:2026": {
		ID:          "ASI09:2026",
		Name:        "Human-Agent Trust Exploitation",
		Description: "Attackers exploit the trust relationship between humans and agents to bypass security controls.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
	"ASI10:2026": {
		ID:          "ASI10:2026",
		Name:        "Inadequate Audit & Observability",
		Description: "Insufficient logging, monitoring, and auditability of agent actions prevents detection and response.",
		Category:    OWASPCategoryAgentic,
		URL:         "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
	},
}

// GetOWASPEntry returns the reference data for an OWASP ID, or nil if not found.
func GetOWASPEntry(id string) *OWASPEntry {
	if e, ok := OWASPAPITop10[id]; ok {
		return &e
	}
	if e, ok := OWASPLLMTop10[id]; ok {
		return &e
	}
	if e, ok := OWASPWebTop10[id]; ok {
		return &e
	}
	if e, ok := OWASPAgenticTop10[id]; ok {
		return &e
	}
	return nil
}

// ValidateOWASPID checks if an OWASP ID is recognized.
func ValidateOWASPID(id string) bool {
	return GetOWASPEntry(id) != nil
}

// GetOWASPCategory returns the category for an OWASP ID, or empty string if not found.
func GetOWASPCategory(id string) OWASPCategory {
	if entry := GetOWASPEntry(id); entry != nil {
		return entry.Category
	}
	return ""
}

// GetAllOWASPEntries returns all OWASP entries for a given category.
func GetAllOWASPEntries(category OWASPCategory) []OWASPEntry {
	var entries []OWASPEntry

	var source map[string]OWASPEntry
	switch category {
	case OWASPCategoryAPI:
		source = OWASPAPITop10
	case OWASPCategoryLLM:
		source = OWASPLLMTop10
	case OWASPCategoryWeb:
		source = OWASPWebTop10
	case OWASPCategoryAgentic:
		source = OWASPAgenticTop10
	default:
		return entries
	}

	for _, e := range source {
		entries = append(entries, e)
	}
	return entries
}
