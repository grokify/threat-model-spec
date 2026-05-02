// Package ir provides the intermediate representation for threat models.
package ir

import (
	"fmt"
	"strings"
	"time"
)

// STIX 2.1 types for export functionality.
// These are defined locally to avoid import cycles with the stix package.

// STIXBundle is a STIX 2.1 Bundle object containing STIX objects.
type STIXBundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []interface{} `json:"objects"`
}

// NewSTIXBundle creates a new STIX Bundle.
func NewSTIXBundle() *STIXBundle {
	return &STIXBundle{
		Type:    "bundle",
		ID:      "bundle--" + generateUUID(),
		Objects: make([]interface{}, 0),
	}
}

// AddObject adds a STIX object to the bundle.
func (b *STIXBundle) AddObject(obj interface{}) {
	if obj != nil {
		b.Objects = append(b.Objects, obj)
	}
}

// STIXIdentity represents a STIX 2.1 Identity object.
type STIXIdentity struct {
	Type          string `json:"type"`
	SpecVersion   string `json:"spec_version"`
	ID            string `json:"id"`
	Created       string `json:"created"`
	Modified      string `json:"modified"`
	Name          string `json:"name"`
	IdentityClass string `json:"identity_class"`
}

// STIXThreatActor represents a STIX 2.1 Threat Actor object.
type STIXThreatActor struct {
	Type               string                   `json:"type"`
	SpecVersion        string                   `json:"spec_version"`
	ID                 string                   `json:"id"`
	Created            string                   `json:"created"`
	Modified           string                   `json:"modified"`
	CreatedByRef       string                   `json:"created_by_ref,omitempty"`
	Name               string                   `json:"name"`
	Description        string                   `json:"description,omitempty"`
	ThreatActorTypes   []string                 `json:"threat_actor_types"`
	Aliases            []string                 `json:"aliases,omitempty"`
	Goals              []string                 `json:"goals,omitempty"`
	Sophistication     string                   `json:"sophistication,omitempty"`
	ResourceLevel      string                   `json:"resource_level,omitempty"`
	PrimaryMotivation  string                   `json:"primary_motivation,omitempty"`
	ExternalReferences []STIXExternalReference  `json:"external_references,omitempty"`
}

// STIXAttackPattern represents a STIX 2.1 Attack Pattern object.
type STIXAttackPattern struct {
	Type               string                   `json:"type"`
	SpecVersion        string                   `json:"spec_version"`
	ID                 string                   `json:"id"`
	Created            string                   `json:"created"`
	Modified           string                   `json:"modified"`
	CreatedByRef       string                   `json:"created_by_ref,omitempty"`
	Name               string                   `json:"name"`
	Description        string                   `json:"description,omitempty"`
	KillChainPhases    []STIXKillChainPhase     `json:"kill_chain_phases,omitempty"`
	ExternalReferences []STIXExternalReference  `json:"external_references,omitempty"`
}

// STIXIndicator represents a STIX 2.1 Indicator object.
type STIXIndicator struct {
	Type           string   `json:"type"`
	SpecVersion    string   `json:"spec_version"`
	ID             string   `json:"id"`
	Created        string   `json:"created"`
	Modified       string   `json:"modified"`
	CreatedByRef   string   `json:"created_by_ref,omitempty"`
	Name           string   `json:"name,omitempty"`
	Description    string   `json:"description,omitempty"`
	IndicatorTypes []string `json:"indicator_types,omitempty"`
	Pattern        string   `json:"pattern"`
	PatternType    string   `json:"pattern_type"`
	ValidFrom      string   `json:"valid_from"`
	ValidUntil     string   `json:"valid_until,omitempty"`
}

// STIXCourseOfAction represents a STIX 2.1 Course of Action object.
type STIXCourseOfAction struct {
	Type         string `json:"type"`
	SpecVersion  string `json:"spec_version"`
	ID           string `json:"id"`
	Created      string `json:"created"`
	Modified     string `json:"modified"`
	CreatedByRef string `json:"created_by_ref,omitempty"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	ActionType   string `json:"action_type,omitempty"`
}

// STIXVulnerability represents a STIX 2.1 Vulnerability object.
type STIXVulnerability struct {
	Type               string                   `json:"type"`
	SpecVersion        string                   `json:"spec_version"`
	ID                 string                   `json:"id"`
	Created            string                   `json:"created"`
	Modified           string                   `json:"modified"`
	CreatedByRef       string                   `json:"created_by_ref,omitempty"`
	Name               string                   `json:"name"`
	Description        string                   `json:"description,omitempty"`
	ExternalReferences []STIXExternalReference  `json:"external_references,omitempty"`
}

// STIXExternalReference represents an external reference in STIX objects.
type STIXExternalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id,omitempty"`
	URL        string `json:"url,omitempty"`
}

// STIXKillChainPhase represents a kill chain phase.
type STIXKillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// STIXExportOptions configures what to include in STIX bundle exports.
type STIXExportOptions struct {
	// IncludeIndicators exports IOCs as STIX Indicators
	IncludeIndicators bool `json:"includeIndicators,omitempty"`
	// IncludeAttackPatterns exports Attacks as STIX Attack Patterns
	IncludeAttackPatterns bool `json:"includeAttackPatterns,omitempty"`
	// IncludeThreatActors exports ThreatActors as STIX Threat Actors
	IncludeThreatActors bool `json:"includeThreatActors,omitempty"`
	// IncludeCourseOfAction exports DetectionRules and Mitigations as Courses of Action
	IncludeCourseOfAction bool `json:"includeCourseOfAction,omitempty"`
	// IncludeVulnerabilities exports CVE mappings as STIX Vulnerabilities
	IncludeVulnerabilities bool `json:"includeVulnerabilities,omitempty"`
	// IncludeRelationships adds relationships between STIX objects
	IncludeRelationships bool `json:"includeRelationships,omitempty"`
	// IdentityName is the organization name for created_by_ref (default: "Threat Model Spec")
	IdentityName string `json:"identityName,omitempty"`
}

// DefaultSTIXExportOptions returns options that include all exportable content.
func DefaultSTIXExportOptions() STIXExportOptions {
	return STIXExportOptions{
		IncludeIndicators:      true,
		IncludeAttackPatterns:  true,
		IncludeThreatActors:    true,
		IncludeCourseOfAction:  true,
		IncludeVulnerabilities: true,
		IncludeRelationships:   true,
		IdentityName:           "Threat Model Spec",
	}
}

// ExportSTIXBundle exports the ThreatModel to a STIX 2.1 Bundle.
func (tm *ThreatModel) ExportSTIXBundle(opts STIXExportOptions) (*STIXBundle, error) {
	bundle := NewSTIXBundle()
	now := time.Now().UTC().Format(time.RFC3339)

	// Create identity for created_by_ref
	identityName := opts.IdentityName
	if identityName == "" {
		identityName = "Threat Model Spec"
	}
	identity := &STIXIdentity{
		Type:          "identity",
		SpecVersion:   "2.1",
		ID:            fmt.Sprintf("identity--%s", generateUUID()),
		Created:       now,
		Modified:      now,
		Name:          identityName,
		IdentityClass: "organization",
	}
	bundle.AddObject(identity)
	createdByRef := identity.ID

	// Export threat actors
	if opts.IncludeThreatActors {
		for _, ta := range tm.ThreatActors {
			stixTA := ta.ToSTIXThreatActor(createdByRef)
			bundle.AddObject(stixTA)
		}
	}

	// Export from diagrams
	for _, diagram := range tm.Diagrams {
		// Export attacks as attack patterns
		if opts.IncludeAttackPatterns {
			for _, attack := range diagram.Attacks {
				ap := attack.ToSTIXAttackPattern(createdByRef)
				bundle.AddObject(ap)
			}
		}

		// Export mitigations as courses of action
		if opts.IncludeCourseOfAction {
			for _, mit := range diagram.Mitigations {
				coa := mitigationToSTIXCourseOfAction(mit, createdByRef)
				bundle.AddObject(coa)
			}
		}
	}

	// Export blue team IOCs as indicators
	if opts.IncludeIndicators && tm.BlueTeam != nil {
		for _, ioc := range tm.BlueTeam.IOCs {
			ind := ioc.ToSTIXIndicator(createdByRef)
			if ind != nil {
				bundle.AddObject(ind)
			}
		}

		// Export detection rules as courses of action
		if opts.IncludeCourseOfAction {
			for _, rule := range tm.BlueTeam.DetectionRules {
				coa := rule.ToSTIXCourseOfAction(createdByRef)
				bundle.AddObject(coa)
			}
		}
	}

	// Export CVE mappings as vulnerabilities
	if opts.IncludeVulnerabilities && tm.Mappings != nil {
		for _, cve := range tm.Mappings.CVE {
			vuln := cveToSTIXVulnerability(cve, createdByRef)
			bundle.AddObject(vuln)
		}
	}

	return bundle, nil
}

// ToSTIXIndicator converts an IOC to a STIX 2.1 Indicator object.
func (ioc *IOC) ToSTIXIndicator(createdByRef string) *STIXIndicator {
	now := time.Now().UTC().Format(time.RFC3339)

	pattern := ioc.toSTIXPattern()
	if pattern == "" {
		return nil
	}

	indicator := &STIXIndicator{
		Type:           "indicator",
		SpecVersion:    "2.1",
		ID:             fmt.Sprintf("indicator--%s", generateUUID()),
		Created:        now,
		Modified:       now,
		CreatedByRef:   createdByRef,
		Name:           fmt.Sprintf("IOC: %s", ioc.Value),
		Description:    ioc.Description,
		IndicatorTypes: []string{ioc.indicatorType()},
		Pattern:        pattern,
		PatternType:    "stix",
		ValidFrom:      now,
	}

	if ioc.ValidUntil != "" {
		indicator.ValidUntil = ioc.ValidUntil
	}

	return indicator
}

// toSTIXPattern converts the IOC to a STIX pattern string.
func (ioc *IOC) toSTIXPattern() string {
	switch ioc.Type {
	case IOCTypeIP:
		return fmt.Sprintf("[ipv4-addr:value = '%s']", ioc.Value)
	case IOCTypeDomain:
		return fmt.Sprintf("[domain-name:value = '%s']", ioc.Value)
	case IOCTypeURL:
		return fmt.Sprintf("[url:value = '%s']", ioc.Value)
	case IOCTypeHash:
		// Assume SHA256 by default, could be enhanced to detect hash type
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", ioc.Value)
	case IOCTypeFilepath:
		return fmt.Sprintf("[file:name = '%s']", ioc.Value)
	case IOCTypeEmail:
		return fmt.Sprintf("[email-addr:value = '%s']", ioc.Value)
	case IOCTypeRegistry:
		return fmt.Sprintf("[windows-registry-key:key = '%s']", ioc.Value)
	case IOCTypeProcess:
		return fmt.Sprintf("[process:name = '%s']", ioc.Value)
	case IOCTypeCert:
		return fmt.Sprintf("[x509-certificate:serial_number = '%s']", ioc.Value)
	case IOCTypePattern:
		// For patterns, use the value directly if it's already a STIX pattern
		if strings.HasPrefix(ioc.Value, "[") {
			return ioc.Value
		}
		return fmt.Sprintf("[file:name MATCHES '%s']", ioc.Value)
	default:
		return ""
	}
}

// indicatorType returns the STIX indicator type for this IOC.
func (ioc *IOC) indicatorType() string {
	switch ioc.Type {
	case IOCTypeIP, IOCTypeDomain, IOCTypeURL:
		return "malicious-activity"
	case IOCTypeHash, IOCTypeFilepath:
		return "anomalous-activity"
	case IOCTypeEmail:
		return "attribution"
	default:
		return "unknown"
	}
}

// ToSTIXThreatActor converts an ir.ThreatActor to a STIX 2.1 Threat Actor object.
func (ta *ThreatActor) ToSTIXThreatActor(createdByRef string) *STIXThreatActor {
	now := time.Now().UTC().Format(time.RFC3339)

	// Get primary motivation if available
	var primaryMotivation string
	if len(ta.Motivations) > 0 {
		primaryMotivation = string(ta.Motivations[0])
	}

	stixTA := &STIXThreatActor{
		Type:              "threat-actor",
		SpecVersion:       "2.1",
		ID:                fmt.Sprintf("threat-actor--%s", generateUUID()),
		Created:           now,
		Modified:          now,
		CreatedByRef:      createdByRef,
		Name:              ta.Name,
		Description:       ta.Description,
		ThreatActorTypes:  []string{string(ta.Type)},
		Aliases:           ta.Aliases,
		Goals:             ta.PrimaryGoals,
		Sophistication:    string(ta.Sophistication),
		ResourceLevel:     string(ta.Resources),
		PrimaryMotivation: primaryMotivation,
	}

	// Add external references for TTPs
	for _, technique := range ta.TTPs {
		stixTA.ExternalReferences = append(stixTA.ExternalReferences, STIXExternalReference{
			SourceName: "mitre-attack",
			ExternalID: technique,
			URL:        fmt.Sprintf("https://attack.mitre.org/techniques/%s", technique),
		})
	}

	return stixTA
}

// ToSTIXAttackPattern converts an Attack to a STIX 2.1 Attack Pattern object.
func (a *Attack) ToSTIXAttackPattern(createdByRef string) *STIXAttackPattern {
	now := time.Now().UTC().Format(time.RFC3339)

	ap := &STIXAttackPattern{
		Type:         "attack-pattern",
		SpecVersion:  "2.1",
		ID:           fmt.Sprintf("attack-pattern--%s", generateUUID()),
		Created:      now,
		Modified:     now,
		CreatedByRef: createdByRef,
		Name:         a.Label,
		Description:  a.Description,
	}

	// Add kill chain phases from MITRE tactic
	if a.MITRETactic != "" {
		ap.KillChainPhases = []STIXKillChainPhase{
			{
				KillChainName: "mitre-attack",
				PhaseName:     string(a.MITRETactic),
			},
		}
	}

	// Add external reference for MITRE technique
	if a.MITRETechnique != "" {
		ap.ExternalReferences = append(ap.ExternalReferences, STIXExternalReference{
			SourceName: "mitre-attack",
			ExternalID: a.MITRETechnique,
			URL:        fmt.Sprintf("https://attack.mitre.org/techniques/%s", strings.ReplaceAll(a.MITRETechnique, ".", "/")),
		})
	}

	// Add external reference for ATLAS technique
	if a.ATLASTechnique != "" {
		ap.ExternalReferences = append(ap.ExternalReferences, STIXExternalReference{
			SourceName: "mitre-atlas",
			ExternalID: a.ATLASTechnique,
			URL:        fmt.Sprintf("https://atlas.mitre.org/techniques/%s", a.ATLASTechnique),
		})
	}

	return ap
}

// ToSTIXCourseOfAction converts a DetectionRule to a STIX 2.1 Course of Action object.
func (dr *DetectionRule) ToSTIXCourseOfAction(createdByRef string) *STIXCourseOfAction {
	now := time.Now().UTC().Format(time.RFC3339)

	coa := &STIXCourseOfAction{
		Type:         "course-of-action",
		SpecVersion:  "2.1",
		ID:           fmt.Sprintf("course-of-action--%s", generateUUID()),
		Created:      now,
		Modified:     now,
		CreatedByRef: createdByRef,
		Name:         dr.Name,
		Description:  fmt.Sprintf("Detection rule in %s format:\n\n%s", dr.Format, dr.Rule),
		ActionType:   "detection",
	}

	return coa
}

// mitigationToSTIXCourseOfAction converts a Mitigation to a STIX Course of Action.
func mitigationToSTIXCourseOfAction(m Mitigation, createdByRef string) *STIXCourseOfAction {
	now := time.Now().UTC().Format(time.RFC3339)

	coa := &STIXCourseOfAction{
		Type:         "course-of-action",
		SpecVersion:  "2.1",
		ID:           fmt.Sprintf("course-of-action--%s", generateUUID()),
		Created:      now,
		Modified:     now,
		CreatedByRef: createdByRef,
		Name:         m.Title,
		Description:  m.Description,
		ActionType:   "mitigation",
	}

	return coa
}

// cveToSTIXVulnerability converts a CVEMapping to a STIX Vulnerability.
func cveToSTIXVulnerability(cve CVEMapping, createdByRef string) *STIXVulnerability {
	now := time.Now().UTC().Format(time.RFC3339)

	vuln := &STIXVulnerability{
		Type:         "vulnerability",
		SpecVersion:  "2.1",
		ID:           fmt.Sprintf("vulnerability--%s", generateUUID()),
		Created:      now,
		Modified:     now,
		CreatedByRef: createdByRef,
		Name:         cve.ID,
		Description:  cve.Description,
		ExternalReferences: []STIXExternalReference{
			{
				SourceName: "cve",
				ExternalID: cve.ID,
				URL:        fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID),
			},
		},
	}

	return vuln
}

// generateUUID generates a simple UUID-like string.
// In production, use a proper UUID library.
func generateUUID() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		time.Now().UnixNano()&0xFFFFFFFF,
		time.Now().UnixNano()>>32&0xFFFF,
		time.Now().UnixNano()>>48&0x0FFF|0x4000,
		time.Now().UnixNano()>>60&0x3F|0x80,
		time.Now().UnixNano()&0xFFFFFFFFFFFF)
}
