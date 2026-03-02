// Package stix provides STIX 2.1 export capabilities for threat models.
// It converts the intermediate representation (IR) to STIX 2.1 bundles
// for sharing threat intelligence with other security tools.
package stix

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/grokify/threat-model-spec/ir"
)

// Exporter converts threat model diagrams to STIX 2.1 bundles.
type Exporter struct {
	// IdentityName is the name used for the identity object (default: "Threat Model Spec").
	IdentityName string

	// IdentityClass is the identity class (default: "organization").
	IdentityClass string

	// CreatedByRef is the STIX ID of the identity that created these objects.
	CreatedByRef string
}

// NewExporter creates a new STIX exporter with default settings.
func NewExporter() *Exporter {
	return &Exporter{
		IdentityName:  "Threat Model Spec",
		IdentityClass: "organization",
	}
}

// Export converts a DiagramIR to a STIX 2.1 Bundle.
func (e *Exporter) Export(d *ir.DiagramIR) (*Bundle, error) {
	bundle := NewBundle()

	// Create identity for created_by_ref
	identity := e.createIdentity()
	bundle.AddObject(identity)
	e.CreatedByRef = identity.ID

	// Export based on diagram type
	switch d.Type {
	case ir.DiagramTypeDFD:
		e.exportDFD(bundle, d)
	case ir.DiagramTypeAttack:
		e.exportAttackChain(bundle, d)
	case ir.DiagramTypeSequence:
		e.exportSequence(bundle, d)
	}

	// Export framework mappings
	if d.Mappings != nil {
		e.exportMappings(bundle, d.Mappings)
	}

	return bundle, nil
}

// ExportJSON converts a DiagramIR to a STIX 2.1 JSON string.
func (e *Exporter) ExportJSON(d *ir.DiagramIR) (string, error) {
	bundle, err := e.Export(d)
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (e *Exporter) createIdentity() *Identity {
	return &Identity{
		Type:          "identity",
		SpecVersion:   "2.1",
		ID:            fmt.Sprintf("identity--%s", generateUUID()),
		Created:       time.Now().UTC().Format(time.RFC3339),
		Modified:      time.Now().UTC().Format(time.RFC3339),
		Name:          e.IdentityName,
		IdentityClass: e.IdentityClass,
	}
}

func (e *Exporter) exportDFD(bundle *Bundle, d *ir.DiagramIR) {
	// Create infrastructure objects for elements
	for _, elem := range d.Elements {
		infra := e.elementToInfrastructure(elem)
		bundle.AddObject(infra)
	}

	// Create relationships for flows
	for _, flow := range d.Flows {
		rel := e.flowToRelationship(flow, d)
		if rel != nil {
			bundle.AddObject(rel)
		}
	}
}

func (e *Exporter) exportAttackChain(bundle *Bundle, d *ir.DiagramIR) {
	// Create threat actor for malicious elements
	for _, elem := range d.Elements {
		if elem.Type == ir.ElementTypeExternalEntity {
			actor := e.elementToThreatActor(elem)
			bundle.AddObject(actor)
		} else {
			infra := e.elementToInfrastructure(elem)
			bundle.AddObject(infra)
		}
	}

	// Create attack patterns for attacks
	for _, attack := range d.Attacks {
		ap := e.attackToAttackPattern(attack)
		bundle.AddObject(ap)

		// Create relationships
		rel := e.attackToRelationship(attack, d)
		if rel != nil {
			bundle.AddObject(rel)
		}
	}

	// Create indicators for targets
	for _, target := range d.Targets {
		ind := e.targetToIndicator(target, d)
		bundle.AddObject(ind)
	}
}

func (e *Exporter) exportSequence(bundle *Bundle, d *ir.DiagramIR) {
	// Create identities/threat actors for actors
	for _, actor := range d.Actors {
		if actor.Malicious {
			ta := e.actorToThreatActor(actor)
			bundle.AddObject(ta)
		}
	}

	// Create attack patterns for malicious messages
	for _, msg := range d.Messages {
		if msg.Type == ir.FlowTypeAttack || msg.Type == ir.FlowTypeExfil {
			ap := e.messageToAttackPattern(msg)
			bundle.AddObject(ap)
		}
	}
}

func (e *Exporter) exportMappings(bundle *Bundle, m *ir.Mappings) {
	// Export MITRE ATT&CK mappings as external references
	for _, attack := range m.MITREAttack {
		ap := e.mitreAttackToAttackPattern(attack)
		bundle.AddObject(ap)
	}

	// Export MITRE ATLAS mappings
	for _, atlas := range m.MITREATLAS {
		ap := e.mitreAtlasToAttackPattern(atlas)
		bundle.AddObject(ap)
	}

	// Export CWE mappings as vulnerabilities
	for _, cwe := range m.CWE {
		vuln := e.cweToVulnerability(cwe)
		bundle.AddObject(vuln)
	}
}

func (e *Exporter) elementToInfrastructure(elem ir.Element) *Infrastructure {
	infraType := "unknown"
	switch elem.Type {
	case ir.ElementTypeProcess:
		infraType = "workstation"
	case ir.ElementTypeDatastore:
		infraType = "data-store"
	case ir.ElementTypeExternalEntity:
		infraType = "external-service"
	case ir.ElementTypeBrowser:
		infraType = "workstation"
	case ir.ElementTypeAgent:
		infraType = "workstation"
	case ir.ElementTypeGateway:
		infraType = "gateway"
	case ir.ElementTypeAPI:
		infraType = "data-store"
	}

	return &Infrastructure{
		Type:         "infrastructure",
		SpecVersion:  "2.1",
		ID:           fmt.Sprintf("infrastructure--%s", generateUUID()),
		Created:      time.Now().UTC().Format(time.RFC3339),
		Modified:     time.Now().UTC().Format(time.RFC3339),
		CreatedByRef: e.CreatedByRef,
		Name:         elem.Label,
		Description:  elem.Description,
		InfraType:    infraType,
	}
}

func (e *Exporter) elementToThreatActor(elem ir.Element) *ThreatActor {
	return &ThreatActor{
		Type:             "threat-actor",
		SpecVersion:      "2.1",
		ID:               fmt.Sprintf("threat-actor--%s", generateUUID()),
		Created:          time.Now().UTC().Format(time.RFC3339),
		Modified:         time.Now().UTC().Format(time.RFC3339),
		CreatedByRef:     e.CreatedByRef,
		Name:             elem.Label,
		Description:      elem.Description,
		ThreatActorTypes: []string{"unknown"},
	}
}

func (e *Exporter) actorToThreatActor(actor ir.Actor) *ThreatActor {
	return &ThreatActor{
		Type:             "threat-actor",
		SpecVersion:      "2.1",
		ID:               fmt.Sprintf("threat-actor--%s", generateUUID()),
		Created:          time.Now().UTC().Format(time.RFC3339),
		Modified:         time.Now().UTC().Format(time.RFC3339),
		CreatedByRef:     e.CreatedByRef,
		Name:             actor.Label,
		ThreatActorTypes: []string{"unknown"},
	}
}

func (e *Exporter) attackToAttackPattern(attack ir.Attack) *AttackPattern {
	var externalRefs []ExternalReference

	// Add MITRE ATT&CK reference if available
	if attack.MITRETechnique != "" {
		externalRefs = append(externalRefs, ExternalReference{
			SourceName: "mitre-attack",
			ExternalID: attack.MITRETechnique,
			URL:        fmt.Sprintf("https://attack.mitre.org/techniques/%s", attack.MITRETechnique),
		})
	}

	return &AttackPattern{
		Type:               "attack-pattern",
		SpecVersion:        "2.1",
		ID:                 fmt.Sprintf("attack-pattern--%s", generateUUID()),
		Created:            time.Now().UTC().Format(time.RFC3339),
		Modified:           time.Now().UTC().Format(time.RFC3339),
		CreatedByRef:       e.CreatedByRef,
		Name:               attack.Label,
		Description:        attack.Description,
		ExternalReferences: externalRefs,
	}
}

func (e *Exporter) messageToAttackPattern(msg ir.Message) *AttackPattern {
	var externalRefs []ExternalReference

	if msg.MITRETechnique != "" {
		externalRefs = append(externalRefs, ExternalReference{
			SourceName: "mitre-attack",
			ExternalID: msg.MITRETechnique,
			URL:        fmt.Sprintf("https://attack.mitre.org/techniques/%s", msg.MITRETechnique),
		})
	}

	return &AttackPattern{
		Type:               "attack-pattern",
		SpecVersion:        "2.1",
		ID:                 fmt.Sprintf("attack-pattern--%s", generateUUID()),
		Created:            time.Now().UTC().Format(time.RFC3339),
		Modified:           time.Now().UTC().Format(time.RFC3339),
		CreatedByRef:       e.CreatedByRef,
		Name:               msg.Label,
		ExternalReferences: externalRefs,
	}
}

func (e *Exporter) mitreAttackToAttackPattern(m ir.MITREAttackMapping) *AttackPattern {
	url := m.URL
	if url == "" {
		url = fmt.Sprintf("https://attack.mitre.org/techniques/%s", m.TechniqueID)
	}

	return &AttackPattern{
		Type:         "attack-pattern",
		SpecVersion:  "2.1",
		ID:           fmt.Sprintf("attack-pattern--%s", generateUUID()),
		Created:      time.Now().UTC().Format(time.RFC3339),
		Modified:     time.Now().UTC().Format(time.RFC3339),
		CreatedByRef: e.CreatedByRef,
		Name:         m.TechniqueName,
		Description:  m.Description,
		ExternalReferences: []ExternalReference{
			{
				SourceName: "mitre-attack",
				ExternalID: m.TechniqueID,
				URL:        url,
			},
		},
	}
}

func (e *Exporter) mitreAtlasToAttackPattern(m ir.MITREATLASMapping) *AttackPattern {
	url := m.URL
	if url == "" {
		url = fmt.Sprintf("https://atlas.mitre.org/techniques/%s", m.TechniqueID)
	}

	return &AttackPattern{
		Type:         "attack-pattern",
		SpecVersion:  "2.1",
		ID:           fmt.Sprintf("attack-pattern--%s", generateUUID()),
		Created:      time.Now().UTC().Format(time.RFC3339),
		Modified:     time.Now().UTC().Format(time.RFC3339),
		CreatedByRef: e.CreatedByRef,
		Name:         m.TechniqueName,
		Description:  m.Description,
		ExternalReferences: []ExternalReference{
			{
				SourceName: "mitre-atlas",
				ExternalID: m.TechniqueID,
				URL:        url,
			},
		},
	}
}

func (e *Exporter) cweToVulnerability(cwe ir.CWEMapping) *Vulnerability {
	url := cwe.URL
	if url == "" {
		// Extract numeric ID from CWE-XXX format
		cweNum := strings.TrimPrefix(cwe.ID, "CWE-")
		url = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cweNum)
	}

	return &Vulnerability{
		Type:         "vulnerability",
		SpecVersion:  "2.1",
		ID:           fmt.Sprintf("vulnerability--%s", generateUUID()),
		Created:      time.Now().UTC().Format(time.RFC3339),
		Modified:     time.Now().UTC().Format(time.RFC3339),
		CreatedByRef: e.CreatedByRef,
		Name:         cwe.Name,
		Description:  cwe.Description,
		ExternalReferences: []ExternalReference{
			{
				SourceName: "cwe",
				ExternalID: cwe.ID,
				URL:        url,
			},
		},
	}
}

func (e *Exporter) targetToIndicator(target ir.Target, d *ir.DiagramIR) *Indicator {
	// Find the element for this target
	var elemLabel string
	for _, elem := range d.Elements {
		if elem.ID == target.ElementID {
			elemLabel = elem.Label
			break
		}
	}

	return &Indicator{
		Type:         "indicator",
		SpecVersion:  "2.1",
		ID:           fmt.Sprintf("indicator--%s", generateUUID()),
		Created:      time.Now().UTC().Format(time.RFC3339),
		Modified:     time.Now().UTC().Format(time.RFC3339),
		CreatedByRef: e.CreatedByRef,
		Name:         fmt.Sprintf("Target: %s", elemLabel),
		Description:  target.Impact,
		Pattern:      fmt.Sprintf("[infrastructure:name = '%s']", elemLabel),
		PatternType:  "stix",
		ValidFrom:    time.Now().UTC().Format(time.RFC3339),
	}
}

func (e *Exporter) flowToRelationship(_ ir.Flow, _ *ir.DiagramIR) *Relationship {
	// Relationships require source_ref and target_ref to existing STIX objects
	// This would need to track object IDs during export
	return nil
}

func (e *Exporter) attackToRelationship(_ ir.Attack, _ *ir.DiagramIR) *Relationship {
	// Relationships require source_ref and target_ref to existing STIX objects
	// This would need to track object IDs during export
	return nil
}

// generateUUID generates a UUID v4 for STIX object IDs.
// In production, use crypto/rand for true randomness.
func generateUUID() string {
	// Simple UUID generation - use crypto/rand for production
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		time.Now().UnixNano()&0xffffffff,
		time.Now().UnixNano()>>32&0xffff,
		0x4000|(time.Now().UnixNano()>>48&0x0fff),
		0x8000|(time.Now().UnixNano()>>60&0x3fff),
		time.Now().UnixNano())
}
