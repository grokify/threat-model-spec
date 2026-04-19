package ir

import (
	"errors"
	"fmt"
	"strings"
)

// ValidationError represents a diagram validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

func (errs ValidationErrors) Error() string {
	if len(errs) == 0 {
		return ""
	}
	var msgs []string
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return fmt.Sprintf("%d validation error(s): %s", len(errs), strings.Join(msgs, "; "))
}

// HasErrors returns true if there are any validation errors.
func (errs ValidationErrors) HasErrors() bool {
	return len(errs) > 0
}

// Validate checks that the DiagramIR is internally consistent.
// It verifies that fields are appropriate for the diagram type and
// that required fields are present.
func (d *DiagramIR) Validate() error {
	var errs ValidationErrors

	// Check required fields
	if d.Type == "" {
		errs = append(errs, ValidationError{"type", "required"})
	}
	if d.Title == "" {
		errs = append(errs, ValidationError{"title", "required"})
	}

	// Validate based on type
	switch d.Type {
	case DiagramTypeDFD:
		errs = append(errs, d.validateDFD()...)
	case DiagramTypeAttack:
		errs = append(errs, d.validateAttackChain()...)
	case DiagramTypeSequence:
		errs = append(errs, d.validateSequence()...)
	case DiagramTypeAttackTree:
		errs = append(errs, d.validateAttackTree()...)
	default:
		if d.Type != "" {
			errs = append(errs, ValidationError{"type", fmt.Sprintf("invalid type %q, must be one of: dfd, attack-chain, sequence, attack-tree", d.Type)})
		}
	}

	// Validate cross-cutting security fields (applicable to all diagram types)
	errs = append(errs, d.validateThreats()...)
	errs = append(errs, d.validateMitigations()...)
	errs = append(errs, d.validateDetections()...)
	errs = append(errs, d.validateResponseActions()...)

	if errs.HasErrors() {
		return errs
	}
	return nil
}

// validateDFD validates a Data Flow Diagram.
func (d *DiagramIR) validateDFD() ValidationErrors {
	var errs ValidationErrors

	// DFD should have elements and flows
	if len(d.Elements) == 0 {
		errs = append(errs, ValidationError{"elements", "DFD requires at least one element"})
	}

	// DFD should NOT have attack-chain or sequence specific fields
	if len(d.Attacks) > 0 {
		errs = append(errs, ValidationError{"attacks", "DFD should not have attacks (use attack-chain type)"})
	}
	if len(d.Targets) > 0 {
		errs = append(errs, ValidationError{"targets", "DFD should not have targets (use attack-chain type)"})
	}
	if len(d.Actors) > 0 {
		errs = append(errs, ValidationError{"actors", "DFD should not have actors (use sequence type)"})
	}
	if len(d.Messages) > 0 {
		errs = append(errs, ValidationError{"messages", "DFD should not have messages (use sequence type)"})
	}
	if len(d.Phases) > 0 {
		errs = append(errs, ValidationError{"phases", "DFD should not have phases (use sequence type)"})
	}

	// Validate element references
	errs = append(errs, d.validateElementReferences()...)

	return errs
}

// validateAttackChain validates an Attack Chain diagram.
func (d *DiagramIR) validateAttackChain() ValidationErrors {
	var errs ValidationErrors

	// Attack chain should have attacks
	if len(d.Attacks) == 0 {
		errs = append(errs, ValidationError{"attacks", "attack-chain requires at least one attack step"})
	}

	// Attack chain should NOT have sequence specific fields
	if len(d.Actors) > 0 {
		errs = append(errs, ValidationError{"actors", "attack-chain should not have actors (use sequence type)"})
	}
	if len(d.Messages) > 0 {
		errs = append(errs, ValidationError{"messages", "attack-chain should not have messages (use sequence type)"})
	}
	if len(d.Phases) > 0 {
		errs = append(errs, ValidationError{"phases", "attack-chain should not have phases (use sequence type)"})
	}

	// Validate attack step numbering
	errs = append(errs, d.validateAttackSteps()...)

	// Validate element references
	errs = append(errs, d.validateElementReferences()...)

	// Validate target references
	errs = append(errs, d.validateTargetReferences()...)

	return errs
}

// validateSequence validates a Sequence diagram.
func (d *DiagramIR) validateSequence() ValidationErrors {
	var errs ValidationErrors

	// Sequence should have actors and messages
	if len(d.Actors) == 0 {
		errs = append(errs, ValidationError{"actors", "sequence requires at least one actor"})
	}
	if len(d.Messages) == 0 {
		errs = append(errs, ValidationError{"messages", "sequence requires at least one message"})
	}

	// Sequence should NOT have DFD or attack-chain specific fields
	if len(d.Elements) > 0 {
		errs = append(errs, ValidationError{"elements", "sequence should not have elements (use dfd or attack-chain type)"})
	}
	if len(d.Boundaries) > 0 {
		errs = append(errs, ValidationError{"boundaries", "sequence should not have boundaries (use dfd or attack-chain type)"})
	}
	if len(d.Flows) > 0 {
		errs = append(errs, ValidationError{"flows", "sequence should not have flows (use dfd type)"})
	}
	if len(d.Attacks) > 0 {
		errs = append(errs, ValidationError{"attacks", "sequence should not have attacks (use attack-chain type)"})
	}
	if len(d.Targets) > 0 {
		errs = append(errs, ValidationError{"targets", "sequence should not have targets (use attack-chain type)"})
	}

	// Validate message references
	errs = append(errs, d.validateMessageReferences()...)

	// Validate message sequencing
	errs = append(errs, d.validateMessageSequencing()...)

	// Validate phase ranges
	errs = append(errs, d.validatePhaseRanges()...)

	return errs
}

// validateElementReferences checks that element parentIds reference valid boundaries.
func (d *DiagramIR) validateElementReferences() ValidationErrors {
	var errs ValidationErrors

	// Build boundary ID set
	boundaryIDs := make(map[string]bool)
	for _, b := range d.Boundaries {
		if b.ID == "" {
			errs = append(errs, ValidationError{"boundaries", "boundary missing required id"})
			continue
		}
		if boundaryIDs[b.ID] {
			errs = append(errs, ValidationError{"boundaries", fmt.Sprintf("duplicate boundary id %q", b.ID)})
		}
		boundaryIDs[b.ID] = true
	}

	// Build element ID set and check parent references
	elementIDs := make(map[string]bool)
	for _, e := range d.Elements {
		if e.ID == "" {
			errs = append(errs, ValidationError{"elements", "element missing required id"})
			continue
		}
		if elementIDs[e.ID] {
			errs = append(errs, ValidationError{"elements", fmt.Sprintf("duplicate element id %q", e.ID)})
		}
		elementIDs[e.ID] = true

		if e.ParentID != "" && !boundaryIDs[e.ParentID] {
			errs = append(errs, ValidationError{"elements", fmt.Sprintf("element %q references unknown boundary %q", e.ID, e.ParentID)})
		}
	}

	// Check flow references
	for i, f := range d.Flows {
		if f.From == "" {
			errs = append(errs, ValidationError{"flows", fmt.Sprintf("flow[%d] missing required from", i)})
		} else if !elementIDs[f.From] && !boundaryIDs[f.From] {
			errs = append(errs, ValidationError{"flows", fmt.Sprintf("flow[%d] from %q references unknown element", i, f.From)})
		}
		if f.To == "" {
			errs = append(errs, ValidationError{"flows", fmt.Sprintf("flow[%d] missing required to", i)})
		} else if !elementIDs[f.To] && !boundaryIDs[f.To] {
			errs = append(errs, ValidationError{"flows", fmt.Sprintf("flow[%d] to %q references unknown element", i, f.To)})
		}
	}

	return errs
}

// validateAttackSteps checks attack step numbering and references.
func (d *DiagramIR) validateAttackSteps() ValidationErrors {
	var errs ValidationErrors

	// Build element ID set (includes boundaries as valid targets)
	validIDs := make(map[string]bool)
	for _, b := range d.Boundaries {
		validIDs[b.ID] = true
	}
	for _, e := range d.Elements {
		validIDs[e.ID] = true
	}

	// Check attack steps
	seenSteps := make(map[int]bool)
	for i, a := range d.Attacks {
		if a.Step <= 0 {
			errs = append(errs, ValidationError{"attacks", fmt.Sprintf("attack[%d] has invalid step %d (must be > 0)", i, a.Step)})
		} else if seenSteps[a.Step] {
			errs = append(errs, ValidationError{"attacks", fmt.Sprintf("attack[%d] has duplicate step %d", i, a.Step)})
		}
		seenSteps[a.Step] = true

		if a.From == "" {
			errs = append(errs, ValidationError{"attacks", fmt.Sprintf("attack[%d] missing required from", i)})
		} else if !validIDs[a.From] {
			errs = append(errs, ValidationError{"attacks", fmt.Sprintf("attack[%d] from %q references unknown element", i, a.From)})
		}
		if a.To == "" {
			errs = append(errs, ValidationError{"attacks", fmt.Sprintf("attack[%d] missing required to", i)})
		} else if !validIDs[a.To] {
			errs = append(errs, ValidationError{"attacks", fmt.Sprintf("attack[%d] to %q references unknown element", i, a.To)})
		}
		if a.Label == "" {
			errs = append(errs, ValidationError{"attacks", fmt.Sprintf("attack[%d] missing required label", i)})
		}
	}

	return errs
}

// validateTargetReferences checks that targets reference valid elements.
func (d *DiagramIR) validateTargetReferences() ValidationErrors {
	var errs ValidationErrors

	elementIDs := make(map[string]bool)
	for _, e := range d.Elements {
		elementIDs[e.ID] = true
	}

	for i, t := range d.Targets {
		if t.ElementID == "" {
			errs = append(errs, ValidationError{"targets", fmt.Sprintf("target[%d] missing required elementId", i)})
		} else if !elementIDs[t.ElementID] {
			errs = append(errs, ValidationError{"targets", fmt.Sprintf("target[%d] references unknown element %q", i, t.ElementID)})
		}
		if t.Classification == "" {
			errs = append(errs, ValidationError{"targets", fmt.Sprintf("target[%d] missing required classification", i)})
		}
	}

	return errs
}

// validateMessageReferences checks that messages reference valid actors.
func (d *DiagramIR) validateMessageReferences() ValidationErrors {
	var errs ValidationErrors

	actorIDs := make(map[string]bool)
	for _, a := range d.Actors {
		if a.ID == "" {
			errs = append(errs, ValidationError{"actors", "actor missing required id"})
			continue
		}
		if actorIDs[a.ID] {
			errs = append(errs, ValidationError{"actors", fmt.Sprintf("duplicate actor id %q", a.ID)})
		}
		actorIDs[a.ID] = true
	}

	for i, m := range d.Messages {
		if m.From == "" {
			errs = append(errs, ValidationError{"messages", fmt.Sprintf("message[%d] missing required from", i)})
		} else if !actorIDs[m.From] {
			errs = append(errs, ValidationError{"messages", fmt.Sprintf("message[%d] from %q references unknown actor", i, m.From)})
		}
		if m.To == "" {
			errs = append(errs, ValidationError{"messages", fmt.Sprintf("message[%d] missing required to", i)})
		} else if !actorIDs[m.To] {
			errs = append(errs, ValidationError{"messages", fmt.Sprintf("message[%d] to %q references unknown actor", i, m.To)})
		}
	}

	return errs
}

// validateMessageSequencing checks that message sequence numbers are valid.
func (d *DiagramIR) validateMessageSequencing() ValidationErrors {
	var errs ValidationErrors

	seenSeqs := make(map[int]bool)
	for i, m := range d.Messages {
		if m.Seq <= 0 {
			errs = append(errs, ValidationError{"messages", fmt.Sprintf("message[%d] has invalid seq %d (must be > 0)", i, m.Seq)})
		} else if seenSeqs[m.Seq] {
			errs = append(errs, ValidationError{"messages", fmt.Sprintf("message[%d] has duplicate seq %d", i, m.Seq)})
		}
		seenSeqs[m.Seq] = true
	}

	return errs
}

// validatePhaseRanges checks that phase message ranges are valid.
func (d *DiagramIR) validatePhaseRanges() ValidationErrors {
	var errs ValidationErrors

	if len(d.Phases) == 0 {
		return errs // Phases are optional
	}

	// Find min and max message seq
	minSeq, maxSeq := 0, 0
	for _, m := range d.Messages {
		if minSeq == 0 || m.Seq < minSeq {
			minSeq = m.Seq
		}
		if m.Seq > maxSeq {
			maxSeq = m.Seq
		}
	}

	for i, p := range d.Phases {
		if p.Name == "" {
			errs = append(errs, ValidationError{"phases", fmt.Sprintf("phase[%d] missing required name", i)})
		}
		if p.StartMessage <= 0 {
			errs = append(errs, ValidationError{"phases", fmt.Sprintf("phase[%d] %q has invalid startMessage %d", i, p.Name, p.StartMessage)})
		}
		if p.EndMessage <= 0 {
			errs = append(errs, ValidationError{"phases", fmt.Sprintf("phase[%d] %q has invalid endMessage %d", i, p.Name, p.EndMessage)})
		}
		if p.StartMessage > p.EndMessage {
			errs = append(errs, ValidationError{"phases", fmt.Sprintf("phase[%d] %q has startMessage > endMessage", i, p.Name)})
		}
		if p.StartMessage < minSeq || p.EndMessage > maxSeq {
			errs = append(errs, ValidationError{"phases", fmt.Sprintf("phase[%d] %q message range [%d-%d] outside message seq range [%d-%d]", i, p.Name, p.StartMessage, p.EndMessage, minSeq, maxSeq)})
		}
	}

	return errs
}

// ValidateStrict performs additional strict validation checks.
// This includes checks that may be warnings rather than errors.
func (d *DiagramIR) ValidateStrict() error {
	// First run normal validation
	if err := d.Validate(); err != nil {
		return err
	}

	var errs ValidationErrors

	// Strict: Direction should be set
	if d.Direction == "" {
		errs = append(errs, ValidationError{"direction", "recommended: set direction for consistent layout"})
	}

	// Strict: Check for orphaned elements (not in any boundary and not referenced)
	if d.Type == DiagramTypeDFD || d.Type == DiagramTypeAttack {
		errs = append(errs, d.checkOrphanedElements()...)
	}

	// Strict: Check attack chain has MITRE mappings
	if d.Type == DiagramTypeAttack {
		for i, a := range d.Attacks {
			if a.MITRETactic == "" {
				errs = append(errs, ValidationError{"attacks", fmt.Sprintf("attack[%d] recommended: set mitreTactic", i)})
			}
		}
	}

	// Strict: Check mitigations have owners
	for i, m := range d.Mitigations {
		if m.Owner == "" {
			errs = append(errs, ValidationError{"mitigations", fmt.Sprintf("mitigation[%d] %q recommended: set owner", i, m.ID)})
		}
	}

	// Strict: Check threats have severity
	for i, t := range d.Threats {
		if t.Severity == "" {
			errs = append(errs, ValidationError{"threats", fmt.Sprintf("threat[%d] %q recommended: set severity", i, t.ID)})
		}
	}

	// Strict: Check detections have data sources
	for i, det := range d.Detections {
		if len(det.DataSources) == 0 {
			errs = append(errs, ValidationError{"detections", fmt.Sprintf("detection[%d] %q recommended: set dataSources", i, det.ID)})
		}
	}

	if errs.HasErrors() {
		return errs
	}
	return nil
}

// checkOrphanedElements finds elements that are not in boundaries and not referenced.
func (d *DiagramIR) checkOrphanedElements() ValidationErrors {
	var errs ValidationErrors

	// Build set of referenced element IDs
	referenced := make(map[string]bool)
	for _, f := range d.Flows {
		referenced[f.From] = true
		referenced[f.To] = true
	}
	for _, a := range d.Attacks {
		referenced[a.From] = true
		referenced[a.To] = true
	}
	for _, t := range d.Targets {
		referenced[t.ElementID] = true
	}

	// Check each element
	for _, e := range d.Elements {
		if e.ParentID == "" && !referenced[e.ID] {
			errs = append(errs, ValidationError{"elements", fmt.Sprintf("element %q is orphaned (no parent boundary and not referenced in flows)", e.ID)})
		}
	}

	return errs
}

// MustValidate panics if validation fails.
func (d *DiagramIR) MustValidate() {
	if err := d.Validate(); err != nil {
		panic(err)
	}
}

// IsValid returns true if the diagram passes validation.
func (d *DiagramIR) IsValid() bool {
	return d.Validate() == nil
}

// validateAttackTree validates an Attack Tree diagram.
func (d *DiagramIR) validateAttackTree() ValidationErrors {
	var errs ValidationErrors

	// Attack tree should have an AttackTree structure
	if d.AttackTree == nil {
		errs = append(errs, ValidationError{"attackTree", "attack-tree requires an attackTree structure"})
		return errs
	}

	if len(d.AttackTree.Nodes) == 0 {
		errs = append(errs, ValidationError{"attackTree.nodes", "attack-tree requires at least one node"})
		return errs
	}

	if d.AttackTree.RootID == "" {
		errs = append(errs, ValidationError{"attackTree.rootId", "attack-tree requires a rootId"})
	}

	// Build node ID set
	nodeIDs := make(map[string]bool)
	for _, n := range d.AttackTree.Nodes {
		if n.ID == "" {
			errs = append(errs, ValidationError{"attackTree.nodes", "node missing required id"})
			continue
		}
		if nodeIDs[n.ID] {
			errs = append(errs, ValidationError{"attackTree.nodes", fmt.Sprintf("duplicate node id %q", n.ID)})
		}
		nodeIDs[n.ID] = true

		if n.Label == "" {
			errs = append(errs, ValidationError{"attackTree.nodes", fmt.Sprintf("node %q missing required label", n.ID)})
		}

		// Children are validated in the second pass below
	}

	// Verify root exists
	if d.AttackTree.RootID != "" && !nodeIDs[d.AttackTree.RootID] {
		errs = append(errs, ValidationError{"attackTree.rootId", fmt.Sprintf("rootId %q references unknown node", d.AttackTree.RootID)})
	}

	// Second pass: validate all child references
	for _, n := range d.AttackTree.Nodes {
		for _, childID := range n.Children {
			if !nodeIDs[childID] {
				errs = append(errs, ValidationError{"attackTree.nodes", fmt.Sprintf("node %q references unknown child %q", n.ID, childID)})
			}
		}
	}

	// Attack tree should NOT have other diagram-specific fields
	if len(d.Actors) > 0 {
		errs = append(errs, ValidationError{"actors", "attack-tree should not have actors (use sequence type)"})
	}
	if len(d.Messages) > 0 {
		errs = append(errs, ValidationError{"messages", "attack-tree should not have messages (use sequence type)"})
	}

	return errs
}

// validateMitigations checks that mitigations have valid references.
func (d *DiagramIR) validateMitigations() ValidationErrors {
	var errs ValidationErrors

	// Build sets of valid IDs for reference checking
	elementIDs := make(map[string]bool)
	for _, e := range d.Elements {
		elementIDs[e.ID] = true
	}
	threatIDs := make(map[string]bool)
	for _, t := range d.Threats {
		threatIDs[t.ID] = true
	}

	mitigationIDs := make(map[string]bool)
	for i, m := range d.Mitigations {
		if m.ID == "" {
			errs = append(errs, ValidationError{"mitigations", fmt.Sprintf("mitigation[%d] missing required id", i)})
			continue
		}
		if mitigationIDs[m.ID] {
			errs = append(errs, ValidationError{"mitigations", fmt.Sprintf("duplicate mitigation id %q", m.ID)})
		}
		mitigationIDs[m.ID] = true

		if m.Title == "" {
			errs = append(errs, ValidationError{"mitigations", fmt.Sprintf("mitigation[%d] %q missing required title", i, m.ID)})
		}
		if m.Status == "" {
			errs = append(errs, ValidationError{"mitigations", fmt.Sprintf("mitigation[%d] %q missing required status", i, m.ID)})
		}

		// Validate threat references if threats are defined
		if len(threatIDs) > 0 {
			for _, tid := range m.ThreatIDs {
				if !threatIDs[tid] && !elementIDs[tid] {
					errs = append(errs, ValidationError{"mitigations", fmt.Sprintf("mitigation %q references unknown threat %q", m.ID, tid)})
				}
			}
		}
	}

	return errs
}

// validateThreats checks that threat entries have valid references.
func (d *DiagramIR) validateThreats() ValidationErrors {
	var errs ValidationErrors

	elementIDs := make(map[string]bool)
	for _, e := range d.Elements {
		elementIDs[e.ID] = true
	}

	mitigationIDs := make(map[string]bool)
	for _, m := range d.Mitigations {
		mitigationIDs[m.ID] = true
	}

	threatIDs := make(map[string]bool)
	for i, t := range d.Threats {
		if t.ID == "" {
			errs = append(errs, ValidationError{"threats", fmt.Sprintf("threat[%d] missing required id", i)})
			continue
		}
		if threatIDs[t.ID] {
			errs = append(errs, ValidationError{"threats", fmt.Sprintf("duplicate threat id %q", t.ID)})
		}
		threatIDs[t.ID] = true

		if t.Title == "" {
			errs = append(errs, ValidationError{"threats", fmt.Sprintf("threat[%d] %q missing required title", i, t.ID)})
		}
		if t.Status == "" {
			errs = append(errs, ValidationError{"threats", fmt.Sprintf("threat[%d] %q missing required status", i, t.ID)})
		}

		// Validate element references
		for _, eid := range t.AffectedElements {
			if !elementIDs[eid] {
				errs = append(errs, ValidationError{"threats", fmt.Sprintf("threat %q references unknown element %q", t.ID, eid)})
			}
		}

		// Validate mitigation references
		for _, mid := range t.MitigationIDs {
			if !mitigationIDs[mid] {
				errs = append(errs, ValidationError{"threats", fmt.Sprintf("threat %q references unknown mitigation %q", t.ID, mid)})
			}
		}
	}

	return errs
}

// validateDetections checks that detections have valid references.
func (d *DiagramIR) validateDetections() ValidationErrors {
	var errs ValidationErrors

	threatIDs := make(map[string]bool)
	for _, t := range d.Threats {
		threatIDs[t.ID] = true
	}

	detectionIDs := make(map[string]bool)
	for i, det := range d.Detections {
		if det.ID == "" {
			errs = append(errs, ValidationError{"detections", fmt.Sprintf("detection[%d] missing required id", i)})
			continue
		}
		if detectionIDs[det.ID] {
			errs = append(errs, ValidationError{"detections", fmt.Sprintf("duplicate detection id %q", det.ID)})
		}
		detectionIDs[det.ID] = true

		if det.Title == "" {
			errs = append(errs, ValidationError{"detections", fmt.Sprintf("detection[%d] %q missing required title", i, det.ID)})
		}
		if det.Coverage == "" {
			errs = append(errs, ValidationError{"detections", fmt.Sprintf("detection[%d] %q missing required coverage", i, det.ID)})
		}

		// Validate threat references
		for _, tid := range det.ThreatIDs {
			if !threatIDs[tid] {
				errs = append(errs, ValidationError{"detections", fmt.Sprintf("detection %q references unknown threat %q", det.ID, tid)})
			}
		}
	}

	return errs
}

// validateResponseActions checks that response actions have valid references.
func (d *DiagramIR) validateResponseActions() ValidationErrors {
	var errs ValidationErrors

	detectionIDs := make(map[string]bool)
	for _, det := range d.Detections {
		detectionIDs[det.ID] = true
	}

	responseIDs := make(map[string]bool)
	for i, r := range d.ResponseActions {
		if r.ID == "" {
			errs = append(errs, ValidationError{"responseActions", fmt.Sprintf("responseAction[%d] missing required id", i)})
			continue
		}
		if responseIDs[r.ID] {
			errs = append(errs, ValidationError{"responseActions", fmt.Sprintf("duplicate responseAction id %q", r.ID)})
		}
		responseIDs[r.ID] = true

		if r.Title == "" {
			errs = append(errs, ValidationError{"responseActions", fmt.Sprintf("responseAction[%d] %q missing required title", i, r.ID)})
		}

		// Validate detection references
		for _, did := range r.TriggerDetectionIDs {
			if !detectionIDs[did] {
				errs = append(errs, ValidationError{"responseActions", fmt.Sprintf("responseAction %q references unknown detection %q", r.ID, did)})
			}
		}
	}

	return errs
}

// Errors implements the error interface check for ValidationErrors.
func (errs ValidationErrors) Unwrap() []error {
	if len(errs) == 0 {
		return nil
	}
	result := make([]error, len(errs))
	for i, e := range errs {
		result[i] = e
	}
	return result
}

// Is implements errors.Is for ValidationErrors.
func (errs ValidationErrors) Is(target error) bool {
	var ve ValidationError
	if errors.As(target, &ve) {
		for _, e := range errs {
			if e.Field == ve.Field {
				return true
			}
		}
	}
	return false
}
