// Package stride provides types for STRIDE threat modeling.
// STRIDE is a threat modeling framework developed by Microsoft that categorizes
// threats into six categories: Spoofing, Tampering, Repudiation, Information
// Disclosure, Denial of Service, and Elevation of Privilege.
package stride

import "fmt"

// ThreatType represents one of the six STRIDE threat categories.
type ThreatType string

const (
	// Spoofing refers to illegally accessing and using another user's
	// authentication information, such as username and password.
	Spoofing ThreatType = "S"

	// Tampering involves malicious modification of data, such as
	// unauthorized changes to persistent data or data in transit.
	Tampering ThreatType = "T"

	// Repudiation refers to users denying performing an action without
	// other parties having any way to prove otherwise.
	Repudiation ThreatType = "R"

	// InformationDisclosure involves exposing information to individuals
	// who are not supposed to have access to it.
	InformationDisclosure ThreatType = "I"

	// DenialOfService refers to attacks that deny service to valid users,
	// making a system unavailable or unusable.
	DenialOfService ThreatType = "D"

	// ElevationOfPrivilege occurs when an unprivileged user gains
	// privileged access, compromising the entire system.
	ElevationOfPrivilege ThreatType = "E"
)

// String returns the full name of the threat type.
func (t ThreatType) String() string {
	switch t {
	case Spoofing:
		return "Spoofing"
	case Tampering:
		return "Tampering"
	case Repudiation:
		return "Repudiation"
	case InformationDisclosure:
		return "Information Disclosure"
	case DenialOfService:
		return "Denial of Service"
	case ElevationOfPrivilege:
		return "Elevation of Privilege"
	default:
		return string(t)
	}
}

// Code returns the single-letter STRIDE code.
func (t ThreatType) Code() string {
	return string(t)
}

// D2Class returns the D2 style class name for this threat type.
func (t ThreatType) D2Class() string {
	switch t {
	case Spoofing:
		return "threat-spoofing"
	case Tampering:
		return "threat-tampering"
	case Repudiation:
		return "threat-repudiation"
	case InformationDisclosure:
		return "threat-info-disclosure"
	case DenialOfService:
		return "threat-dos"
	case ElevationOfPrivilege:
		return "threat-elevation"
	default:
		return ""
	}
}

// D2BoxClass returns the D2 style class name for threat annotation boxes.
func (t ThreatType) D2BoxClass() string {
	switch t {
	case Spoofing:
		return "threat-box-spoofing"
	case Tampering:
		return "threat-box-tampering"
	case Repudiation:
		return "threat-box-repudiation"
	case InformationDisclosure:
		return "threat-box-info-disclosure"
	case DenialOfService:
		return "threat-box-dos"
	case ElevationOfPrivilege:
		return "threat-box-elevation"
	default:
		return ""
	}
}

// Color returns the primary color associated with this threat type.
func (t ThreatType) Color() string {
	switch t {
	case Spoofing:
		return "#c62828" // Red
	case Tampering:
		return "#f9a825" // Yellow
	case Repudiation:
		return "#7b1fa2" // Purple
	case InformationDisclosure:
		return "#1565c0" // Blue
	case DenialOfService:
		return "#d84315" // Orange
	case ElevationOfPrivilege:
		return "#2e7d32" // Green
	default:
		return "#424242"
	}
}

// AllThreatTypes returns all STRIDE threat types in order.
func AllThreatTypes() []ThreatType {
	return []ThreatType{
		Spoofing,
		Tampering,
		Repudiation,
		InformationDisclosure,
		DenialOfService,
		ElevationOfPrivilege,
	}
}

// Threat represents a specific threat instance in a threat model.
type Threat struct {
	// Type is the STRIDE category of this threat.
	Type ThreatType `json:"type"`

	// Title is a short name for the threat.
	Title string `json:"title"`

	// Description provides details about the threat.
	Description string `json:"description,omitempty"`

	// Mitigation describes how to address the threat.
	Mitigation string `json:"mitigation,omitempty"`

	// ElementID references the diagram element this threat applies to.
	ElementID string `json:"elementId,omitempty"`

	// Severity indicates the threat severity (e.g., "High", "Medium", "Low").
	Severity string `json:"severity,omitempty"`
}

// Label returns a formatted label for use in diagrams.
func (t Threat) Label() string {
	if t.Title != "" {
		return fmt.Sprintf("%s - %s", t.Type.Code(), t.Title)
	}
	return fmt.Sprintf("%s - %s", t.Type.Code(), t.Type.String())
}

// D2ID returns a valid D2 identifier for this threat.
func (t Threat) D2ID() string {
	if t.ElementID != "" {
		return fmt.Sprintf("threat-%s-%s", t.Type.Code(), t.ElementID)
	}
	return fmt.Sprintf("threat-%s", t.Type.Code())
}
