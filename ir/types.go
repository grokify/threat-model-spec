// Package ir provides the intermediate representation for threat modeling diagrams.
// All types are designed to be Go-friendly and generate clean JSON schemas
// without polymorphic anyOf/oneOf constructs.
package ir

import "github.com/invopop/jsonschema"

// DiagramType identifies the type of diagram.
type DiagramType string

const (
	DiagramTypeDFD        DiagramType = "dfd"
	DiagramTypeAttack     DiagramType = "attack-chain"
	DiagramTypeSequence   DiagramType = "sequence"
	DiagramTypeAttackTree DiagramType = "attack-tree"
)

// JSONSchema implements jsonschema.JSONSchemaer for DiagramType.
func (DiagramType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"dfd", "attack-chain", "sequence", "attack-tree"},
	}
}

// ElementType identifies the type of DFD element.
type ElementType string

const (
	ElementTypeProcess        ElementType = "process"
	ElementTypeDatastore      ElementType = "datastore"
	ElementTypeExternalEntity ElementType = "external-entity"
	ElementTypeGateway        ElementType = "gateway"
	ElementTypeBrowser        ElementType = "browser"
	ElementTypeAgent          ElementType = "agent"
	ElementTypeAPI            ElementType = "api"
)

// JSONSchema implements jsonschema.JSONSchemaer for ElementType.
func (ElementType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"process", "datastore", "external-entity", "gateway", "browser", "agent", "api"},
	}
}

// BoundaryType identifies the type of trust boundary.
type BoundaryType string

const (
	BoundaryTypeBrowser   BoundaryType = "browser"
	BoundaryTypeLocalhost BoundaryType = "localhost"
	BoundaryTypeNetwork   BoundaryType = "network"
	BoundaryTypeCloud     BoundaryType = "cloud"
	BoundaryTypeBreached  BoundaryType = "breached"
)

// JSONSchema implements jsonschema.JSONSchemaer for BoundaryType.
func (BoundaryType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"browser", "localhost", "network", "cloud", "breached"},
	}
}

// FlowType identifies the type of data flow or attack flow.
type FlowType string

const (
	FlowTypeNormal FlowType = "normal"
	FlowTypeAttack FlowType = "attack"
	FlowTypeExfil  FlowType = "exfil"
)

// JSONSchema implements jsonschema.JSONSchemaer for FlowType.
func (FlowType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"normal", "attack", "exfil"},
	}
}

// AssetClassification identifies the value/sensitivity of an asset.
type AssetClassification string

const (
	AssetClassificationCrownJewel AssetClassification = "crown-jewel"
	AssetClassificationHigh       AssetClassification = "high"
	AssetClassificationMedium     AssetClassification = "medium"
	AssetClassificationLow        AssetClassification = "low"
)

// JSONSchema implements jsonschema.JSONSchemaer for AssetClassification.
func (AssetClassification) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"crown-jewel", "high", "medium", "low"},
	}
}

// STRIDEThreat identifies a STRIDE threat category.
type STRIDEThreat string

const (
	STRIDESpoofing             STRIDEThreat = "S"
	STRIDETampering            STRIDEThreat = "T"
	STRIDERepudiation          STRIDEThreat = "R"
	STRIDEInformationDisc      STRIDEThreat = "I"
	STRIDEDenialOfService      STRIDEThreat = "D"
	STRIDEElevationOfPrivilege STRIDEThreat = "E"
)

// JSONSchema implements jsonschema.JSONSchemaer for STRIDEThreat.
func (STRIDEThreat) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"S", "T", "R", "I", "D", "E"},
	}
}

// MITRETactic identifies a MITRE ATT&CK tactic.
type MITRETactic string

const (
	MITREInitialAccess     MITRETactic = "TA0001"
	MITREExecution         MITRETactic = "TA0002"
	MITREPersistence       MITRETactic = "TA0003"
	MITREPrivilegeEsc      MITRETactic = "TA0004"
	MITREDefenseEvasion    MITRETactic = "TA0005"
	MITRECredentialAccess  MITRETactic = "TA0006"
	MITREDiscovery         MITRETactic = "TA0007"
	MITRELateralMovement   MITRETactic = "TA0008"
	MITRECollection        MITRETactic = "TA0009"
	MITREExfiltration      MITRETactic = "TA0010"
	MITRECommandAndControl MITRETactic = "TA0011"
	MITREImpact            MITRETactic = "TA0040"
)

// JSONSchema implements jsonschema.JSONSchemaer for MITRETactic.
func (MITRETactic) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{
			"TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006",
			"TA0007", "TA0008", "TA0009", "TA0010", "TA0011", "TA0040",
		},
	}
}

// Direction specifies the layout direction of the diagram.
type Direction string

const (
	DirectionRight Direction = "right"
	DirectionDown  Direction = "down"
	DirectionLeft  Direction = "left"
	DirectionUp    Direction = "up"
)

// JSONSchema implements jsonschema.JSONSchemaer for Direction.
func (Direction) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"right", "down", "left", "up"},
	}
}
