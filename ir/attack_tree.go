package ir

import "github.com/invopop/jsonschema"

// AttackTreeNodeType identifies the logic type of an attack tree node.
type AttackTreeNodeType string

const (
	// AttackTreeNodeTypeAND requires all child nodes to be true.
	AttackTreeNodeTypeAND AttackTreeNodeType = "AND"

	// AttackTreeNodeTypeOR requires any child node to be true.
	AttackTreeNodeTypeOR AttackTreeNodeType = "OR"

	// AttackTreeNodeTypeLeaf is a leaf node with no children.
	AttackTreeNodeTypeLeaf AttackTreeNodeType = "LEAF"
)

// JSONSchema implements jsonschema.JSONSchemaer for AttackTreeNodeType.
func (AttackTreeNodeType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string",
		Enum: []any{"AND", "OR", "LEAF"},
	}
}

// AttackTreeNode represents a node in an attack tree.
// Attack trees are hierarchical decompositions of attack goals.
type AttackTreeNode struct {
	// ID is the unique identifier for the node.
	ID string `json:"id"`

	// Label is the display name or goal description.
	Label string `json:"label"`

	// NodeType identifies the logic type (AND, OR, LEAF).
	NodeType AttackTreeNodeType `json:"nodeType"`

	// Description provides additional context about this attack step.
	Description string `json:"description,omitempty"`

	// Children contains the child node IDs (for AND/OR nodes).
	Children []string `json:"children,omitempty"`

	// MITRETechnique is the MITRE ATT&CK technique ID (for leaf nodes).
	MITRETechnique string `json:"mitreTechnique,omitempty"`

	// STRIDEThreats lists applicable STRIDE threats.
	STRIDEThreats []STRIDEThreat `json:"strideThreats,omitempty"`

	// Probability is the estimated probability of success (0.0 - 1.0).
	Probability float64 `json:"probability,omitempty"`

	// Cost estimates the attacker cost (low, medium, high).
	Cost string `json:"cost,omitempty"`

	// Difficulty estimates the attack difficulty (trivial, low, medium, high, expert).
	Difficulty string `json:"difficulty,omitempty"`

	// Countermeasure describes how to prevent this attack step.
	Countermeasure string `json:"countermeasure,omitempty"`

	// Mitigated indicates if this attack path is mitigated.
	Mitigated bool `json:"mitigated,omitempty"`
}

// AttackTree represents the root of an attack tree structure.
type AttackTree struct {
	// RootID is the ID of the root goal node.
	RootID string `json:"rootId"`

	// Nodes contains all nodes in the attack tree.
	Nodes []AttackTreeNode `json:"nodes"`
}

// GetNode returns the node with the given ID, or nil if not found.
func (t *AttackTree) GetNode(id string) *AttackTreeNode {
	for i := range t.Nodes {
		if t.Nodes[i].ID == id {
			return &t.Nodes[i]
		}
	}
	return nil
}

// GetRoot returns the root node of the attack tree.
func (t *AttackTree) GetRoot() *AttackTreeNode {
	return t.GetNode(t.RootID)
}

// GetChildren returns the child nodes of the given node.
func (t *AttackTree) GetChildren(node *AttackTreeNode) []*AttackTreeNode {
	var children []*AttackTreeNode
	for _, childID := range node.Children {
		if child := t.GetNode(childID); child != nil {
			children = append(children, child)
		}
	}
	return children
}

// IsLeaf returns true if the node has no children.
func (n *AttackTreeNode) IsLeaf() bool {
	return n.NodeType == AttackTreeNodeTypeLeaf || len(n.Children) == 0
}

// GetNodeTypeSymbol returns the D2-friendly symbol for the node type.
func (n *AttackTreeNode) GetNodeTypeSymbol() string {
	switch n.NodeType {
	case AttackTreeNodeTypeAND:
		return "∧" // AND gate symbol
	case AttackTreeNodeTypeOR:
		return "∨" // OR gate symbol
	default:
		return ""
	}
}
