package ir

import (
	"encoding/json"
	"testing"
)

func TestAttackTreeNodeType_JSONSchema(t *testing.T) {
	schema := AttackTreeNodeType("").JSONSchema()
	if schema.Type != "string" {
		t.Errorf("expected type string, got %s", schema.Type)
	}
	if len(schema.Enum) != 3 {
		t.Errorf("expected 3 enum values, got %d", len(schema.Enum))
	}
}

func TestAttackTreeNode_JSON(t *testing.T) {
	node := AttackTreeNode{
		ID:             "goal-1",
		Label:          "Compromise System",
		NodeType:       AttackTreeNodeTypeOR,
		Description:    "Root goal: compromise the target system",
		Children:       []string{"attack-1", "attack-2"},
		MITRETechnique: "",
		STRIDEThreats:  []STRIDEThreat{STRIDEElevationOfPrivilege},
		Probability:    0.7,
		Cost:           "medium",
		Difficulty:     "medium",
		Countermeasure: "Defense in depth",
		Mitigated:      false,
	}

	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded AttackTreeNode
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != node.ID {
		t.Errorf("expected ID %q, got %q", node.ID, decoded.ID)
	}
	if decoded.NodeType != AttackTreeNodeTypeOR {
		t.Errorf("expected nodeType %q, got %q", AttackTreeNodeTypeOR, decoded.NodeType)
	}
	if len(decoded.Children) != 2 {
		t.Errorf("expected 2 children, got %d", len(decoded.Children))
	}
}

func TestAttackTree_GetNode(t *testing.T) {
	tree := &AttackTree{
		RootID: "root",
		Nodes: []AttackTreeNode{
			{ID: "root", Label: "Root Goal", NodeType: AttackTreeNodeTypeOR, Children: []string{"child1", "child2"}},
			{ID: "child1", Label: "Attack Path 1", NodeType: AttackTreeNodeTypeLeaf},
			{ID: "child2", Label: "Attack Path 2", NodeType: AttackTreeNodeTypeLeaf},
		},
	}

	root := tree.GetNode("root")
	if root == nil {
		t.Fatal("expected to find root node")
	}
	if root.Label != "Root Goal" {
		t.Errorf("expected label %q, got %q", "Root Goal", root.Label)
	}

	child := tree.GetNode("child1")
	if child == nil {
		t.Fatal("expected to find child1 node")
	}

	missing := tree.GetNode("missing")
	if missing != nil {
		t.Error("expected nil for missing node")
	}
}

func TestAttackTree_GetRoot(t *testing.T) {
	tree := &AttackTree{
		RootID: "root",
		Nodes: []AttackTreeNode{
			{ID: "root", Label: "Root Goal", NodeType: AttackTreeNodeTypeOR},
		},
	}

	root := tree.GetRoot()
	if root == nil {
		t.Fatal("expected to find root node")
	}
	if root.ID != "root" {
		t.Errorf("expected ID %q, got %q", "root", root.ID)
	}
}

func TestAttackTree_GetChildren(t *testing.T) {
	tree := &AttackTree{
		RootID: "root",
		Nodes: []AttackTreeNode{
			{ID: "root", Label: "Root Goal", NodeType: AttackTreeNodeTypeOR, Children: []string{"child1", "child2"}},
			{ID: "child1", Label: "Attack Path 1", NodeType: AttackTreeNodeTypeLeaf},
			{ID: "child2", Label: "Attack Path 2", NodeType: AttackTreeNodeTypeLeaf},
		},
	}

	root := tree.GetRoot()
	children := tree.GetChildren(root)

	if len(children) != 2 {
		t.Errorf("expected 2 children, got %d", len(children))
	}
}

func TestAttackTreeNode_IsLeaf(t *testing.T) {
	tests := []struct {
		name     string
		node     AttackTreeNode
		expected bool
	}{
		{
			name:     "explicit leaf",
			node:     AttackTreeNode{NodeType: AttackTreeNodeTypeLeaf},
			expected: true,
		},
		{
			name:     "no children",
			node:     AttackTreeNode{NodeType: AttackTreeNodeTypeOR, Children: nil},
			expected: true,
		},
		{
			name:     "has children",
			node:     AttackTreeNode{NodeType: AttackTreeNodeTypeOR, Children: []string{"child1"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.node.IsLeaf()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAttackTreeNode_GetNodeTypeSymbol(t *testing.T) {
	tests := []struct {
		nodeType AttackTreeNodeType
		expected string
	}{
		{AttackTreeNodeTypeAND, "∧"},
		{AttackTreeNodeTypeOR, "∨"},
		{AttackTreeNodeTypeLeaf, ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.nodeType), func(t *testing.T) {
			node := AttackTreeNode{NodeType: tt.nodeType}
			symbol := node.GetNodeTypeSymbol()
			if symbol != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, symbol)
			}
		})
	}
}

func TestAttackTreeNodeType_Values(t *testing.T) {
	types := []AttackTreeNodeType{
		AttackTreeNodeTypeAND,
		AttackTreeNodeTypeOR,
		AttackTreeNodeTypeLeaf,
	}

	for _, typ := range types {
		t.Run(string(typ), func(t *testing.T) {
			data, err := json.Marshal(typ)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			var decoded AttackTreeNodeType
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if decoded != typ {
				t.Errorf("expected %q, got %q", typ, decoded)
			}
		})
	}
}

func TestDiagramIR_AttackTree_Render(t *testing.T) {
	d := &DiagramIR{
		Type:  DiagramTypeAttackTree,
		Title: "Test Attack Tree",
		AttackTree: &AttackTree{
			RootID: "root",
			Nodes: []AttackTreeNode{
				{ID: "root", Label: "Compromise System", NodeType: AttackTreeNodeTypeOR, Children: []string{"path1", "path2"}},
				{ID: "path1", Label: "Exploit Vulnerability", NodeType: AttackTreeNodeTypeLeaf, MITRETechnique: "T1190"},
				{ID: "path2", Label: "Social Engineering", NodeType: AttackTreeNodeTypeLeaf, Mitigated: true},
			},
		},
	}

	output := d.RenderD2()

	// Check that output contains expected elements
	if !containsHelper(output, "# Test Attack Tree") {
		t.Error("expected title in output")
	}
	if !containsHelper(output, "root:") {
		t.Error("expected root node in output")
	}
	if !containsHelper(output, "path1:") {
		t.Error("expected path1 node in output")
	}
	if !containsHelper(output, "root -> path1") {
		t.Error("expected connection in output")
	}
}
