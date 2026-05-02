package ir

import (
	"strings"
	"testing"
)

func TestValidateAttackTree(t *testing.T) {
	tests := []struct {
		name        string
		diagram     DiagramIR
		wantErr     bool
		errContains []string
	}{
		{
			name: "valid attack tree",
			diagram: DiagramIR{
				Type:  DiagramTypeAttackTree,
				Title: "Test Attack Tree",
				AttackTree: &AttackTree{
					RootID: "root",
					Nodes: []AttackTreeNode{
						{ID: "root", Label: "Root Goal", NodeType: AttackTreeNodeTypeOR, Children: []string{"sub1"}},
						{ID: "sub1", Label: "Sub Goal 1", NodeType: AttackTreeNodeTypeOR, Children: []string{"leaf1"}},
						{ID: "leaf1", Label: "Attack 1", NodeType: AttackTreeNodeTypeLeaf},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing attack tree structure",
			diagram: DiagramIR{
				Type:       DiagramTypeAttackTree,
				Title:      "Test",
				AttackTree: nil,
			},
			wantErr:     true,
			errContains: []string{"attackTree", "requires an attackTree structure"},
		},
		{
			name: "empty nodes",
			diagram: DiagramIR{
				Type:  DiagramTypeAttackTree,
				Title: "Test",
				AttackTree: &AttackTree{
					RootID: "root",
					Nodes:  []AttackTreeNode{},
				},
			},
			wantErr:     true,
			errContains: []string{"attackTree.nodes", "at least one node"},
		},
		{
			name: "missing root ID",
			diagram: DiagramIR{
				Type:  DiagramTypeAttackTree,
				Title: "Test",
				AttackTree: &AttackTree{
					RootID: "",
					Nodes: []AttackTreeNode{
						{ID: "node1", Label: "Node 1", NodeType: AttackTreeNodeTypeLeaf},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"rootId"},
		},
		{
			name: "node missing ID",
			diagram: DiagramIR{
				Type:  DiagramTypeAttackTree,
				Title: "Test",
				AttackTree: &AttackTree{
					RootID: "root",
					Nodes: []AttackTreeNode{
						{ID: "root", Label: "Root", NodeType: AttackTreeNodeTypeLeaf},
						{ID: "", Label: "Missing ID", NodeType: AttackTreeNodeTypeLeaf},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"missing required id"},
		},
		{
			name: "duplicate node ID",
			diagram: DiagramIR{
				Type:  DiagramTypeAttackTree,
				Title: "Test",
				AttackTree: &AttackTree{
					RootID: "root",
					Nodes: []AttackTreeNode{
						{ID: "root", Label: "Root", NodeType: AttackTreeNodeTypeLeaf},
						{ID: "root", Label: "Duplicate", NodeType: AttackTreeNodeTypeLeaf},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"duplicate node id"},
		},
		{
			name: "node missing label",
			diagram: DiagramIR{
				Type:  DiagramTypeAttackTree,
				Title: "Test",
				AttackTree: &AttackTree{
					RootID: "root",
					Nodes: []AttackTreeNode{
						{ID: "root", Label: "", NodeType: AttackTreeNodeTypeLeaf},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"missing required label"},
		},
		{
			name: "invalid child reference",
			diagram: DiagramIR{
				Type:  DiagramTypeAttackTree,
				Title: "Test",
				AttackTree: &AttackTree{
					RootID: "root",
					Nodes: []AttackTreeNode{
						{ID: "root", Label: "Root", NodeType: AttackTreeNodeTypeOR, Children: []string{"nonexistent"}},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"references unknown child"},
		},
		{
			name: "root ID not in nodes",
			diagram: DiagramIR{
				Type:  DiagramTypeAttackTree,
				Title: "Test",
				AttackTree: &AttackTree{
					RootID: "missing-root",
					Nodes: []AttackTreeNode{
						{ID: "node1", Label: "Node 1", NodeType: AttackTreeNodeTypeLeaf},
					},
				},
			},
			wantErr:     true,
			errContains: []string{"rootId", "references unknown node"},
		},
		{
			name: "valid tree with all node types",
			diagram: DiagramIR{
				Type:  DiagramTypeAttackTree,
				Title: "Test Attack Tree",
				AttackTree: &AttackTree{
					RootID: "root",
					Nodes: []AttackTreeNode{
						{ID: "root", Label: "Compromise System", NodeType: AttackTreeNodeTypeOR, Children: []string{"or1", "and1"}},
						{ID: "or1", Label: "OR Gate", NodeType: AttackTreeNodeTypeOR, Children: []string{"leaf1"}},
						{ID: "and1", Label: "AND Gate", NodeType: AttackTreeNodeTypeAND, Children: []string{"leaf2"}},
						{ID: "leaf1", Label: "SQL Injection", NodeType: AttackTreeNodeTypeLeaf},
						{ID: "leaf2", Label: "XSS Attack", NodeType: AttackTreeNodeTypeLeaf},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.diagram.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && len(tt.errContains) > 0 {
				errStr := err.Error()
				for _, want := range tt.errContains {
					if !strings.Contains(errStr, want) {
						t.Errorf("Error should contain %q, got: %s", want, errStr)
					}
				}
			}
		})
	}
}

func TestValidateAttackTreeWithMitigations(t *testing.T) {
	// Test attack tree with mitigations (cross-cutting validation)
	diagram := DiagramIR{
		Type:  DiagramTypeAttackTree,
		Title: "Test Attack Tree with Mitigations",
		AttackTree: &AttackTree{
			RootID: "root",
			Nodes: []AttackTreeNode{
				{ID: "root", Label: "Root Goal", NodeType: AttackTreeNodeTypeOR, Children: []string{"attack1"}},
				{ID: "attack1", Label: "Attack 1", NodeType: AttackTreeNodeTypeLeaf},
			},
		},
		Mitigations: []Mitigation{
			{ID: "m1", Title: "Mitigation 1", ThreatIDs: []string{"root"}, Status: MitigationStatusImplemented},
		},
	}

	err := diagram.Validate()
	if err != nil {
		t.Errorf("Valid attack tree with mitigations should pass validation, got: %v", err)
	}
}

func TestValidateAttackTreeWithThreats(t *testing.T) {
	// Test attack tree with threats
	diagram := DiagramIR{
		Type:  DiagramTypeAttackTree,
		Title: "Test Attack Tree with Threats",
		AttackTree: &AttackTree{
			RootID: "root",
			Nodes: []AttackTreeNode{
				{ID: "root", Label: "Root Goal", NodeType: AttackTreeNodeTypeLeaf},
			},
		},
		Threats: []ThreatEntry{
			{ID: "t1", Title: "Threat 1", Status: ThreatStatusIdentified},
		},
	}

	err := diagram.Validate()
	if err != nil {
		t.Errorf("Valid attack tree with threats should pass validation, got: %v", err)
	}
}
