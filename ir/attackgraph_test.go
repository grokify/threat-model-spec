package ir

import (
	"encoding/json"
	"testing"
)

func TestAttackGraphJSONRoundTrip(t *testing.T) {
	graph := &AttackGraph{
		ID:            "test-graph",
		ThreatModelID: "test-model",
		Nodes: []GraphNode{
			{ID: "n1", Type: GraphNodeTypeElement, Label: "Web Server", RiskScore: 5.0},
			{ID: "n2", Type: GraphNodeTypeAsset, Label: "Database", RiskScore: 8.0},
			{ID: "n3", Type: GraphNodeTypeThreat, Label: "SQL Injection", RiskScore: 9.0},
		},
		Edges: []GraphEdge{
			{ID: "e1", Source: "n1", Target: "n2", Type: GraphEdgeTypeFlow, Label: "query"},
			{ID: "e2", Source: "n3", Target: "n2", Type: GraphEdgeTypeAttack, Label: "exploit", Weight: 3.0},
		},
		EntryPoints: []string{"n1"},
		Targets:     []string{"n2"},
	}

	data, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal AttackGraph: %v", err)
	}

	var decoded AttackGraph
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AttackGraph: %v", err)
	}

	if decoded.ID != "test-graph" {
		t.Errorf("ID = %s, want test-graph", decoded.ID)
	}
	if len(decoded.Nodes) != 3 {
		t.Errorf("Nodes length = %d, want 3", len(decoded.Nodes))
	}
	if len(decoded.Edges) != 2 {
		t.Errorf("Edges length = %d, want 2", len(decoded.Edges))
	}
}

func TestNewAttackGraph(t *testing.T) {
	graph := NewAttackGraph("test")

	if graph.ID != "test" {
		t.Errorf("ID = %s, want test", graph.ID)
	}
	if len(graph.Nodes) != 0 {
		t.Errorf("Nodes should be empty, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 0 {
		t.Errorf("Edges should be empty, got %d", len(graph.Edges))
	}
}

func TestAttackGraphAddNode(t *testing.T) {
	graph := NewAttackGraph("test")

	graph.AddNode(GraphNode{
		ID:    "node1",
		Type:  GraphNodeTypeElement,
		Label: "Test Node",
	})

	if len(graph.Nodes) != 1 {
		t.Fatalf("Nodes length = %d, want 1", len(graph.Nodes))
	}
	if graph.Nodes[0].ID != "node1" {
		t.Errorf("Node ID = %s, want node1", graph.Nodes[0].ID)
	}
}

func TestAttackGraphAddEdge(t *testing.T) {
	graph := NewAttackGraph("test")
	graph.AddNode(GraphNode{ID: "n1", Type: GraphNodeTypeElement, Label: "Node 1"})
	graph.AddNode(GraphNode{ID: "n2", Type: GraphNodeTypeElement, Label: "Node 2"})

	graph.AddEdge(GraphEdge{
		ID:     "e1",
		Source: "n1",
		Target: "n2",
		Type:   GraphEdgeTypeFlow,
		Label:  "connection",
	})

	if len(graph.Edges) != 1 {
		t.Fatalf("Edges length = %d, want 1", len(graph.Edges))
	}
	if graph.Edges[0].Source != "n1" {
		t.Errorf("Edge Source = %s, want n1", graph.Edges[0].Source)
	}
}

func TestAttackGraphGetNode(t *testing.T) {
	graph := NewAttackGraph("test")
	graph.AddNode(GraphNode{ID: "n1", Type: GraphNodeTypeElement, Label: "Node 1"})
	graph.AddNode(GraphNode{ID: "n2", Type: GraphNodeTypeAsset, Label: "Node 2"})

	node := graph.GetNode("n1")
	if node == nil {
		t.Fatal("GetNode returned nil for existing node")
	}
	if node.Label != "Node 1" {
		t.Errorf("Node Label = %s, want Node 1", node.Label)
	}

	nilNode := graph.GetNode("nonexistent")
	if nilNode != nil {
		t.Error("GetNode should return nil for nonexistent node")
	}
}

func TestAttackGraphGetOutgoingEdges(t *testing.T) {
	graph := NewAttackGraph("test")
	graph.AddNode(GraphNode{ID: "n1", Type: GraphNodeTypeElement, Label: "Node 1"})
	graph.AddNode(GraphNode{ID: "n2", Type: GraphNodeTypeElement, Label: "Node 2"})
	graph.AddNode(GraphNode{ID: "n3", Type: GraphNodeTypeElement, Label: "Node 3"})

	graph.AddEdge(GraphEdge{ID: "e1", Source: "n1", Target: "n2", Type: GraphEdgeTypeFlow})
	graph.AddEdge(GraphEdge{ID: "e2", Source: "n1", Target: "n3", Type: GraphEdgeTypeFlow})
	graph.AddEdge(GraphEdge{ID: "e3", Source: "n2", Target: "n3", Type: GraphEdgeTypeFlow})

	edges := graph.GetOutgoingEdges("n1")
	if len(edges) != 2 {
		t.Errorf("Outgoing edges from n1 = %d, want 2", len(edges))
	}

	edges = graph.GetOutgoingEdges("n3")
	if len(edges) != 0 {
		t.Errorf("Outgoing edges from n3 = %d, want 0", len(edges))
	}
}

func TestAttackGraphGetNeighbors(t *testing.T) {
	graph := NewAttackGraph("test")
	graph.AddNode(GraphNode{ID: "n1", Type: GraphNodeTypeElement, Label: "Node 1"})
	graph.AddNode(GraphNode{ID: "n2", Type: GraphNodeTypeElement, Label: "Node 2"})
	graph.AddNode(GraphNode{ID: "n3", Type: GraphNodeTypeElement, Label: "Node 3"})

	graph.AddEdge(GraphEdge{ID: "e1", Source: "n1", Target: "n2", Type: GraphEdgeTypeFlow})
	graph.AddEdge(GraphEdge{ID: "e2", Source: "n1", Target: "n3", Type: GraphEdgeTypeFlow})

	neighbors := graph.GetNeighbors("n1")
	if len(neighbors) != 2 {
		t.Errorf("Neighbors of n1 = %d, want 2", len(neighbors))
	}
}

func TestAttackGraphNodeAndEdgeCount(t *testing.T) {
	graph := NewAttackGraph("test")
	graph.AddNode(GraphNode{ID: "n1", Type: GraphNodeTypeElement, Label: "Node 1"})
	graph.AddNode(GraphNode{ID: "n2", Type: GraphNodeTypeElement, Label: "Node 2"})
	graph.AddEdge(GraphEdge{ID: "e1", Source: "n1", Target: "n2", Type: GraphEdgeTypeFlow})

	if graph.NodeCount() != 2 {
		t.Errorf("NodeCount = %d, want 2", graph.NodeCount())
	}
	if graph.EdgeCount() != 1 {
		t.Errorf("EdgeCount = %d, want 1", graph.EdgeCount())
	}
}

func TestBuildAttackGraphFromDiagram(t *testing.T) {
	diagram := &DiagramIR{
		Title: "Test Diagram",
		Type:  DiagramTypeDFD,
		Elements: []Element{
			{ID: "e1", Label: "Client", Type: ElementTypeExternalEntity},
			{ID: "e2", Label: "Server", Type: ElementTypeProcess},
			{ID: "e3", Label: "Database", Type: ElementTypeDatastore},
		},
		Flows: []Flow{
			{From: "e1", To: "e2", Label: "request"},
			{From: "e2", To: "e3", Label: "query"},
		},
		Attacks: []Attack{
			{Step: 1, From: "e1", To: "e2", Label: "SQL Injection"},
		},
	}

	graph := BuildAttackGraphFromDiagram(diagram)

	if graph == nil {
		t.Fatal("BuildAttackGraphFromDiagram returned nil")
	}
	if graph.NodeCount() != 3 {
		t.Errorf("NodeCount = %d, want 3", graph.NodeCount())
	}
	if graph.EdgeCount() != 3 { // 2 flows + 1 attack
		t.Errorf("EdgeCount = %d, want 3", graph.EdgeCount())
	}
}

func TestBuildAttackGraphFromNilDiagram(t *testing.T) {
	graph := BuildAttackGraphFromDiagram(nil)
	if graph != nil {
		t.Error("BuildAttackGraphFromDiagram(nil) should return nil")
	}
}

func TestGraphNodeTypeConstants(t *testing.T) {
	if GraphNodeTypeElement != "element" {
		t.Errorf("GraphNodeTypeElement = %s, want element", GraphNodeTypeElement)
	}
	if GraphNodeTypeThreat != "threat" {
		t.Errorf("GraphNodeTypeThreat = %s, want threat", GraphNodeTypeThreat)
	}
	if GraphNodeTypeControl != "control" {
		t.Errorf("GraphNodeTypeControl = %s, want control", GraphNodeTypeControl)
	}
	if GraphNodeTypeAsset != "asset" {
		t.Errorf("GraphNodeTypeAsset = %s, want asset", GraphNodeTypeAsset)
	}
	if GraphNodeTypeActor != "actor" {
		t.Errorf("GraphNodeTypeActor = %s, want actor", GraphNodeTypeActor)
	}
}

func TestGraphEdgeTypeConstants(t *testing.T) {
	if GraphEdgeTypeFlow != "flow" {
		t.Errorf("GraphEdgeTypeFlow = %s, want flow", GraphEdgeTypeFlow)
	}
	if GraphEdgeTypeAttack != "attack" {
		t.Errorf("GraphEdgeTypeAttack = %s, want attack", GraphEdgeTypeAttack)
	}
	if GraphEdgeTypeMitigation != "mitigation" {
		t.Errorf("GraphEdgeTypeMitigation = %s, want mitigation", GraphEdgeTypeMitigation)
	}
}
