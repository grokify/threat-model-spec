package ir

import (
	"encoding/json"
	"testing"
)

func TestAttackPathJSONRoundTrip(t *testing.T) {
	path := AttackPath{
		Nodes:       []string{"n1", "n2", "n3"},
		Edges:       []string{"e1", "e2"},
		TotalWeight: 5.5,
		RiskScore:   7.2,
		Length:      2,
	}

	data, err := json.MarshalIndent(path, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal AttackPath: %v", err)
	}

	var decoded AttackPath
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AttackPath: %v", err)
	}

	if len(decoded.Nodes) != 3 {
		t.Errorf("Nodes length = %d, want 3", len(decoded.Nodes))
	}
	if decoded.TotalWeight != 5.5 {
		t.Errorf("TotalWeight = %f, want 5.5", decoded.TotalWeight)
	}
	if decoded.Length != 2 {
		t.Errorf("Length = %d, want 2", decoded.Length)
	}
}

func createTestGraph() *AttackGraph {
	graph := NewAttackGraph("test")

	// Create a simple graph: n1 -> n2 -> n3 -> n4
	//                            \-> n5 -/
	graph.AddNode(GraphNode{ID: "n1", Type: GraphNodeTypeActor, Label: "Entry", RiskScore: 2.0})
	graph.AddNode(GraphNode{ID: "n2", Type: GraphNodeTypeElement, Label: "Server", RiskScore: 5.0})
	graph.AddNode(GraphNode{ID: "n3", Type: GraphNodeTypeElement, Label: "App", RiskScore: 6.0})
	graph.AddNode(GraphNode{ID: "n4", Type: GraphNodeTypeAsset, Label: "Database", RiskScore: 9.0})
	graph.AddNode(GraphNode{ID: "n5", Type: GraphNodeTypeElement, Label: "Cache", RiskScore: 3.0})

	graph.AddEdge(GraphEdge{ID: "e1", Source: "n1", Target: "n2", Type: GraphEdgeTypeFlow, Weight: 1.0})
	graph.AddEdge(GraphEdge{ID: "e2", Source: "n2", Target: "n3", Type: GraphEdgeTypeFlow, Weight: 2.0})
	graph.AddEdge(GraphEdge{ID: "e3", Source: "n2", Target: "n5", Type: GraphEdgeTypeFlow, Weight: 1.0})
	graph.AddEdge(GraphEdge{ID: "e4", Source: "n3", Target: "n4", Type: GraphEdgeTypeFlow, Weight: 3.0})
	graph.AddEdge(GraphEdge{ID: "e5", Source: "n5", Target: "n4", Type: GraphEdgeTypeFlow, Weight: 2.0})

	graph.EntryPoints = []string{"n1"}
	graph.Targets = []string{"n4"}

	return graph
}

func TestFindAllPaths(t *testing.T) {
	graph := createTestGraph()

	paths := graph.FindAllPaths("n1", "n4", 0)

	// Should find 2 paths: n1->n2->n3->n4 and n1->n2->n5->n4
	if len(paths) != 2 {
		t.Errorf("FindAllPaths found %d paths, want 2", len(paths))
		for i, p := range paths {
			t.Logf("Path %d: %v", i, p.Nodes)
		}
	}
}

func TestFindAllPathsWithDepthLimit(t *testing.T) {
	graph := createTestGraph()

	// With depth limit of 2, should not find paths of length > 2
	paths := graph.FindAllPaths("n1", "n4", 2)

	// No direct path of length <= 2 exists
	if len(paths) != 0 {
		t.Errorf("FindAllPaths with depth=2 found %d paths, want 0", len(paths))
	}

	// With depth limit of 4, should find both paths
	paths = graph.FindAllPaths("n1", "n4", 4)
	if len(paths) != 2 {
		t.Errorf("FindAllPaths with depth=4 found %d paths, want 2", len(paths))
	}
}

func TestFindShortestPath(t *testing.T) {
	graph := createTestGraph()

	path := graph.FindShortestPath("n1", "n4")

	if path == nil {
		t.Fatal("FindShortestPath returned nil")
	}

	// Shortest path should be n1->n2->n5->n4 (weight: 1+1+2 = 4)
	// vs n1->n2->n3->n4 (weight: 1+2+3 = 6)
	if path.TotalWeight != 4.0 {
		t.Errorf("TotalWeight = %f, want 4.0", path.TotalWeight)
	}

	if len(path.Nodes) != 4 {
		t.Errorf("Path length = %d, want 4 nodes", len(path.Nodes))
	}

	// Verify path is n1 -> n2 -> n5 -> n4
	expected := []string{"n1", "n2", "n5", "n4"}
	for i, nodeID := range expected {
		if path.Nodes[i] != nodeID {
			t.Errorf("Path[%d] = %s, want %s", i, path.Nodes[i], nodeID)
		}
	}
}

func TestFindShortestPathNoPath(t *testing.T) {
	graph := NewAttackGraph("test")
	graph.AddNode(GraphNode{ID: "n1", Type: GraphNodeTypeElement, Label: "Node 1"})
	graph.AddNode(GraphNode{ID: "n2", Type: GraphNodeTypeElement, Label: "Node 2"})
	// No edges between nodes

	path := graph.FindShortestPath("n1", "n2")

	if path != nil {
		t.Error("FindShortestPath should return nil when no path exists")
	}
}

func TestCalculatePathRisk(t *testing.T) {
	graph := createTestGraph()

	path := &AttackPath{
		Nodes: []string{"n1", "n2", "n4"},
	}

	risk := graph.CalculatePathRisk(path)

	// Risk should be positive
	if risk <= 0 {
		t.Errorf("CalculatePathRisk = %f, want > 0", risk)
	}
}

func TestCalculatePathRiskNilPath(t *testing.T) {
	graph := createTestGraph()

	risk := graph.CalculatePathRisk(nil)
	if risk != 0 {
		t.Errorf("CalculatePathRisk(nil) = %f, want 0", risk)
	}

	risk = graph.CalculatePathRisk(&AttackPath{})
	if risk != 0 {
		t.Errorf("CalculatePathRisk(empty) = %f, want 0", risk)
	}
}

func TestFindCriticalPaths(t *testing.T) {
	graph := createTestGraph()

	criticalPaths := graph.FindCriticalPaths(5)

	if len(criticalPaths) == 0 {
		t.Error("FindCriticalPaths should find at least one path")
	}

	// Verify paths are sorted by risk score (descending)
	for i := 1; i < len(criticalPaths); i++ {
		if criticalPaths[i].RiskScore > criticalPaths[i-1].RiskScore {
			t.Error("Critical paths should be sorted by risk score descending")
		}
	}
}

func TestReachabilityAnalysis(t *testing.T) {
	graph := createTestGraph()

	result := graph.ReachabilityAnalysis()

	if result == nil {
		t.Fatal("ReachabilityAnalysis returned nil")
	}

	// All nodes should be reachable from n1
	if len(result.ReachableNodes) != 5 {
		t.Errorf("ReachableNodes = %d, want 5", len(result.ReachableNodes))
	}

	// No unreachable targets
	if len(result.UnreachableTargets) != 0 {
		t.Errorf("UnreachableTargets = %d, want 0", len(result.UnreachableTargets))
	}
}

func TestReachabilityAnalysisWithUnreachable(t *testing.T) {
	graph := NewAttackGraph("test")
	graph.AddNode(GraphNode{ID: "n1", Type: GraphNodeTypeElement, Label: "Node 1"})
	graph.AddNode(GraphNode{ID: "n2", Type: GraphNodeTypeElement, Label: "Node 2"})
	graph.AddNode(GraphNode{ID: "n3", Type: GraphNodeTypeElement, Label: "Isolated"})

	graph.AddEdge(GraphEdge{ID: "e1", Source: "n1", Target: "n2", Type: GraphEdgeTypeFlow})

	graph.EntryPoints = []string{"n1"}
	graph.Targets = []string{"n2", "n3"} // n3 is unreachable

	result := graph.ReachabilityAnalysis()

	// n3 should be unreachable
	if len(result.UnreachableTargets) != 1 {
		t.Errorf("UnreachableTargets = %d, want 1", len(result.UnreachableTargets))
	}
	if len(result.UnreachableTargets) > 0 && result.UnreachableTargets[0] != "n3" {
		t.Errorf("UnreachableTargets[0] = %s, want n3", result.UnreachableTargets[0])
	}
}

func TestAnalyzePaths(t *testing.T) {
	graph := createTestGraph()

	result := graph.AnalyzePaths()

	if result == nil {
		t.Fatal("AnalyzePaths returned nil")
	}

	// Should have reachable nodes
	if len(result.ReachableNodes) == 0 {
		t.Error("AnalyzePaths should find reachable nodes")
	}

	// Should have critical paths
	if len(result.CriticalPaths) == 0 {
		t.Error("AnalyzePaths should find critical paths")
	}

	// Should have shortest path
	if result.ShortestPath == nil {
		t.Error("AnalyzePaths should find shortest path")
	}
}

func TestPathAnalysisResultJSONRoundTrip(t *testing.T) {
	result := PathAnalysisResult{
		AllPaths: []AttackPath{
			{Nodes: []string{"a", "b", "c"}, Length: 2, RiskScore: 5.0},
		},
		ShortestPath: &AttackPath{
			Nodes: []string{"a", "c"}, Length: 1, RiskScore: 3.0,
		},
		CriticalPaths: []AttackPath{
			{Nodes: []string{"a", "b", "c"}, Length: 2, RiskScore: 8.0},
		},
		ReachableNodes:     []string{"a", "b", "c"},
		UnreachableTargets: []string{"d"},
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal PathAnalysisResult: %v", err)
	}

	var decoded PathAnalysisResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal PathAnalysisResult: %v", err)
	}

	if len(decoded.AllPaths) != 1 {
		t.Errorf("AllPaths length = %d, want 1", len(decoded.AllPaths))
	}
	if decoded.ShortestPath == nil {
		t.Error("ShortestPath should not be nil")
	}
	if len(decoded.UnreachableTargets) != 1 {
		t.Errorf("UnreachableTargets length = %d, want 1", len(decoded.UnreachableTargets))
	}
}
