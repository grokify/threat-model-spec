package ir

import (
	"container/heap"
	"math"
)

// AttackPath represents a sequence of nodes and edges forming an attack path
type AttackPath struct {
	// Nodes contains the ordered list of node IDs in the path
	Nodes []string `json:"nodes"`

	// Edges contains the edge IDs traversed (len = len(Nodes) - 1)
	Edges []string `json:"edges,omitempty"`

	// TotalWeight is the sum of all edge weights in the path
	TotalWeight float64 `json:"totalWeight"`

	// RiskScore is the cumulative risk score for the path
	RiskScore float64 `json:"riskScore"`

	// Length is the number of edges (hops) in the path
	Length int `json:"length"`
}

// PathAnalysisResult contains the results of attack path analysis
type PathAnalysisResult struct {
	// AllPaths contains all paths found between source and target
	AllPaths []AttackPath `json:"allPaths,omitempty"`

	// ShortestPath is the path with minimum weight
	ShortestPath *AttackPath `json:"shortestPath,omitempty"`

	// CriticalPaths are paths with highest risk scores
	CriticalPaths []AttackPath `json:"criticalPaths,omitempty"`

	// ReachableNodes lists all nodes reachable from entry points
	ReachableNodes []string `json:"reachableNodes,omitempty"`

	// UnreachableTargets lists targets that cannot be reached
	UnreachableTargets []string `json:"unreachableTargets,omitempty"`
}

// FindAllPaths finds all paths between source and target nodes
// Uses DFS with cycle detection; maxDepth limits search depth (0 = unlimited)
func (g *AttackGraph) FindAllPaths(source, target string, maxDepth int) []AttackPath {
	if g.nodeIndex == nil {
		g.buildIndex()
	}

	var paths []AttackPath
	visited := make(map[string]bool)
	currentPath := []string{source}

	g.findPathsDFS(source, target, maxDepth, visited, currentPath, &paths)

	return paths
}

// findPathsDFS is a helper for DFS-based path finding
func (g *AttackGraph) findPathsDFS(current, target string, maxDepth int, visited map[string]bool, currentPath []string, paths *[]AttackPath) {
	if current == target {
		// Found a path - calculate metrics
		path := AttackPath{
			Nodes:  make([]string, len(currentPath)),
			Length: len(currentPath) - 1,
		}
		copy(path.Nodes, currentPath)
		path.TotalWeight, path.RiskScore = g.calculatePathMetrics(path.Nodes)
		*paths = append(*paths, path)
		return
	}

	// Check depth limit
	if maxDepth > 0 && len(currentPath) > maxDepth {
		return
	}

	visited[current] = true
	defer func() { visited[current] = false }()

	for _, edge := range g.GetOutgoingEdges(current) {
		if !visited[edge.Target] {
			g.findPathsDFS(edge.Target, target, maxDepth, visited, append(currentPath, edge.Target), paths)
		}
	}
}

// calculatePathMetrics calculates weight and risk for a path
func (g *AttackGraph) calculatePathMetrics(nodeIDs []string) (totalWeight float64, riskScore float64) {
	for i := 0; i < len(nodeIDs)-1; i++ {
		for _, edge := range g.GetOutgoingEdges(nodeIDs[i]) {
			if edge.Target == nodeIDs[i+1] {
				totalWeight += edge.Weight
				break
			}
		}
	}

	// Calculate risk as average of node risk scores
	var totalRisk float64
	for _, nodeID := range nodeIDs {
		if node := g.GetNode(nodeID); node != nil {
			totalRisk += node.RiskScore
		}
	}
	if len(nodeIDs) > 0 {
		riskScore = totalRisk / float64(len(nodeIDs))
	}

	return totalWeight, riskScore
}

// dijkstraItem is used in the priority queue for Dijkstra's algorithm
type dijkstraItem struct {
	nodeID   string
	distance float64
	index    int
}

// dijkstraHeap implements heap.Interface for Dijkstra's algorithm
type dijkstraHeap []*dijkstraItem

func (h dijkstraHeap) Len() int           { return len(h) }
func (h dijkstraHeap) Less(i, j int) bool { return h[i].distance < h[j].distance }
func (h dijkstraHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *dijkstraHeap) Push(x interface{}) {
	n := len(*h)
	item := x.(*dijkstraItem)
	item.index = n
	*h = append(*h, item)
}

func (h *dijkstraHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*h = old[0 : n-1]
	return item
}

// FindShortestPath finds the shortest path using Dijkstra's algorithm
func (g *AttackGraph) FindShortestPath(source, target string) *AttackPath {
	if g.nodeIndex == nil {
		g.buildIndex()
	}

	// Initialize distances
	dist := make(map[string]float64)
	prev := make(map[string]string)
	for _, node := range g.Nodes {
		dist[node.ID] = math.Inf(1)
	}
	dist[source] = 0

	// Priority queue
	pq := &dijkstraHeap{}
	heap.Init(pq)
	heap.Push(pq, &dijkstraItem{nodeID: source, distance: 0})

	visited := make(map[string]bool)

	for pq.Len() > 0 {
		item := heap.Pop(pq).(*dijkstraItem)
		current := item.nodeID

		if visited[current] {
			continue
		}
		visited[current] = true

		if current == target {
			// Reconstruct path
			return g.reconstructPath(source, target, prev, dist[target])
		}

		for _, edge := range g.GetOutgoingEdges(current) {
			if visited[edge.Target] {
				continue
			}

			weight := edge.Weight
			if weight == 0 {
				weight = 1 // Default weight
			}

			newDist := dist[current] + weight
			if newDist < dist[edge.Target] {
				dist[edge.Target] = newDist
				prev[edge.Target] = current
				heap.Push(pq, &dijkstraItem{nodeID: edge.Target, distance: newDist})
			}
		}
	}

	// No path found
	return nil
}

// reconstructPath builds the path from predecessor map
func (g *AttackGraph) reconstructPath(source, target string, prev map[string]string, totalWeight float64) *AttackPath {
	path := &AttackPath{
		Nodes:       []string{},
		TotalWeight: totalWeight,
	}

	current := target
	for current != "" {
		path.Nodes = append([]string{current}, path.Nodes...)
		if current == source {
			break
		}
		current = prev[current]
	}

	path.Length = len(path.Nodes) - 1
	_, path.RiskScore = g.calculatePathMetrics(path.Nodes)

	return path
}

// CalculatePathRisk calculates the cumulative risk for a given path
func (g *AttackGraph) CalculatePathRisk(path *AttackPath) float64 {
	if path == nil || len(path.Nodes) == 0 {
		return 0
	}

	var maxRisk float64
	var totalRisk float64

	for _, nodeID := range path.Nodes {
		if node := g.GetNode(nodeID); node != nil {
			totalRisk += node.RiskScore
			if node.RiskScore > maxRisk {
				maxRisk = node.RiskScore
			}
		}
	}

	// Risk is combination of max risk and path length
	avgRisk := totalRisk / float64(len(path.Nodes))
	return (maxRisk + avgRisk) / 2.0 * float64(path.Length+1) / 5.0
}

// FindCriticalPaths finds the paths with highest risk scores
func (g *AttackGraph) FindCriticalPaths(limit int) []AttackPath {
	if g.nodeIndex == nil {
		g.buildIndex()
	}

	var allPaths []AttackPath

	// Find paths from all entry points to all targets
	for _, entry := range g.EntryPoints {
		for _, target := range g.Targets {
			paths := g.FindAllPaths(entry, target, 10)
			allPaths = append(allPaths, paths...)
		}
	}

	// Sort by risk score (descending)
	for i := 0; i < len(allPaths); i++ {
		for j := i + 1; j < len(allPaths); j++ {
			if allPaths[j].RiskScore > allPaths[i].RiskScore {
				allPaths[i], allPaths[j] = allPaths[j], allPaths[i]
			}
		}
	}

	// Return top N paths
	if limit > 0 && len(allPaths) > limit {
		return allPaths[:limit]
	}
	return allPaths
}

// ReachabilityAnalysis determines which nodes are reachable from entry points
func (g *AttackGraph) ReachabilityAnalysis() *PathAnalysisResult {
	if g.nodeIndex == nil {
		g.buildIndex()
	}

	result := &PathAnalysisResult{}

	// BFS from all entry points
	visited := make(map[string]bool)
	queue := make([]string, 0, len(g.EntryPoints))
	queue = append(queue, g.EntryPoints...)

	for _, entry := range g.EntryPoints {
		visited[entry] = true
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result.ReachableNodes = append(result.ReachableNodes, current)

		for _, edge := range g.GetOutgoingEdges(current) {
			if !visited[edge.Target] {
				visited[edge.Target] = true
				queue = append(queue, edge.Target)
			}
		}
	}

	// Check which targets are unreachable
	for _, target := range g.Targets {
		if !visited[target] {
			result.UnreachableTargets = append(result.UnreachableTargets, target)
		}
	}

	return result
}

// AnalyzePaths performs comprehensive path analysis
func (g *AttackGraph) AnalyzePaths() *PathAnalysisResult {
	result := g.ReachabilityAnalysis()

	// Find critical paths
	result.CriticalPaths = g.FindCriticalPaths(5)

	// Find shortest paths from each entry to each target
	for _, entry := range g.EntryPoints {
		for _, target := range g.Targets {
			if path := g.FindShortestPath(entry, target); path != nil {
				if result.ShortestPath == nil || path.TotalWeight < result.ShortestPath.TotalWeight {
					result.ShortestPath = path
				}
			}
		}
	}

	return result
}
