package ir

// GraphNodeType represents the type of node in an attack graph
type GraphNodeType string

const (
	GraphNodeTypeElement GraphNodeType = "element"
	GraphNodeTypeThreat  GraphNodeType = "threat"
	GraphNodeTypeControl GraphNodeType = "control"
	GraphNodeTypeAsset   GraphNodeType = "asset"
	GraphNodeTypeActor   GraphNodeType = "actor"
)

// GraphEdgeType represents the type of edge in an attack graph
type GraphEdgeType string

const (
	GraphEdgeTypeFlow       GraphEdgeType = "flow"
	GraphEdgeTypeAttack     GraphEdgeType = "attack"
	GraphEdgeTypeMitigation GraphEdgeType = "mitigation"
	GraphEdgeTypeThreat     GraphEdgeType = "threat"
	GraphEdgeTypeAccess     GraphEdgeType = "access"
)

// GraphNode represents a node in the attack graph
type GraphNode struct {
	// ID is the unique identifier for this node
	ID string `json:"id"`

	// Type identifies what kind of node this is
	Type GraphNodeType `json:"type"`

	// Label is the human-readable name
	Label string `json:"label"`

	// RiskScore is the node's inherent risk (0-10)
	RiskScore float64 `json:"riskScore,omitempty"`

	// Properties contains additional node-specific data
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// GraphEdge represents a directed edge in the attack graph
type GraphEdge struct {
	// ID is the unique identifier for this edge
	ID string `json:"id"`

	// Source is the ID of the source node
	Source string `json:"source"`

	// Target is the ID of the target node
	Target string `json:"target"`

	// Type identifies the edge relationship type
	Type GraphEdgeType `json:"type"`

	// Label describes the edge
	Label string `json:"label,omitempty"`

	// Weight represents the traversal cost/risk (higher = more costly/risky)
	Weight float64 `json:"weight,omitempty"`

	// Properties contains additional edge-specific data
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// AttackGraph represents a directed graph of attack paths
type AttackGraph struct {
	// ID is the unique identifier for this graph
	ID string `json:"id,omitempty"`

	// ThreatModelID links to the source threat model
	ThreatModelID string `json:"threatModelId,omitempty"`

	// Nodes contains all nodes in the graph
	Nodes []GraphNode `json:"nodes"`

	// Edges contains all edges in the graph
	Edges []GraphEdge `json:"edges"`

	// EntryPoints lists node IDs that are potential entry points
	EntryPoints []string `json:"entryPoints,omitempty"`

	// Targets lists node IDs that are high-value targets
	Targets []string `json:"targets,omitempty"`

	// nodeIndex maps node IDs to nodes for fast lookup
	nodeIndex map[string]*GraphNode

	// adjacency maps source node ID to list of edges
	adjacency map[string][]GraphEdge
}

// NewAttackGraph creates a new empty attack graph
func NewAttackGraph(id string) *AttackGraph {
	return &AttackGraph{
		ID:        id,
		Nodes:     []GraphNode{},
		Edges:     []GraphEdge{},
		nodeIndex: make(map[string]*GraphNode),
		adjacency: make(map[string][]GraphEdge),
	}
}

// AddNode adds a node to the graph
func (g *AttackGraph) AddNode(node GraphNode) {
	g.Nodes = append(g.Nodes, node)
	g.nodeIndex[node.ID] = &g.Nodes[len(g.Nodes)-1]
}

// AddEdge adds an edge to the graph
func (g *AttackGraph) AddEdge(edge GraphEdge) {
	g.Edges = append(g.Edges, edge)
	g.adjacency[edge.Source] = append(g.adjacency[edge.Source], edge)
}

// GetNode returns a node by ID
func (g *AttackGraph) GetNode(id string) *GraphNode {
	if g.nodeIndex == nil {
		g.buildIndex()
	}
	return g.nodeIndex[id]
}

// GetOutgoingEdges returns all edges leaving from a node
func (g *AttackGraph) GetOutgoingEdges(nodeID string) []GraphEdge {
	if g.adjacency == nil {
		g.buildIndex()
	}
	return g.adjacency[nodeID]
}

// GetNeighbors returns all nodes directly reachable from a given node
func (g *AttackGraph) GetNeighbors(nodeID string) []string {
	edges := g.GetOutgoingEdges(nodeID)
	neighbors := make([]string, 0, len(edges))
	for _, e := range edges {
		neighbors = append(neighbors, e.Target)
	}
	return neighbors
}

// buildIndex builds the internal indices for fast lookup
func (g *AttackGraph) buildIndex() {
	g.nodeIndex = make(map[string]*GraphNode)
	g.adjacency = make(map[string][]GraphEdge)

	for i := range g.Nodes {
		g.nodeIndex[g.Nodes[i].ID] = &g.Nodes[i]
	}

	for _, edge := range g.Edges {
		g.adjacency[edge.Source] = append(g.adjacency[edge.Source], edge)
	}
}

// NodeCount returns the number of nodes in the graph
func (g *AttackGraph) NodeCount() int {
	return len(g.Nodes)
}

// EdgeCount returns the number of edges in the graph
func (g *AttackGraph) EdgeCount() int {
	return len(g.Edges)
}

// BuildAttackGraphFromDiagram creates an attack graph from a DiagramIR
func BuildAttackGraphFromDiagram(diagram *DiagramIR) *AttackGraph {
	if diagram == nil {
		return nil
	}

	graph := NewAttackGraph(diagram.Title)
	graph.ThreatModelID = diagram.Title

	// Add elements as nodes
	for _, elem := range diagram.Elements {
		var nodeType GraphNodeType
		switch elem.Type {
		case ElementTypeExternalEntity:
			nodeType = GraphNodeTypeActor
		case ElementTypeDatastore:
			nodeType = GraphNodeTypeAsset
		default:
			nodeType = GraphNodeTypeElement
		}

		graph.AddNode(GraphNode{
			ID:    elem.ID,
			Type:  nodeType,
			Label: elem.Label,
		})
	}

	// Add flows as edges
	for i, flow := range diagram.Flows {
		edgeID := ""
		if i > 0 {
			edgeID = string(rune('f' + i))
		} else {
			edgeID = "f0"
		}
		graph.AddEdge(GraphEdge{
			ID:     edgeID,
			Source: flow.From,
			Target: flow.To,
			Type:   GraphEdgeTypeFlow,
			Label:  flow.Label,
		})
	}

	// Add attacks as edges with attack type
	for _, attack := range diagram.Attacks {
		edgeID := ""
		if attack.Step > 0 {
			edgeID = string(rune('a' + attack.Step - 1))
		}
		graph.AddEdge(GraphEdge{
			ID:     edgeID,
			Source: attack.From,
			Target: attack.To,
			Type:   GraphEdgeTypeAttack,
			Label:  attack.Label,
			Weight: float64(attack.Step), // Use step as weight for ordering
		})
	}

	// Add threats as nodes
	for _, threat := range diagram.Threats {
		graph.AddNode(GraphNode{
			ID:        threat.ID,
			Type:      GraphNodeTypeThreat,
			Label:     threat.Title,
			RiskScore: float64(threat.Risk.Likelihood) * float64(threat.Risk.Impact) / 25.0 * 10.0,
		})

		// Connect threats to affected elements
		for _, elemID := range threat.AffectedElements {
			graph.AddEdge(GraphEdge{
				Source: threat.ID,
				Target: elemID,
				Type:   GraphEdgeTypeThreat,
				Label:  "threatens",
			})
		}
	}

	// Add mitigations as nodes and edges
	for _, mit := range diagram.Mitigations {
		graph.AddNode(GraphNode{
			ID:    mit.ID,
			Type:  GraphNodeTypeControl,
			Label: mit.Title,
		})

		// Connect mitigations to threats they address
		for _, threatID := range mit.ThreatIDs {
			graph.AddEdge(GraphEdge{
				Source: mit.ID,
				Target: threatID,
				Type:   GraphEdgeTypeMitigation,
				Label:  "mitigates",
			})
		}
	}

	return graph
}
