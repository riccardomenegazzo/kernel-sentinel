package evidence

import (
	"sort"
	"sync"
	"time"
)

type Kind string

const (
	KindRuntime    Kind = "runtime"
	KindMetric     Kind = "metric"
	KindTrace      Kind = "trace"
	KindKubernetes Kind = "kubernetes"
	KindDeployment Kind = "deployment"
	KindDecision   Kind = "decision"
)

type Node struct {
	ID         string            `json:"id"`
	Kind       Kind              `json:"kind"`
	ObservedAt time.Time         `json:"observed_at"`
	Source     string            `json:"source"`
	Summary    string            `json:"summary"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Confidence float64           `json:"confidence,omitempty"`
}

type Edge struct {
	From     string  `json:"from"`
	To       string  `json:"to"`
	Relation string  `json:"relation"`
	Weight   float64 `json:"weight,omitempty"`
}

type Snapshot struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Graph struct {
	mu    sync.RWMutex
	nodes map[string]Node
	edges []Edge
}

func New() *Graph { return &Graph{nodes: make(map[string]Node)} }

func (g *Graph) Add(n Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n.Attributes == nil {
		n.Attributes = map[string]string{}
	}
	g.nodes[n.ID] = n
}

func (g *Graph) Link(e Edge) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.nodes[e.From]; !ok {
		return false
	}
	if _, ok := g.nodes[e.To]; !ok {
		return false
	}
	g.edges = append(g.edges, e)
	return true
}

func (g *Graph) Snapshot() Snapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	nodes := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].ObservedAt.Equal(nodes[j].ObservedAt) {
			return nodes[i].ID < nodes[j].ID
		}
		return nodes[i].ObservedAt.Before(nodes[j].ObservedAt)
	})
	edges := append([]Edge(nil), g.edges...)
	return Snapshot{Nodes: nodes, Edges: edges}
}
