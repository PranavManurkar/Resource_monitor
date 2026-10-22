package proc

import (
	"fmt"
	"sort"
)

type ProcessNode struct {
	Stats           *ProcessStats
	Children        []*ProcessNode
	TotalSubtreeCPU float64
	TotalSubtreeRAM uint64
}

// SortChildrenByCPU sorts immediate children of a node by TotalSubtreeCPU descending
func (n *ProcessNode) SortChildrenByCPU() {
	sort.Slice(n.Children, func(i, j int) bool {
		return n.Children[i].TotalSubtreeCPU > n.Children[j].TotalSubtreeCPU
	})

	// Recursively sort children of children
	for _, child := range n.Children {
		child.SortChildrenByCPU()
	}
}

// SortRootsByCPU sorts a slice of root nodes by TotalSubtreeCPU descending
func SortRootsByCPU(roots []*ProcessNode) {
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].TotalSubtreeCPU > roots[j].TotalSubtreeCPU
	})
}

// (Keep your existing BuildUserProcessTree, AggregateMetrics, and PrintTree functions below)


// BuildUserProcessTree forms parent-child linkages for user processes sequentially
func BuildUserProcessTree(procMap map[int]*ProcessStats, filterUserOnly bool) map[int]*ProcessNode {
	nodeMap := make(map[int]*ProcessNode)

	for pid, stat := range procMap {
		if filterUserOnly && !IsUserProcess(stat) {
			continue
		}
		nodeMap[pid] = &ProcessNode{
			Stats:    stat,
			Children: make([]*ProcessNode, 0),
		}
	}

	for pid, node := range nodeMap {
		ppid := node.Stats.PPID
		if parent, exists := nodeMap[ppid]; exists && pid != ppid {
			parent.Children = append(parent.Children, node)
		}
	}

	return nodeMap
}

// AggregateMetrics calculates combined CPU & RAM for a node and all its children
func (n *ProcessNode) AggregateMetrics() (float64, uint64) {
	totalCPU := n.Stats.CPUUsage
	totalRAM := n.Stats.RAMBytes

	for _, child := range n.Children {
		childCPU, childRAM := child.AggregateMetrics()
		totalCPU += childCPU
		totalRAM += childRAM
	}

	n.TotalSubtreeCPU = totalCPU
	n.TotalSubtreeRAM = totalRAM
	return totalCPU, totalRAM
}

// PrintTree renders subtree structure to standard output
func PrintTree(node *ProcessNode, indent string, isLast bool) {
	marker := "├── "
	if isLast {
		marker = "└── "
	}

	ramMB := float64(node.TotalSubtreeRAM) / (1024 * 1024)

	fmt.Printf("%s%s[%d] %-16s | Self CPU: %5.1f%% | Subtree CPU: %5.1f%% | Subtree RAM: %6.1f MB\n",
		indent, marker, node.Stats.PID, node.Stats.Comm, node.Stats.CPUUsage, node.TotalSubtreeCPU, ramMB)

	childIndent := indent
	if isLast {
		childIndent += "    "
	} else {
		childIndent += "│   "
	}

	for i, child := range node.Children {
		PrintTree(child, childIndent, i == len(node.Children)-1)
	}
}

func (n *ProcessNode) GetAllSubtreePIDs() []int {
	pids := []int{n.Stats.PID}
	for _, child := range n.Children {
		pids = append(pids, child.GetAllSubtreePIDs()...)
	}
	return pids
}