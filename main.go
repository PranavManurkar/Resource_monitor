package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"resmon/cgroup"
	"resmon/proc"
)

func ClearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}

func main() {
	cm, err := cgroup.NewManager()
	if err != nil {
		fmt.Printf("Error initializing cgroup manager: %v\n", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		ClearScreen()
		fmt.Println("Shutting down monitor... Restoring process states...")
		cm.Cleanup()
		os.Exit(0)
	}()

	collector := proc.NewCollector()
	collector.CollectSnapshots()

	ClearScreen()
	fmt.Println("Initializing process monitor... Computing CPU baseline (1s)...")
	time.Sleep(1 * time.Second)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	const maxTreesToDisplay = 5
	const targetCoreLimit = 1.5 // cores a throttled tree is capped to

	// A throttled tree's subtree CPU (normalized against total system capacity)
	// will hover around this value while it's still busy but capped, e.g. 1.5
	// cores out of 12 total ≈ 12.5%. The release threshold must sit clearly
	// below this - not below some arbitrary fixed number - or we'd release
	// trees that are still saturating their cap and immediately re-throttle
	// them next tick.
	cgroupCapPercent := (targetCoreLimit / float64(cgroup.GetSystemCoreCount())) * 100.0
	cpuReleaseThreshold := cgroupCapPercent * 0.5

	for range ticker.C {
		ClearScreen()

		rawProcMap := collector.CollectSnapshots()
		userNodeMap := proc.BuildUserProcessTree(rawProcMap, true)

		// Create a fast lookup map of all currently active PIDs
		activePIDs := make(map[int]bool, len(rawProcMap))
		for pid := range rawProcMap {
			activePIDs[pid] = true
		}

		// Clean up cgroups for processes that have terminated
		cm.ReconcileThrottledPIDs(activePIDs)

		var rootNodes []*proc.ProcessNode
		var alerts []string

		// 1. Calculate subtree metrics for all nodes
		for _, node := range userNodeMap {
			node.AggregateMetrics()
			node.SortChildrenByCPU()

			_, parentInUserSpace := userNodeMap[node.Stats.PPID]
			if !parentInUserSpace {
				rootNodes = append(rootNodes, node)
			}
		}

		// 2. Evaluate Thresholds & Throttling
		const cpuHighThreshold = 40.0 // 40% system CPU triggers throttle

		for _, node := range userNodeMap {
			isThrottled := cm.IsThrottled(node.Stats.PID)

			// Case A: Process tree exceeds threshold and isn't throttled yet -> Throttle it
			if !isThrottled && node.TotalSubtreeCPU >= cpuHighThreshold {
				allSubtreePIDs := node.GetAllSubtreePIDs()
				err := cm.ThrottleTree(node.Stats.PID, allSubtreePIDs, targetCoreLimit)
				if err != nil {
					alerts = append(alerts, fmt.Sprintf("\033[1;33m [Cgroup Error] Could not throttle PID %d: %v\033[0m", node.Stats.PID, err))
				} else {
					isThrottled = true
				}
			}

			if isThrottled {
				// Case B: Currently throttled but load has actually died down -> release it.
				// Without this, a tree only ever gets unthrottled once every PID inside it
				// has fully exited (see ReconcileThrottledPIDs), so a still-alive parent
				// (e.g. the shell that spawned the heavy children) keeps the cgroup - and
				// the alert banner - around forever even after the heavy work is gone.
				if node.TotalSubtreeCPU < cpuReleaseThreshold {
					cm.UnthrottleTree(node.Stats.PID)
					continue
				}

				// Case C: Still throttled and still hot -> keep the alert banner up.
				alertMsg := fmt.Sprintf("\033[1;31m ⚠️ ALERT: Process Tree [%d] (%s) THROTTLED! (Subtree CPU: %.1f%% -> Cap: %.1f Cores)\033[0m",
					node.Stats.PID, node.Stats.Comm, node.TotalSubtreeCPU, targetCoreLimit)
				alerts = append(alerts, alertMsg)
			}
		}

		proc.SortRootsByCPU(rootNodes)

		// Render Dashboard Header
		fmt.Println("==========================================================================================================")
		fmt.Printf(" LIVE USER PROCESS MONITOR & GOVERNOR | %s | Cores: %d | Active Trees: %d\n",
			time.Now().Format("15:04:05"), cgroup.GetSystemCoreCount(), len(rootNodes))
		fmt.Println("==========================================================================================================")

		if len(alerts) > 0 {
			fmt.Println(" ACTIVE RESOURCE ALERTS & CGROUP THROTTLES:")
			for _, alert := range alerts {
				fmt.Println(alert)
			}
			fmt.Println("----------------------------------------------------------------------------------------------------------")
		}

		if len(rootNodes) == 0 {
			fmt.Println("No active user process trees detected.")
			continue
		}

		displayCount := len(rootNodes)
		if displayCount > maxTreesToDisplay {
			displayCount = maxTreesToDisplay
		}

		for i := 0; i < displayCount; i++ {
			root := rootNodes[i]
			proc.PrintTree(root, "", true)
			fmt.Println("----------------------------------------------------------------------------------------------------------")
		}
	}
}