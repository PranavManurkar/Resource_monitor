package proc

import (
	"runtime"
	"sync"
)

// ScanAllProcessesConcurrent uses worker routines to scan /proc
func ScanAllProcessesConcurrent() map[int]*ProcessStats {
	pids, err := GetAllPIDs()
	if err != nil || len(pids) == 0 {
		return nil
	}

	numPIDs := len(pids)
	numWorkers := runtime.NumCPU() * 2
	if numWorkers > 16 {
		numWorkers = 16
	}

	jobs := make(chan int, numPIDs)
	results := make(chan *ProcessStats, numPIDs)
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pid := range jobs {
				stat, err := ReadProcessStat(pid)
				if err == nil && stat != nil {
					results <- stat
				}
			}
		}()
	}

	for _, pid := range pids {
		jobs <- pid
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	processes := make(map[int]*ProcessStats, numPIDs)
	for stat := range results {
		processes[stat.PID] = stat
	}

	return processes
}

// Collector tracks previous state to calculate delta CPU percentage
type Collector struct {
	previousSnapshots map[int]*ProcessStats
}

func NewCollector() *Collector {
	return &Collector{
		previousSnapshots: make(map[int]*ProcessStats),
	}
}

// CollectSnapshots computes CPU % over the time window between scans
func (c *Collector) CollectSnapshots() map[int]*ProcessStats {
	currentSnapshots := ScanAllProcessesConcurrent()
	numCPU := float64(runtime.NumCPU())
	clockTicksPerSec := 100.0 // Linux default sysconf(_SC_CLK_TCK)

	for pid, curr := range currentSnapshots {
		if prev, exists := c.previousSnapshots[pid]; exists {
			dt := curr.Timestamp.Sub(prev.Timestamp).Seconds()
			if dt > 0 {
				deltaTicks := float64(curr.TotalTicks() - prev.TotalTicks())
				procSeconds := deltaTicks / clockTicksPerSec
				cpuPercent := (procSeconds / (dt * numCPU)) * 100.0

				if cpuPercent < 0 {
					cpuPercent = 0
				}
				curr.CPUUsage = cpuPercent
			}
		} else {
			curr.CPUUsage = 0.0
		}
	}

	c.previousSnapshots = currentSnapshots
	return currentSnapshots
}