package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const CgroupRoot = "/sys/fs/cgroup"

type Manager struct {
	mu            sync.Mutex
	throttledPIDs map[int]string
}

func NewManager() (*Manager, error) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); os.IsNotExist(err) {
		return nil, fmt.Errorf("cgroup v2 hierarchy not found at /sys/fs/cgroup")
	}

	return &Manager{
		throttledPIDs: make(map[int]string),
	}, nil
}

// ThrottleTree sets an effective multi-core quota and lowers process scheduling priority
func (m *Manager) ThrottleTree(rootPID int, allPIDs []int, targetCores float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cgroupDir := filepath.Join(CgroupRoot, fmt.Sprintf("resmon_job_%d", rootPID))

	if err := os.MkdirAll(cgroupDir, 0755); err != nil {
		return fmt.Errorf("mkdir cgroup failed: %w", err)
	}

	// 1. Calculate quota scaled by cores
	// TargetCores = 1.5 means 1.5 full cores max (150000 / 100000)
	period := 100000
	quota := int(targetCores * float64(period))
	if quota < 10000 {
		quota = 10000 // Floor at 10% of 1 core
	}

	limitStr := fmt.Sprintf("%d %d", quota, period)
	err := os.WriteFile(filepath.Join(cgroupDir, "cpu.max"), []byte(limitStr), 0644)
	if err != nil {
		fmt.Printf("\033[1;33m[Cgroup Notice] Writing cpu.max failed (PID %d): %v\033[0m\n", rootPID, err)
	}

	// 2. Attach processes to cgroup and lower priority (nice level 15)
	procsFile := filepath.Join(cgroupDir, "cgroup.procs")
	for _, pid := range allPIDs {
		_ = os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0644)

		// Set low execution priority (nice 15) so background tasks yield to desktop UI
		_ = syscall.Setpriority(syscall.PRIO_PROCESS, pid, 15)
	}

	m.throttledPIDs[rootPID] = cgroupDir
	return nil
}

func (m *Manager) IsThrottled(rootPID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.throttledPIDs[rootPID]
	return exists
}

func (m *Manager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	defaultProcsPath := "/sys/fs/cgroup/cgroup.procs"

	for pid, cgroupDir := range m.throttledPIDs {
		data, err := os.ReadFile(filepath.Join(cgroupDir, "cgroup.procs"))
		if err == nil {
			pids := strings.Fields(string(data))
			for _, pStr := range pids {
				_ = os.WriteFile(defaultProcsPath, []byte(pStr), 0644)
				if p, parseErr := strconv.Atoi(pStr); parseErr == nil {
					// Reset process priority back to normal (nice 0)
					_ = syscall.Setpriority(syscall.PRIO_PROCESS, p, 0)
				}
			}
		}
		_ = os.Remove(cgroupDir)
		delete(m.throttledPIDs, pid)
	}
}

// GetSystemCoreCount returns total available CPU threads
func GetSystemCoreCount() int {
	return runtime.NumCPU()
}

// ReconcileThrottledPIDs removes cgroups for PIDs that are no longer running
// ReconcileThrottledPIDs checks all tracked cgroups and cleans up empty or dead ones
func (m *Manager) ReconcileThrottledPIDs(activePIDs map[int]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for rootPID, cgroupDir := range m.throttledPIDs {
		procsFile := filepath.Join(cgroupDir, "cgroup.procs")
		data, err := os.ReadFile(procsFile)

		// Case 1: Cgroup folder missing or unreadable -> Clean up map entry
		if err != nil {
			delete(m.throttledPIDs, rootPID)
			continue
		}

		// Case 2: Read PIDs inside the cgroup
		pidsInCgroup := strings.Fields(string(data))
		
		// Count how many processes inside this cgroup are still alive in /proc
		aliveCount := 0
		for _, pStr := range pidsInCgroup {
			if pid, parseErr := strconv.Atoi(pStr); parseErr == nil {
				if activePIDs[pid] {
					aliveCount++
				}
			}
		}

		// If no processes in the cgroup are running anymore (or parent died and cgroup is empty)
		if aliveCount == 0 || len(pidsInCgroup) == 0 {
			_ = os.Remove(cgroupDir)
			delete(m.throttledPIDs, rootPID)
		}
	}
}

// UnthrottleTree moves processes back to default cgroup and deletes the job cgroup
func (m *Manager) UnthrottleTree(rootPID int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cgroupDir, exists := m.throttledPIDs[rootPID]
	if !exists {
		return
	}

	defaultProcsPath := "/sys/fs/cgroup/cgroup.procs"

	// Read attached processes and return them to the default cgroup
	data, err := os.ReadFile(filepath.Join(cgroupDir, "cgroup.procs"))
	if err == nil {
		pids := strings.Fields(string(data))
		for _, pStr := range pids {
			_ = os.WriteFile(defaultProcsPath, []byte(pStr), 0644)
			if p, parseErr := strconv.Atoi(pStr); parseErr == nil {
				// Restore normal process scheduling priority (nice 0)
				_ = syscall.Setpriority(syscall.PRIO_PROCESS, p, 0)
			}
		}
	}

	// Remove cgroup directory and remove from map
	_ = os.Remove(cgroupDir)
	delete(m.throttledPIDs, rootPID)
}