package proc

import "strings"

// IsUserProcess isolates user-generated processes from system daemons and kernel threads
func IsUserProcess(stat *ProcessStats) bool {
	// 1. Skip Kernel Threads immediately
	if stat.IsKernel || stat.Vsize == 0 {
		return false
	}

	// 2. Skip root init (PID 1) and kernel parent (PPID 0)
	if stat.PID == 1 || stat.PPID == 0 {
		return false
	}

	// 3. Skip systemd background system services
	if strings.Contains(stat.Cgroup, "system.slice") {
		return false
	}

	// 4. Require regular user account (UID >= 1000) OR placement inside user.slice
	isRegularUser := stat.UID >= 1000
	isInUserSlice := strings.Contains(stat.Cgroup, "user.slice") || strings.Contains(stat.Cgroup, "user-")

	return isRegularUser || isInUserSlice
}