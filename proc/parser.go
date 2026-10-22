package proc

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProcessStats holds raw process metadata read from /proc
type ProcessStats struct {
	PID       int
	Comm      string
	State     string
	PPID      int
	Utime     uint64
	Stime     uint64
	Vsize     uint64
	Rss       uint64
	RAMBytes  uint64
	UID       int
	Cgroup    string
	IsKernel  bool
	CPUUsage  float64   // Populated by Collector
	Timestamp time.Time // Capture timestamp
}

// TotalTicks returns cumulative user + system CPU clock ticks
func (p *ProcessStats) TotalTicks() uint64 {
	return p.Utime + p.Stime
}

// ReadProcessStat reads and parses a single PID's status from /proc
func ReadProcessStat(pid int) (*ProcessStats, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return nil, err
	}

	line := string(data)
	openParen := strings.Index(line, "(")
	closeParen := strings.LastIndex(line, ")")
	if openParen == -1 || closeParen == -1 || closeParen <= openParen {
		return nil, fmt.Errorf("malformed stat for PID %d", pid)
	}

	parsedPID, err := strconv.Atoi(strings.TrimSpace(line[:openParen]))
	if err != nil {
		return nil, err
	}

	comm := line[openParen+1 : closeParen]
	fields := strings.Fields(strings.TrimSpace(line[closeParen+1:]))

	if len(fields) < 22 {
		return nil, fmt.Errorf("insufficient fields for PID %d", pid)
	}

	state := fields[0]
	ppid, _ := strconv.Atoi(fields[1])
	flags, _ := strconv.ParseUint(fields[6], 10, 64)
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)
	vsize, _ := strconv.ParseUint(fields[20], 10, 64)
	rssPages, _ := strconv.ParseUint(fields[21], 10, 64)

	const PF_KTHREAD = 0x00200000
	isKernel := (flags&PF_KTHREAD != 0) || (vsize == 0)
	pageSize := uint64(os.Getpagesize())

	return &ProcessStats{
		PID:       parsedPID,
		Comm:      comm,
		State:     state,
		PPID:      ppid,
		Utime:     utime,
		Stime:     stime,
		Vsize:     vsize,
		Rss:       rssPages,
		RAMBytes:  rssPages * pageSize,
		UID:       readUID(pid),
		Cgroup:    readCgroup(pid),
		IsKernel:  isKernel,
		Timestamp: time.Now(),
	}, nil
}

func readUID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, _ := strconv.Atoi(fields[1])
				return uid
			}
		}
	}
	return -1
}

func readCgroup(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	return string(data)
}

// GetAllPIDs discovers numeric directories under /proc
func GetAllPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var pids []int
	for _, entry := range entries {
		if entry.IsDir() {
			if pid, err := strconv.Atoi(entry.Name()); err == nil {
				pids = append(pids, pid)
			}
		}
	}
	return pids, nil
}