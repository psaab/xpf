// Package sysinfo provides shared host-system information renderers.
package sysinfo

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// WriteProcessesSummary writes the Junos-style process summary shared by the
// embedded and remote CLIs. psOutput is captured by each caller's bounded
// process-execution path.
func WriteProcessesSummary(w io.Writer, psOutput []byte) {
	loadAvg := "0.00, 0.00, 0.00"
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			loadAvg = fmt.Sprintf("%s, %s, %s", fields[0], fields[1], fields[2])
		}
	}

	uptimeStr := ""
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			if secs, err := strconv.ParseFloat(fields[0], 64); err == nil {
				days := int(secs) / 86400
				hours := (int(secs) % 86400) / 3600
				mins := (int(secs) % 3600) / 60
				if days > 0 {
					uptimeStr = fmt.Sprintf("up %d+%02d:%02d", days, hours, mins)
				} else {
					uptimeStr = fmt.Sprintf("up %02d:%02d", hours, mins)
				}
			}
		}
	}

	var memTotal, memFree, memAvailable, memBuffers, memCached, swapTotal, swapFree uint64
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			val *= 1024
			switch strings.TrimSuffix(fields[0], ":") {
			case "MemTotal":
				memTotal = val
			case "MemFree":
				memFree = val
			case "MemAvailable":
				memAvailable = val
			case "Buffers":
				memBuffers = val
			case "Cached":
				memCached = val
			case "SwapTotal":
				swapTotal = val
			case "SwapFree":
				swapFree = val
			}
		}
	}
	memUsed := memTotal - memFree - memBuffers - memCached
	if memTotal < memFree+memBuffers+memCached {
		memUsed = memTotal - memAvailable
	}

	var userPct, sysPct, idlePct float64
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				user, _ := strconv.ParseFloat(fields[1], 64)
				nice, _ := strconv.ParseFloat(fields[2], 64)
				system, _ := strconv.ParseFloat(fields[3], 64)
				idle, _ := strconv.ParseFloat(fields[4], 64)
				total := user + nice + system + idle
				if len(fields) >= 8 {
					iowait, _ := strconv.ParseFloat(fields[5], 64)
					irq, _ := strconv.ParseFloat(fields[6], 64)
					softirq, _ := strconv.ParseFloat(fields[7], 64)
					total += iowait + irq + softirq
				}
				if total > 0 {
					userPct = (user + nice) / total * 100
					sysPct = system / total * 100
					idlePct = idle / total * 100
				}
			}
			break
		}
	}

	var running, sleeping, stopped, zombie int
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if _, err := strconv.Atoi(entry.Name()); err != nil {
				continue
			}
			data, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
			if err != nil {
				continue
			}
			line := string(data)
			idx := strings.LastIndex(line, ") ")
			if idx < 0 || idx+2 >= len(line) {
				continue
			}
			switch line[idx+2 : idx+3] {
			case "R":
				running++
			case "S", "D", "I":
				sleeping++
			case "T", "t":
				stopped++
			case "Z":
				zombie++
			}
		}
	}
	totalTasks := running + sleeping + stopped + zombie

	fmt.Fprintf(w, "load averages: %s  %s    %s\n", loadAvg, uptimeStr, time.Now().Format("15:04:05"))
	fmt.Fprintf(w, "%d processes: %d running, %d sleeping, %d stopped, %d zombie\n",
		totalTasks, running, sleeping, stopped, zombie)
	fmt.Fprintf(w, "CPU: %.1f%% user, %.1f%% system, %.1f%% idle\n", userPct, sysPct, idlePct)
	fmt.Fprintf(w, "Mem: %s Active, %s Buf, %s Cached, %s Free\n",
		formatBytes(memUsed), formatBytes(memBuffers), formatBytes(memCached), formatBytes(memFree))
	fmt.Fprintf(w, "Swap: %s Total, %s Free\n\n", formatBytes(swapTotal), formatBytes(swapFree))

	lines := strings.Split(strings.TrimSpace(string(psOutput)), "\n")
	fmt.Fprintln(w, "  PID USERNAME    PRI NICE   SIZE    RES STATE   TIME    WCPU COMMAND")
	limit := 20
	if len(lines)-1 < limit {
		limit = len(lines) - 1
	}
	for i := 1; i <= limit; i++ {
		fields := strings.Fields(lines[i])
		if len(fields) < 10 {
			continue
		}
		vsz, _ := strconv.ParseUint(fields[4], 10, 64)
		rss, _ := strconv.ParseUint(fields[5], 10, 64)
		fmt.Fprintf(w, "%5s %-11s %4s %4s %7s %7s %-7s %8s %6s%% %s\n",
			fields[0], fields[1], fields[2], fields[3],
			formatBytes(vsz*1024), formatBytes(rss*1024), fields[6], fields[7], fields[8], fields[9])
	}
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
