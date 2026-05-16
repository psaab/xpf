package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"golang.org/x/sys/unix"
)

// readLinkSpeed reads the link speed in Mbps from sysfs. Returns 0 on error.

func (c *CLI) showSystemBuffers() error {
	if c.dp == nil {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	if provider, ok := c.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); ok {
		status, err := provider.Status()
		if err != nil {
			fmt.Printf("Userspace buffer metrics unavailable: %v\n", err)
			return nil
		}
		fmt.Print(dpuserspace.FormatSystemBuffers(status, false))
		return nil
	}
	stats := c.dp.GetMapStats()
	if len(stats) == 0 {
		fmt.Println("No BPF maps available")
		return nil
	}
	fmt.Printf("%-24s %-14s %10s %10s %8s %s\n", "Map", "Type", "Max", "Used", "Usage%", "Status")
	fmt.Println(strings.Repeat("-", 78))
	var warnings int
	for _, s := range stats {
		usage := ""
		status := ""
		if s.MaxEntries > 0 && s.Type != "Array" && s.Type != "PerCPUArray" {
			pct := float64(s.UsedCount) / float64(s.MaxEntries) * 100
			usage = fmt.Sprintf("%.1f%%", pct)
			if pct >= 90 {
				status = "CRITICAL"
				warnings++
			} else if pct >= 80 {
				status = "WARNING"
				warnings++
			}
		} else {
			usage = "-"
		}
		used := fmt.Sprintf("%d", s.UsedCount)
		if s.Type == "Array" || s.Type == "PerCPUArray" {
			used = "-"
		}
		fmt.Printf("%-24s %-14s %10d %10s %8s %s\n", s.Name, s.Type, s.MaxEntries, used, usage, status)
	}
	if warnings > 0 {
		fmt.Printf("\n%d map(s) at high utilization — consider increasing max_entries\n", warnings)
	}

	// Session counts
	v4, v6 := c.dp.SessionCount()
	if v4 > 0 || v6 > 0 {
		fmt.Printf("\nActive sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
	}
	return nil
}

func (c *CLI) showSystemBuffersDetail() error {
	if c.dp == nil {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	if provider, ok := c.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); ok {
		status, err := provider.Status()
		if err != nil {
			fmt.Printf("Userspace buffer metrics unavailable: %v\n", err)
			return nil
		}
		fmt.Print(dpuserspace.FormatSystemBuffers(status, true))
		return nil
	}
	stats := c.dp.GetMapStats()
	if len(stats) == 0 {
		fmt.Println("No BPF maps available")
		return nil
	}

	// Filter out Array/PerCPUArray types (always "full") and compute usage
	type mapDetail struct {
		name       string
		mapType    string
		maxEntries uint32
		usedCount  uint32
		keySize    uint32
		valueSize  uint32
		pct        float64
	}
	var details []mapDetail
	for _, s := range stats {
		if s.Type == "Array" || s.Type == "PerCPUArray" {
			continue
		}
		pct := float64(0)
		if s.MaxEntries > 0 {
			pct = float64(s.UsedCount) / float64(s.MaxEntries) * 100
		}
		details = append(details, mapDetail{
			name:       s.Name,
			mapType:    s.Type,
			maxEntries: s.MaxEntries,
			usedCount:  s.UsedCount,
			keySize:    s.KeySize,
			valueSize:  s.ValueSize,
			pct:        pct,
		})
	}

	// Sort by usage percentage descending
	sort.Slice(details, func(i, j int) bool {
		return details[i].pct > details[j].pct
	})

	fmt.Printf("BPF Map Details (sorted by utilization):\n\n")
	for _, d := range details {
		status := "OK"
		if d.pct >= 90 {
			status = "CRITICAL"
		} else if d.pct >= 80 {
			status = "WARNING"
		}
		fmt.Printf("Map: %s\n", d.name)
		fmt.Printf("  Type: %s, Max: %d, Used: %d, Usage: %.1f%%\n", d.mapType, d.maxEntries, d.usedCount, d.pct)
		fmt.Printf("  Key size: %d bytes, Value size: %d bytes\n", d.keySize, d.valueSize)
		fmt.Printf("  Status: %s\n\n", status)
	}

	// Session counts
	v4, v6 := c.dp.SessionCount()
	if v4 > 0 || v6 > 0 {
		fmt.Printf("Active sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
	}
	return nil
}

func (c *CLI) showCoreDumps() error {
	dirs := []string{"/var/crash", "/var/lib/systemd/coredump"}
	var found bool
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			if !found {
				fmt.Printf("%-40s %-20s %10s\n", "Name", "Date", "Size")
				found = true
			}
			fmt.Printf("%-40s %-20s %10d\n", e.Name(), info.ModTime().Format("2006-01-02 15:04:05"), info.Size())
		}
	}
	if !found {
		fmt.Println("No core dumps found")
	}
	return nil
}

func (c *CLI) showTask() error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	uptime := time.Since(c.startTime).Truncate(time.Second)
	fmt.Println("Task: xpfd daemon")
	fmt.Printf("  Goroutines: %d\n", runtime.NumGoroutine())
	fmt.Printf("  Memory allocated: %.1f MB\n", float64(m.Alloc)/1024/1024)
	fmt.Printf("  System memory: %.1f MB\n", float64(m.Sys)/1024/1024)
	fmt.Printf("  GC cycles: %d\n", m.NumGC)
	fmt.Printf("  Uptime: %s\n", uptime)
	return nil
}

func (c *CLI) showBackupRouter() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	if cfg.System.BackupRouter == "" {
		fmt.Println("No backup router configured")
		return nil
	}
	fmt.Printf("Backup router: %s\n", cfg.System.BackupRouter)
	if cfg.System.BackupRouterDst != "" {
		fmt.Printf("  Destination: %s\n", cfg.System.BackupRouterDst)
	} else {
		fmt.Println("  Destination: 0.0.0.0/0 (default)")
	}
	return nil
}

func (c *CLI) showSystemNTP() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if len(cfg.System.NTPServers) == 0 {
		fmt.Println("No NTP servers configured")
		return nil
	}

	fmt.Println("NTP servers:")
	for _, server := range cfg.System.NTPServers {
		fmt.Printf("  %s\n", server)
	}
	if cfg.System.NTPThreshold > 0 && cfg.System.NTPThresholdAction != "" {
		fmt.Printf("  Threshold: %d seconds (%s)\n", cfg.System.NTPThreshold, cfg.System.NTPThresholdAction)
	}

	// Try chronyc tracking for detailed sync status
	if out, err := exec.Command("chronyc", "tracking").CombinedOutput(); err == nil {
		fmt.Println()
		printChronyTracking(string(out))
		// Also show source list
		if src, err := exec.Command("chronyc", "-n", "sources").CombinedOutput(); err == nil {
			fmt.Printf("\nNTP sources:\n%s", string(src))
		}
	} else if out, err := exec.Command("ntpq", "-pn").CombinedOutput(); err == nil {
		fmt.Printf("\nNTP peers:\n%s\n", string(out))
	} else if out, err := exec.Command("timedatectl", "show", "--property=NTPSynchronized", "--value").CombinedOutput(); err == nil {
		synced := strings.TrimSpace(string(out))
		fmt.Printf("\nNTP synchronized: %s\n", synced)
	}

	return nil
}

// printChronyTracking parses chronyc tracking output and prints key fields.

func (c *CLI) showSystemServices() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	fmt.Println("System services:")

	// gRPC
	fmt.Println("  gRPC:           127.0.0.1:50051 (always on)")
	// HTTP REST
	fmt.Println("  HTTP REST:      127.0.0.1:8080 (always on)")

	// SSH
	if cfg.System.Services != nil && cfg.System.Services.SSH != nil {
		if cfg.System.Services.SSH.RootLogin == "allow" {
			fmt.Println("  SSH root login: enabled")
		}
	}

	// SNMP
	if cfg.System.SNMP != nil {
		fmt.Println("  SNMP:           enabled")
		if cfg.System.SNMP.Description != "" {
			fmt.Printf("    Description:  %s\n", cfg.System.SNMP.Description)
		}
		if cfg.System.SNMP.Location != "" {
			fmt.Printf("    Location:     %s\n", cfg.System.SNMP.Location)
		}
		for name, comm := range cfg.System.SNMP.Communities {
			fmt.Printf("    Community:    %s (%s)\n", name, comm.Authorization)
		}
	}

	// Web management / API auth
	if cfg.System.Services != nil && cfg.System.Services.WebManagement != nil {
		wm := cfg.System.Services.WebManagement
		if wm.APIAuth != nil && (len(wm.APIAuth.Users) > 0 || len(wm.APIAuth.APIKeys) > 0) {
			fmt.Printf("  API auth:       %d user(s), %d API key(s)\n", len(wm.APIAuth.Users), len(wm.APIAuth.APIKeys))
		}
	}

	// DHCP server
	if cfg.System.DHCPServer.DHCPLocalServer != nil && len(cfg.System.DHCPServer.DHCPLocalServer.Groups) > 0 {
		fmt.Printf("  DHCP server:    %d group(s)\n", len(cfg.System.DHCPServer.DHCPLocalServer.Groups))
	}
	if cfg.System.DHCPServer.DHCPv6LocalServer != nil && len(cfg.System.DHCPServer.DHCPv6LocalServer.Groups) > 0 {
		fmt.Printf("  DHCPv6 server:  %d group(s)\n", len(cfg.System.DHCPServer.DHCPv6LocalServer.Groups))
	}

	// DNS
	if len(cfg.System.NameServers) > 0 {
		fmt.Printf("  DNS servers:    %s\n", strings.Join(cfg.System.NameServers, ", "))
	}

	// NTP
	if len(cfg.System.NTPServers) > 0 {
		fmt.Printf("  NTP servers:    %s\n", strings.Join(cfg.System.NTPServers, ", "))
		if cfg.System.NTPThreshold > 0 && cfg.System.NTPThresholdAction != "" {
			fmt.Printf("  NTP threshold:  %d seconds (%s)\n", cfg.System.NTPThreshold, cfg.System.NTPThresholdAction)
		}
	}

	// Syslog
	if len(cfg.Security.Log.Streams) > 0 {
		fmt.Printf("  Syslog:         %d stream(s)\n", len(cfg.Security.Log.Streams))
		for _, stream := range cfg.Security.Log.Streams {
			sev := "all"
			if stream.Severity != "" {
				sev = stream.Severity + "+"
			}
			cat := "all"
			if stream.Category != "" && stream.Category != "all" {
				cat = stream.Category
			}
			fmt.Printf("    %-16s %s:%d (severity=%s, category=%s)\n", stream.Name, stream.Host, stream.Port, sev, cat)
		}
	}

	// Flow monitoring / NetFlow
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.Version9 != nil {
		fmt.Printf("  NetFlow v9:     %d template(s)\n", len(cfg.Services.FlowMonitoring.Version9.Templates))
	}
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.VersionIPFIX != nil {
		fmt.Printf("  IPFIX:          %d template(s)\n", len(cfg.Services.FlowMonitoring.VersionIPFIX.Templates))
	}

	// Application identification
	if cfg.Services.ApplicationIdentification {
		fmt.Println("  AppID:          enabled")
	}

	// RPM probes
	if cfg.Services.RPM != nil && len(cfg.Services.RPM.Probes) > 0 {
		total := 0
		for _, probe := range cfg.Services.RPM.Probes {
			total += len(probe.Tests)
		}
		fmt.Printf("  RPM probes:     %d probe(s), %d test(s)\n", len(cfg.Services.RPM.Probes), total)
	}

	return nil
}

// showSystemSyslog displays system syslog configuration.

func (c *CLI) showSystemSyslog() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if cfg.System.Syslog == nil {
		fmt.Println("No system syslog configuration")
		return nil
	}

	sys := cfg.System.Syslog

	if len(sys.Hosts) > 0 {
		fmt.Println("Syslog hosts:")
		for _, h := range sys.Hosts {
			fmt.Printf("  %-20s", h.Address)
			if h.AllowDuplicates {
				fmt.Print(" allow-duplicates")
			}
			fmt.Println()
			for _, f := range h.Facilities {
				fmt.Printf("    %-20s %s\n", f.Facility, f.Severity)
			}
		}
	}

	if len(sys.Files) > 0 {
		fmt.Println("Syslog files:")
		for _, f := range sys.Files {
			fmt.Printf("  %-20s %s %s\n", f.Name, f.Facility, f.Severity)
		}
	}

	if len(sys.Users) > 0 {
		fmt.Println("Syslog users:")
		for _, u := range sys.Users {
			fmt.Printf("  %-20s %s %s\n", u.User, u.Facility, u.Severity)
		}
	}

	return nil
}

// matchPolicyAddr checks if an IP matches a list of address-book references.

func (c *CLI) showSystemUptime() error {
	// Read /proc/uptime
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return fmt.Errorf("reading uptime: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return fmt.Errorf("unexpected /proc/uptime format")
	}
	var upSec float64
	fmt.Sscanf(fields[0], "%f", &upSec)

	days := int(upSec) / 86400
	hours := (int(upSec) % 86400) / 3600
	mins := (int(upSec) % 3600) / 60
	secs := int(upSec) % 60

	now := time.Now()
	fmt.Printf("Current time: %s\n", now.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("System booted: %s\n", now.Add(-time.Duration(upSec)*time.Second).Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Daemon uptime: %s\n", time.Since(c.startTime).Truncate(time.Second))
	if days > 0 {
		fmt.Printf("System uptime: %d days, %d hours, %d minutes, %d seconds\n", days, hours, mins, secs)
	} else {
		fmt.Printf("System uptime: %d hours, %d minutes, %d seconds\n", hours, mins, secs)
	}
	return nil
}

// showSystemBootMessages shows recent boot messages via journalctl.

func (c *CLI) showSystemBootMessages() error {
	cmd := exec.Command("journalctl", "--boot", "-n", "100", "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// showSystemMemory shows memory usage (like Junos "show system memory").

func (c *CLI) showSystemMemory() error {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return fmt.Errorf("reading meminfo: %w", err)
	}

	info := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := strings.TrimSuffix(parts[0], ":")
			val, _ := strconv.ParseUint(parts[1], 10, 64)
			info[key] = val
		}
	}

	total := info["MemTotal"]
	free := info["MemFree"]
	buffers := info["Buffers"]
	cached := info["Cached"]
	available := info["MemAvailable"]
	used := total - free - buffers - cached

	fmt.Printf("%-20s %10s\n", "Type", "kB")
	fmt.Printf("%-20s %10d\n", "Total memory", total)
	fmt.Printf("%-20s %10d\n", "Used memory", used)
	fmt.Printf("%-20s %10d\n", "Free memory", free)
	fmt.Printf("%-20s %10d\n", "Buffers", buffers)
	fmt.Printf("%-20s %10d\n", "Cached", cached)
	fmt.Printf("%-20s %10d\n", "Available", available)
	if total > 0 {
		fmt.Printf("Utilization: %.1f%%\n", float64(used)/float64(total)*100)
	}
	return nil
}

// showSystemProcesses shows top resource consumers.
// When summary=true, shows a top-like summary (Junos "show system processes summary" format).

func (c *CLI) showSystemProcesses(summary bool) error {
	if !summary {
		cmd := exec.Command("ps", "aux", "--sort=-rss")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	// Read load average
	loadAvg := "0.00, 0.00, 0.00"
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			loadAvg = fmt.Sprintf("%s, %s, %s", fields[0], fields[1], fields[2])
		}
	}

	// Read uptime
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

	// Read meminfo
	var memTotal, memFree, memAvailable, memBuffers, memCached, swapTotal, swapFree uint64
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			val *= 1024 // convert kB to bytes
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

	// Read CPU stats from /proc/stat
	var userPct, sysPct, idlePct float64
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "cpu ") {
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
	}

	// Count threads by state
	var running, sleeping, stopped, zombie int
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if _, err := strconv.Atoi(e.Name()); err != nil {
				continue
			}
			statPath := "/proc/" + e.Name() + "/stat"
			if data, err := os.ReadFile(statPath); err == nil {
				// state is after the comm field (in parens)
				line := string(data)
				idx := strings.LastIndex(line, ") ")
				if idx >= 0 && idx+2 < len(line) {
					state := line[idx+2 : idx+3]
					switch state {
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
		}
	}
	totalTasks := running + sleeping + stopped + zombie

	now := time.Now().Format("15:04:05")
	fmt.Printf("load averages: %s  %s    %s\n", loadAvg, uptimeStr, now)
	fmt.Printf("%d processes: %d running, %d sleeping, %d stopped, %d zombie\n",
		totalTasks, running, sleeping, stopped, zombie)
	fmt.Printf("CPU: %.1f%% user, %.1f%% system, %.1f%% idle\n",
		userPct, sysPct, idlePct)
	fmt.Printf("Mem: %s Active, %s Buf, %s Cached, %s Free\n",
		fmtBytes(memUsed), fmtBytes(memBuffers), fmtBytes(memCached), fmtBytes(memFree))
	fmt.Printf("Swap: %s Total, %s Free\n",
		fmtBytes(swapTotal), fmtBytes(swapFree))
	fmt.Println()

	// Top processes by CPU/RSS
	cmd := exec.Command("ps", "-eo", "pid,user,pri,ni,vsz,rss,stat,time,pcpu,comm", "--sort=-pcpu")
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	fmt.Printf("  PID USERNAME    PRI NICE   SIZE    RES STATE   TIME    WCPU COMMAND\n")
	limit := 20
	if len(lines)-1 < limit {
		limit = len(lines) - 1
	}
	for i := 1; i <= limit; i++ {
		fields := strings.Fields(lines[i])
		if len(fields) < 10 {
			continue
		}
		pid := fields[0]
		user := fields[1]
		pri := fields[2]
		nice := fields[3]
		vsz, _ := strconv.ParseUint(fields[4], 10, 64)
		rss, _ := strconv.ParseUint(fields[5], 10, 64)
		state := fields[6]
		timeStr := fields[7]
		cpu := fields[8]
		comm := fields[9]
		fmt.Printf("%5s %-11s %4s %4s %7s %7s %-7s %8s %6s%% %s\n",
			pid, user, pri, nice,
			fmtBytes(vsz*1024), fmtBytes(rss*1024),
			state, timeStr, cpu, comm)
	}
	return nil
}

// showSystemStorage shows filesystem usage (like Junos "show system storage").

func (c *CLI) showSystemStorage() error {
	var stat unix.Statfs_t
	mounts := []struct {
		path string
		name string
	}{
		{"/", "Root (/)"},
		{"/var", "/var"},
		{"/tmp", "/tmp"},
	}

	fmt.Printf("%-20s %12s %12s %12s %6s\n", "Filesystem", "Size", "Used", "Avail", "Use%")
	for _, m := range mounts {
		if err := unix.Statfs(m.path, &stat); err != nil {
			continue
		}
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		used := total - (stat.Bfree * uint64(stat.Bsize))
		pct := float64(0)
		if total > 0 {
			pct = float64(used) / float64(total) * 100
		}
		fmt.Printf("%-20s %12s %12s %12s %5.0f%%\n",
			m.name, fmtBytes(total), fmtBytes(used), fmtBytes(free), pct)
	}
	return nil
}

// showSystemUsers shows configured login users from the active config.

func (c *CLI) showSystemUsers() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
		fmt.Println("No login users configured")
		return nil
	}

	fmt.Printf("%-20s %-8s %-20s %s\n", "Username", "UID", "Class", "SSH Keys")
	for _, u := range cfg.System.Login.Users {
		uid := "-"
		if u.UID > 0 {
			uid = strconv.Itoa(u.UID)
		}
		class := u.Class
		if class == "" {
			class = "-"
		}
		keys := strconv.Itoa(len(u.SSHKeys))
		fmt.Printf("%-20s %-8s %-20s %s\n", u.Name, uid, class, keys)
	}
	return nil
}

// showSystemConnections shows active TCP connections.

func (c *CLI) showSystemConnections() error {
	cmd := exec.Command("ss", "-tnp")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// showVersion displays software version information.

func (c *CLI) showVersion() error {
	ver := c.version
	if ver == "" {
		ver = "dev"
	}
	fmt.Printf("xpf eBPF firewall %s\n", ver)
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		sysname := strings.TrimRight(string(uts.Sysname[:]), "\x00")
		release := strings.TrimRight(string(uts.Release[:]), "\x00")
		machine := strings.TrimRight(string(uts.Machine[:]), "\x00")
		nodename := strings.TrimRight(string(uts.Nodename[:]), "\x00")
		fmt.Printf("Hostname: %s\n", nodename)
		fmt.Printf("Kernel: %s %s (%s)\n", sysname, release, machine)
	}
	return nil
}

// showDaemonLog displays recent daemon log entries from journald,
// or if a filename argument is given, reads from /var/log/<filename>.

func (c *CLI) showDaemonLog(args []string) error {
	// If first arg is not a number, treat it as a syslog file name
	if len(args) > 0 {
		if _, err := strconv.Atoi(args[0]); err != nil {
			// Argument is a filename like "messages"
			filename := args[0]
			n := 50
			if len(args) > 1 {
				if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
					n = v
				}
			}
			logPath := filepath.Join("/var/log", filepath.Base(filename))
			out, err := exec.Command("tail", "-n", strconv.Itoa(n), logPath).CombinedOutput()
			if err != nil {
				return fmt.Errorf("read %s: %w", logPath, err)
			}
			fmt.Print(string(out))
			return nil
		}
	}

	n := 50
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}

	out, err := exec.Command("journalctl", "-u", "xpfd", "-n", strconv.Itoa(n), "--no-pager").CombinedOutput()
	if err != nil {
		return fmt.Errorf("journalctl: %w", err)
	}
	fmt.Print(string(out))
	return nil
}

// #1044c Phase 1: handleShowSystem relocated from cli.go (no behavior change).
func (c *CLI) handleShowSystem(args []string) error {
	sysTree := operationalTree["show"].Children["system"].Children
	if len(args) == 0 {
		fmt.Println("show system:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(sysTree))
		return nil
	}

	switch args[0] {
	case "commit":
		// "show system commit history"
		if len(args) >= 2 && args[1] == "history" {
			entries, err := c.store.ListCommitHistory(50)
			if err != nil {
				return fmt.Errorf("commit history: %v", err)
			}
			if len(entries) == 0 {
				fmt.Println("No commit history available")
				return nil
			}
			for i, e := range entries {
				detail := ""
				if e.Detail != "" {
					detail = "  " + e.Detail
				}
				fmt.Printf("  %d  %s  %s%s\n", i, e.Timestamp.Format("2006-01-02 15:04:05"), e.Action, detail)
			}
			return nil
		}
		fmt.Println("show system commit:")
		fmt.Println("  history              Show recent commit log")
		return nil

	case "rollback":
		if len(args) >= 2 {
			// "show system rollback compare N" — diff rollback N against active
			if args[1] == "compare" {
				if len(args) < 3 {
					return fmt.Errorf("usage: show system rollback compare <N>")
				}
				n, err := strconv.Atoi(args[2])
				if err != nil || n < 1 {
					return fmt.Errorf("usage: show system rollback compare <N>")
				}
				diff, err := c.store.ShowCompareRollback(n)
				if err != nil {
					return err
				}
				if diff == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(diff)
				}
				return nil
			}

			// "show system rollback N" — show specific rollback content.
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return fmt.Errorf("usage: show system rollback <N>")
			}
			rest := strings.Join(args[2:], " ")
			if strings.Contains(rest, "| display set") {
				content, err := c.store.ShowRollbackSet(n)
				if err != nil {
					return err
				}
				fmt.Print(content)
			} else if strings.Contains(rest, "compare") {
				diff, err := c.store.ShowCompareRollback(n)
				if err != nil {
					return err
				}
				if diff == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(diff)
				}
			} else {
				content, err := c.store.ShowRollback(n)
				if err != nil {
					return err
				}
				fmt.Print(content)
			}
			return nil
		}

		// List all rollback entries with timestamps.
		entries := c.store.ListHistory()
		if len(entries) == 0 {
			fmt.Println("No rollback history available")
			return nil
		}
		for i, entry := range entries {
			fmt.Printf("  rollback %d: %s\n", i+1, entry.Timestamp.Format("2006-01-02 15:04:05"))
		}
		return nil

	case "uptime":
		return c.showSystemUptime()

	case "memory":
		return c.showSystemMemory()

	case "processes":
		summary := len(args) >= 2 && args[1] == "summary"
		return c.showSystemProcesses(summary)

	case "storage":
		return c.showSystemStorage()

	case "alarms":
		cfg := c.store.ActiveConfig()
		if cfg != nil {
			warnings := config.ValidateConfig(cfg)
			if len(warnings) == 0 {
				fmt.Println("No alarms currently active")
			} else {
				fmt.Printf("%d active alarm(s):\n", len(warnings))
				for _, w := range warnings {
					fmt.Printf("  WARNING: %s\n", w)
				}
			}
		} else {
			fmt.Println("No active configuration loaded")
		}
		return nil

	case "users":
		return c.showSystemUsers()

	case "connections":
		return c.showSystemConnections()

	case "boot-messages":
		return c.showSystemBootMessages()

	case "core-dumps":
		return c.showCoreDumps()

	case "license":
		fmt.Println("License: open-source (no license required)")
		return nil

	case "backup-router":
		return c.showBackupRouter()

	case "ntp":
		return c.showSystemNTP()

	case "services":
		return c.showSystemServices()

	case "syslog":
		return c.showSystemSyslog()

	case "buffers":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showSystemBuffersDetail()
		}
		return c.showSystemBuffers()

	case "login":
		cfg := c.store.ActiveConfig()
		if cfg == nil {
			return fmt.Errorf("no active configuration")
		}
		fmt.Print(c.store.ShowActivePath([]string{"system", "login"}))
		return nil

	case "internet-options":
		cfg := c.store.ActiveConfig()
		if cfg == nil {
			return fmt.Errorf("no active configuration")
		}
		fmt.Print(c.store.ShowActivePath([]string{"system", "internet-options"}))
		return nil

	case "root-authentication":
		cfg := c.store.ActiveConfig()
		if cfg == nil {
			return fmt.Errorf("no active configuration")
		}
		fmt.Print(c.store.ShowActivePath([]string{"system", "root-authentication"}))
		return nil

	case "configuration":
		if len(args) >= 2 && args[1] == "rescue" {
			content, err := c.store.LoadRescueConfig()
			if err != nil {
				return err
			}
			if content == "" {
				fmt.Println("No rescue configuration saved")
			} else {
				fmt.Print(content)
			}
			return nil
		}
		fmt.Println("show system configuration:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["show"].Children["system"].Children["configuration"].Children))
		return nil

	default:
		return fmt.Errorf("unknown show system target: %s", args[0])
	}
}
