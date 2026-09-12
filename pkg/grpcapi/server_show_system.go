// Phase 7 of #1043: extract the system-info ShowText case bodies into
// dedicated methods. Same methodology as Phases 1-6 (#1148, #1150,
// #1151, #1153, #1154, #1155): semantic relocation, no behavior
// change. Each case body is moved verbatim apart from `&buf`
// references becoming `buf` (passed-in `*strings.Builder`).
//
// `showCommitHistory` returns `error` (the original case had an early
// `return nil, status.Errorf` path) — same pattern as Phase 6's
// interfaces methods. The dispatcher rewraps via
// `if err := …; err != nil { return nil, err }`.
//
// Cases that used `break` on a no-config guard (system-services, ntp,
// system-syslog) are converted to early `return` so the rest of the
// method body is dead-code-skipped, semantically identical to the
// original `break`-out-of-switch behavior because the original
// statements after the `break` were inside the same case body and
// therefore unreachable too.

package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
	"github.com/psaab/xpf/pkg/sysservices"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/termsafe"
)

// showVersion renders daemon version, hostname, kernel, and uptime.
func (s *Server) showVersion(buf *strings.Builder) {
	ver := s.version
	if ver == "" {
		ver = "dev"
	}
	fmt.Fprintf(buf, "xpf stateful firewall %s\n", ver)
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		sysname := strings.TrimRight(string(uts.Sysname[:]), "\x00")
		release := strings.TrimRight(string(uts.Release[:]), "\x00")
		machine := strings.TrimRight(string(uts.Machine[:]), "\x00")
		nodename := strings.TrimRight(string(uts.Nodename[:]), "\x00")
		fmt.Fprintf(buf, "Hostname: %s\n", nodename)
		fmt.Fprintf(buf, "Kernel: %s %s (%s)\n", sysname, release, machine)
	}
	fmt.Fprintf(buf, "Daemon uptime: %s\n", time.Since(s.startTime).Truncate(time.Second))
}

// showStorage renders /, /var, /tmp filesystem usage.
func (s *Server) showStorage(buf *strings.Builder) {
	var stat unix.Statfs_t
	mounts := []struct{ path, name string }{
		{"/", "Root (/)"},
		{"/var", "/var"},
		{"/tmp", "/tmp"},
	}
	fmt.Fprintf(buf, "%-20s %12s %12s %12s %6s\n", "Filesystem", "Size", "Used", "Avail", "Use%")
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
		fmt.Fprintf(buf, "%-20s %11.1fG %11.1fG %11.1fG %5.0f%%\n",
			m.name,
			float64(total)/float64(1<<30),
			float64(used)/float64(1<<30),
			float64(free)/float64(1<<30),
			pct)
	}
}

// showCommitHistory renders the most recent 50 commit-history entries.
// Returns error when the underlying configstore lookup fails so the
// dispatcher can re-raise as a gRPC status error.
func (s *Server) showCommitHistory(buf *strings.Builder) error {
	entries, err := s.store.ListCommitHistory(50)
	if err != nil {
		return status.Errorf(codes.Internal, "commit history: %v", err)
	}
	if len(entries) == 0 {
		buf.WriteString("No commit history available\n")
		return nil
	}
	for i, e := range entries {
		detail := ""
		if e.Detail != "" {
			detail = "  " + e.Detail
		}
		fmt.Fprintf(buf, "  %d  %s  %s%s\n", i, e.Timestamp.Format("2006-01-02 15:04:05"), e.Action, detail)
	}
	return nil
}

// showAlarms renders config-validation warnings as alarms.
func (s *Server) showAlarms(buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		buf.WriteString("No active configuration loaded\n")
		return
	}
	warnings := config.ValidateConfig(cfg)
	// #9530: a peer config sync that discarded a local commit is an alarm too.
	divergence := s.store.ConfigSyncDivergenceAlarm()
	n := len(warnings)
	if divergence != "" {
		n++
	}
	if n == 0 {
		buf.WriteString("No alarms currently active\n")
		return
	}
	fmt.Fprintf(buf, "%d active alarm(s):\n", n)
	if divergence != "" {
		fmt.Fprintf(buf, "  CRITICAL: %s\n", divergence)
	}
	for _, w := range warnings {
		fmt.Fprintf(buf, "  WARNING: %s\n", w)
	}
}

// showChassisEnvironment renders thermal-zone temperatures and the
// system uptime + load average.
func (s *Server) showChassisEnvironment(buf *strings.Builder) {
	thermalZones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	if len(thermalZones) > 0 {
		fmt.Fprintln(buf, "Temperature:")
		for _, tz := range thermalZones {
			data, err := os.ReadFile(tz)
			if err != nil {
				continue
			}
			millideg, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
			if err != nil {
				continue
			}
			typeFile := filepath.Join(filepath.Dir(tz), "type")
			name := filepath.Base(filepath.Dir(tz))
			if typeData, err := os.ReadFile(typeFile); err == nil {
				name = strings.TrimSpace(string(typeData))
			}
			fmt.Fprintf(buf, "  %-30s %d.%d C\n", name, millideg/1000, (millideg%1000)/100)
		}
		fmt.Fprintln(buf)
	}
	var sysinfo unix.Sysinfo_t
	if err := unix.Sysinfo(&sysinfo); err == nil {
		days := sysinfo.Uptime / 86400
		hours := (sysinfo.Uptime % 86400) / 3600
		mins := (sysinfo.Uptime % 3600) / 60
		fmt.Fprintf(buf, "System uptime: %d days, %d:%02d\n", days, hours, mins)
		fmt.Fprintf(buf, "Load average: %.2f %.2f %.2f\n",
			float64(sysinfo.Loads[0])/65536.0,
			float64(sysinfo.Loads[1])/65536.0,
			float64(sysinfo.Loads[2])/65536.0)
	}
}

// showSystemServices renders gRPC/HTTP/SSH/WebManagement/DNS/NTP and
// derived service-state summaries (security log, syslog, NetFlow,
// IPFIX, AppID, RPM).

// effectiveListeners returns the shared management-listener snapshot for
// `show system services` (#6385): the daemon-owned effective addresses when
// wired (Config.ListenersFn -> Daemon.effectiveListeners), else the documented
// loopback defaults for a no-daemon unit-test build. The defaults preserve the
// pre-#6385 output shape when there is no live bind to read.
func (s *Server) effectiveListeners() sysservices.Listeners {
	if s.listenersFn != nil {
		return s.listenersFn()
	}
	return sysservices.Listeners{
		GRPC: sysservices.Listener{Addr: "127.0.0.1:50051", State: sysservices.StateListening},
		HTTP: sysservices.Listener{Addr: "127.0.0.1:8080", State: sysservices.StateListening},
	}
}

func (s *Server) showSystemServices(buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	fmt.Fprintln(buf, "System services:")
	// #6385: report the EFFECTIVE (post-clamp, post-bind) listener addresses
	// from the shared daemon-owned snapshot, not the hardcoded requested
	// defaults. listenersFn is nil only in a no-daemon unit-test build, where we
	// fall back to the documented loopback defaults. This is the SAME snapshot
	// and the SAME renderer (Listeners.Lines) the local CLI uses, so the remote
	// gRPC path (the common operator path) and the local console can never
	// disagree — the divergence that dropped the #6384 A10-b2-F5 attempt.
	ls := s.effectiveListeners()
	for _, line := range ls.Lines() {
		fmt.Fprintln(buf, line)
	}
	if cfg.System.Services != nil {
		if cfg.System.Services.SSH != nil {
			rootLogin := cfg.System.Services.SSH.RootLogin
			if rootLogin == "" {
				rootLogin = "deny"
			}
			fmt.Fprintf(buf, "  SSH:            enabled (root-login: %s)\n", rootLogin)
		}
		if cfg.System.Services.WebManagement != nil {
			wm := cfg.System.Services.WebManagement
			if wm.HTTP {
				iface := "all"
				if wm.HTTPInterface != "" {
					iface = wm.HTTPInterface
				}
				fmt.Fprintf(buf, "  Web HTTP:       enabled (interface: %s)\n", iface)
			}
			if wm.HTTPS {
				iface := "all"
				if wm.HTTPSInterface != "" {
					iface = wm.HTTPSInterface
				}
				cert := ""
				if wm.SystemGeneratedCert {
					cert = ", system-generated-certificate"
				}
				fmt.Fprintf(buf, "  Web HTTPS:      enabled (interface: %s%s)\n", iface, cert)
			}
		}
		if cfg.System.Services.DNSEnabled {
			fmt.Fprintln(buf, "  DNS:            enabled")
		}
	}
	if len(cfg.System.NameServers) > 0 {
		fmt.Fprintf(buf, "  DNS servers:    %s\n", strings.Join(cfg.System.NameServers, ", "))
	}
	if len(cfg.System.NTPServers) > 0 {
		fmt.Fprintf(buf, "  NTP servers:    %s\n", strings.Join(cfg.System.NTPServers, ", "))
		if cfg.System.NTPThreshold > 0 && cfg.System.NTPThresholdAction != "" {
			fmt.Fprintf(buf, "  NTP threshold:  %d seconds (%s)\n", cfg.System.NTPThreshold, cfg.System.NTPThresholdAction)
		}
	}
	if cfg.Security.Log.Mode != "" {
		fmt.Fprintf(buf, "  Security log:   mode %s\n", cfg.Security.Log.Mode)
	}
	if len(cfg.Security.Log.Streams) > 0 {
		fmt.Fprintf(buf, "  Syslog:         %d stream(s)\n", len(cfg.Security.Log.Streams))
	}
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.Version9 != nil {
		fmt.Fprintf(buf, "  NetFlow v9:     %d template(s)\n", len(cfg.Services.FlowMonitoring.Version9.Templates))
	}
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.VersionIPFIX != nil {
		fmt.Fprintf(buf, "  IPFIX:          %d template(s)\n", len(cfg.Services.FlowMonitoring.VersionIPFIX.Templates))
	}
	if cfg.Services.ApplicationIdentification {
		fmt.Fprintln(buf, "  AppID:          enabled")
	}
	if cfg.Services.RPM != nil && len(cfg.Services.RPM.Probes) > 0 {
		total := 0
		for _, probe := range cfg.Services.RPM.Probes {
			total += len(probe.Tests)
		}
		fmt.Fprintf(buf, "  RPM probes:     %d probe(s), %d test(s)\n", len(cfg.Services.RPM.Probes), total)
	}
}

// showNTP renders configured NTP servers and chronyc/ntpq tracking. The
// handler ctx is plumbed in (#1805) so the NTP execs are bounded by the
// request lifetime in addition to the per-exec timeout.
func (s *Server) showNTP(ctx context.Context, buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	if len(cfg.System.NTPServers) == 0 {
		fmt.Fprintln(buf, "No NTP servers configured")
		return
	}
	fmt.Fprintln(buf, "NTP servers:")
	for _, server := range cfg.System.NTPServers {
		fmt.Fprintf(buf, "  %s\n", server)
	}
	if cfg.System.NTPThreshold > 0 && cfg.System.NTPThresholdAction != "" {
		fmt.Fprintf(buf, "  Threshold: %d seconds (%s)\n", cfg.System.NTPThreshold, cfg.System.NTPThresholdAction)
	}
	// Fallback chain: chronyc tracking → (success) chronyc sources;
	// else ntpq; else timedatectl. Each exec carries its own 15s+5s
	// bound, so the worst case for this handler is the timeouts
	// stacking across the chain: 3×20s = 60s if every fallback wedges
	// (40s on the chronyc success path). That is deliberate — each
	// step only runs because the previous binary failed, and the
	// request ctx still cancels the whole chain on client disconnect.
	if out, err := combinedOutputTimeout(ctx, "chronyc", "tracking"); err == nil {
		writeChronyTracking(buf, termsafe.SanitizeBlockForDisplay(string(out)))
		if src, err := combinedOutputTimeout(ctx, "chronyc", "-n", "sources"); err == nil {
			fmt.Fprintf(buf, "\nNTP sources:\n%s", termsafe.SanitizeBlockForDisplay(string(src)))
		}
	} else if out, err := combinedOutputTimeout(ctx, "ntpq", "-pn"); err == nil {
		fmt.Fprintf(buf, "\nNTP peers:\n%s\n", termsafe.SanitizeBlockForDisplay(string(out)))
	} else if out, err := combinedOutputTimeout(ctx, "timedatectl", "show", "--property=NTPSynchronized", "--value"); err == nil {
		fmt.Fprintf(buf, "\nNTP synchronized: %s\n", termsafe.SanitizeForDisplay(strings.TrimSpace(string(out))))
	}
}

// showSystemSyslog renders configured syslog hosts/files/users.
func (s *Server) showSystemSyslog(buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	if cfg.System.Syslog == nil {
		fmt.Fprintln(buf, "No system syslog configuration")
		return
	}
	sys := cfg.System.Syslog
	if len(sys.Hosts) > 0 {
		fmt.Fprintln(buf, "Syslog hosts:")
		for _, h := range sys.Hosts {
			fmt.Fprintf(buf, "  %-20s", h.Address)
			if h.AllowDuplicates {
				fmt.Fprint(buf, " allow-duplicates")
			}
			fmt.Fprintln(buf)
			for _, f := range h.Facilities {
				fmt.Fprintf(buf, "    %-20s %s\n", f.Facility, f.Severity)
			}
		}
	}
	// #7187: file and user destinations carry EVERY authored selector now, so
	// they render one line per selector — the same shape the host sink above
	// has always used. Showing only the first would reproduce, in the operator's
	// own `show` output, the discard this change fixed.
	if len(sys.Files) > 0 {
		fmt.Fprintln(buf, "Syslog files:")
		for _, f := range sys.Files {
			fmt.Fprintf(buf, "  %-20s\n", f.Name)
			for _, sel := range f.Selectors {
				fmt.Fprintf(buf, "    %-20s %s\n", sel.Facility, sel.Severity)
			}
		}
	}
	if len(sys.Users) > 0 {
		fmt.Fprintln(buf, "Syslog users:")
		for _, u := range sys.Users {
			fmt.Fprintf(buf, "  %-20s\n", u.User)
			for _, sel := range u.Selectors {
				fmt.Fprintf(buf, "    %-20s %s\n", sel.Facility, sel.Severity)
			}
		}
	}
}

// --- #1700: residual ShowText branches ---

func (s *Server) showLogin(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
		buf.WriteString("No login users configured\n")
	} else {
		fmt.Fprintf(buf, "%-16s %-6s %-14s %s\n", "User", "UID", "Class", "SSH Keys")
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
			fmt.Fprintf(buf, "%-16s %-6s %-14s %s\n", u.Name, uid, class, keys)
		}
	}
}

func (s *Server) showInternetOptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.System.InternetOptions == nil {
		buf.WriteString("No internet-options configured\n")
	} else {
		io := cfg.System.InternetOptions
		buf.WriteString("Internet options:\n")
		fmt.Fprintf(buf, "  no-ipv6-reject-zero-hop-limit: %s\n", boolStatus(io.NoIPv6RejectZeroHopLimit))
	}
}

func (s *Server) showRootAuthentication(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.System.RootAuthentication == nil {
		buf.WriteString("No root authentication configured\n")
	} else {
		ra := cfg.System.RootAuthentication
		if ra.EncryptedPassword != "" {
			buf.WriteString("Root password: configured (encrypted)\n")
		}
		if len(ra.SSHKeys) > 0 {
			fmt.Fprintf(buf, "Root SSH keys: %d\n", len(ra.SSHKeys))
			for _, key := range ra.SSHKeys {
				// Show key type and fingerprint prefix
				parts := strings.Fields(key)
				if len(parts) >= 2 {
					comment := ""
					if len(parts) >= 3 {
						comment = " " + parts[2]
					}
					fmt.Fprintf(buf, "  %s%s\n", parts[0], comment)
				}
			}
		}
	}
}

func (s *Server) showCoreDumps(cfg *config.Config, buf *strings.Builder) {
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
				fmt.Fprintf(buf, "%-40s %-20s %10s\n", "Name", "Date", "Size")
				found = true
			}
			fmt.Fprintf(buf, "%-40s %-20s %10d\n", e.Name(), info.ModTime().Format("2006-01-02 15:04:05"), info.Size())
		}
	}
	if !found {
		buf.WriteString("No core dumps found\n")
	}
}

func (s *Server) showTask(cfg *config.Config, buf *strings.Builder) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	uptime := time.Since(s.startTime).Truncate(time.Second)
	buf.WriteString("Task: xpfd daemon\n")
	fmt.Fprintf(buf, "  Goroutines: %d\n", runtime.NumGoroutine())
	fmt.Fprintf(buf, "  Memory allocated: %.1f MB\n", float64(m.Alloc)/1024/1024)
	fmt.Fprintf(buf, "  System memory: %.1f MB\n", float64(m.Sys)/1024/1024)
	fmt.Fprintf(buf, "  GC cycles: %d\n", m.NumGC)
	fmt.Fprintf(buf, "  Uptime: %s\n", uptime)
}

func (s *Server) showBuffers(cfg *config.Config, buf *strings.Builder) error {
	// #2114/#6743-F3: `dp != nil` no longer means "a dataplane exists" —
	// the daemon publishes a permanently non-nil live indirection, so a
	// daemon whose startup arm FAILED and cleared the cell would fall into
	// the backend arm and answer "No BPF maps available" (a statement
	// about a loaded backend's maps) for a firewall that has no backend at
	// all.
	//
	// r7: ONE cell load feeds every decision in this render.
	// dataplane.Published() (a predicate deleted in r2-B6 — it was
	// `Unwrap(p) != nil`), dpProbe() and s.dp.GetMapStats() were three
	// INDEPENDENT cell loads, so a setDataplane(nil) landing between them
	// re-created the exact confusion that check was added to prevent: the
	// publication check
	// passed against backend A, the status probe then resolved nil, and the
	// map arm printed "No BPF maps available" for a daemon that no longer
	// had a backend at all. Loading once and asserting every capability
	// off that single value makes the whole render describe one instant.
	//
	// r4-F1 CORRECTION: r7 asserted this sentence here while the render
	// still took TWO loads. The map-stats arm below ended in
	// `s.dp.SessionCount()`, which under the live indirection resolves the
	// cell again; only the userspace arm had been converted to
	// backendSessionCount(backend). The comment was the whole guard, and a
	// comment cannot fail. The residual is fixed and the property is now
	// bound by TestShowBuffersTakesOneCellLoad, whose fixture counts CELL
	// LOADS — not Unwrap calls, which is what the r7 guard counted and why
	// it stayed green over a second load that was not an Unwrap.
	if backend := dataplane.Unwrap(s.dp); backend != nil {
		// #5782: this render ends with a full v4+v6 SessionCount() table walk
		// (same per-bucket BPF-map lock contention as the session read-scans).
		// Gate the whole render through the shared diagcmd.SessionWalkLimiter and
		// fail fast with ResourceExhausted on contention — the same mechanism
		// sessions-top and the GetSessions RPCs use (ShowText returns this
		// verbatim) — so a `show system buffers` scrape flood cannot drive
		// unbounded concurrent table walks.
		release, err := sessionWalkLimiter.Acquire()
		if err != nil {
			return status.Error(codes.ResourceExhausted,
				"session scan concurrency limit reached; retry shortly")
		}
		defer release()
		if provider, ok := backend.(userspaceStatusProvider); ok {
			status, err := provider.Status()
			if err != nil {
				fmt.Fprintf(buf, "Userspace buffer metrics unavailable: %v\n", err)
			} else {
				buf.WriteString(dpformat.FormatSystemBuffers(status, false))
				v4, v6 := backendSessionCount(backend)
				if v4 > 0 || v6 > 0 {
					fmt.Fprintf(buf, "\nActive sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
				}
			}
		} else {
			stats := backendMapStats(backend)
			if len(stats) == 0 {
				buf.WriteString("No BPF maps available\n")
			} else {
				fmt.Fprintf(buf, "%-24s %-14s %10s %10s %8s %s\n", "Map", "Type", "Max", "Used", "Usage%", "Status")
				buf.WriteString(strings.Repeat("-", 78) + "\n")
				var warnings int
				for _, st := range stats {
					usage := "-"
					used := "-"
					sts := ""
					if st.Type != "Array" && st.Type != "PerCPUArray" {
						used = fmt.Sprintf("%d", st.UsedCount)
						if st.MaxEntries > 0 {
							pct := float64(st.UsedCount) / float64(st.MaxEntries) * 100
							usage = fmt.Sprintf("%.1f%%", pct)
							if pct >= 90 {
								sts = "CRITICAL"
								warnings++
							} else if pct >= 80 {
								sts = "WARNING"
								warnings++
							}
						}
					}
					fmt.Fprintf(buf, "%-24s %-14s %10d %10s %8s %s\n", st.Name, st.Type, st.MaxEntries, used, usage, sts)
				}
				if warnings > 0 {
					fmt.Fprintf(buf, "\n%d map(s) at high utilization — consider increasing max_entries\n", warnings)
				}
			}
			// #6743 r4-F1: backendSessionCount(backend), never
			// s.dp.SessionCount(). The live indirection resolves the cell
			// INSIDE SessionCount as well (liveDataPlane.SessionCount ->
			// resolve(), daemon_dp_live.go), so calling it here is a
			// SECOND load of the same cell: the map table above would
			// describe backend A while this line described whatever the
			// cell held an instant later, and against an emptied cell it
			// returns (0,0) and silently DROPS the "Active sessions" line
			// rather than reporting anything. The userspace arm three
			// lines up was converted in the original #2114 pass for
			// exactly this reason; this arm was missed there because no
			// fixture entered it. Bound by
			// TestShowBuffersTakesOneCellLoad.
			v4, v6 := backendSessionCount(backend)
			if v4 > 0 || v6 > 0 {
				fmt.Fprintf(buf, "\nActive sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
			}
		}
	} else {
		buf.WriteString("Dataplane not loaded\n")
	}
	return nil
}

func (s *Server) showBuffersDetail(cfg *config.Config, buf *strings.Builder) error {
	// #2114/#6743-F3 + r7: same single-LOAD contract as showBuffers — one
	// Unwrap feeds the publication check, the optional status probe, the
	// map-stats fallback AND the session-count tail, so the whole render
	// describes one instant instead of several separate cell loads. The
	// tail is the r4-F1 correction: it read s.dp.SessionCount() here too.
	// Bound, for this render as well, by TestShowBuffersTakesOneCellLoad.
	if backend := dataplane.Unwrap(s.dp); backend != nil {
		// #5782: same full-table SessionCount() walk gate as showBuffers.
		release, err := sessionWalkLimiter.Acquire()
		if err != nil {
			return status.Error(codes.ResourceExhausted,
				"session scan concurrency limit reached; retry shortly")
		}
		defer release()
		if provider, ok := backend.(userspaceStatusProvider); ok {
			status, err := provider.Status()
			if err != nil {
				fmt.Fprintf(buf, "Userspace buffer metrics unavailable: %v\n", err)
			} else {
				buf.WriteString(dpformat.FormatSystemBuffers(status, true))
				v4, v6 := backendSessionCount(backend)
				if v4 > 0 || v6 > 0 {
					fmt.Fprintf(buf, "\nActive sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
				}
			}
		} else {
			stats := backendMapStats(backend)
			if len(stats) == 0 {
				buf.WriteString("No BPF maps available\n")
			} else {
				type mapDetail struct {
					name      string
					mapType   string
					max       uint32
					used      uint32
					keySize   uint32
					valueSize uint32
					pct       float64
				}
				var details []mapDetail
				for _, st := range stats {
					if st.Type == "Array" || st.Type == "PerCPUArray" {
						continue
					}
					pct := float64(0)
					if st.MaxEntries > 0 {
						pct = float64(st.UsedCount) / float64(st.MaxEntries) * 100
					}
					details = append(details, mapDetail{
						name: st.Name, mapType: st.Type, max: st.MaxEntries,
						used: st.UsedCount, keySize: st.KeySize, valueSize: st.ValueSize, pct: pct,
					})
				}
				sort.Slice(details, func(i, j int) bool {
					return details[i].pct > details[j].pct
				})
				buf.WriteString("BPF Map Details (sorted by utilization):\n\n")
				for _, d := range details {
					sts := "OK"
					if d.pct >= 90 {
						sts = "CRITICAL"
					} else if d.pct >= 80 {
						sts = "WARNING"
					}
					fmt.Fprintf(buf, "Map: %s\n", d.name)
					fmt.Fprintf(buf, "  Type: %s, Max: %d, Used: %d, Usage: %.1f%%\n", d.mapType, d.max, d.used, d.pct)
					fmt.Fprintf(buf, "  Key size: %d bytes, Value size: %d bytes\n", d.keySize, d.valueSize)
					fmt.Fprintf(buf, "  Status: %s\n\n", sts)
				}
			}
			// #6743 r4-F1: backendSessionCount(backend), never
			// s.dp.SessionCount(). The live indirection resolves the cell
			// INSIDE SessionCount as well (liveDataPlane.SessionCount ->
			// resolve(), daemon_dp_live.go), so calling it here is a
			// SECOND load of the same cell: the map table above would
			// describe backend A while this line described whatever the
			// cell held an instant later, and against an emptied cell it
			// returns (0,0) and silently DROPS the "Active sessions" line
			// rather than reporting anything. The userspace arm three
			// lines up was converted in the original #2114 pass for
			// exactly this reason; this arm was missed there because no
			// fixture entered it. Bound by
			// TestShowBuffersTakesOneCellLoad.
			v4, v6 := backendSessionCount(backend)
			if v4 > 0 || v6 > 0 {
				fmt.Fprintf(buf, "Active sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
			}
		}
	} else {
		buf.WriteString("Dataplane not loaded\n")
	}
	return nil
}

func (s *Server) showBackupRouter(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.System.BackupRouter == "" {
		buf.WriteString("No backup router configured\n")
	} else {
		fmt.Fprintf(buf, "Backup router: %s\n", cfg.System.BackupRouter)
		if cfg.System.BackupRouterDst != "" {
			fmt.Fprintf(buf, "  Destination: %s\n", cfg.System.BackupRouterDst)
		} else {
			buf.WriteString("  Destination: 0.0.0.0/0 (default)\n")
		}
	}
}
