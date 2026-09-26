package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
	"github.com/psaab/xpf/pkg/devicemap"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fabricRedirectCounters captures global counters describing how many
// packets traversed the fabric redirect path.
type fabricRedirectCounters struct {
	total uint64
	fab0  uint64
	fab1  uint64
	zone  uint64
	drops uint64
}

// readFabricRedirectCounters samples the dataplane fabric counters.
// Returns (zeroed, false, nil) when the dataplane is not loaded. The third
// value is the first global-counter read error (#3345) so the caller can
// surface a degraded counter bridge instead of presenting clean zeros.
func (c *CLI) readFabricRedirectCounters() (fabricRedirectCounters, bool, error) {
	if !c.dataplaneLoaded() {
		return fabricRedirectCounters{}, false, nil
	}
	telemetry := dataplane.TelemetryOf(c.dp)
	var readErr error
	read := func(index uint32) uint64 {
		v, err := telemetry.GlobalCounter(index)
		if err != nil && readErr == nil {
			readErr = err
		}
		return v
	}
	return fabricRedirectCounters{
		total: read(dataplane.GlobalCtrFabricRedirect),
		fab0:  read(dataplane.GlobalCtrFabricRedirectFab0),
		fab1:  read(dataplane.GlobalCtrFabricRedirectFab1),
		zone:  read(dataplane.GlobalCtrFabricRedirectZone),
		drops: read(dataplane.GlobalCtrFabricFwdDrop),
	}, true, readErr
}

// showChassis shows hardware information (like Junos "show chassis hardware").

func (c *CLI) showChassis(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "hardware":
			return c.showChassisHardware()
		case "cluster":
			return c.showChassisCluster(args[1:])
		case "environment":
			return c.showChassisEnvironment()
		case "forwarding":
			return c.showChassisForwarding()
		case "device-map":
			return c.showChassisDeviceMap(args[1:])
		}
	}
	cmdtree.PrintTreeHelp("show chassis:", operationalTree, "show", "chassis")
	return nil
}

// showChassisDeviceMap renders the #1956 bare-metal device-map: the resolved
// bindings of the active config, or — with `candidates` — every present NIC's
// identity so an operator can copy-paste a map without memorizing PCI BDFs.
func (c *CLI) showChassisDeviceMap(args []string) error {
	if len(args) > 0 && args[0] == "candidates" {
		return c.showChassisDeviceMapCandidates()
	}

	// Check device-map presence BEFORE enumerating NICs (Codex r3 LOW:
	// match the gRPC server's safer order — no sysfs walk when not configured).
	cfg := c.store.ActiveConfig()
	var dm *config.DeviceMapConfig
	if cfg != nil {
		dm = cfg.Chassis.DeviceMap
	}
	if !dm.Active() {
		fmt.Println("Device-map: not configured (positional interface naming is in effect).")
		fmt.Println("Run 'show chassis device-map candidates' to list NICs, then")
		fmt.Println("'set chassis device-map interface <name> pci <addr>' to author a map.")
		return nil
	}

	nics, err := devicemap.EnumeratePresentNICs()
	if err != nil {
		return fmt.Errorf("enumerate NICs: %w", err)
	}
	bindings := devicemap.Resolve(dm.Entries, nics, devicemap.RethMembersFromConfig(cfg))
	fmt.Printf("Device-map (unmapped-interface-policy: %s):\n\n", dm.EffectiveUnmappedPolicy())
	fmt.Printf("%-12s %-24s %-16s %s\n", "Logical", "Identity (key)", "Resolved kernel", "Status")
	fmt.Printf("%-12s %-24s %-16s %s\n", "-------", "--------------", "---------------", "------")
	for _, b := range bindings {
		ident := b.Entry.PCIAddr
		if ident == "" {
			ident = b.Entry.MAC
		} else if b.Entry.MAC != "" {
			ident += " (+mac)"
		}
		resolved := b.CurrentNIC
		if resolved == "" {
			resolved = "—"
		} else {
			resolved = fmt.Sprintf("%s→%s", resolved, b.Logical)
		}
		fmt.Printf("%-12s %-24s %-16s %s\n", b.Entry.LogicalName, ident, resolved, b.Status.String())
	}
	return nil
}

// showChassisDeviceMapCandidates lists every present NIC with its PCI address,
// permanent MAC, current name, and link state — the copy-paste source for
// authoring a device-map (operator priority: no hand-typed BDF archaeology).
func (c *CLI) showChassisDeviceMapCandidates() error {
	nics, err := devicemap.EnumeratePresentNICs()
	if err != nil {
		return fmt.Errorf("enumerate NICs: %w", err)
	}
	if len(nics) == 0 {
		fmt.Println("No PCI network interfaces found.")
		return nil
	}
	fmt.Print("Device-map candidates (copy a PCI address into a map entry):\n\n")
	fmt.Printf("%-16s %-18s %-14s %s\n", "PCI address", "Permanent MAC", "Current name", "Link")
	fmt.Printf("%-16s %-18s %-14s %s\n", "-----------", "-------------", "------------", "----")
	for _, n := range nics {
		// #6786: single-sourced so the local CLI and the remote/gRPC
		// renderer cannot drift, and so an UNREAD identity is not reported
		// as "(none)"/"down" — which would assert facts the failed read
		// does not support.
		perm := n.PermMACDisplay()
		link := n.LinkDisplay()
		fmt.Printf("%-16s %-18s %-14s %s\n", n.PCIAddr, perm, n.Name, link)
	}
	fmt.Println("\nExample:")
	fmt.Printf("  set chassis device-map interface ge-0/0/3 pci %s\n", nics[0].PCIAddr)
	fmt.Println("  set chassis device-map unmapped-interface-policy leave-alone")
	return nil
}

// showChassisCluster shows cluster/HA configuration and status.

func (c *CLI) showChassisCluster(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return c.showChassisClusterStatus()
		case "interfaces":
			return c.showChassisClusterInterfaces()
		case "information":
			return c.showChassisClusterInformation()
		case "statistics":
			return c.showChassisClusterStatistics()
		case "fabric":
			if len(args) > 1 && args[1] == "statistics" {
				return c.showChassisClusterFabricStatistics()
			}
			cmdtree.PrintTreeHelp("show chassis cluster fabric:", operationalTree, "show", "chassis", "cluster", "fabric")
			return nil
		case "control-plane":
			if len(args) > 1 && args[1] == "statistics" {
				return c.showChassisClusterControlPlaneStats()
			}
			cmdtree.PrintTreeHelp("show chassis cluster control-plane:", operationalTree, "show", "chassis", "cluster", "control-plane")
			return nil
		case "data-plane":
			if len(args) > 1 {
				switch args[1] {
				case "statistics":
					return c.showChassisClusterDataPlaneStats()
				case "interfaces":
					return c.showChassisClusterDataPlaneInterfaces()
				case "fairness":
					return c.showChassisClusterDataPlaneFairness()
				case "flows":
					limit, err := dpformat.ParseFlowWorkerMapLimitSpec(strings.Join(args[2:], " "))
					if err != nil {
						return err
					}
					return c.showChassisClusterDataPlaneFlows(limit)
				}
			}
			cmdtree.PrintTreeHelp("show chassis cluster data-plane:", operationalTree, "show", "chassis", "cluster", "data-plane")
			return nil
		case "ip-monitoring":
			if len(args) > 1 && args[1] == "status" {
				return c.showChassisClusterIPMonitoringStatus()
			}
			cmdtree.PrintTreeHelp("show chassis cluster ip-monitoring:", operationalTree, "show", "chassis", "cluster", "ip-monitoring")
			return nil
		}
	}
	// Default: show status
	return c.showChassisClusterStatus()
}

func (c *CLI) showChassisClusterStatus() error {
	if c.cluster != nil {
		fmt.Print(c.cluster.FormatStatus())
	} else {
		fmt.Println("Cluster not configured")
	}
	c.appendClockSkewAlarm()

	// Show config-derived VRRP group details. The rows are explicitly qualified
	// as configured, rather than implied to be live mastership (#10844).
	fmt.Print(cluster.FormatVRRPConfigRows(c.store.ActiveConfig()))
	return nil
}

// appendClockSkewAlarm surfaces the daemon-resident pre-break fabric-auth
// alarm next to the local cluster status (#10025). Empty or unwired snapshots
// are silent so healthy status output remains unchanged.
func (c *CLI) appendClockSkewAlarm() {
	if c.clockSkewAlarmsFn == nil {
		return
	}
	for _, alarm := range c.clockSkewAlarmsFn() {
		fmt.Printf("\nWarning: %s\n", alarm.Summary())
	}
}

func (c *CLI) showChassisClusterInterfaces() error {
	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	input := c.buildInterfacesInput()
	fmt.Print(c.cluster.FormatInterfaces(input))
	return nil
}

func (c *CLI) showChassisClusterInformation() error {
	if c.cluster != nil {
		fmt.Print(c.cluster.FormatInformation())
		return nil
	}
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	cc := cfg.Chassis.Cluster
	hbInterval := cc.HeartbeatInterval
	if hbInterval == 0 {
		hbInterval = 1000
	}
	hbThreshold := cc.HeartbeatThreshold
	if hbThreshold == 0 {
		hbThreshold = 3
	}
	fmt.Printf("Cluster ID: %d\n", cc.ClusterID)
	fmt.Printf("Node ID: %d\n", cc.NodeID)
	fmt.Printf("RETH count: %d\n", cc.RethCount)
	fmt.Printf("Heartbeat interval: %d ms\n", hbInterval)
	fmt.Printf("Heartbeat threshold: %d\n", hbThreshold)
	fmt.Printf("Redundancy groups: %d\n", len(cc.RedundancyGroups))
	return nil
}

func (c *CLI) showChassisClusterStatistics() error {
	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	fmt.Print(c.cluster.FormatStatistics())
	return nil
}

func (c *CLI) showChassisClusterFabricStatistics() error {
	counters, ok, readErr := c.readFabricRedirectCounters()
	if !ok {
		fmt.Println("Dataplane not loaded")
		return nil
	}

	fmt.Println("Fabric redirect statistics:")
	if readErr != nil {
		fmt.Printf("warning: fabric counter read failed (statistics may be incomplete): %v\n", readErr)
	}
	fmt.Printf("    Total redirects:          %d\n", counters.total)
	fmt.Printf("    fab0 redirects:           %d\n", counters.fab0)
	fmt.Printf("    fab1 redirects:           %d\n", counters.fab1)
	fmt.Printf("    Zone-encoded redirects:   %d\n", counters.zone)
	fmt.Printf("    Redirect drops:           %d\n", counters.drops)
	fmt.Println()
	fmt.Println("Note: XDP-redirected packets bypass AF_PACKET (tcpdump).")
	fmt.Println("Use these counters or 'monitor interface <fab>' for fabric telemetry.")
	return nil
}

func (c *CLI) showChassisClusterControlPlaneStats() error {
	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	fmt.Print(c.cluster.FormatControlPlaneStatistics())
	return nil
}

func (c *CLI) showChassisClusterDataPlaneStats() error {
	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	fmt.Print(c.cluster.FormatDataPlaneStatistics())
	if status, err := c.userspaceDataplaneStatus(); err == nil {
		fmt.Println()
		fmt.Print(dpformat.FormatStatusSummary(status))
	}
	return nil
}

func (c *CLI) showChassisClusterDataPlaneInterfaces() error {
	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	fmt.Print(c.cluster.FormatDataPlaneInterfaces())
	if status, err := c.userspaceDataplaneStatus(); err == nil {
		fmt.Println()
		fmt.Print(dpformat.FormatBindings(status))
	}
	return nil
}

func (c *CLI) showChassisClusterDataPlaneFairness() error {
	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	status, err := c.userspaceDataplaneStatus()
	if err != nil {
		return err
	}
	fmt.Print(dpformat.FormatFairnessRSS(status, dpuserspace.FairnessRSSExpectationsFromConfig(c.store.ActiveConfig())))
	return nil
}

func (c *CLI) showChassisClusterDataPlaneFlows(limit int) error {
	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	status, err := c.userspaceDataplaneStatus()
	if err != nil {
		return err
	}
	fmt.Print(dpformat.FormatFlowWorkerMap(status, limit))
	return nil
}

func (c *CLI) showChassisClusterIPMonitoringStatus() error {
	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}
	fmt.Print(c.cluster.FormatIPMonitoringStatus())
	return nil
}

// showChassisEnvironment shows system temperature and power info.

func (c *CLI) showChassisEnvironment() error {
	// Thermal zones
	thermalZones, _ := filepath.Glob(thermalZoneGlob)
	if len(thermalZones) > 0 {
		fmt.Println("Temperature:")
		for _, tz := range thermalZones {
			data, err := os.ReadFile(tz)
			if err != nil {
				continue
			}
			millideg, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
			if err != nil {
				continue
			}
			// Read type for zone name
			typeFile := filepath.Join(filepath.Dir(tz), "type")
			name := filepath.Base(filepath.Dir(tz))
			if typeData, err := os.ReadFile(typeFile); err == nil {
				name = strings.TrimSpace(string(typeData))
			}
			fmt.Printf("  %-30s %s C\n", sanitizeTerminalText(name), formatMilliCelsius(millideg))
		}
		fmt.Println()
	}

	// Power supply
	powerFiles, _ := filepath.Glob("/sys/class/power_supply/*/status")
	if len(powerFiles) > 0 {
		fmt.Println("Power supplies:")
		for _, pf := range powerFiles {
			name := filepath.Base(filepath.Dir(pf))
			status, err := os.ReadFile(pf)
			if err != nil {
				continue
			}
			fmt.Printf("  %-20s %s\n", sanitizeTerminalText(name),
				sanitizeTerminalText(strings.TrimSpace(string(status))))
		}
		fmt.Println()
	}

	// System uptime and load
	var sysinfo unix.Sysinfo_t
	if err := unix.Sysinfo(&sysinfo); err == nil {
		days := sysinfo.Uptime / 86400
		hours := (sysinfo.Uptime % 86400) / 3600
		mins := (sysinfo.Uptime % 3600) / 60
		fmt.Printf("System uptime: %d days, %d:%02d\n", days, hours, mins)
		fmt.Printf("Load average: %.2f %.2f %.2f\n",
			float64(sysinfo.Loads[0])/65536.0,
			float64(sysinfo.Loads[1])/65536.0,
			float64(sysinfo.Loads[2])/65536.0)
		fmt.Printf("Total RAM: %s, Free: %s\n",
			fmtBytes(sysinfo.Totalram), fmtBytes(sysinfo.Freeram))
	}

	return nil
}

// showChassisHardware shows CPU, memory, and NIC information.

func (c *CLI) showChassisHardware() error {
	// CPU info
	cpuData, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		cpuModel := ""
		cpuCount := 0
		for _, line := range strings.Split(string(cpuData), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					cpuModel = strings.TrimSpace(parts[1])
				}
				cpuCount++
			}
		}
		if cpuModel != "" {
			fmt.Printf("CPU: %s (%d cores)\n", cpuModel, cpuCount)
		}
	}

	// Memory
	memData, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(memData), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if kb, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						fmt.Printf("Memory: %s total\n", fmtBytes(kb*1024))
					}
				}
				break
			}
		}
	}

	// Kernel version
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		release := strings.TrimRight(string(uts.Release[:]), "\x00")
		machine := strings.TrimRight(string(uts.Machine[:]), "\x00")
		fmt.Printf("Kernel: %s (%s)\n", release, machine)
	}

	// Network interfaces
	fmt.Println("\nNetwork interfaces:")
	links, err := netlink.LinkList()
	if err == nil {
		for _, link := range links {
			attrs := link.Attrs()
			if attrs.Name == "lo" {
				continue
			}
			state := "down"
			if attrs.OperState == netlink.OperUp {
				state = "up"
			}
			driver := link.Type()
			fmt.Printf("  %-16s %-8s %-10s %s\n", attrs.Name, state, driver, attrs.HardwareAddr)
		}
	}
	return nil
}
