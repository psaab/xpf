package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

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
		}
	}
	cmdtree.PrintTreeHelp("show chassis:", operationalTree, "show", "chassis")
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
					limit, err := dpuserspace.ParseFlowWorkerMapLimitSpec(strings.Join(args[2:], " "))
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

	// Show VRRP status if any
	cfg := c.store.ActiveConfig()
	if cfg != nil && cfg.Security.Zones != nil {
		for _, zone := range cfg.Security.Zones {
			for _, iface := range zone.Interfaces {
				ifCfg, ok := cfg.Interfaces.Interfaces[iface]
				if !ok {
					continue
				}
				for _, unit := range ifCfg.Units {
					for addr, vg := range unit.VRRPGroups {
						fmt.Printf("VRRP on %s.%d: group %d, priority %d, VIP %s, address %s\n",
							iface, unit.Number, vg.ID, vg.Priority,
							strings.Join(vg.VirtualAddresses, ","), addr)
					}
				}
			}
		}
	}
	return nil
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
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	total, _ := c.dp.ReadGlobalCounter(dataplane.GlobalCtrFabricRedirect)
	fab0, _ := c.dp.ReadGlobalCounter(dataplane.GlobalCtrFabricRedirectFab0)
	fab1, _ := c.dp.ReadGlobalCounter(dataplane.GlobalCtrFabricRedirectFab1)
	zone, _ := c.dp.ReadGlobalCounter(dataplane.GlobalCtrFabricRedirectZone)
	drops, _ := c.dp.ReadGlobalCounter(dataplane.GlobalCtrFabricFwdDrop)

	fmt.Println("Fabric redirect statistics:")
	fmt.Printf("    Total redirects:          %d\n", total)
	fmt.Printf("    fab0 redirects:           %d\n", fab0)
	fmt.Printf("    fab1 redirects:           %d\n", fab1)
	fmt.Printf("    Zone-encoded redirects:   %d\n", zone)
	fmt.Printf("    Redirect drops:           %d\n", drops)
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
		fmt.Print(dpuserspace.FormatStatusSummary(status))
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
		fmt.Print(dpuserspace.FormatBindings(status))
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
	fmt.Print(dpuserspace.FormatFairnessRSS(status))
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
	fmt.Print(dpuserspace.FormatFlowWorkerMap(status, limit))
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
	thermalZones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
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
			fmt.Printf("  %-30s %d.%d C\n", name, millideg/1000, (millideg%1000)/100)
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
			fmt.Printf("  %-20s %s\n", name, strings.TrimSpace(string(status)))
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
