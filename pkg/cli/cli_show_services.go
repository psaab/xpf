package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/scheduler"
)

// handleShowServices dispatches `show services ...` to the appropriate
// presenter (RPM, application-identification, ...).
func (c *CLI) handleShowServices(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show services:", operationalTree, "show", "services")
		return nil
	}
	switch args[0] {
	case "rpm":
		rest := args[1:]
		if len(rest) > 0 && rest[0] == "probe-results" {
			return c.showRPMProbeResults()
		}
		return c.showRPMProbeResults()
	case "ip-monitoring":
		// #1827: cmdtree leaf is `ip-monitoring status`; reject other
		// targets so typos surface as usage errors. Distinct from
		// `show chassis cluster ip-monitoring status` (RG weights).
		rest := args[1:]
		if len(rest) == 0 {
			cmdtree.PrintTreeHelp("show services ip-monitoring:",
				operationalTree, "show", "services", "ip-monitoring")
			return nil
		}
		if rest[0] != "status" {
			return fmt.Errorf("unknown ip-monitoring target: %s (expected `status`)", rest[0])
		}
		return c.showIPMonitoringStatus()
	case "application-identification":
		// #653: surface what xpf AppID actually does today vs the
		// vSRX application-identification feature. Honest contract,
		// not the catalog-completeness illusion. Per cmdtree the
		// only valid leaf is `application-identification status`;
		// reject anything else so typos surface as usage errors
		// instead of being silently swallowed.
		rest := args[1:]
		if len(rest) == 0 {
			cmdtree.PrintTreeHelp("show services application-identification:",
				operationalTree, "show", "services", "application-identification")
			return nil
		}
		if rest[0] != "status" {
			return fmt.Errorf("unknown application-identification target: %s "+
				"(expected `status`)", rest[0])
		}
		return c.showApplicationIdentificationStatus()
	case "dynamic-dns":
		// #2691 P2: Surface A (router/interface-address) DDNS status.
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showServicesDynamicDNS(detail)
	default:
		return fmt.Errorf("unknown services target: %s", args[0])
	}
}

func (c *CLI) showRPMProbeResults() error {
	// Show live results if RPM manager is available
	if c.rpmResultsFn != nil {
		results := c.rpmResultsFn()
		if len(results) > 0 {
			fmt.Println("RPM Probe Results:")
			for _, r := range results {
				fmt.Printf("  Probe: %s, Test: %s\n", r.ProbeName, r.TestName)
				fmt.Printf("    Type: %s, Target: %s\n", r.ProbeType, config.RedactURL(r.Target))
				fmt.Printf("    Status: %s", r.LastStatus)
				if r.LastRTT > 0 {
					fmt.Printf(", RTT: %s", r.LastRTT)
				}
				fmt.Println()
				if r.MinRTT > 0 {
					fmt.Printf("    RTT: min %s, max %s, avg %s, jitter %s\n",
						r.MinRTT, r.MaxRTT, r.AvgRTT, r.Jitter)
				}
				fmt.Printf("    Sent: %d, Received: %d", r.TotalSent, r.TotalRecv)
				if r.TotalSent > 0 {
					loss := float64(r.TotalSent-r.TotalRecv) / float64(r.TotalSent) * 100
					fmt.Printf(", Loss: %.1f%%", loss)
				}
				fmt.Println()
				if !r.LastProbeAt.IsZero() {
					fmt.Printf("    Last probe: %s\n", r.LastProbeAt.Format("2006-01-02 15:04:05"))
				}
			}
			return nil
		}
	}

	// Fallback: show config only
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	if cfg.Services.RPM == nil || len(cfg.Services.RPM.Probes) == 0 {
		fmt.Println("No RPM probes configured")
		return nil
	}

	fmt.Println("RPM Probe Configuration:")
	for _, probeName := range rpm.SortedProbeNames(cfg.Services.RPM.Probes) {
		probe := cfg.Services.RPM.Probes[probeName]
		for _, testName := range rpm.SortedTestNames(probe.Tests) {
			rpm.WriteConfiguredTest(os.Stdout, probeName, testName, probe.Tests[testName])
			fmt.Println()
		}
	}
	return nil
}

// showIPMonitoringStatus renders live ip-monitoring policy status via
// the shared pkg/ipmon formatter (#1827) so local CLI and gRPC output
// stay byte-identical.
func (c *CLI) showIPMonitoringStatus() error {
	if c.ipmonStatusFn == nil {
		fmt.Println("IP monitoring engine not running")
		return nil
	}
	var buf strings.Builder
	ipmon.FormatStatus(&buf, c.ipmonStatusFn())
	fmt.Print(buf.String())
	return nil
}

// showApplicationIdentificationStatus delegates to the shared
// renderer in `pkg/appid` so the local CLI and the gRPC
// text-show surface stay byte-identical (Copilot review #5 on
// PR #1196). #653.
func (c *CLI) showApplicationIdentificationStatus() error {
	cfg := c.store.ActiveConfig()
	var buf strings.Builder
	appid.RenderStatus(&buf, cfg)
	fmt.Print(buf.String())
	return nil
}

// showSchedulers renders the configured scheduler entries via the shared
// pkg/scheduler formatter (#12922), so the local CLI output stays
// byte-identical to the REST show-text and gRPC ShowText surfaces and —
// unlike the private copy it replaces — carries the daily exclude/all-day
// qualifiers and the per-weekday override arms that decide whether a shown
// window ever applies.
func (c *CLI) showSchedulers() error {
	var buf strings.Builder
	scheduler.FormatSchedulers(&buf, c.store.ActiveConfig())
	fmt.Print(buf.String())
	return nil
}
