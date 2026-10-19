package config

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// #15649: shared show-surface renderers (SSOT) for the Cohort C1 divergence
// cohort (V2-02, V10-04, V11-04, V12-04, V17-04). Before this file each of
// local CLI, gRPC text and REST hand-rolled its own renderer with hardcoded
// literals, so the same config read differently depending on the surface.
// The helpers below are the single authority all three surfaces call.

// --- V11-04: flow session timeouts ---------------------------------------

// Dataplane UDP/ICMP session windows mirrored from
// userspace-dp/src/session/mod.rs (DEFAULT_UDP_SESSION_TIMEOUT_NS /
// DEFAULT_ICMP_SESSION_TIMEOUT_NS, both 60s). Re-pinned against the Rust
// constants by flow_show_15649_test.go.
const (
	DataplaneUDPSessionTimeoutSecs  = 60
	DataplaneICMPSessionTimeoutSecs = 60
)

// FlowTimeoutCell renders one timeout value: the configured seconds, or
// "<default>s (default)" when unset (val <= 0).
func FlowTimeoutCell(val, def int) string {
	if val > 0 {
		return fmt.Sprintf("%ds", val)
	}
	return fmt.Sprintf("%ds (default)", def)
}

// GREAccelerationLine is the single operator wording for
// gre-performance-acceleration (#7188, superseding stale #5804 text that
// claimed GRE sessions "remain 5-tuple keyed"). Empty label selects the
// bare phrase; surfaces prefix their own label.
func GREAccelerationLine() string {
	return "configured (partial; transit GRE keyed on the RFC 2890 discriminator locally, NOT across HA sync — per-tunnel identity does not survive failover — #7188)"
}

// RenderFlowTimeouts writes the unified `show security flow` timeout view
// shared by CLI, gRPC and REST. All rows (including TCP when no tcp-session
// stanza exists) always render with dataplane defaults for unset leaves, so
// no surface prints a bare "0s" for an unset timeout.
func RenderFlowTimeouts(w io.Writer, cfg *Config) {
	if cfg == nil {
		fmt.Fprintln(w, "No active configuration")
		return
	}
	flow := &cfg.Security.Flow
	fmt.Fprintln(w, "Flow session timeouts:")
	tcp := flow.TCPSession
	if tcp == nil {
		tcp = &TCPSessionConfig{}
	}
	tcpRow := func(name, leaf string, val int) {
		var cell string
		switch def, ok := TCPSessionTimeoutDataplaneDefault(leaf); {
		case val > 0:
			cell = fmt.Sprintf("%ds", val)
		case ok:
			cell = fmt.Sprintf("%ds (default)", def)
		default:
			cell = "not set"
		}
		fmt.Fprintf(w, "  %-30s %s\n", name+":", AnnotateTCPSessionTimeout(leaf, cell))
	}
	tcpRow("TCP established timeout", TCPSessionEstablishedTimeoutLeaf, tcp.EstablishedTimeout)
	tcpRow("TCP initial timeout", TCPSessionInitialTimeoutLeaf, tcp.InitialTimeout)
	tcpRow("TCP closing timeout", TCPSessionClosingTimeoutLeaf, tcp.ClosingTimeout)
	tcpRow("TCP time-wait timeout", TCPSessionTimeWaitTimeoutLeaf, tcp.TimeWaitTimeout)
	fmt.Fprintf(w, "  %-30s %s\n", "UDP session timeout:", FlowTimeoutCell(flow.UDPSessionTimeout, DataplaneUDPSessionTimeoutSecs))
	fmt.Fprintf(w, "  %-30s %s\n", "ICMP session timeout:", FlowTimeoutCell(flow.ICMPSessionTimeout, DataplaneICMPSessionTimeoutSecs))

	if flow.TCPMSSAllTCP > 0 || flow.TCPMSSIPsecVPN > 0 || flow.TCPMSSGreIn > 0 || flow.TCPMSSGreOut > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "TCP MSS clamping:")
		if flow.TCPMSSAllTCP > 0 {
			fmt.Fprintf(w, "  %-30s %d\n", "All TCP MSS:", flow.TCPMSSAllTCP)
		}
		if flow.TCPMSSIPsecVPN > 0 {
			fmt.Fprintf(w, "  %-30s %d\n", "IPsec VPN MSS (not enforced):", flow.TCPMSSIPsecVPN)
		}
		if flow.TCPMSSGreIn > 0 {
			fmt.Fprintf(w, "  %-30s %d\n", "GRE ingress MSS:", flow.TCPMSSGreIn)
		}
		if flow.TCPMSSGreOut > 0 {
			fmt.Fprintf(w, "  %-30s %d\n", "GRE egress MSS:", flow.TCPMSSGreOut)
		}
	}
	if flow.AllowDNSReply || flow.AllowEmbeddedICMP || flow.GREPerformanceAcceleration || flow.PowerModeDisable {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Flow options:")
		if flow.AllowDNSReply {
			fmt.Fprintln(w, "  allow-dns-reply:               enabled")
		}
		if flow.AllowEmbeddedICMP {
			fmt.Fprintln(w, "  allow-embedded-icmp:           enabled")
		}
		if flow.GREPerformanceAcceleration {
			fmt.Fprintf(w, "  gre-performance-acceleration:  %s\n", GREAccelerationLine())
		}
		if flow.PowerModeDisable {
			fmt.Fprintln(w, "  power-mode-disable:            yes")
		}
	}
}

// --- V2-02: policy detail count + session statistics ---------------------

// PolicyCounter is the show-surface view of a policy hit counter.
type PolicyCounter struct {
	Packets uint64
	Bytes   uint64
}

// ErrPolicyCounterUnpublished mirrors dpuserspace.ErrPolicyCounterUnpublished
// for the shared renderer; adapters translate.
var ErrPolicyCounterUnpublished = errors.New("policy counter not yet published by the dataplane")

// PolicyDetailStats renders the `then count` marker and Session statistics
// block for one policy-detail row. countIndent prefixes the count line,
// statsIndent prefixes the statistics header/values. It returns
// (statsDisabled, readErr): statsDisabled is true when the block was omitted
// because policy-stats is off and the rule carries no `count`, so callers
// can emit the single trailing #8177 note.
func PolicyDetailStats(w io.Writer, countIndent, statsIndent string, pol *Policy, quarantined, statsEnabled bool, read func(uint32) (PolicyCounter, error), ruleID uint32) (statsDisabled bool, readErr error) {
	if pol == nil {
		return false, nil
	}
	if pol.Count {
		fmt.Fprintf(w, "%scount\n", countIndent)
	}
	if quarantined {
		fmt.Fprintf(w, "%sSession statistics: %s\n", statsIndent, ZoneQuarantineLiveCountersUnavailable)
		return false, nil
	}
	if (statsEnabled || pol.Count) && read != nil {
		counters, err := read(ruleID)
		switch {
		case err == nil:
			fmt.Fprintf(w, "%sSession statistics:\n", statsIndent)
			fmt.Fprintf(w, "%s  %d packets, %d bytes\n", statsIndent, counters.Packets, counters.Bytes)
		case errors.Is(err, ErrPolicyCounterUnpublished):
			fmt.Fprintf(w, "%sSession statistics: not available (not yet published by the dataplane)\n", statsIndent)
		default:
			readErr = err
		}
		return false, readErr
	}
	if !statsEnabled && !pol.Count {
		return true, nil
	}
	return false, nil
}

// --- V12-04: application resolution / expansion --------------------------

// ExpandedApplicationNames returns the leaf application names a show surface
// must detail for the named application or application-set: ExpandApplicationSet
// for sets (user or predefined, nested), or the single resolved application.
// ok=false means the name resolves to neither.
func ExpandedApplicationNames(cfg *Config, name string) ([]string, bool) {
	if cfg == nil {
		if _, ok := ResolveApplication(name, nil); ok {
			return []string{name}, true
		}
		if _, err := ExpandApplicationSet(name, &ApplicationsConfig{}); err == nil {
			names, _ := ExpandApplicationSet(name, &ApplicationsConfig{})
			return names, true
		}
		return nil, false
	}
	apps := &cfg.Applications
	if _, isSet := ResolveApplicationSet(name, apps.ApplicationSets); isSet {
		if names, err := ExpandApplicationSet(name, apps); err == nil {
			return names, true
		}
		return nil, true
	}
	if _, ok := ResolveApplication(name, apps.Applications); ok {
		return []string{name}, true
	}
	return nil, false
}

// ResolvedApplication returns the effective application for a leaf name.
func ResolvedApplication(cfg *Config, name string) (*Application, bool) {
	var userApps map[string]*Application
	if cfg != nil {
		userApps = cfg.Applications.Applications
	}
	app, ok := ResolveApplication(name, userApps)
	if !ok || app == nil {
		return nil, false
	}
	return app, true
}

// ApplicationSetExpandedMembers renders "name -> leaf1, leaf2" for a set,
// using ExpandApplicationSet so nested/term/predefined members expand.
// Falls back to raw members when expansion fails (dangling member on the
// tolerant path) so the surface still shows what was configured.
func ApplicationSetExpandedMembers(cfg *Config, set *ApplicationSet) string {
	if set == nil {
		return ""
	}
	if cfg != nil {
		if names, err := ExpandApplicationSet(set.Name, &cfg.Applications); err == nil && len(names) > 0 {
			return strings.Join(names, ", ")
		}
	}
	return strings.Join(set.Applications, ", ")
}

// --- V17-04: flow monitoring ---------------------------------------------

// HasFlowMonitoring reports whether any v9 or IPFIX template config exists.
func HasFlowMonitoring(cfg *Config) bool {
	if cfg == nil || cfg.Services.FlowMonitoring == nil {
		return false
	}
	fm := cfg.Services.FlowMonitoring
	return (fm.Version9 != nil && len(fm.Version9.Templates) > 0) ||
		(fm.VersionIPFIX != nil && len(fm.VersionIPFIX.Templates) > 0)
}

// RenderFlowMonitoring writes the unified flow-monitoring view: v9 and
// IPFIX templates (IPFIX-only configs must not read as unconfigured), plus
// sampling flow-server template bindings and NOT-INSTALLED suffixes via
// FlowServerExcludedReason. suffixFor may be nil.
func RenderFlowMonitoring(w io.Writer, cfg *Config, suffixFor func(*FlowServer) string) {
	if cfg == nil {
		fmt.Fprintln(w, "No active configuration")
		return
	}
	has := false
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.Version9 != nil && len(cfg.Services.FlowMonitoring.Version9.Templates) > 0 {
		has = true
		fmt.Fprintln(w, "Flow monitoring (NetFlow v9):")
		for _, name := range SortedFlowTemplateNames(cfg.Services.FlowMonitoring.Version9.Templates) {
			tmpl := cfg.Services.FlowMonitoring.Version9.Templates[name]
			if tmpl == nil {
				continue
			}
			fmt.Fprintf(w, "  Template: %s\n", name)
			if tmpl.FlowActiveTimeout > 0 {
				fmt.Fprintf(w, "    Active timeout: %ds\n", tmpl.FlowActiveTimeout)
			}
			if tmpl.FlowInactiveTimeout > 0 {
				fmt.Fprintf(w, "    Inactive timeout: %ds\n", tmpl.FlowInactiveTimeout)
			}
			if tmpl.TemplateRefreshRate > 0 {
				fmt.Fprintf(w, "    Template refresh: %ds\n", tmpl.TemplateRefreshRate)
			}
			if len(tmpl.ExportExtensions) > 0 {
				fmt.Fprintf(w, "    Export extensions: %s\n", strings.Join(tmpl.ExportExtensions, ", "))
			}
		}
	}
	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.VersionIPFIX != nil && len(cfg.Services.FlowMonitoring.VersionIPFIX.Templates) > 0 {
		has = true
		fmt.Fprintln(w, "Flow monitoring (IPFIX):")
		for _, name := range SortedIPFIXTemplateNames(cfg.Services.FlowMonitoring.VersionIPFIX.Templates) {
			tmpl := cfg.Services.FlowMonitoring.VersionIPFIX.Templates[name]
			if tmpl == nil {
				continue
			}
			fmt.Fprintf(w, "  Template: %s\n", name)
			if tmpl.FlowActiveTimeout > 0 {
				fmt.Fprintf(w, "    Active timeout: %ds\n", tmpl.FlowActiveTimeout)
			}
			if tmpl.FlowInactiveTimeout > 0 {
				fmt.Fprintf(w, "    Inactive timeout: %ds\n", tmpl.FlowInactiveTimeout)
			}
			if tmpl.TemplateRefreshRate > 0 {
				fmt.Fprintf(w, "    Template refresh: %ds\n", tmpl.TemplateRefreshRate)
			}
			if len(tmpl.ExportExtensions) > 0 {
				fmt.Fprintf(w, "    Export extensions: %s\n", strings.Join(tmpl.ExportExtensions, ", "))
			}
		}
	}
	// Sampling flow-servers carry the template bindings that tie a collector
	// to the templates above; render them on this surface too.
	if cfg.ForwardingOptions.Sampling != nil {
		for _, iname := range SortedSamplingInstanceNames(cfg.ForwardingOptions.Sampling.Instances) {
			inst := cfg.ForwardingOptions.Sampling.Instances[iname]
			if inst == nil {
				continue
			}
			for _, fam := range []*SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
				if fam == nil {
					continue
				}
				for _, fs := range fam.FlowServers {
					if fs == nil {
						continue
					}
					has = true
					suffix := ""
					if suffixFor != nil {
						suffix = suffixFor(fs)
					}
					fmt.Fprintf(w, "  Flow server: %s:%d%s\n", fs.Address, fs.Port, suffix)
					if fs.Version9Template != "" {
						fmt.Fprintf(w, "    Version 9 template: %s\n", fs.Version9Template)
					}
					if fs.VersionIPFIXTemplate != "" {
						fmt.Fprintf(w, "    IPFIX template: %s\n", fs.VersionIPFIXTemplate)
					}
					if fs.SourceAddress != "" {
						fmt.Fprintf(w, "    Source address: %s\n", fs.SourceAddress)
					}
				}
				if fam.InlineJflow {
					fmt.Fprintf(w, "  Inline jflow: enabled (instance %s)\n", iname)
				}
				if fam.InlineJflowSourceAddress != "" {
					fmt.Fprintf(w, "  Inline jflow source: %s (instance %s)\n", fam.InlineJflowSourceAddress, iname)
				}
			}
		}
	}
	if !has {
		fmt.Fprintln(w, "No flow monitoring configured")
	}
}

func SortedFlowTemplateNames(m map[string]*NetFlowV9Template) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func SortedIPFIXTemplateNames(m map[string]*NetFlowIPFIXTemplate) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func SortedSamplingInstanceNames(m map[string]*SamplingInstance) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
