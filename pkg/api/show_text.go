package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/natshow"
)

// sortedKeys returns the keys of a string-keyed map in ascending order. The
// show-text handlers render config maps as operator/automation-facing text, so
// iterating them in sorted order keeps the output deterministic across requests
// (Go map iteration order is randomized). See #4712.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) showTextHandler(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Query().Get("topic")
	if topic == "" {
		writeError(w, http.StatusBadRequest, "topic parameter required")
		return
	}

	cfg := s.store.ActiveConfig()
	var buf strings.Builder

	switch topic {
	case "schedulers":
		if cfg == nil || len(cfg.Schedulers) == 0 {
			buf.WriteString("No schedulers configured\n")
		} else {
			for _, name := range sortedKeys(cfg.Schedulers) {
				sched := cfg.Schedulers[name]
				if sched == nil {
					// #10439: tolerate present-but-nil slots from lenient
					// restore/peer-sync loads.
					continue
				}
				fmt.Fprintf(&buf, "Scheduler: %s\n", name)
				if sched.StartTime != "" {
					fmt.Fprintf(&buf, "  Start time: %s\n", sched.StartTime)
				}
				if sched.StopTime != "" {
					fmt.Fprintf(&buf, "  Stop time:  %s\n", sched.StopTime)
				}
				if sched.StartDate != "" {
					fmt.Fprintf(&buf, "  Start date: %s\n", sched.StartDate)
				}
				if sched.StopDate != "" {
					fmt.Fprintf(&buf, "  Stop date:  %s\n", sched.StopDate)
				}
				if sched.Daily {
					buf.WriteString("  Recurrence: daily\n")
				}
				buf.WriteString("\n")
			}
		}

	case "snmp":
		if cfg == nil || cfg.System.SNMP == nil {
			buf.WriteString("No SNMP configured\n")
		} else {
			snmpCfg := cfg.System.SNMP
			if snmpCfg.Location != "" {
				fmt.Fprintf(&buf, "Location:    %s\n", snmpCfg.Location)
			}
			if snmpCfg.Contact != "" {
				fmt.Fprintf(&buf, "Contact:     %s\n", snmpCfg.Contact)
			}
			if snmpCfg.Description != "" {
				fmt.Fprintf(&buf, "Description: %s\n", snmpCfg.Description)
			}
			if len(snmpCfg.Communities) > 0 {
				buf.WriteString("Communities:\n")
				// #5315: the SNMPv1/v2c community string IS the shared secret
				// (it authorizes the request on the wire) and it is also the
				// Communities map key. Emitting the raw key here leaked the
				// cleartext credential over the REST show-text surface, which
				// has no login-class authz and is loopback-open by default.
				// Mask it with the shared raw-AST placeholder — the same token
				// pkg/cli `show snmp` uses for a redacted community (#4111) — so
				// this manual renderer matches the established redaction
				// boundary. The authorization mode stays visible; only the
				// secret is masked. Iteration still runs over the real (sorted)
				// keys so ordering stays deterministic (#4712).
				//
				// #6532 routed the mask through the shared
				// config.SNMPCommunityDisplayName helper so this surface, the
				// pkg/cli status commands and the gRPC ShowText topic cannot
				// drift apart again. redact=true is unconditional here: REST
				// show-text carries no login class to gate on.
				for _, name := range sortedKeys(snmpCfg.Communities) {
					comm := snmpCfg.Communities[name]
					if comm == nil {
						// #10439: tolerate present-but-nil slots from lenient
						// restore/peer-sync loads.
						continue
					}
					fmt.Fprintf(&buf, "  %s: %s\n",
						config.SNMPCommunityDisplayName(name, true), comm.Authorization)
				}
			}
			if len(snmpCfg.TrapGroups) > 0 {
				buf.WriteString("Trap groups:\n")
				for _, name := range sortedKeys(snmpCfg.TrapGroups) {
					tg := snmpCfg.TrapGroups[name]
					if tg == nil {
						// #10439: tolerate present-but-nil slots from lenient
						// restore/peer-sync loads.
						continue
					}
					fmt.Fprintf(&buf, "  %s: %s\n", name, strings.Join(tg.Targets, ", "))
				}
			}
		}

	case "dhcp-relay":
		if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
			buf.WriteString("No DHCP relay configured\n")
		} else {
			relay := cfg.ForwardingOptions.DHCPRelay
			if len(relay.ServerGroups) > 0 {
				buf.WriteString("Server groups:\n")
				for _, name := range sortedKeys(relay.ServerGroups) {
					sg := relay.ServerGroups[name]
					if sg == nil {
						// #10439: tolerate present-but-nil slots from lenient
						// restore/peer-sync loads.
						continue
					}
					fmt.Fprintf(&buf, "  %s: %s\n", name, strings.Join(sg.Servers, ", "))
				}
			}
			if len(relay.Groups) > 0 {
				buf.WriteString("Relay groups:\n")
				for _, name := range sortedKeys(relay.Groups) {
					g := relay.Groups[name]
					if g == nil {
						// #10439: tolerate present-but-nil slots from lenient
						// restore/peer-sync loads.
						continue
					}
					fmt.Fprintf(&buf, "  %s:\n", name)
					fmt.Fprintf(&buf, "    Interfaces: %s\n", strings.Join(g.Interfaces, ", "))
					fmt.Fprintf(&buf, "    Active server group: %s\n", g.ActiveServerGroup)
				}
			}
		}

	case "firewall":
		hasFilters := cfg != nil && (len(cfg.Firewall.FiltersInet) > 0 || len(cfg.Firewall.FiltersInet6) > 0)
		if !hasFilters {
			buf.WriteString("No firewall filters configured\n")
		} else {
			printFilters := func(family string, filters map[string]*config.FirewallFilter) {
				for _, name := range sortedKeys(filters) {
					filter := filters[name]
					if filter == nil {
						// #10439: tolerate present-but-nil slots from lenient
						// restore/peer-sync loads.
						continue
					}
					fmt.Fprintf(&buf, "Filter: %s (family: %s)\n", name, family)
					for _, term := range filter.Terms {
						if term == nil {
							// #10439: tolerate present-but-nil terms from
							// lenient restore/peer-sync loads.
							continue
						}
						fmt.Fprintf(&buf, "  Term: %s\n", term.Name)
						if len(term.Protocols) > 0 {
							fmt.Fprintf(&buf, "    From protocol: %s\n", strings.Join(term.Protocols, ", "))
						}
						if len(term.DestinationPorts) > 0 {
							fmt.Fprintf(&buf, "    From destination-port: %s\n", strings.Join(term.DestinationPorts, ", "))
						}
						if len(term.SourceAddresses) > 0 {
							fmt.Fprintf(&buf, "    From source-address: %s\n", strings.Join(term.SourceAddresses, ", "))
						}
						if len(term.DSCPs) > 0 {
							fmt.Fprintf(&buf, "    From dscp: %s\n", strings.Join(term.DSCPs, ", "))
						}
						if term.Action != "" {
							fmt.Fprintf(&buf, "    Then: %s\n", term.Action)
						}
					}
					buf.WriteString("\n")
				}
			}
			printFilters("inet", cfg.Firewall.FiltersInet)
			printFilters("inet6", cfg.Firewall.FiltersInet6)
		}

	case "alg":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			// #7423 row 6: see the note on the gRPC copy. `enabled` overstated
			// all four; wording, proto set and order are shared via pkg/config.
			alg := cfg.Security.ALG
			for _, proto := range config.ALGModeledProtos() {
				fmt.Fprintf(&buf, "%-5s %s\n", config.ALGDisplayName(proto)+":",
					config.ALGStatusText(proto, alg.ALGDisabled(proto)))
			}
			for _, proto := range alg.ALGUnmodeledConfigured() {
				fmt.Fprintf(&buf, "%-5s %s\n", config.ALGDisplayName(proto)+":",
					config.ALGStatusUnmodeled())
			}
		}

	case "dynamic-address":
		if cfg == nil || len(cfg.Security.DynamicAddress.FeedServers) == 0 {
			buf.WriteString("No dynamic address feeds configured\n")
		} else {
			for _, name := range sortedKeys(cfg.Security.DynamicAddress.FeedServers) {
				feed := cfg.Security.DynamicAddress.FeedServers[name]
				if feed == nil {
					// #10439: tolerate present-but-nil slots from lenient
					// restore/peer-sync loads.
					continue
				}
				fmt.Fprintf(&buf, "Feed server: %s\n", name)
				// Redact embedded userinfo / query-string credentials before
				// rendering to the REST client (#5521).
				fmt.Fprintf(&buf, "  URL: %s\n", config.RedactURL(feed.URL))
				if feed.FeedName != "" {
					fmt.Fprintf(&buf, "  Feed name: %s\n", feed.FeedName)
				}
				if feed.UpdateInterval > 0 {
					fmt.Fprintf(&buf, "  Update interval: %ds\n", feed.UpdateInterval)
				}
				if feed.HoldInterval > 0 {
					fmt.Fprintf(&buf, "  Hold interval: %ds\n", feed.HoldInterval)
				}
				buf.WriteString("\n")
			}
		}

	case "address-book":
		if cfg == nil || cfg.Security.AddressBook == nil {
			buf.WriteString("No address book configured\n")
		} else {
			ab := cfg.Security.AddressBook
			if len(ab.Addresses) > 0 {
				buf.WriteString("Addresses:\n")
				for _, name := range sortedKeys(ab.Addresses) {
					addr := ab.Addresses[name]
					if addr == nil {
						// #10439: tolerate present-but-nil slots from lenient
						// restore/peer-sync loads.
						continue
					}
					fmt.Fprintf(&buf, "  %-20s %s\n", name, addr.Value)
				}
			}
			if len(ab.AddressSets) > 0 {
				buf.WriteString("Address sets:\n")
				for _, name := range sortedKeys(ab.AddressSets) {
					as := ab.AddressSets[name]
					if as == nil {
						// #10439: tolerate present-but-nil slots from lenient
						// restore/peer-sync loads.
						continue
					}
					fmt.Fprintf(&buf, "  %-20s members: %s\n", name, strings.Join(as.Addresses, ", "))
				}
			}
		}

	case "applications":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			if len(cfg.Applications.Applications) > 0 {
				buf.WriteString("Applications:\n")
				for _, name := range sortedKeys(cfg.Applications.Applications) {
					app := cfg.Applications.Applications[name]
					if app == nil {
						// #10439: tolerate present-but-nil slots from lenient
						// restore/peer-sync loads.
						continue
					}
					fmt.Fprintf(&buf, "  %-20s proto=%-6s", name, app.Protocol)
					if app.DestinationPort != "" {
						fmt.Fprintf(&buf, " dst-port=%s", app.DestinationPort)
					}
					buf.WriteString("\n")
				}
			}
			if len(cfg.Applications.ApplicationSets) > 0 {
				buf.WriteString("Application sets:\n")
				for _, name := range sortedKeys(cfg.Applications.ApplicationSets) {
					as := cfg.Applications.ApplicationSets[name]
					if as == nil {
						// #5221: a present-but-nil application-set map value is
						// admitted by the tolerant-load / peer-sync path (#1960)
						// that the resolver (#5179) already tolerates. Skip it
						// rather than dereferencing as.Applications and panicking
						// the REST handler.
						continue
					}
					fmt.Fprintf(&buf, "  %-20s members: %s\n", name, strings.Join(as.Applications, ", "))
				}
			}
		}

	case "flow-monitoring":
		if cfg == nil || cfg.Services.FlowMonitoring == nil || cfg.Services.FlowMonitoring.Version9 == nil {
			buf.WriteString("No flow monitoring configured\n")
		} else {
			v9 := cfg.Services.FlowMonitoring.Version9
			buf.WriteString("Flow monitoring (NetFlow v9):\n")
			for _, name := range sortedKeys(v9.Templates) {
				tmpl := v9.Templates[name]
				if tmpl == nil {
					// #10439: tolerate present-but-nil slots from lenient
					// restore/peer-sync loads.
					continue
				}
				fmt.Fprintf(&buf, "  Template: %s\n", name)
				if tmpl.FlowActiveTimeout > 0 {
					fmt.Fprintf(&buf, "    Active timeout: %ds\n", tmpl.FlowActiveTimeout)
				}
				if tmpl.FlowInactiveTimeout > 0 {
					fmt.Fprintf(&buf, "    Inactive timeout: %ds\n", tmpl.FlowInactiveTimeout)
				}
				if tmpl.TemplateRefreshRate > 0 {
					fmt.Fprintf(&buf, "    Template refresh: %ds\n", tmpl.TemplateRefreshRate)
				}
			}
		}

	case "flow-timeouts":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			flow := cfg.Security.Flow
			buf.WriteString("Flow session timeouts:\n")
			if flow.TCPSession != nil {
				// #6539: only established-timeout has a dataplane wire
				// carrier; the other three never leave the control plane and
				// must not be printed in the same shape as the enforced one.
				// The annotation comes from config.AnnotateTCPSessionTimeout,
				// shared with the CLI/gRPC surfaces and the commit advisory.
				tcpRow := func(label, leaf string, secs int) {
					fmt.Fprintf(&buf, "  %-21s %s\n", label+":",
						config.AnnotateTCPSessionTimeout(leaf, fmt.Sprintf("%ds", secs)))
				}
				tcpRow("TCP established", config.TCPSessionEstablishedTimeoutLeaf, flow.TCPSession.EstablishedTimeout)
				tcpRow("TCP initial", config.TCPSessionInitialTimeoutLeaf, flow.TCPSession.InitialTimeout)
				tcpRow("TCP closing", config.TCPSessionClosingTimeoutLeaf, flow.TCPSession.ClosingTimeout)
				tcpRow("TCP time-wait", config.TCPSessionTimeWaitTimeoutLeaf, flow.TCPSession.TimeWaitTimeout)
			}
			fmt.Fprintf(&buf, "  UDP session:          %ds\n", flow.UDPSessionTimeout)
			fmt.Fprintf(&buf, "  ICMP session:         %ds\n", flow.ICMPSessionTimeout)
			if flow.TCPMSSAllTCP > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (all-tcp):    %d\n", flow.TCPMSSAllTCP)
			}
			if flow.TCPMSSIPsecVPN > 0 {
				// #2486: ipsec-vpn rejected at commit; not enforced.
				fmt.Fprintf(&buf, "  TCP MSS (IPsec VPN):  %d (not enforced)\n", flow.TCPMSSIPsecVPN)
			}
			if flow.TCPMSSGreIn > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (GRE in):     %d\n", flow.TCPMSSGreIn)
			}
			if flow.TCPMSSGreOut > 0 {
				fmt.Fprintf(&buf, "  TCP MSS (GRE out):    %d\n", flow.TCPMSSGreOut)
			}
			if flow.AllowDNSReply {
				buf.WriteString("  Allow DNS reply:      enabled\n")
			}
			if flow.AllowEmbeddedICMP {
				buf.WriteString("  Allow embedded ICMP:  enabled\n")
			}
		}

	// #6565: BOTH NAT views delegate to the SHARED pkg/natshow renderers, the
	// same ones the CLI (cli_show_nat.go) and gRPC (server_show_nat.go) call.
	//
	// REST used to reimplement them, printing every rule straight from config.
	// That third copy is what made the fail-closed annotations a per-surface
	// lottery: #5323 taught two surfaces to say NOT INSTALLED for a rule the
	// userspace snapshot builder drops, and #6534 taught two surfaces a further
	// set of exclusion reasons — each time leaving REST rendering the dropped
	// rule as though it were live. An operator (or an automation) reading the
	// REST surface saw a configured NPTv6 prefix rewrite or static-NAT rule
	// reported as installed when nothing was programmed.
	//
	// The CLI and gRPC surfaces had a byte-equality test against the shared
	// renderer (#1687) and REST did not, which is exactly why REST is the copy
	// that drifted. show_nat_shared_test.go now closes that gap.
	case "nat-static":
		natshow.RenderStatic(&buf, cfg)

	case "nat-nptv6":
		natshow.RenderNPTv6(&buf, cfg)

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown topic: %s", topic))
		return
	}

	writeOK(w, TextResponse{Output: buf.String()})
}
