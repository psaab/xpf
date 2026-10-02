package main

// show.go is the dispatch shell for the remote-CLI `show` umbrella.
// The per-feature `show` handlers that historically lived here as one
// ~2100-line grab-bag (#4660) now live in sibling files in this package
// (same package, so unexported symbols stay reachable):
//
//	show_security.go   security zones/policies/screen/match-policies/
//	                   statistics/log/vrrp/ike/ipsec renderers
//	show_flow.go       security flow session parse + render + summary +
//	                   flow statistics
//	show_nat.go        security nat source/destination renderers
//	show_interfaces.go show interfaces
//	show_protocols.go  show protocols ospf/bgp/bfd/rip/isis
//	show_firewall_effective.go  arg helpers for show firewall … effective (#4967)
//	show_system.go     show system (commit/rollback/uptime/...)
//	show_services.go   show services (rpm/ip-monitoring/app-id/ddns)
//	show_dhcp.go       show dhcp leases / client-identifier
//
// The split is pure code motion — no behavior change. The gRPC call
// sequences and the text-proxy fallthrough (showText / showTextFiltered)
// are preserved verbatim so the remote CLI stays bit-identical.

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (c *ctl) handleShow(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show: specify what to show", "show")
		return nil
	}

	switch args[0] {
	case "chassis":
		if len(args) >= 2 {
			switch args[1] {
			case "cluster":
				if len(args) >= 3 {
					switch args[2] {
					case "status":
						return c.showCommand("show chassis cluster status")
					case "interfaces":
						return c.showCommand("show chassis cluster interfaces")
					case "information":
						return c.showCommand("show chassis cluster information")
					case "statistics":
						return c.showCommand("show chassis cluster statistics")
					case "control-plane", "data-plane", "ip-monitoring", "fabric":
						// #5459: an UNRECOGNIZED sub-arg must surface a
						// usage error, not silently render the default
						// view (mirrors the strict #1827 `show services
						// ip-monitoring` handler). A bare subsystem with
						// no sub-arg keeps its historical default view.
						topic, filter, err := clusterSubsystemView(args[2], args[3:])
						if err != nil {
							return err
						}
						return c.showTextFiltered(topic, filter)
					}
				}
				return c.showCommand("show chassis cluster")
			case "environment":
				return c.showCommand("show chassis environment")
			case "forwarding":
				return c.showCommand("show chassis forwarding")
			case "hardware":
				return c.showCommand("show chassis hardware")
			case "device-map":
				if len(args) >= 3 && args[2] == "candidates" {
					return c.showCommand("show chassis device-map candidates")
				}
				return c.showCommand("show chassis device-map")
			}
		}
		return c.showCommand("show chassis")

	case "configuration":
		format := pb.ConfigFormat_HIERARCHICAL
		rest := strings.Join(args[1:], " ")
		if strings.Contains(rest, "| display json") {
			format = pb.ConfigFormat_JSON
		} else if strings.Contains(rest, "| display set") {
			format = pb.ConfigFormat_SET
		} else if strings.Contains(rest, "| display xml") {
			format = pb.ConfigFormat_XML
		} else if strings.Contains(rest, "| display inheritance") {
			format = pb.ConfigFormat_INHERITANCE
		} else if idx := strings.Index(rest, "| "); idx >= 0 {
			pipeParts := strings.Fields(strings.TrimSpace(rest[idx+2:]))
			if len(pipeParts) >= 2 && pipeParts[0] == "display" {
				fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
			} else if len(pipeParts) > 0 {
				fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
			}
			return nil
		}
		var path []string
		for _, a := range args[1:] {
			if a == "|" {
				break
			}
			path = append(path, a)
		}
		resp, err := c.client.ShowConfig(c.ctx(), &pb.ShowConfigRequest{
			Format: format,
			Target: pb.ConfigTarget_ACTIVE,
			Path:   path,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if resp.Output == "" && len(path) > 0 {
			fmt.Printf("configuration path not found: %s\n", strings.Join(path, " "))
		} else {
			fmt.Print(resp.Output)
		}
		return nil

	case "class-of-service":
		if len(args) >= 2 {
			switch args[1] {
			case "interface":
				topic := "class-of-service"
				if len(args) >= 3 {
					topic += ":" + args[2]
				}
				return c.showText(topic)
			case "classifier":
				// #4228 Gap 7: encode optional `name <n>` / `type <t>`
				// filters into the topic params.
				return c.showText(cosNameTypeTopic("cos-classifier", args[2:]))
			case "rewrite-rule":
				// #6848: identical filter grammar to `classifier`, so it shares
				// the same topic builder. Without this arm the command works in
				// the local CLI and silently falls through to the help text on
				// the REMOTE cli binary, which is the surface most operators
				// actually use.
				return c.showText(cosNameTypeTopic("cos-rewrite-rule", args[2:]))
			case "scheduler-map":
				topic := "cos-scheduler-map"
				if len(args) >= 3 {
					topic += ":" + args[2]
				}
				return c.showText(topic)
			case "forwarding-class":
				return c.showCommand("show class-of-service forwarding-class")
			}
		}
		printRemoteTreeHelp("show class-of-service:", "show", "class-of-service")
		return nil

	case "dhcp":
		if len(args) >= 2 {
			switch args[1] {
			case "leases":
				return c.showDHCPLeases()
			case "client-identifier":
				return c.showDHCPClientIdentifier()
			}
		}
		printRemoteTreeHelp("show dhcp:", "show", "dhcp")
		return nil

	case "route":
		if len(args) >= 2 && args[1] == "fib" {
			return c.showCommand("show route fib")
		}
		if len(args) >= 2 && args[1] == "terse" {
			return c.showCommand("show route terse")
		}
		if len(args) >= 2 && args[1] == "detail" {
			return c.showCommand("show route detail")
		}
		if len(args) >= 2 && args[1] == "summary" {
			return c.showCommand("show route summary")
		}
		if len(args) >= 3 && args[1] == "instance" {
			return c.showTextFiltered("route-instance", args[2])
		}
		if len(args) >= 3 && args[1] == "table" {
			return c.showText("route-table:" + args[2])
		}
		if len(args) >= 3 && args[1] == "protocol" {
			return c.showText("route-protocol:" + args[2])
		}
		if len(args) >= 2 && (strings.Contains(args[1], "/") || strings.Contains(args[1], ".") || strings.Contains(args[1], ":")) {
			topic := "route-prefix:" + args[1]
			if len(args) >= 3 {
				switch args[2] {
				case "exact", "longer", "orlonger":
					topic += " " + args[2]
				}
			}
			return c.showText(topic)
		}
		return c.showRoutes()

	case "security":
		return c.handleShowSecurity(args[1:])

	case "interfaces":
		return c.showInterfaces(args[1:])

	case "protocols":
		return c.handleShowProtocols(args[1:])

	case "bgp":
		// #4967: `show bgp ...` is the advertised alias for `show protocols
		// bgp ...` (cmdtree). The local CLI implements it; the remote
		// dispatcher previously had no bgp case, so tab-completing and running
		// `show bgp summary` errored. handleShowProtocols switches on args[0],
		// which is already "bgp" here, so pass args verbatim.
		return c.handleShowProtocols(args)

	case "system":
		return c.handleShowSystem(args[1:])

	case "schedulers":
		return c.showCommand("show schedulers")

	case "snmp":
		if len(args) >= 2 && args[1] == "v3" {
			return c.showCommand("show snmp v3")
		}
		return c.showCommand("show snmp")

	case "lldp":
		if len(args) >= 2 && args[1] == "neighbors" {
			return c.showCommand("show lldp neighbors")
		}
		return c.showCommand("show lldp")

	case "dhcp-relay":
		return c.showCommand("show dhcp-relay")

	case "dhcp-server":
		if len(args) >= 2 && args[1] == "dynamic-dns" {
			if len(args) >= 3 && args[2] == "detail" {
				return c.showCommand("show dhcp-server dynamic-dns detail")
			}
			return c.showCommand("show dhcp-server dynamic-dns")
		}
		if len(args) >= 2 && args[1] == "detail" {
			return c.showCommand("show dhcp-server detail")
		}
		return c.showCommand("show dhcp-server")

	case "firewall":
		// #4967: `show firewall [filter <name>] effective [family <f>]` renders
		// the compiled FirewallFilterSnapshot the dataplane receives. cmdtree
		// advertises `effective` and the local CLI implements it, but the remote
		// dispatcher previously fell through to showText("firewall") — the RAW
		// config, not the compiled snapshot. Route it to the dedicated server
		// topics (which share the SSOT renderer) so the two surfaces agree.
		// `effective` is a trailing modifier, matching the local grammar.
		if firewallArgsContain(args, "effective") {
			family := firewallFamilyValue(args)
			if name := firewallFilterName(args); name != "" {
				topic := "firewall-effective-filter:" + name
				if family != "" {
					topic += ":" + family
				}
				return c.showText(topic)
			}
			topic := "firewall-effective"
			if family != "" {
				topic += ":" + family
			}
			return c.showText(topic)
		}
		if len(args) >= 3 && args[1] == "filter" {
			topic := "firewall-filter:" + args[2]
			if len(args) >= 5 && args[3] == "family" {
				topic += ":" + args[4]
			}
			return c.showText(topic)
		}
		return c.showCommand("show firewall")

	case "flow-monitoring":
		// #2464: `show flow-monitoring statistics` renders per-collector
		// write-health; bare `show flow-monitoring` renders configuration.
		if len(args) > 1 && args[1] == "statistics" {
			return c.showCommand("show flow-monitoring statistics")
		}
		return c.showCommand("show flow-monitoring")

	case "log":
		if len(args) > 1 {
			return c.showText("log:" + strings.Join(args[1:], ":"))
		}
		return c.showCommand("show log")

	case "services":
		return c.handleShowServices(args[1:])

	case "version":
		return c.showCommand("show version")

	case "arp":
		return c.showSystemInfo("arp")

	case "ipv6":
		if len(args) >= 2 && args[1] == "neighbors" {
			return c.showSystemInfo("ipv6-neighbors")
		}
		if len(args) >= 2 && args[1] == "router-advertisement" {
			return c.showCommand("show ipv6 router-advertisement")
		}
		printRemoteTreeHelp("show ipv6:", "show", "ipv6")
		return nil

	case "policy-options":
		return c.showCommand("show policy-options")

	case "route-map":
		return c.showCommand("show route-map")

	case "event-options":
		return c.showCommand("show event-options")

	case "routing-options":
		return c.showCommand("show routing-options")

	case "routing-instances":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showCommand("show routing-instances detail")
		}
		return c.showCommand("show routing-instances")

	case "forwarding-options":
		if len(args) >= 2 && args[1] == "port-mirroring" {
			return c.showCommand("show forwarding-options port-mirroring")
		}
		return c.showCommand("show forwarding-options")

	case "vlans":
		return c.showCommand("show vlans")

	case "task":
		return c.showCommand("show task")

	case "monitor":
		if len(args) >= 3 && args[1] == "security" && args[2] == "flow" {
			return c.showCommand("show monitor security flow")
		}
		printRemoteTreeHelp("show monitor:", "show", "monitor")
		return nil

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}

func (c *ctl) showRoutes() error {
	return c.showCommand("show route")
}

func (c *ctl) handleConfigShow(args []string) error {
	line := strings.Join(args, " ")

	if strings.Contains(line, "| compare") {
		if idx := strings.Index(line, "| compare rollback"); idx >= 0 {
			rest := strings.TrimSpace(line[idx+len("| compare rollback"):])
			// #5052: parse into the RPC's int32 via the shared selector
			// parser. strconv.Atoi + int32() wrapped an out-of-range
			// value (e.g. 4294967297 -> 1) and silently compared the
			// wrong slot with a success exit.
			n, err := parseRollbackSelector(rest, "usage: show | compare rollback <N>", 1)
			if err != nil {
				return err
			}
			resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{RollbackN: n})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Print(resp.Output)
			return nil
		}
		resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	}

	format := pb.ConfigFormat_HIERARCHICAL
	if strings.Contains(line, "| display json") {
		format = pb.ConfigFormat_JSON
	} else if strings.Contains(line, "| display set") {
		format = pb.ConfigFormat_SET
	} else if strings.Contains(line, "| display xml") {
		format = pb.ConfigFormat_XML
	} else if strings.Contains(line, "| display inheritance") {
		format = pb.ConfigFormat_INHERITANCE
	} else if idx := strings.Index(line, "| "); idx >= 0 {
		pipeParts := strings.Fields(strings.TrimSpace(line[idx+2:]))
		if len(pipeParts) >= 2 && pipeParts[0] == "display" {
			fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
		} else if len(pipeParts) > 0 {
			fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
		}
		return nil
	}
	var path []string
	if len(c.editPath) > 0 {
		path = append(path, c.editPath...)
	}
	for _, a := range args {
		if a == "|" {
			break
		}
		path = append(path, a)
	}
	resp, err := c.client.ShowConfig(c.ctx(), &pb.ShowConfigRequest{
		Format: format,
		Target: pb.ConfigTarget_CANDIDATE,
		Path:   path,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

// clusterSubsystemView maps a `show chassis cluster <sub> [arg ...]` request to
// the text-proxy topic (and optional filter) to render. sub is the subsystem
// token (args[2]); rest is everything after it (args[3:]).
//
// #5459 (typo suppression): historically each subsystem case fell back to its
// default view for ANY value of rest[0], so an operator typo like
// `show chassis cluster control-plane foobaz` rendered control-plane statistics
// and exited 0. This mirrors the strict #1827 `show services ip-monitoring`
// handler instead: a bare subsystem (len(rest)==0) keeps its historical default
// view, but a present-but-unrecognized token returns a usage error naming the
// valid subcommands. The recognized paths render exactly the same topic/filter
// as before. An empty filter is equivalent to showText (showText delegates to
// showTextFiltered with "").
func clusterSubsystemView(sub string, rest []string) (topic, filter string, err error) {
	switch sub {
	case "control-plane":
		if len(rest) > 0 && rest[0] != "statistics" {
			return "", "", fmt.Errorf("unknown control-plane target: %s (expected `statistics`)", rest[0])
		}
		return "chassis-cluster-control-plane-statistics", "", nil
	case "data-plane":
		if len(rest) > 0 {
			switch rest[0] {
			case "statistics":
				return "chassis-cluster-data-plane-statistics", "", nil
			case "interfaces":
				return "chassis-cluster-data-plane-interfaces", "", nil
			case "fairness":
				return "chassis-cluster-data-plane-fairness", "", nil
			case "flows":
				return "chassis-cluster-data-plane-flows", strings.Join(rest[1:], " "), nil
			default:
				return "", "", fmt.Errorf("unknown data-plane target: %s (expected `statistics`, `interfaces`, `fairness`, or `flows`)", rest[0])
			}
		}
		return "chassis-cluster-data-plane-statistics", "", nil
	case "ip-monitoring":
		if len(rest) > 0 && rest[0] != "status" {
			return "", "", fmt.Errorf("unknown ip-monitoring target: %s (expected `status`)", rest[0])
		}
		return "chassis-cluster-ip-monitoring-status", "", nil
	case "fabric":
		if len(rest) > 0 && rest[0] != "statistics" {
			return "", "", fmt.Errorf("unknown fabric target: %s (expected `statistics`)", rest[0])
		}
		return "chassis-cluster-fabric-statistics", "", nil
	}
	return "", "", fmt.Errorf("unknown cluster subsystem: %s", sub)
}

// showCommand sends the ShowText topic that a canonical operational command
// emits, resolving it through pkg/cmdtree — the SSOT both this binary and the
// daemon's authorization gate read (#8058).
//
// Call sites name the COMMAND, not the topic. That is the point: the command is
// self-evident in the switch arm a reader is already looking at, whereas a topic
// string is an encoding detail that has to be looked up elsewhere to be
// checked. Before #8058 those topic literals were a second, independent
// transcription of the same correspondence the server holds, and nothing made
// the two agree.
//
// An unresolvable command is a programming error in THIS file, not operator
// input — the operator's line has already been dispatched to this arm — so it
// fails loudly rather than guessing a topic. A guess is how the two sides would
// start disagreeing again.
func (c *ctl) showCommand(command string) error {
	topic, ok := cmdtree.ShowTextTopicForCommand(command)
	if !ok {
		return fmt.Errorf("internal: no ShowText topic registered for %q; "+
			"add it to showTextTopicCommand in pkg/cmdtree/showtext_topic.go", command)
	}
	return c.showTextFiltered(topic, "")
}

func (c *ctl) showText(topic string) error {
	return c.showTextFiltered(topic, "")
}

func (c *ctl) showTextFiltered(topic, filter string) error {
	resp, err := c.client.ShowText(c.ctx(), &pb.ShowTextRequest{
		Topic:  topic,
		Filter: filter,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) showSystemInfo(typ string) error {
	resp, err := c.client.GetSystemInfo(c.ctx(), &pb.GetSystemInfoRequest{Type: typ})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

// cosNameTypeTopic encodes the `name <n>` / `type <t>` filters shared by
// `show class-of-service classifier` and `show class-of-service rewrite-rule`
// into a gRPC ShowText topic (#6848).
//
// #6858: it delegates BOTH halves — the argument grammar and the topic
// encoding — to cmdtree, which the local CLI (pkg/cli) and the gRPC decoder
// (pkg/grpcapi) also call. The remote and local paths do not merely agree on
// the grammar by convention; they execute the same code, so they cannot give
// different answers for the same keystrokes.
func cosNameTypeTopic(prefix string, rest []string) string {
	nameFilter, typeFilter := cmdtree.ParseCoSNameTypeArgs(rest)
	return cmdtree.CoSNameTypeTopic(prefix, nameFilter, typeFilter)
}
