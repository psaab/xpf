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

	"github.com/psaab/xpf/pkg/cliterm"
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
					case "status", "interfaces", "information", "statistics", "fence-status":
						if len(args) > 3 {
							return fmt.Errorf("unknown chassis cluster target: %s", strings.Join(args[3:], " "))
						}
						return c.showCommand("show chassis cluster " + args[2])
					case "control-plane", "data-plane", "ip-monitoring", "fabric":
						topic, filter, err := cliterm.ClusterSubsystemView(args[2], args[3:])
						if err != nil {
							return err
						}
						return c.showTextFiltered(topic, filter)
					default:
						return fmt.Errorf("unknown chassis cluster target: %s (expected `status`, `interfaces`, `information`, `statistics`, `fence-status`, `fabric`, `control-plane`, `data-plane`, or `ip-monitoring`)", args[2])
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
		path, pipe, err := splitShowPipe(args[1:], nil)
		if err != nil {
			return err
		}
		if len(pipe) > 0 && pipe[0] == "compare" {
			return opShowConfigurationCompareErr(path, pipe)
		}
		format, err := parseShowDisplay(pipe, true, true, true)
		if err != nil {
			return err
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
				topic, err := cosNameTypeTopic("cos-classifier", args[2:])
				if err != nil {
					return err
				}
				return c.showText(topic)
			case "rewrite-rule":
				// #6848: identical filter grammar to `classifier`, so it shares
				// the same topic builder. Without this arm the command works in
				// the local CLI and silently falls through to the help text on
				// the REMOTE cli binary, which is the surface most operators
				// actually use.
				topic, err := cosNameTypeTopic("cos-rewrite-rule", args[2:])
				if err != nil {
					return err
				}
				return c.showText(topic)
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
		// #15723: exact-arity mirror of pkg/cli handleShowRoute. A dangling
		// table/instance/protocol selector, an unknown subcommand, and any
		// unrecognised trailing token must error instead of widening to
		// showRoutes() (route-all, the full table) or silently dropping the
		// trailing token. The usage string is cliterm.ShowRouteUsage
		// (#17230), shared with pkg/cli via the dependency-light package
		// both binaries already import.
		showRouteUsage := cliterm.ShowRouteUsage
		if len(args) == 1 {
			return c.showRoutes()
		}
		switch args[1] {
		case "fib", "terse", "detail", "summary":
			if len(args) != 2 {
				return fmt.Errorf("%s", showRouteUsage)
			}
			return c.showCommand("show route " + args[1])
		case "instance":
			if len(args) != 3 {
				return fmt.Errorf("%s", showRouteUsage)
			}
			return c.showTextFiltered("route-instance", args[2])
		case "table":
			if len(args) != 3 {
				return fmt.Errorf("%s", showRouteUsage)
			}
			return c.showText("route-table:" + args[2])
		case "protocol":
			if len(args) != 3 {
				return fmt.Errorf("%s", showRouteUsage)
			}
			return c.showText("route-protocol:" + args[2])
		}
		if strings.Contains(args[1], "/") || strings.Contains(args[1], ".") || strings.Contains(args[1], ":") {
			topic := "route-prefix:" + args[1]
			if len(args) == 3 {
				switch args[2] {
				case "exact", "longer", "orlonger":
					topic += " " + args[2]
				default:
					return fmt.Errorf("%s", showRouteUsage)
				}
			} else if len(args) > 3 {
				return fmt.Errorf("%s", showRouteUsage)
			}
			return c.showText(topic)
		}
		return fmt.Errorf("%s", showRouteUsage)

	case "vrrp":
		return c.showVRRP()

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
		// #14687: a dangling `filter` selector must error, not widen to the
		// all-filters listing.
		if len(args) >= 2 && args[1] == "filter" && len(args) < 3 {
			return fmt.Errorf("usage: show firewall filter <name> [family inet|inet6] [effective]")
		}
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
			if len(args) >= 4 && args[3] == "family" {
				if len(args) < 5 {
					return fmt.Errorf("usage: show firewall filter <name> family inet|inet6")
				}
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

func (c *ctl) handleConfigShow(args []string, quoted []bool) error {
	path, pipe, err := splitShowPipe(args, quoted)
	if err != nil {
		return err
	}
	if len(pipe) > 0 && pipe[0] == "compare" {
		// #15272 B24-03: scoped compare filters server-side; the path is
		// editPath+typed path, exactly as the local console computes it.
		comparePath := append(append([]string(nil), c.editPath...), path...)
		var n int32
		switch {
		case len(pipe) == 1:
		case len(pipe) == 3 && pipe[1] == "rollback":
			// #5052: parse into the RPC's int32 via the shared selector
			// parser. strconv.Atoi + int32() wrapped an out-of-range
			// value (e.g. 4294967297 -> 1) and silently compared the
			// wrong slot with a success exit. #15657: min 0 (active).
			var err error
			n, err = parseRollbackSelector(pipe[2], "usage: show | compare rollback <N> (0 = active configuration)", 0)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("usage: show | compare [rollback <N>]")
		}
		resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{RollbackN: n, Path: comparePath})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	}
	format, err := parseShowDisplay(pipe, true, true, true)
	if err != nil {
		return err
	}
	if len(c.editPath) > 0 {
		path = append(append([]string(nil), c.editPath...), path...)
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

// opShowConfigurationCompareErr refuses operational `show configuration
// [<path>] | compare [rollback <N>]`, which Junos supports and this surface
// does not (#18664, #18669). The refusal points at the command that answers
// the operator's question, so the message depends on the shape.
//
//   - Unscoped `| compare rollback <N>` asks Junos's question: what changed
//     between rollback N and the ACTIVE configuration. `show system rollback
//     <N> | compare` answers exactly that operationally (ShowCompare with
//     ActiveBaseline), with no configuration mode and so no PermConfig
//     dead-end for a view-only class. The typed N is echoed into the pointer.
//   - Bare `| compare` and any scoped path: the rollback compare has no
//     subtree selector on this surface, so the pointer is configuration-mode
//     `show [<path>] | compare [rollback <N>]`. Configuration mode diffs the
//     CANDIDATE, and the message says so.
func opShowConfigurationCompareErr(path, pipe []string) error {
	if len(path) == 0 && len(pipe) >= 2 && pipe[1] == "rollback" {
		n := "<N>"
		if len(pipe) == 3 {
			n = pipe[2]
		}
		return fmt.Errorf("syntax error: `| compare rollback %s` is not supported on "+
			"operational `show configuration`; use `show system rollback %s | compare`, "+
			"which diffs rollback %s against the active configuration", n, n, n)
	}
	return fmt.Errorf("syntax error: `| compare` is not supported on operational " +
		"`show configuration`; use configuration mode (`configure`, then " +
		"`show [<path>] | compare [rollback <N>]`), which compares the candidate configuration")
}

// showPipeIndex returns the index of the first bare `|` operator token in
// args, or -1. It is the one rule in this binary for where a command ends and
// its pipe begins: splitShowPipe (the handlers) and the #16798 keyword-only
// gate in dispatchOperational (#18664) both call it, so the gate cannot judge
// a different command from the one the handler runs. Quote provenance
// (quoted[i]) makes a quoted "|" path data; a nil mask means args came from
// an already-tokenized caller. A `|` glued to a word (`|display`,
// `configuration|display`) is NOT the operator. It is an ordinary word here,
// as it is in cliterm.SplitPipe, which splits only on a space-delimited " | ".
func showPipeIndex(args []string, quoted []bool) int {
	for i, arg := range args {
		if arg == "|" && !(i < len(quoted) && quoted[i]) {
			return i
		}
	}
	return -1
}

// splitShowPipe separates a show command's path from its single pipe modifier.
// Quote provenance distinguishes a quoted path token equal to "|" from the
// bare operator; a nil mask means args came from an already-tokenized caller.
func splitShowPipe(args []string, quoted []bool) (path, pipe []string, err error) {
	pipeIndex := showPipeIndex(args, quoted)
	if pipeIndex < 0 {
		return args, nil, nil
	}
	var tailQuoted []bool
	if pipeIndex+1 < len(quoted) {
		tailQuoted = quoted[pipeIndex+1:]
	}
	if showPipeIndex(args[pipeIndex+1:], tailQuoted) >= 0 {
		return nil, nil, fmt.Errorf("syntax error: only one pipe modifier is allowed")
	}
	if pipeIndex == len(args)-1 {
		return nil, nil, fmt.Errorf("syntax error: missing pipe modifier")
	}
	return args[:pipeIndex], args[pipeIndex+1:], nil
}

// parseShowDisplay accepts an exact display modifier (or no modifier) and
// rejects unknown formats and trailing tokens before any RPC is issued.
func parseShowDisplay(pipe []string, allowJSON, allowXML, allowInheritance bool) (pb.ConfigFormat, error) {
	if len(pipe) == 0 {
		return pb.ConfigFormat_HIERARCHICAL, nil
	}
	if pipe[0] != "display" {
		// #18664: name the verb, in the console's wording (pkg/cli
		// handleShow `configuration` arm), instead of a generic usage
		// line that never says what was wrong.
		return 0, fmt.Errorf("syntax error: unknown pipe command %q", pipe[0])
	}
	if len(pipe) != 2 {
		return 0, fmt.Errorf("usage: | display <supported-format>")
	}
	switch pipe[1] {
	case "json":
		if allowJSON {
			return pb.ConfigFormat_JSON, nil
		}
	case "set":
		return pb.ConfigFormat_SET, nil
	case "xml":
		if allowXML {
			return pb.ConfigFormat_XML, nil
		}
	case "inheritance":
		if allowInheritance {
			return pb.ConfigFormat_INHERITANCE, nil
		}
	}
	return 0, fmt.Errorf("unknown display format %q", pipe[1])
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
			"add it to the ShowText registry in pkg/optopic", command)
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
func cosNameTypeTopic(prefix string, rest []string) (string, error) {
	nameFilter, typeFilter, err := cmdtree.ParseCoSNameTypeArgs(rest)
	if err != nil {
		return "", err
	}
	return cmdtree.CoSNameTypeTopic(prefix, nameFilter, typeFilter), nil
}
