package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/termsafe"
)

// handleMonitor dispatches monitor sub-commands.
func (c *CLI) handleMonitor(args []string) error {
	monTree := operationalTree["monitor"].Children
	if len(args) == 0 {
		fmt.Println("monitor:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(monTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(monTree))
	if err != nil {
		return err
	}

	switch resolved {
	case "traffic":
		return c.handleMonitorTraffic(args[1:])
	case "interface":
		return c.handleMonitorInterface(args[1:])
	case "security":
		return c.handleMonitorSecurity(args[1:])
	default:
		return fmt.Errorf("unknown monitor target: %s", resolved)
	}
}

// monitorTrafficKeywords are the option keywords the monitor traffic
// grammar recognizes. They terminate a greedy `matching <filter>`
// expression so a multi-token filter never swallows a following option
// (e.g. `matching tcp port 80 count 20`).
const monitorTrafficHostInterfaceFlag = "allow-host-interface"

var monitorTrafficKeywords = map[string]bool{
	"interface":                     true,
	"matching":                      true,
	"count":                         true,
	monitorTrafficHostInterfaceFlag: true,
}

// splitMonitorTrafficHostOverride removes the host-interface override flag
// before the monitor-traffic parser sees its positional arguments.
func splitMonitorTrafficHostOverride(args []string) ([]string, bool) {
	hasOverride := false
	for _, arg := range args {
		if arg == monitorTrafficHostInterfaceFlag {
			hasOverride = true
			break
		}
	}
	if !hasOverride {
		return args, false
	}
	filtered := make([]string, 0, len(args)-1)
	for _, arg := range args {
		if arg != monitorTrafficHostInterfaceFlag {
			filtered = append(filtered, arg)
		}
	}
	return filtered, true
}

// resolveConfiguredMonitorTrafficInterface maps an operator-supplied
// configured name or kernel spelling to its configured kernel device.
func resolveConfiguredMonitorTrafficInterface(cfg *config.Config, requested string) (string, bool) {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return "", false
	}
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if requested == name || requested == config.LinuxIfName(name) ||
			(ifc.Name != "" && (requested == ifc.Name || requested == config.LinuxIfName(ifc.Name))) {
			return cfg.ResolveKernelIfName(name), true
		}
		for unit, unitConfig := range ifc.Units {
			if unitConfig == nil {
				continue
			}
			ref := name + "." + strconv.Itoa(unit)
			if requested == ref || requested == config.LinuxIfName(ref) {
				return cfg.ResolveKernelIfName(ref), true
			}
		}
	}
	return "", false
}

// resolveMonitorTrafficInterface enforces the configured-interface allowlist.
// A host device is available only when the operator supplies the explicit
// allow-host-interface override.
func resolveMonitorTrafficInterface(cfg *config.Config, requested string, allowHost bool) (string, error) {
	if kernelName, ok := resolveConfiguredMonitorTrafficInterface(cfg, requested); ok {
		return kernelName, nil
	}
	if !allowHost {
		return "", fmt.Errorf("monitor traffic: interface %q is not configured; use %q to capture a host interface",
			requested, monitorTrafficHostInterfaceFlag)
	}
	if _, err := net.InterfaceByName(requested); err != nil {
		return "", fmt.Errorf("monitor traffic: unknown host interface %q", requested)
	}
	return requested, nil
}

func monitorTrafficCaptureLine(captureInterface, requestedInterface string) string {
	return fmt.Sprintf("Capturing on %s (requested %s) (Ctrl+C to stop)...",
		captureInterface, requestedInterface)
}

// handleMonitorTraffic wraps tcpdump for live packet capture.
func (c *CLI) handleMonitorTraffic(args []string) error {
	ifaceArgs, allowHost := splitMonitorTrafficHostOverride(args)
	iface, filter, count, err := parseMonitorTrafficArgs(ifaceArgs)
	if err != nil {
		return err
	}

	if iface == "" {
		fmt.Printf("usage: monitor traffic interface <name> [matching <filter>] [count <N>] [%s]\n",
			monitorTrafficHostInterfaceFlag)
		return nil
	}

	// Defense-in-depth (#4524): reject a filter that smuggles a tcpdump
	// option (`-w`, `-z`, ...) before it can reach the argv. The "--"
	// separator in buildMonitorTrafficArgv already neutralizes it, but a
	// clear rejection beats an opaque libpcap syntax error.
	if err := validateMonitorFilter(filter); err != nil {
		return err
	}

	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	kernelIface, err := resolveMonitorTrafficInterface(cfg, iface, allowHost)
	if err != nil {
		return err
	}

	// Resolve fabric IPVLAN overlays to physical parent (#136).
	origName := iface
	iface = resolveFabricParent(kernelIface)

	// Warn about XDP redirect visibility on fabric interfaces (#138).
	if strings.HasPrefix(origName, "fab") || strings.HasPrefix(origName, "em") {
		fmt.Println("WARNING: XDP-redirected packets bypass AF_PACKET and will not appear in tcpdump.")
		fmt.Println("For fabric redirect telemetry, use: show chassis cluster fabric statistics")
		fmt.Println()
	}

	cmdArgs := buildMonitorTrafficArgv(iface, filter, count)

	fmt.Println(monitorTrafficCaptureLine(iface, origName))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	defer func() {
		c.cmdMu.Lock()
		c.cmdCancel = nil
		c.cmdMu.Unlock()
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	// #7389: sanitize this command's output before it reaches the
	// terminal. See wireSanitizedOutput for why both streams go through one
	// call.
	defer wireSanitizedOutput(cmd)()
	err = cmd.Run()
	if ctx.Err() != nil {
		fmt.Println() // newline after ^C
		return nil
	}
	return err
}

// parseMonitorTrafficArgs parses the `monitor traffic ...` argument
// vector into the interface name, the pcap/BPF filter expression, and the
// packet count. The CLI tokenizer (strings.Fields) splits on whitespace
// and does NOT honor shell quoting, so a multi-token filter typed as
// `matching "tcp port 80"` arrives as the separate tokens `"tcp`, `port`,
// `80"`. The `matching` clause therefore consumes EVERY following token up
// to the next recognized option keyword (none of which are pcap
// primitives), joins them into one filter expression, and strips any
// surrounding quotes the operator typed. Reading only the first token
// truncated `tcp port 80` down to `tcp` and silently captured far more
// traffic than requested (#4005).
func parseMonitorTrafficArgs(args []string) (iface, filter, count string, err error) {
	count = "0" // 0 = unlimited

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "interface":
			// The value after `interface` must be a real interface name,
			// not a missing value or another grammar keyword. Without this
			// guard `interface matching tcp port 80` consumed `matching` as
			// the interface name → tcpdump "no such device" or an
			// unfiltered capture; a trailing bare `interface` consumed
			// nothing and fell through to the usage message (#4540).
			if i+1 >= len(args) || monitorTrafficKeywords[args[i+1]] {
				return "", "", "", fmt.Errorf("monitor traffic: 'interface' requires a value")
			}
			i++
			iface = args[i]
		case "matching":
			rest := make([]string, 0, len(args)-i-1)
			for j := i + 1; j < len(args); j++ {
				if monitorTrafficKeywords[args[j]] {
					break
				}
				rest = append(rest, args[j])
			}
			// `matching` with no filter expression — a trailing bare
			// `matching`, or `matching` immediately followed by another
			// grammar keyword (`matching count 20`) — previously left
			// filter="" and launched an UNFILTERED privileged capture that
			// exposes ALL interface traffic instead of the intended flow
			// (#4883-A). Require an actual filter expression.
			if len(rest) == 0 {
				return "", "", "", fmt.Errorf("monitor traffic: 'matching' requires a filter expression")
			}
			i += len(rest)
			filter = stripSurroundingQuotes(strings.Join(rest, " "))
		case "count":
			// `count` needs a numeric value. A missing value (a trailing
			// bare `count`, or a following grammar keyword) previously left
			// count at "0" = unlimited, silently ignoring the operator's
			// intent to bound the capture; a non-numeric value reached
			// tcpdump's `-c` and produced an opaque error (#4540).
			if i+1 >= len(args) || monitorTrafficKeywords[args[i+1]] {
				return "", "", "", fmt.Errorf("monitor traffic: 'count' requires a value")
			}
			i++
			count = args[i]
			n, cerr := strconv.Atoi(count)
			if cerr != nil {
				return "", "", "", fmt.Errorf("monitor traffic: 'count' requires a numeric value, got %q", count)
			}
			// Bound the count like the sibling `monitor security packet-drop`
			// (1..8192, monitor.go). 0 stays the explicit "unlimited" mode
			// (buildMonitorTrafficArgv omits `-c` when count=="0"); a negative
			// previously reached tcpdump's `-c` as an opaque "invalid packet
			// count" error, and an unbounded huge value is redundant with the
			// already-supported 0=unlimited mode. Reject both CLI-side so the
			// numeric leaf matches the project's sibling-command bounding.
			if n < 0 || n > 8192 {
				return "", "", "", fmt.Errorf("monitor traffic: 'count' must be 0 (unlimited) or 1..8192, got %q", count)
			}
		default:
			// Any token that is neither a grammar keyword nor a value
			// consumed by one is a typo/stray token. A mistyped predicate
			// like `matchng tcp port 443` used to hit no switch arm and be
			// silently discarded, dropping the filter and starting an
			// UNFILTERED capture (#4883-A). Reject it with a clear error
			// instead of broadening the capture.
			return "", "", "", fmt.Errorf("monitor traffic: unrecognized token %q", args[i])
		}
	}
	return iface, filter, count, nil
}

// buildMonitorTrafficArgv assembles the tcpdump argv for a live capture.
// The full filter expression is passed as trailing arguments exactly as
// tcpdump/libpcap expects a filter (all tokens, verbatim), but only AFTER
// an explicit "--" end-of-options separator so no filter token can be
// interpreted as a tcpdump option.
func buildMonitorTrafficArgv(iface, filter, count string) []string {
	cmdArgs := []string{"tcpdump", "-i", iface, "-n", "-l"}
	if count != "0" {
		cmdArgs = append(cmdArgs, "-c", count)
	}
	if filter != "" {
		// Insert a "--" end-of-options separator before the operator-supplied
		// filter (#4524), mirroring the diagcmd ping/traceroute #2084
		// treatment. The `matching <filter>` clause greedily absorbs every
		// token up to the next keyword, so without the separator a filter
		// like `-w /etc/cron.d/x` or `-z <cmd>` reaches tcpdump as an OPTION
		// under glibc getopt argv permutation — arbitrary root file-write
		// (-w) or post-rotate command execution (-z) past the capture-only
		// RBAC boundary. After "--", getopt stops scanning for options and
		// tcpdump treats every remaining token as part of the pcap filter
		// EXPRESSION, so an injected `-w`/`-z` becomes a (harmless) filter
		// operand that libpcap rejects at compile time rather than an option.
		//
		// tcpdump accepts the filter expression as separate argv tokens;
		// splitting on whitespace keeps a multi-token filter intact and
		// matches how tcpdump joins its own trailing filter arguments.
		cmdArgs = append(cmdArgs, "--")
		cmdArgs = append(cmdArgs, strings.Fields(filter)...)
	}
	return cmdArgs
}

// monitorFilterOptionToken reports whether tok would be interpreted by
// tcpdump/getopt as an option flag rather than as a pcap filter primitive.
// A legitimate pcap filter expression never begins a term with an option
// flag (`-w`, `-z`, `-r`, `--postrotate-command`, ...): filter primitives
// are keywords (host/port/tcp/udp/net/...), addresses, numbers, boolean
// operators (and/or/not) and parentheses. Such an option-looking token can
// therefore only be an attempt to smuggle a tcpdump option past the
// capture-only contract (#4524). A bare "-" (getopt's stdin sentinel, not
// an option) is allowed so an arithmetic subtraction term is never falsely
// rejected. This is defense-in-depth: the "--" separator in
// buildMonitorTrafficArgv already neutralizes the option, but rejecting the
// token here gives the operator a clear error instead of an opaque libpcap
// compile failure.
func monitorFilterOptionToken(tok string) bool {
	// #4556 N-01: a mismatched-quote wrapper (e.g. `'-w ...` / `"-z ...`)
	// can leave a literal leading quote on the token, so tok[0] is `'`/`"`
	// instead of `-` and a smuggled option would slip past the tok[0]=='-'
	// check. Peel one leading quote before testing. The "--" separator in
	// buildMonitorTrafficArgv already neutralizes any such option downstream
	// (#4527), so this only closes a defense-in-depth validator gap — but it
	// keeps the operator error clear rather than opaque. A legitimate pcap
	// filter primitive never begins with a quote, so peeling one is a no-op
	// for normal tokens (host/port/tcp/... and a bare "-").
	if len(tok) > 0 && (tok[0] == '\'' || tok[0] == '"') {
		tok = tok[1:]
	}
	return len(tok) > 1 && tok[0] == '-'
}

// validateMonitorFilter rejects a pcap filter that contains an
// option-looking token (see monitorFilterOptionToken). Returns nil for an
// empty filter or any legitimate pcap expression.
func validateMonitorFilter(filter string) error {
	for _, tok := range strings.Fields(filter) {
		if monitorFilterOptionToken(tok) {
			return fmt.Errorf("invalid filter token %q: a capture filter cannot contain a tcpdump option flag", tok)
		}
	}
	return nil
}

// wireSanitizedOutput points cmd's stdout and stderr at line-wise sanitizing
// writers and returns the flush to defer.
//
// #7389: extracted rather than written inline at each site, and it wires BOTH
// streams together on purpose. The #6584 census is FUNCTION-level -- it asks
// whether a forking function references termsafe at all -- so with the two
// streams wired separately, reverting only `cmd.Stdout` left the function
// still referencing termsafe through `cmd.Stderr` and the census stayed
// GREEN. That was a measured escape, not a hypothetical: the mutation
// survived. Routing both through one call makes the partial revert
// inexpressible, so the only way to unwire a site is to delete the call --
// which the census does catch.
func wireSanitizedOutput(cmd *exec.Cmd) func() {
	outw := termsafe.NewSanitizingWriter(os.Stdout)
	errw := termsafe.NewSanitizingWriter(os.Stderr)
	cmd.Stdout = outw
	cmd.Stderr = errw
	return func() {
		_ = outw.Flush()
		_ = errw.Flush()
	}
}
