// Package cli implements the Junos-style interactive CLI for xpf.
package cli

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"github.com/psaab/xpf/pkg/vrrp"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// CLI is the interactive command-line interface.
type CLI struct {
	rl              *readline.Instance
	store           *configstore.Store
	dp              dataplane.DataPlane
	eventBuf        *logging.EventBuffer
	eventReader     *logging.EventReader
	routing         *routing.Manager
	frr             *frr.Manager
	ipsec           *ipsec.Manager
	dhcp            *dhcp.Manager
	dhcpRelay       *dhcprelay.Manager
	cluster         *cluster.Manager
	rpmResultsFn    func() []*rpm.ProbeResult
	feedsFn         func() map[string]feeds.FeedInfo
	lldpNeighborsFn func() []*lldp.Neighbor
	hostname        string
	username        string
	userClass       string
	version         string
	startTime       time.Time

	vrrpMgr *vrrp.Manager

	// fwdSampler supplies 5s/1m/5m CPU windows to
	// `show chassis forwarding` (#881).  Nil when no sampler is
	// wired — Build() falls back to all-invalid windows.
	fwdSampler *fwdstatus.Sampler

	// applyConfigFn is the daemon's full reconcile callback used by
	// non-commit paths (e.g. confirm/rollback). For commits, the CLI
	// prefers commitFn / commitConfirmedFn so the commit→apply pair
	// is atomic under the daemon's apply semaphore (#846). When
	// commitFn is nil (CLI spawned outside daemon), the CLI falls
	// back to store.Commit() + applyConfigFn, and ultimately to
	// applyToDataplane when neither is wired.
	applyConfigFn func(*config.Config)
	// #846: atomic commit+apply callbacks. When set, handleCommit
	// routes through these instead of calling store.Commit directly.
	// Same callback the HTTP/gRPC handlers use, so commits from all
	// three paths serialize against each other.
	commitFn          func(ctx context.Context, comment string) (*config.Config, error)
	commitConfirmedFn func(ctx context.Context, minutes int) (*config.Config, error)

	// Fabric peer dialing for cluster-wide queries (fab0 + optional fab1).
	fabricPeerAddrFn   func() []string
	fabricVRFDevice    string
	peerSystemActionFn func(ctx context.Context, action string) (string, error)

	// Monitor security flow state (per-CLI-session).
	monitorFlow *monitorFlowState

	// Command cancellation: Ctrl-C during a running external command cancels it.
	// commitCancel is a SEPARATE slot used by handleCommit so an
	// external-command cancel and a commit cancel can never displace
	// each other (the slots are single-writer per call site).
	cmdMu        sync.Mutex
	cmdCancel    context.CancelFunc
	commitCancel context.CancelFunc
}

// New creates a new CLI.
func New(store *configstore.Store, dp dataplane.DataPlane, eventBuf *logging.EventBuffer, eventReader *logging.EventReader, rm *routing.Manager, fm *frr.Manager, im *ipsec.Manager, dm *dhcp.Manager, dr *dhcprelay.Manager, cm *cluster.Manager) *CLI {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	username := os.Getenv("USER")
	if username == "" {
		username = "root"
	}

	return &CLI{
		store:       store,
		dp:          dp,
		eventBuf:    eventBuf,
		eventReader: eventReader,
		routing:     rm,
		startTime:   time.Now(),
		frr:         fm,
		ipsec:       im,
		dhcp:        dm,
		dhcpRelay:   dr,
		cluster:     cm,
		hostname:    hostname,
		username:    username,
	}
}

// SetForwardingSampler wires the pkg/fwdstatus Sampler into the CLI
// so `show chassis forwarding` can read 5s/1m/5m CPU windows.
// Pass nil to disable windowed CPU display (Build falls back to
// all-invalid columns and the formatter prints `-`).
func (c *CLI) SetForwardingSampler(s *fwdstatus.Sampler) {
	c.fwdSampler = s
}

// SetRPMResultsFn sets a callback for retrieving live RPM probe results.
func (c *CLI) SetRPMResultsFn(fn func() []*rpm.ProbeResult) {
	c.rpmResultsFn = fn
}

// SetFeedsFn sets a callback for retrieving live dynamic address feed status.
func (c *CLI) SetFeedsFn(fn func() map[string]feeds.FeedInfo) {
	c.feedsFn = fn
}

// SetLLDPNeighborsFn sets a callback for retrieving live LLDP neighbor data.
func (c *CLI) SetLLDPNeighborsFn(fn func() []*lldp.Neighbor) {
	c.lldpNeighborsFn = fn
}

// SetVersion sets the software version string for show version.
func (c *CLI) SetVersion(v string) {
	c.version = v
}

// SetUserClass sets the login class for RBAC permission checks.
func (c *CLI) SetUserClass(class string) {
	c.userClass = class
}

// SetVRRPManager sets the VRRP manager for runtime state queries.
func (c *CLI) SetVRRPManager(m *vrrp.Manager) {
	c.vrrpMgr = m
}

// SetApplyConfigFn wires the daemon's full reconcile callback into the
// CLI so commits issued through the in-process CLI go through the same
// path gRPC/HTTP use. Required for D3 RSS indirection reapply on
// `set system dataplane workers N` and `rss-indirection enable|disable`
// (#797 H2). When nil, CLI commits fall back to the legacy
// applyToDataplane() path.
func (c *CLI) SetApplyConfigFn(fn func(*config.Config)) {
	c.applyConfigFn = fn
}

// SetCommitFns wires the daemon's atomic commit+apply callbacks
// (#846). When set, handleCommit routes through these instead of
// calling store.Commit directly so the commit→apply pair is atomic
// against HTTP/gRPC/event-engine commits.
func (c *CLI) SetCommitFns(
	commitFn func(ctx context.Context, comment string) (*config.Config, error),
	commitConfirmedFn func(ctx context.Context, minutes int) (*config.Config, error),
) {
	c.commitFn = commitFn
	c.commitConfirmedFn = commitConfirmedFn
}

// SetFabricPeer configures fabric peer dialing for cluster-wide queries.
func (c *CLI) SetFabricPeer(addrFn func() []string, vrfDevice string) {
	c.fabricPeerAddrFn = addrFn
	c.fabricVRFDevice = vrfDevice
}

// dialPeer establishes a gRPC connection to the cluster peer, trying fab0
// then fab1 if dual-fabric is configured. Returns nil if not in cluster mode.
func (c *CLI) dialPeer() *grpc.ClientConn {
	if c.fabricPeerAddrFn == nil {
		return nil
	}
	peerIPs := c.fabricPeerAddrFn()
	if len(peerIPs) == 0 {
		return nil
	}

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if c.fabricVRFDevice != "" {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: func(network, address string, rc syscall.RawConn) error {
					var err error
					rc.Control(func(fd uintptr) {
						err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.fabricVRFDevice)
					})
					return err
				},
			}
			return dialer.DialContext(ctx, "tcp", addr)
		}))
	}

	for _, ip := range peerIPs {
		peerAddr := fmt.Sprintf("%s:50051", ip)
		conn, err := grpc.NewClient(peerAddr, dialOpts...)
		if err != nil {
			continue
		}
		// Quick TCP probe to verify the address is reachable.
		d := &net.Dialer{Timeout: 2 * time.Second}
		if c.fabricVRFDevice != "" {
			d.Control = func(network, address string, rc syscall.RawConn) error {
				var err error
				rc.Control(func(fd uintptr) {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.fabricVRFDevice)
				})
				return err
			}
		}
		tc, err := d.DialContext(context.Background(), "tcp", peerAddr)
		if err != nil {
			conn.Close()
			slog.Debug("peer dial failed, trying next fabric address", "addr", peerAddr, "err", err)
			continue
		}
		tc.Close()
		return conn
	}
	slog.Warn("failed to dial peer on any fabric address")
	return nil
}

func (c *CLI) requestPeerSystemAction(ctx context.Context, action string) (string, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	if c.peerSystemActionFn != nil {
		return c.peerSystemActionFn(ctx, action)
	}
	conn := c.dialPeer()
	if conn == nil {
		return "", fmt.Errorf("cluster peer not reachable")
	}
	defer conn.Close()

	peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := pb.NewBpfrxServiceClient(conn).SystemAction(peerCtx, &pb.SystemActionRequest{Action: action})
	if err != nil {
		return "", err
	}
	return resp.Message, nil
}

// checkPermission verifies the current user's login class permits the given action.
// If userClass is empty (not set), all actions are allowed for backward compatibility.
func (c *CLI) checkPermission(action string) error {
	if c.userClass == "" {
		return nil
	}

	perms, ok := config.LoginClassPermissions[c.userClass]
	if !ok {
		return fmt.Errorf("permission denied: unknown login class %q", c.userClass)
	}

	// Determine required permission for the action.
	var required config.LoginClassPermission
	switch action {
	case "show", "ping", "traceroute", "monitor":
		required = config.PermView
	case "clear":
		required = config.PermClear
	case "request", "test":
		required = config.PermControl
	case "configure":
		required = config.PermConfig
	default:
		required = config.PermAll
	}

	for _, p := range perms {
		if p == config.PermAll || p == required {
			return nil
		}
	}

	return fmt.Errorf("permission denied: %q requires class super-user or higher", action)
}

// completionNode is a static command completion tree node.
// completionNode is an alias for the canonical cmdtree.Node type.
type completionNode = cmdtree.Node

// operationalTree references the canonical tree in pkg/cmdtree.
var operationalTree = cmdtree.OperationalTree

// configTopLevel references the canonical config tree in pkg/cmdtree.
var configTopLevel = cmdtree.ConfigTopLevel

// cliCompleter implements readline.AutoCompleter.
type cliCompleter struct {
	cli         *CLI
	helpWritten bool // set by ? Listener to suppress duplicate help from Do()
}

func (cc *cliCompleter) Do(line []rune, pos int) ([][]rune, int) {
	// If the ? Listener already wrote help, suppress duplicate output.
	if cc.helpWritten {
		cc.helpWritten = false
		return nil, 0
	}

	text := string(line[:pos])

	// Pipe filter completion: "show ... | <tab>"
	if pipeCandidates, handled := completePipeFilter(text); handled {
		if len(pipeCandidates) == 0 {
			return nil, 0
		}
		// Determine partial (text after "| ")
		idx := strings.LastIndex(text, "|")
		after := strings.TrimLeft(text[idx+1:], " ")
		partial := after

		sort.Slice(pipeCandidates, func(i, j int) bool { return pipeCandidates[i].name < pipeCandidates[j].name })
		if len(pipeCandidates) == 1 {
			suffix := pipeCandidates[0].name[len(partial):]
			return [][]rune{[]rune(suffix + " ")}, len(partial)
		}
		writeCompletionHelp(cc.cli.rl.Stdout(), pipeCandidates)
		names := make([]string, len(pipeCandidates))
		for i, c := range pipeCandidates {
			names[i] = c.name
		}
		cp := commonPrefix(names)
		suffix := cp[len(partial):]
		if suffix == "" {
			return nil, 0
		}
		return [][]rune{[]rune(suffix)}, len(partial)
	}

	words := strings.Fields(text)
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
		words = words[:len(words)-1]
	}

	var candidates []completionCandidate
	if cc.cli.store.InConfigMode() {
		candidates = cc.cli.completeConfigWithDesc(words, partial)
	} else {
		// "show configuration <path>" — delegate sub-path to config schema
		if subPath, ok := showConfigurationSubPath(words); ok {
			if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
				subPath = resolvedPath
			}
			schemaCompletions := config.CompleteSetPathWithValues(subPath, cc.cli.valueProvider)
			if schemaCompletions != nil {
				for _, sc := range schemaCompletions {
					if partial == "" || strings.HasPrefix(sc.Name, partial) {
						candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
					}
				}
			}
		}
		if len(candidates) == 0 {
			candidates = completeFromTreeWithDesc(operationalTree, words, partial, cc.cli.store.ActiveConfig())
		}
	}
	if len(candidates) == 0 {
		return nil, 0
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })

	if len(candidates) == 1 {
		suffix := candidates[0].name[len(partial):]
		return [][]rune{[]rune(suffix + " ")}, len(partial)
	}

	// Multiple matches: show descriptions above prompt.
	writeCompletionHelp(cc.cli.rl.Stdout(), candidates)

	// Complete common prefix.
	names := make([]string, len(candidates))
	for i, c := range candidates {
		names[i] = c.name
	}
	cp := commonPrefix(names)
	suffix := cp[len(partial):]
	if suffix == "" {
		return nil, 0
	}
	return [][]rune{[]rune(suffix)}, len(partial)
}

func (c *CLI) completeConfigWithDesc(words []string, partial string) []completionCandidate {
	if len(words) == 0 {
		return filterTreeCandidates(configTopLevel, partial)
	}

	resolvedTop, ok := resolveUniqueTreePrefix(configTopLevel, words[0])
	if !ok {
		if len(words) == 1 {
			return filterTreeCandidates(configTopLevel, words[0])
		}
		return nil
	}

	switch resolvedTop {
	case "set", "delete", "show", "edit":
		pathWords := words[1:]
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(pathWords); resolved {
			pathWords = resolvedPath
		}
		schemaCompletions := config.CompleteSetPathWithValues(pathWords, c.valueProvider)
		if schemaCompletions == nil {
			return nil
		}
		var candidates []completionCandidate
		for _, sc := range schemaCompletions {
			if strings.HasPrefix(sc.Name, partial) {
				candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
			}
		}
		return candidates

	case "run":
		return completeFromTreeWithDesc(operationalTree, words[1:], partial, c.store.ActiveConfig())

	case "commit", "load":
		if len(words) == 1 {
			node := configTopLevel[resolvedTop]
			if node == nil || node.Children == nil {
				return nil
			}
			var candidates []completionCandidate
			for name, child := range node.Children {
				if strings.HasPrefix(name, partial) {
					candidates = append(candidates, completionCandidate{name: name, desc: child.Desc})
				}
			}
			return candidates
		}
		return nil

	default:
		return nil
	}
}

// resolveCommand performs Junos-style prefix matching.
// Given a partial input and a list of valid commands, it returns:
// - The full command name if exactly one match
// - "" and an error if ambiguous (multiple matches)
// - "" and an error if no match
func resolveCommand(input string, validCommands []string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("missing command")
	}
	// Exact match first
	for _, cmd := range validCommands {
		if cmd == input {
			return cmd, nil
		}
	}
	// Prefix match
	var matches []string
	for _, cmd := range validCommands {
		if strings.HasPrefix(cmd, input) {
			matches = append(matches, cmd)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("unknown command: %s", input)
	case 1:
		return matches[0], nil
	default:
		sort.Strings(matches)
		return "", fmt.Errorf("'%s' is ambiguous.\nPossible completions:\n%s",
			input, formatAmbiguousMatches(matches))
	}
}

func formatAmbiguousMatches(matches []string) string {
	var sb strings.Builder
	maxWidth := 0
	for _, m := range matches {
		if len(m) > maxWidth {
			maxWidth = len(m)
		}
	}
	for _, m := range matches {
		sb.WriteString(fmt.Sprintf("  %s\n", m))
	}
	return sb.String()
}

// Run starts the interactive CLI loop.
func (c *CLI) Run() error {
	var err error
	completer := &cliCompleter{cli: c}
	c.rl, err = readline.NewEx(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     filepath.Join(os.Getenv("HOME"), ".xpf_history"),
		HistoryLimit:    10000,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    completer,
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		Listener: readline.FuncListener(func(line []rune, pos int, key rune) ([]rune, int, bool) {
			if key != '?' || pos < 1 {
				return line, pos, false
			}
			// Strip the '?' that readline already inserted.
			cleanLine := make([]rune, 0, len(line)-1)
			cleanLine = append(cleanLine, line[:pos-1]...)
			cleanLine = append(cleanLine, line[pos:]...)
			// Parse words from text before cursor.
			text := string(cleanLine[:pos-1])

			// Pipe filter help: "show ... | ?"
			if pipeCandidates, handled := completePipeFilter(text + " "); handled {
				if len(pipeCandidates) > 0 {
					writeCompletionHelp(c.rl.Stdout(), pipeCandidates)
				}
				// Suppress duplicate help if readline calls Do() for this key.
				completer.helpWritten = true
				return cleanLine, pos - 1, true
			}

			words := strings.Fields(text)
			trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
			var partial string
			if !trailingSpace && len(words) > 0 {
				partial = words[len(words)-1]
				words = words[:len(words)-1]
			}
			var candidates []completionCandidate
			if c.store.InConfigMode() {
				candidates = c.completeConfigWithDesc(words, partial)
			} else {
				// "show configuration <path>" — delegate sub-path to config schema
				if subPath, ok := showConfigurationSubPath(words); ok {
					if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
						subPath = resolvedPath
					}
					schemaCompletions := config.CompleteSetPathWithValues(subPath, c.valueProvider)
					if schemaCompletions != nil {
						for _, sc := range schemaCompletions {
							if partial == "" || strings.HasPrefix(sc.Name, partial) {
								candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
							}
						}
					}
				}
				if len(candidates) == 0 {
					candidates = completeFromTreeWithDesc(operationalTree, words, partial, c.store.ActiveConfig())
				}
			}
			if len(candidates) > 0 {
				writeCompletionHelp(c.rl.Stdout(), candidates)
			}
			// Suppress duplicate help if readline calls Do() for this key.
			completer.helpWritten = true
			return cleanLine, pos - 1, true
		}),
	})
	if err != nil {
		return fmt.Errorf("readline init: %w", err)
	}
	defer c.rl.Close()

	// Register auto-rollback handler for commit confirmed.
	// Prefer the daemon's full reconcile (applyConfigFn) so D3,
	// cluster, VRRP, etc. all re-converge on rollback — matches the
	// gRPC/HTTP rollback path. Falls back to applyToDataplane if
	// applyConfigFn is not wired (e.g. CLI spawned outside daemon).
	c.store.SetCentralRollbackHandler(func(cfg *config.Config) {
		if c.applyConfigFn != nil {
			c.applyConfigFn(cfg)
		} else if c.dp != nil {
			if err := c.applyToDataplane(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "\nwarning: auto-rollback dataplane apply failed: %v\n", err)
			}
		}
		c.reloadSyslog(cfg)
		fmt.Fprintf(os.Stderr, "\ncommit confirmed timed out, configuration has been rolled back\n")
	})

	fmt.Println("xpf firewall - Junos-style eBPF firewall")
	fmt.Println("Type '?' for help")
	fmt.Println()

	// Catch SIGINT to prevent process termination.
	// readline handles ^C during input (returns ErrInterrupt).
	// During dispatch, this absorbs the signal so it doesn't kill the daemon.
	// Double Ctrl-C within 2s exits the CLI.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	exitCh := make(chan struct{})
	go func() {
		var lastInterrupt time.Time
		for range sigCh {
			// If a commit or an external command is running, cancel
			// it. commitCancel takes priority because a commit
			// hanging on the apply semaphore is the only path that
			// actually needs ctx-aware cancellation; external
			// commands fall back if no commit is in flight.
			c.cmdMu.Lock()
			commitCancel := c.commitCancel
			cmdCancel := c.cmdCancel
			c.cmdMu.Unlock()
			if commitCancel != nil {
				commitCancel()
				continue
			}
			if cmdCancel != nil {
				cmdCancel()
				continue
			}
			now := time.Now()
			if now.Sub(lastInterrupt) < 2*time.Second {
				if c.store.InConfigMode() {
					c.store.ExitConfigure()
				}
				close(exitCh)
				return
			}
			lastInterrupt = now
		}
	}()

	for {
		select {
		case <-exitCh:
			return nil
		default:
		}
		if c.store.IsConfirmPending() {
			fmt.Println("[commit confirmed pending - issue 'commit' to confirm]")
		}
		line, err := c.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				// Ctrl-D: exit config mode, or exit CLI if already in operational mode.
				if c.store.InConfigMode() {
					c.store.ExitConfigure()
					c.rl.SetPrompt(c.operationalPrompt())
					fmt.Println("\nExiting configuration mode")
					continue
				}
				return nil
			}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := c.dispatch(line); err != nil {
			if err == errExit {
				return nil
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		// Refresh prompt after every command so cluster role
		// changes (failover) are reflected immediately.
		c.refreshPrompt()
	}
	return nil
}



// parsePolicyZoneFilter extracts from-zone/to-zone filters from args.
func enabledStr(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

func parsePolicyZoneFilter(args []string) (fromZone, toZone string) {
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "from-zone":
			fromZone = args[i+1]
		case "to-zone":
			toZone = args[i+1]
		}
	}
	return
}

// showPoliciesHitCount displays a Junos-style policy hit count table.
func resolveAddressDetail(cfg *config.Config, name string) string {
	ab := cfg.Security.AddressBook
	if ab != nil {
		if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
			return addr.Value
		}
	}
	return name
}

// printAppDetail prints Junos-style application detail lines (protocol, ports, timeout).
func (c *CLI) printAppDetail(cfg *config.Config, appName string) {
	if appName == "any" {
		fmt.Printf("    IP protocol: 0, ALG: 0, Inactivity timeout: 0\n")
		fmt.Printf("      Source port range: [0-0]\n")
		fmt.Printf("      Destination ports: [0-0]\n")
		return
	}
	if cfg.Applications.Applications == nil {
		return
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return
	}
	proto := app.Protocol
	if proto == "" {
		proto = "0"
	}
	timeout := 0
	if app.InactivityTimeout > 0 {
		timeout = app.InactivityTimeout
	}
	algVal := "0"
	if app.ALG != "" {
		algVal = app.ALG
	}
	fmt.Printf("    IP protocol: %s, ALG: %s, Inactivity timeout: %d\n", proto, algVal, timeout)
	srcPort := "0-0"
	if app.SourcePort != "" {
		srcPort = app.SourcePort
	}
	dstPort := "0-0"
	if app.DestinationPort != "" {
		dstPort = app.DestinationPort
	}
	fmt.Printf("      Source port range: [%s]\n", srcPort)
	fmt.Printf("      Destination ports: [%s]\n", dstPort)
}

// resolveAddress looks up a named address in the global address book and returns its CIDR suffix.
func resolveAddress(cfg *config.Config, name string) string {
	if name == "any" {
		return ""
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return ""
	}
	if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
		return " (" + addr.Value + ")"
	}
	if _, ok := ab.AddressSets[name]; ok {
		return " (address-set)"
	}
	return ""
}

// capitalizeFirst returns the string with the first letter capitalized.
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (c *CLI) handleShowSecurity(args []string) error {
	secTree := operationalTree["show"].Children["security"].Children
	if len(args) == 0 {
		fmt.Println("show security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(secTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(secTree))
	if err != nil {
		return err
	}
	args[0] = resolved

	cfg := c.store.ActiveConfig()
	if cfg == nil && args[0] != "statistics" && args[0] != "ipsec" && args[0] != "alarms" {
		fmt.Println("no active configuration")
		return nil
	}

	switch args[0] {
	case "zones":
		detail := false
		filterZone := ""
		if len(args) >= 2 {
			if args[1] == "detail" {
				detail = true
			} else {
				filterZone = args[1]
				if len(args) >= 3 && args[2] == "detail" {
					detail = true
				}
			}
		}
		return c.showZonesDisplay(cfg, detail, filterZone)

	case "policies":
		// Parse optional zone-pair filter: from-zone X to-zone Y
		fromZone, toZone := parsePolicyZoneFilter(args[1:])
		// "show security policies global" — only show global policies
		globalOnly := len(args) >= 2 && args[1] == "global"
		// "show security policies hit-count" — Junos-style hit count table
		if len(args) >= 2 && args[1] == "hit-count" {
			return c.showPoliciesHitCount(cfg, fromZone, toZone)
		}
		// "show security policies detail" — expanded Junos-style detail view
		if len(args) >= 2 && args[1] == "detail" {
			return c.showPoliciesDetail(cfg, fromZone, toZone)
		}
		brief := len(args) >= 2 && args[1] == "brief"
		if brief {
			// Brief tabular summary
			fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
				"From", "To", "Name", "Action", "Hits")
			policySetID := uint32(0)
			for _, zpp := range cfg.Security.Policies {
				if fromZone != "" && zpp.FromZone != fromZone {
					policySetID++
					continue
				}
				if toZone != "" && zpp.ToZone != toZone {
					policySetID++
					continue
				}
				for i, pol := range zpp.Policies {
					action := "permit"
					switch pol.Action {
					case 1:
						action = "deny"
					case 2:
						action = "reject"
					}
					ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					hits := "-"
					if c.dp != nil && c.dp.IsLoaded() {
						if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
							hits = fmt.Sprintf("%d", counters.Packets)
						}
					}
					fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
						zpp.FromZone, zpp.ToZone, pol.Name, action, hits)
				}
				policySetID++
			}
			// Global policies in brief view
			if len(cfg.Security.GlobalPolicies) > 0 && fromZone == "" && toZone == "" {
				for i, pol := range cfg.Security.GlobalPolicies {
					action := "permit"
					switch pol.Action {
					case 1:
						action = "deny"
					case 2:
						action = "reject"
					}
					ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					hits := "-"
					if c.dp != nil && c.dp.IsLoaded() {
						if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
							hits = fmt.Sprintf("%d", counters.Packets)
						}
					}
					fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
						"*", "*", pol.Name, action, hits)
				}
			}
			return nil
		}

		policySetID := uint32(0)
		if !globalOnly {
			for _, zpp := range cfg.Security.Policies {
				if fromZone != "" && zpp.FromZone != fromZone {
					policySetID++
					continue
				}
				if toZone != "" && zpp.ToZone != toZone {
					policySetID++
					continue
				}
				// Junos format: "From zone: X, To zone: Y" header
				fmt.Printf("From zone: %s, To zone: %s\n", zpp.FromZone, zpp.ToZone)
				for i, pol := range zpp.Policies {
					action := "permit"
					switch pol.Action {
					case 1:
						action = "deny"
					case 2:
						action = "reject"
					}
					ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					// Junos: Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>
					fmt.Printf("  Policy: %s, State: enabled, Index: %d, Scope Policy: 0, Sequence number: %d\n",
						pol.Name, ruleID, i+1)
					if pol.Description != "" {
						fmt.Printf("    Description: %s\n", pol.Description)
					}
					fmt.Printf("    Source addresses: %s\n",
						strings.Join(pol.Match.SourceAddresses, ", "))
					fmt.Printf("    Destination addresses: %s\n",
						strings.Join(pol.Match.DestinationAddresses, ", "))
					fmt.Printf("    Applications: %s\n",
						strings.Join(pol.Match.Applications, ", "))
					actionStr := action
					if pol.Log != nil {
						actionStr += ", log"
					}
					fmt.Printf("    Action: %s\n", actionStr)
				}
				policySetID++
			}
		} else {
			// When globalOnly, still count zone-pair policy sets to get correct global ruleID base
			policySetID = uint32(len(cfg.Security.Policies))
		}
		// Global policies
		if len(cfg.Security.GlobalPolicies) > 0 && (globalOnly || (fromZone == "" && toZone == "")) {
			fmt.Println("Global policies:")
			for i, pol := range cfg.Security.GlobalPolicies {
				action := "permit"
				switch pol.Action {
				case 1:
					action = "deny"
				case 2:
					action = "reject"
				}
				ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				// Junos global: Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>
				fmt.Printf("  Policy: %s, State: enabled, Index: %d, Scope Policy: 0, Sequence number: %d\n",
					pol.Name, ruleID, i+1)
				if pol.Description != "" {
					fmt.Printf("    Description: %s\n", pol.Description)
				}
				fmt.Printf("    From zones: any\n")
				fmt.Printf("    To zones: any\n")
				fmt.Printf("    Source addresses: %s\n",
					strings.Join(pol.Match.SourceAddresses, ", "))
				fmt.Printf("    Destination addresses: %s\n",
					strings.Join(pol.Match.DestinationAddresses, ", "))
				fmt.Printf("    Applications: %s\n",
					strings.Join(pol.Match.Applications, ", "))
				actionStr := action
				if pol.Log != nil {
					actionStr += ", log"
				}
				fmt.Printf("    Action: %s\n", actionStr)
			}
		}
		return nil

	case "flow":
		if len(args) >= 2 && args[1] == "session" {
			return c.showFlowSession(args[2:])
		}
		if len(args) >= 2 && args[1] == "traceoptions" {
			return c.showFlowTraceoptions()
		}
		if len(args) >= 2 && args[1] == "statistics" {
			return c.showFlowStatistics()
		}
		if len(args) == 1 {
			return c.showFlowTimeouts()
		}
		return fmt.Errorf("unknown show security flow target")

	case "screen":
		return c.handleShowScreen(args[1:])

	case "nat":
		return c.handleShowNAT(args[1:])

	case "address-book":
		return c.showAddressBook(args[1:])

	case "applications":
		return c.showApplications(args[1:])

	case "log":
		return c.showSecurityLog(args[1:])

	case "statistics":
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showStatistics(detail)

	case "ipsec":
		return c.showIPsec(args[1:])

	case "ike":
		return c.showIKE(args[1:])

	case "alarms":
		return c.showSecurityAlarms(args[1:])

	case "alg":
		// Accept optional "status" subcommand
		return c.showALG()

	case "dynamic-address":
		return c.showDynamicAddress()

	case "match-policies":
		return c.showMatchPolicies(cfg, args[1:])

	case "vrrp":
		return c.showVRRP()

	default:
		return fmt.Errorf("unknown show security target: %s", args[0])
	}
}

func (c *CLI) handleShowScreen(args []string) error {
	if len(args) == 0 {
		return c.showScreen()
	}
	switch args[0] {
	case "ids-option":
		if len(args) < 2 {
			return c.showScreen()
		}
		if len(args) >= 3 && args[2] == "detail" {
			return c.showScreenIdsOptionDetail(args[1])
		}
		return c.showScreenIdsOption(args[1])
	case "statistics":
		if len(args) >= 2 && args[1] == "zone" && len(args) >= 3 {
			return c.showScreenStatistics(args[2])
		}
		return c.showScreenStatisticsAll()
	default:
		return c.showScreen()
	}
}


func (c *CLI) refreshPrompt() {
	if h, err := os.Hostname(); err == nil && h != "" {
		c.hostname = h
	}
	if c.rl != nil {
		if c.store.InConfigMode() {
			c.rl.SetPrompt(c.configPrompt())
		} else {
			c.rl.SetPrompt(c.operationalPrompt())
		}
	}
}

func (c *CLI) reloadSyslog(cfg *config.Config) {
	if c.eventReader == nil {
		return
	}
	// Update zone name mapping for structured log format
	// Uses sorted zone names → sequential IDs (matches compiler order)
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	znMap := make(map[uint16]string, len(names))
	for i, name := range names {
		znMap[uint16(i+1)] = name
	}
	c.eventReader.SetZoneNames(znMap)

	var clients []*logging.SyslogClient
	for name, stream := range cfg.Security.Log.Streams {
		client, err := logging.NewSyslogClient(stream.Host, stream.Port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: syslog stream %s: %v\n", name, err)
			continue
		}
		if stream.Severity != "" {
			client.MinSeverity = logging.ParseSeverity(stream.Severity)
		}
		if stream.Category != "" {
			client.Categories = logging.ParseCategory(stream.Category)
		}
		// Per-stream format overrides global log format
		format := stream.Format
		if format == "" {
			format = cfg.Security.Log.Format
		}
		if format != "" {
			client.Format = format
		}
		clients = append(clients, client)
	}
	c.eventReader.ReplaceSyslogClients(clients)
}

func (c *CLI) applyToDataplane(cfg *config.Config) error {
	// 1. Create tunnel interfaces first
	if c.routing != nil {
		var tunnels []*config.TunnelConfig
		for _, ifc := range cfg.Interfaces.Interfaces {
			if ifc.Tunnel != nil && ifc.Tunnel.Source != "" {
				tunnels = append(tunnels, ifc.Tunnel)
			}
			for _, unit := range ifc.Units {
				if unit.Tunnel != nil {
					tunnels = append(tunnels, unit.Tunnel)
				}
			}
		}
		if err := c.routing.ApplyTunnels(tunnels); err != nil {
			fmt.Fprintf(os.Stderr, "warning: tunnel apply failed: %v\n", err)
		}
		if err := c.routing.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: xfrmi apply failed: %v\n", err)
		}
	}

	// 2. Compile eBPF dataplane
	if c.dp != nil && c.dp.IsLoaded() {
		if _, err := c.dp.Compile(cfg); err != nil {
			return err
		}
	}

	// 3. Apply all routes + dynamic protocols via FRR
	if c.frr != nil {
		// Collect interface bandwidths and point-to-point flags for FRR.
		ifaceBandwidths := make(map[string]uint64)
		ifaceP2P := make(map[string]bool)
		for name, ifc := range cfg.Interfaces.Interfaces {
			if ifc.Bandwidth > 0 {
				ifaceBandwidths[name] = ifc.Bandwidth
			}
			for _, unit := range ifc.Units {
				if unit.PointToPoint {
					ifaceP2P[name] = true
				}
			}
		}

		fc := &frr.FullConfig{
			OSPF:                  cfg.Protocols.OSPF,
			OSPFv3:                cfg.Protocols.OSPFv3,
			BGP:                   cfg.Protocols.BGP,
			StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
			InterfaceBandwidths:   ifaceBandwidths,
			InterfacePointToPoint: ifaceP2P,
		}
		if c.dhcp != nil {
			for _, lease := range c.dhcp.Leases() {
				if !lease.Gateway.IsValid() {
					continue
				}
				fc.DHCPRoutes = append(fc.DHCPRoutes, frr.DHCPRoute{
					Gateway:   lease.Gateway.String(),
					Interface: lease.Interface,
					IsIPv6:    lease.Family == dhcp.AFInet6,
				})
			}
		}
		for _, ri := range cfg.RoutingInstances {
			fc.Instances = append(fc.Instances, frr.InstanceConfig{
				VRFName:      "vrf-" + ri.Name,
				OSPF:         ri.OSPF,
				OSPFv3:       ri.OSPFv3,
				BGP:          ri.BGP,
				StaticRoutes: ri.StaticRoutes,
			})
		}
		if err := c.frr.ApplyFull(fc); err != nil {
			fmt.Fprintf(os.Stderr, "warning: FRR apply failed: %v\n", err)
		}
	}

	// 5. Apply IPsec config
	if c.ipsec != nil {
		if err := c.ipsec.Apply(ipsec.PrepareConfig(cfg)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: IPsec apply failed: %v\n", err)
		}
	}

	return nil
}

// builtinApp defines a well-known Junos application by protocol and port.
type builtinApp struct {
	proto uint8
	port  uint16
}

// builtinApps maps Junos application names to protocol/port.
var builtinApps = map[string]builtinApp{
	"junos-http":        {proto: 6, port: 80},
	"junos-https":       {proto: 6, port: 443},
	"junos-ssh":         {proto: 6, port: 22},
	"junos-telnet":      {proto: 6, port: 23},
	"junos-ftp":         {proto: 6, port: 21},
	"junos-smtp":        {proto: 6, port: 25},
	"junos-dns-tcp":     {proto: 6, port: 53},
	"junos-dns-udp":     {proto: 17, port: 53},
	"junos-bgp":         {proto: 6, port: 179},
	"junos-ntp":         {proto: 17, port: 123},
	"junos-snmp":        {proto: 17, port: 161},
	"junos-syslog":      {proto: 17, port: 514},
	"junos-dhcp-client": {proto: 17, port: 68},
	"junos-ike":         {proto: 17, port: 500},
	"junos-ipsec-nat-t": {proto: 17, port: 4500},
}

// resolveAppName resolves a session's protocol and destination port to a
// known application name, checking user-defined apps first then builtins.
func resolveAppName(proto uint8, dstPort uint16, cfg *config.Config) string {
	if cfg != nil {
		for name, app := range cfg.Applications.Applications {
			var appProto uint8
			switch strings.ToLower(app.Protocol) {
			case "tcp":
				appProto = 6
			case "udp":
				appProto = 17
			case "icmp":
				appProto = 1
			default:
				continue
			}
			if appProto != proto {
				continue
			}
			// Parse destination port (handle ranges like "8080-8090")
			portStr := app.DestinationPort
			if portStr == "" {
				continue
			}
			if strings.Contains(portStr, "-") {
				parts := strings.SplitN(portStr, "-", 2)
				lo, err1 := strconv.Atoi(parts[0])
				hi, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && int(dstPort) >= lo && int(dstPort) <= hi {
					return name
				}
			} else {
				if v, err := strconv.Atoi(portStr); err == nil && uint16(v) == dstPort {
					return name
				}
			}
		}
	}
	for name, ba := range builtinApps {
		if ba.proto == proto && ba.port == dstPort {
			return name
		}
	}
	return ""
}

// sessionFilter holds parsed filter criteria for session display.
type sessionFilter struct {
	zoneID   uint16 // 0 = any
	proto    uint8  // 0 = any
	srcNet   *net.IPNet
	dstNet   *net.IPNet
	srcPort  uint16         // 0 = any
	dstPort  uint16         // 0 = any
	natOnly  bool           // show only NAT sessions
	iface    string         // ingress/egress interface name filter
	summary  bool           // only show count
	brief    bool           // compact tabular view
	appName  string         // application name filter
	sortBy   string         // "bytes" or "packets" for top-talkers
	cfg      *config.Config // for application resolution
	appNames map[uint16]string

	// Populated by showFlowSession before iteration for interface matching.
	zoneIfaces      map[uint16]string          // zone ID → first interface name
	egressIfacesMap map[sessionIfaceKey]string // {ifindex,vlanID} → interface name
}

func (c *CLI) parseSessionFilter(args []string) sessionFilter {
	var f sessionFilter
	f.cfg = c.store.ActiveConfig()
	if c.dp != nil {
		if cr := c.dp.LastCompileResult(); cr != nil {
			f.appNames = cr.AppNames
		}
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				if c.dp != nil {
					if cr := c.dp.LastCompileResult(); cr != nil {
						f.zoneID = cr.ZoneIDs[args[i]]
					}
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				switch strings.ToLower(args[i]) {
				case "tcp":
					f.proto = 6
				case "udp":
					f.proto = 17
				case "icmp":
					f.proto = 1
				case "icmpv6":
					f.proto = dataplane.ProtoICMPv6
				}
			}
		case "source-prefix":
			if i+1 < len(args) {
				i++
				cidr := args[i]
				if !strings.Contains(cidr, "/") {
					if strings.Contains(cidr, ":") {
						cidr += "/128"
					} else {
						cidr += "/32"
					}
				}
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil {
					f.srcNet = ipNet
				}
			}
		case "destination-prefix":
			if i+1 < len(args) {
				i++
				cidr := args[i]
				if !strings.Contains(cidr, "/") {
					if strings.Contains(cidr, ":") {
						cidr += "/128"
					} else {
						cidr += "/32"
					}
				}
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil {
					f.dstNet = ipNet
				}
			}
		case "source-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					f.srcPort = uint16(v)
				}
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					f.dstPort = uint16(v)
				}
			}
		case "nat", "nat-only":
			f.natOnly = true
		case "interface":
			if i+1 < len(args) {
				i++
				f.iface = args[i]
			}
		case "application":
			if i+1 < len(args) {
				i++
				f.appName = args[i]
			}
		case "summary":
			f.summary = true
		case "brief":
			f.brief = true
		case "sort-by":
			if i+1 < len(args) {
				i++
				f.sortBy = args[i] // "bytes" or "packets"
			}
		}
	}
	return f
}

func (f *sessionFilter) matchesV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if f.zoneID != 0 && val.IngressZone != f.zoneID && val.EgressZone != f.zoneID {
		return false
	}
	if f.iface != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := f.resolveEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone)
		if !f.ifaceMatches(inIf) && !f.ifaceMatches(outIf) {
			return false
		}
	}
	if f.proto != 0 && key.Protocol != f.proto {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if f.srcPort != 0 && key.SrcPort != f.srcPort {
		return false
	}
	if f.dstPort != 0 && key.DstPort != f.dstPort {
		return false
	}
	if f.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if f.appName != "" {
		if !appid.SessionMatches(f.appName, f.appNames, f.cfg,
			key.Protocol, ntohs(key.DstPort), val.AppID) {
			return false
		}
	}
	return true
}

func (f *sessionFilter) matchesV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	if f.zoneID != 0 && val.IngressZone != f.zoneID && val.EgressZone != f.zoneID {
		return false
	}
	if f.iface != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := f.resolveEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone)
		if !f.ifaceMatches(inIf) && !f.ifaceMatches(outIf) {
			return false
		}
	}
	if f.proto != 0 && key.Protocol != f.proto {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if f.srcPort != 0 && key.SrcPort != f.srcPort {
		return false
	}
	if f.dstPort != 0 && key.DstPort != f.dstPort {
		return false
	}
	if f.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if f.appName != "" {
		if !appid.SessionMatches(f.appName, f.appNames, f.cfg,
			key.Protocol, ntohs(key.DstPort), val.AppID) {
			return false
		}
	}
	return true
}

func (f *sessionFilter) hasFilter() bool {
	return f.zoneID != 0 || f.proto != 0 || f.srcNet != nil || f.dstNet != nil ||
		f.srcPort != 0 || f.dstPort != 0 || f.natOnly || f.iface != "" || f.appName != ""
}

// ifaceMatches checks whether ifName matches the filter's interface name.
// It matches the exact name or the parent interface (e.g. filter "ge-0/0/0"
// matches session interface "ge-0/0/0.50").
func (f *sessionFilter) ifaceMatches(ifName string) bool {
	if ifName == "" {
		return false
	}
	return ifName == f.iface || strings.HasPrefix(ifName, f.iface+".")
}

// resolveEgressIface resolves a session's egress interface name from FIB
// lookup result, falling back to the zone's first interface.
func (f *sessionFilter) resolveEgressIface(fibIfindex uint32, fibVlanID uint16, egressZone uint16) string {
	if fibIfindex != 0 {
		if ifName, ok := f.egressIfacesMap[sessionIfaceKey{ifindex: fibIfindex, vlanID: fibVlanID}]; ok && ifName != "" {
			return ifName
		}
	}
	return f.zoneIfaces[egressZone]
}

func (c *CLI) fetchPeerSessions(f sessionFilter) *pb.GetSessionsResponse {
	conn := c.dialPeer()
	if conn == nil {
		return nil
	}
	defer conn.Close()

	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.GetSessionsRequest{Limit: 10000}
	if f.proto != 0 {
		req.Protocol = strings.ToUpper(protoNameFromNum(f.proto))
	}
	if f.srcNet != nil {
		req.SourcePrefix = f.srcNet.String()
	}
	if f.dstNet != nil {
		req.DestinationPrefix = f.dstNet.String()
	}
	if f.srcPort != 0 {
		req.SourcePort = uint32(f.srcPort)
	}
	if f.dstPort != 0 {
		req.DestinationPort = uint32(f.dstPort)
	}
	if f.natOnly {
		req.NatOnly = true
	}
	if f.appName != "" {
		req.Application = f.appName
	}
	if f.iface != "" {
		req.InterfaceFilter = f.iface
	}

	resp, err := client.GetSessions(ctx, req)
	if err != nil {
		slog.Warn("failed to fetch peer sessions", "err", err)
		return nil
	}
	return resp
}

// fetchPeerSessionSummary dials the cluster peer's gRPC and returns its session summary.
func (c *CLI) fetchPeerSessionSummary() *pb.GetSessionSummaryResponse {
	conn := c.dialPeer()
	if conn == nil {
		return nil
	}
	defer conn.Close()

	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := client.GetSessionSummary(ctx, &pb.GetSessionSummaryRequest{})
	if err != nil {
		slog.Warn("failed to fetch peer session summary", "err", err)
		return nil
	}
	return resp
}

// topTalkerEntry holds a session's display info for sorting.
type topTalkerEntry struct {
	src, dst, proto, zone, state, app string
	fwdPkts, revPkts                  uint64
	fwdBytes, revBytes                uint64
	age                               uint64
}

func (c *CLI) handleShowNAT(args []string) error {
	cfg := c.store.ActiveConfig()

	if len(args) == 0 {
		fmt.Println("show security nat:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["show"].Children["security"].Children["nat"].Children))
		return nil
	}

	switch args[0] {
	case "source":
		if len(args) >= 2 && args[1] == "persistent-nat-table" {
			if len(args) >= 3 && args[2] == "detail" {
				return c.showPersistentNATDetail()
			}
			return c.showPersistentNAT()
		}
		return c.showNATSource(cfg, args[1:])
	case "destination":
		return c.showNATDestination(cfg, args[1:])
	case "static":
		return c.showNATStatic(cfg)
	case "nat64":
		return c.showNAT64(cfg)
	case "nptv6":
		return c.showNPTv6(cfg)
	default:
		return fmt.Errorf("unknown show security nat target: %s", args[0])
	}
}

func (c *CLI) handleShowRoute(args []string) error {
	if len(args) >= 2 && args[0] == "instance" {
		return c.showRoutesForInstance(args[1])
	}
	if len(args) >= 2 && args[0] == "table" {
		return c.showRoutesForVRF(args[1])
	}
	if len(args) >= 2 && args[0] == "protocol" {
		return c.showRoutesForProtocol(args[1])
	}
	if len(args) >= 1 && args[0] == "terse" {
		return c.showRouteTerse()
	}
	if len(args) >= 1 && args[0] == "summary" {
		return c.showRouteSummary()
	}
	if len(args) >= 1 && args[0] == "detail" {
		return c.showRouteDetail()
	}
	// Treat first arg as prefix filter (e.g. "show route 10.0.1.0/24")
	// Optional second arg is a modifier: exact, longer, orlonger
	if len(args) >= 1 && (strings.Contains(args[0], "/") || strings.Contains(args[0], ".") || strings.Contains(args[0], ":")) {
		modifier := ""
		if len(args) >= 2 {
			switch args[1] {
			case "exact", "longer", "orlonger":
				modifier = args[1]
			}
		}
		return c.showRoutesForPrefix(args[0], modifier)
	}
	return c.showRoutes()
}

func (c *CLI) handleShowProtocols(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show protocols:", operationalTree, "show", "protocols")
		return nil
	}

	switch args[0] {
	case "ospf":
		return c.showOSPF(args[1:])
	case "bgp":
		return c.showBGP(args[1:])
	case "bfd":
		return c.showBFD(args[1:])
	case "rip":
		return c.showRIP()
	case "isis":
		return c.showISIS(args[1:])
	default:
		return fmt.Errorf("unknown show protocols target: %s", args[0])
	}
}

func (c *CLI) dhcpLease(ifaceName string, af dhcp.AddressFamily) *dhcp.Lease {
	if c.dhcp == nil {
		return nil
	}
	return c.dhcp.LeaseFor(ifaceName, af)
}

// showInterfacesDetail shows per-interface info with key stats but less
// verbose than extensive (omits per-error-type breakdowns and BPF counters).

func readLinkSpeed(ifaceName string) int {
	data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/speed")
	if err != nil {
		return 0
	}
	speed, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || speed <= 0 {
		return 0
	}
	return speed
}

// readLinkDuplex reads the link duplex from sysfs. Returns "" on error.
func readLinkDuplex(ifaceName string) string {
	data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/duplex")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// formatSpeed formats a link speed in Mbps to a human-readable string.
func formatSpeed(mbps int) string {
	if mbps >= 1000 {
		return fmt.Sprintf("%dGbps", mbps/1000)
	}
	return fmt.Sprintf("%dMbps", mbps)
}

// formatDuplex formats a sysfs duplex string to display form.
func formatDuplex(duplex string) string {
	switch strings.ToLower(duplex) {
	case "full":
		return "Full-duplex"
	case "half":
		return "Half-duplex"
	default:
		return duplex
	}
}


func printChronyTracking(output string) {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, " : "); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+3:])
			fields[key] = val
		}
	}

	fmt.Println("NTP sync status:")
	if v, ok := fields["Reference ID"]; ok {
		fmt.Printf("  Reference: %s\n", v)
	}
	if v, ok := fields["Stratum"]; ok {
		fmt.Printf("  Stratum: %s\n", v)
	}
	if v, ok := fields["Ref time (UTC)"]; ok {
		fmt.Printf("  Reference time: %s\n", v)
	}
	if v, ok := fields["System time"]; ok {
		fmt.Printf("  System time offset: %s\n", v)
	}
	if v, ok := fields["Last offset"]; ok {
		fmt.Printf("  Last offset: %s\n", v)
	}
	if v, ok := fields["RMS offset"]; ok {
		fmt.Printf("  RMS offset: %s\n", v)
	}
	if v, ok := fields["Frequency"]; ok {
		fmt.Printf("  Frequency: %s\n", v)
	}
	if v, ok := fields["Root delay"]; ok {
		fmt.Printf("  Root delay: %s\n", v)
	}
	if v, ok := fields["Root dispersion"]; ok {
		fmt.Printf("  Root dispersion: %s\n", v)
	}
	if v, ok := fields["Update interval"]; ok {
		fmt.Printf("  Poll interval: %s\n", v)
	}
	if v, ok := fields["Leap status"]; ok {
		fmt.Printf("  Leap status: %s\n", v)
	}
}

// showSystemServices displays configured system services.

func protoNameFromNum(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 4:
		return "ipip"
	case 41:
		return "ipv6"
	case dataplane.ProtoICMPv6:
		return "icmpv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// protoNameToID converts a protocol name (e.g. "TCP") to its numeric string ("6").
func protoNameToID(name string) string {
	switch strings.ToUpper(name) {
	case "TCP":
		return "6"
	case "UDP":
		return "17"
	case "ICMP":
		return "1"
	case "GRE":
		return "47"
	case "ICMPV6":
		return "58"
	default:
		return name
	}
}

// splitAddrPort splits "addr:port" into address and port strings.
// Handles IPv6 bracket notation like "[::1]:443".
func splitAddrPort(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	// IPv6 bracket notation: [addr]:port
	if strings.HasPrefix(s, "[") {
		idx := strings.LastIndex(s, "]:")
		if idx >= 0 {
			return s[1:idx], s[idx+2:]
		}
		return strings.Trim(s, "[]"), ""
	}
	// IPv4: last colon separates addr:port
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, ""
	}
	// Make sure it's not an IPv6 address without brackets
	if strings.Count(s, ":") > 1 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// uint32ToIP converts a network byte order uint32 to net.IP.
func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

func sessionStateName(state uint8) string {
	switch state {
	case dataplane.SessStateNone:
		return "None"
	case dataplane.SessStateNew:
		return "New"
	case dataplane.SessStateSynSent:
		return "SYN_SENT"
	case dataplane.SessStateSynRecv:
		return "SYN_RECV"
	case dataplane.SessStateEstablished:
		return "Established"
	case dataplane.SessStateFINWait:
		return "FIN_WAIT"
	case dataplane.SessStateCloseWait:
		return "CLOSE_WAIT"
	case dataplane.SessStateTimeWait:
		return "TIME_WAIT"
	case dataplane.SessStateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

// ntohs converts a uint16 from network to host byte order.
func ntohs(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}


func (c *CLI) clusterPrefix() string {
	if c.cluster == nil {
		return ""
	}
	rg0 := c.cluster.GroupState(0)
	if rg0 == nil {
		return ""
	}
	role := "secondary"
	if rg0.State == cluster.StatePrimary {
		role = "primary"
	}
	return fmt.Sprintf("{%s:node%d}", role, c.cluster.NodeID())
}

func (c *CLI) operationalPrompt() string {
	return fmt.Sprintf("%s%s@%s> ", c.clusterPrefix(), c.username, c.hostname)
}

func (c *CLI) configPrompt() string {
	return fmt.Sprintf("%s%s@%s# ", c.clusterPrefix(), c.username, c.hostname)
}

func (c *CLI) handleShowClassOfService(args []string) error {
	if len(args) == 0 || args[0] != "interface" {
		cmdtree.PrintTreeHelp("show class-of-service:", operationalTree, "show", "class-of-service")
		return nil
	}
	selector := ""
	if len(args) > 1 {
		selector = args[1]
	}
	return c.showClassOfServiceInterface(selector)
}

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
	default:
		return fmt.Errorf("unknown services target: %s", args[0])
	}
}
