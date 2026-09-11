// Package cli implements the Junos-style interactive CLI for xpf.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"github.com/psaab/xpf/pkg/bootstrapshow"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	ddnspkg "github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/natpoolalarm"
	"github.com/psaab/xpf/pkg/osident"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/sysservices"
	"github.com/psaab/xpf/pkg/upgrade"
	"github.com/psaab/xpf/pkg/vrrp"
)

// CLI is the interactive command-line interface.
type CLI struct {
	rl *readline.Instance
	// readLineFn overrides rl.Readline for the multi-line terminal-input
	// paths. It is a TEST SEAM, nil in production: the `load ... terminal`
	// read loop is a security-relevant control flow (a Ctrl-C-aborted paste
	// must not be applied, #6548) and it was unguarded for exactly as long as
	// it had no injectable input. See readLine below.
	readLineFn      func() (string, error)
	store           *configstore.Store
	dp              cliRuntime
	eventBuf        *logging.EventBuffer
	eventReader     *logging.EventReader
	routing         *routing.Manager
	frr             *frr.Manager
	ipsec           *ipsec.Manager
	dhcp            *dhcp.Manager
	dhcpRelay       *dhcprelay.Manager
	cluster         *cluster.Manager
	rpmResultsFn    func() []*rpm.ProbeResult
	ipmonStatusFn   func() []ipmon.PolicyStatus
	natPoolAlarmsFn func() []natpoolalarm.ActiveAlarm
	feedsFn         func() map[string]feeds.FeedInfo
	// feedOverlayFn returns the live dynamic-address feed-prefix overlay
	// (#3105): an address-name -> union-of-live-feed-CIDR-strings map, the same
	// source the REST/gRPC simulators consume (daemon SnapshotForBindings). The
	// local `show security match-policies` / `test policy` simulators pass this
	// into policymatch so a feed-backed address-name resolves to its live CIDRs
	// on-box, matching what the dataplane enforces. Nil (CLI spawned outside the
	// daemon, or no feed manager) means no overlay — exactly the pre-#3105
	// behavior (feed-backed names resolve to static content only).
	feedOverlayFn      func() map[string][]string
	lldpNeighborsFn    func() []*lldp.Neighbor
	ddnsStatsFn        func() *dhcpserver.DDNSStats
	ddnsOwnedRecordsFn func() []dhcpserver.DDNSOwnedRecordView
	// dhcpServerFn builds the dhcpserver.Manager used by `show dhcp server`
	// (#5967). Production leaves it nil → dhcpserver.New(); a test seam injects a
	// manager pointed at a controlled Kea lease-file set so the degraded-source
	// banner (parity with the gRPC handler) can be exercised without /var/lib/kea.
	dhcpServerFn func() *dhcpserver.Manager
	// #2691 P2: Surface A (router/interface-address) DDNS status sources for
	// `show services dynamic-dns [detail]`.
	surfaceADDNSStatsFn  func() *ddnspkg.SurfaceAStats
	surfaceADDNSStatusFn func() []ddnspkg.SurfaceAStatusView
	// surfaceADDNSForceFn is the operator force-now / check-now verb for
	// `request system dynamic-dns update|check` (#3276). It arms the Surface A
	// force latch + nudges an immediate reconcile (force=true) or only nudges a
	// re-observe pass (force=false), honoring the per-RG owner gate. Returns
	// (ok, message). Nil when the manager is absent (NoDataplane).
	surfaceADDNSForceFn func(force bool) (bool, string)
	// flowCollectorHealthFn surfaces live per-collector NetFlow v9 / IPFIX
	// write-health for `show flow-monitoring statistics` (#2464). Nil
	// leaves the show reporting "no flow export configured".
	flowCollectorHealthFn func() []flowexport.ExporterCollectorHealth
	// listenersFn returns the EFFECTIVE (post-clamp, post-bind) management
	// listener addresses `show system services` reports (#6385). The daemon
	// wires it to Daemon.effectiveListeners — the SAME snapshot the remote gRPC
	// renderer reads — so the local console and the remote `cli` can never
	// disagree. Nil when the CLI is spawned outside the daemon (offline recovery
	// / unit test): showSystemServices falls back to the documented loopback
	// defaults.
	listenersFn func() sysservices.Listeners
	// bootstrapImportFn returns the recorded day-0 / bootstrap config-import
	// outcome for `show system bootstrap-import` (#6496). The daemon wires it
	// to Daemon.BootstrapImportSnapshot — the SAME snapshot /health and the
	// gRPC ShowText path read. Nil in a `cli` spawned outside the daemon,
	// where the command reports that no outcome has been recorded.
	bootstrapImportFn func() bootstrapshow.Snapshot
	// kernelUpgradeStatusFn returns the #1930 kernel-channel state for
	// `show system kernel-upgrade` (#6495). The daemon wires the same reader
	// the gRPC path uses, so the console and the remote `cli` cannot disagree
	// about a node mid-roll. Nil outside the daemon, where the command reports
	// an idle channel.
	kernelUpgradeStatusFn func() upgrade.ChannelStatus
	hostname              string
	username              string
	userClass             string
	// pendingPipeSuffix carries the output-pipe suffix that cliterm.SplitPipe
	// removed, so the #7172 command gate can match the command as the operator
	// typed it. Junos counts the pipe as part of the command, and a gate that
	// cannot see past `|` cannot restrict `show configuration | save /tmp/x`.
	//
	// Set and cleared by dispatchWithPipe around its single recursive dispatch;
	// it is never read outside that window. A field rather than a parameter
	// because dispatchOperational has five callers and the suffix is relevant
	// to exactly one of them.
	pendingPipeSuffix string
	version           string
	startTime         time.Time

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

	// factoryResetFn routes `request system zeroize` through the DAEMON's
	// coordinated factory-reset transaction (#5871) — the SAME gate the gRPC
	// zeroize path uses (grpcapi.Config.ZeroizeFn -> daemon.factoryReset). It
	// acquires the daemon's apply semaphore (draining any in-flight apply,
	// blocking a concurrent one) and enters the terminal reset generation BEFORE
	// the wipe closure runs, so no concurrent/subsequent commit / HA-sync /
	// reconcile re-persists the erased .configdb SSOT or re-renders the wiped
	// secrets (frr.conf / swanctl PSKs / Kea / login accounts). The wipe closure
	// it receives is the shared grpcapi.PerformZeroizeWipe primitive (via the
	// zeroizeFullWipe seam), so the console and gRPC paths run an identical,
	// single-source-of-truth reset under identical fencing. Nil ONLY when the CLI
	// is spawned OUTSIDE the daemon (offline recovery / unit test): there is no
	// running reconcile loop to race, so performConsoleZeroize falls back to an
	// ungated direct wipe, mirroring grpcapi.runZeroize's zeroizeFn==nil path.
	factoryResetFn func(ctx context.Context, wipe func() error) error

	// Fabric peer dialing for cluster-wide queries (fab0 + optional fab1).
	fabricPeerAddrFn func() []string
	fabricVRFDevice  string
	// fabricAuthKeyFn resolves the #4107 control-link PSK the CLI attaches to
	// peer fabric dials (dialPeer). Nil in production, where fabricAuthKey()
	// falls back to the cluster manager's live key; a test seam sets it
	// directly so tests need not construct a keyed cluster.Manager (#5324).
	fabricAuthKeyFn func() []byte
	// fabricPeerPort overrides the peer gRPC port (default 50051 when 0). A
	// test seam so dialPeer can target an ephemeral loopback fabric server.
	fabricPeerPort     int
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
func New(store *configstore.Store, dp cliRuntime, eventBuf *logging.EventBuffer, eventReader *logging.EventReader, rm *routing.Manager, fm *frr.Manager, im *ipsec.Manager, dm *dhcp.Manager, dr *dhcprelay.Manager, cm *cluster.Manager) *CLI {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	// #6701: the shell prompt identity comes from the KERNEL (real uid ->
	// passwd), never from $USER. The prompt is display-only — RBAC is carried
	// by userClass, set by the daemon through SetUserClass — but a prompt
	// sourced from a caller-controlled environment variable renders whatever
	// the caller typed, so `USER=root cli` printed a root prompt to a
	// read-only operator and to anyone reading over their shoulder. An
	// unresolvable identity renders as `uid-<n>` rather than a fabricated
	// plausible account name.
	username := osident.Current().String()

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

func (c *CLI) applyResult() *dataplane.ApplyResult {
	if c == nil {
		return nil
	}
	return dataplane.LastApplyResultOf(c.dp)
}

func (c *CLI) dataplaneLoaded() bool {
	return c != nil && c.dp != nil && c.dp.IsLoaded()
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

// SetIPMonStatusFn sets a callback for retrieving live ip-monitoring
// policy status (#1827).
func (c *CLI) SetIPMonStatusFn(fn func() []ipmon.PolicyStatus) {
	c.ipmonStatusFn = fn
}

// SetNATPoolAlarmsFn sets a callback for retrieving the active NAT
// pool-utilization alarms surfaced by `show security alarms` (#2079).
func (c *CLI) SetNATPoolAlarmsFn(fn func() []natpoolalarm.ActiveAlarm) {
	c.natPoolAlarmsFn = fn
}

// SetFeedsFn sets a callback for retrieving live dynamic address feed status.
func (c *CLI) SetFeedsFn(fn func() map[string]feeds.FeedInfo) {
	c.feedsFn = fn
}

// SetFeedOverlayFn sets a callback for retrieving the live dynamic-address
// feed-prefix overlay (#3105) consumed by the local `show security
// match-policies` / `test policy` simulators. The callback returns the same
// address-name -> union-of-feed-CIDRs map the REST/gRPC simulators use
// (daemon feedSnapshotsForConfig -> feeds.Manager.SnapshotForBindings), read
// from daemon-local state — no control-socket call. Nil leaves the local
// simulators overlay-free (feed-backed names resolve to static content only).
func (c *CLI) SetFeedOverlayFn(fn func() map[string][]string) {
	c.feedOverlayFn = fn
}

// feedOverlay returns the live feed-prefix overlay for the policy simulators,
// or nil when no provider is wired (CLI spawned outside the daemon) — nil is a
// valid policymatch.Query.FeedOverlay (no feed enforcement), so the caller
// behaves exactly as before #3105.
func (c *CLI) feedOverlay() map[string][]string {
	if c == nil || c.feedOverlayFn == nil {
		return nil
	}
	return c.feedOverlayFn()
}

// SetLLDPNeighborsFn sets a callback for retrieving live LLDP neighbor data.
func (c *CLI) SetLLDPNeighborsFn(fn func() []*lldp.Neighbor) {
	c.lldpNeighborsFn = fn
}

// SetDDNSStatsFn sets a callback for retrieving live DHCP dynamic-DNS
// counters (#1387 inc-2). Nil leaves the show config-only.
func (c *CLI) SetDDNSStatsFn(fn func() *dhcpserver.DDNSStats) {
	c.ddnsStatsFn = fn
}

// SetFlowCollectorHealthFn sets a callback for retrieving live
// per-collector NetFlow v9 / IPFIX write-health (#2464). Nil leaves
// `show flow-monitoring statistics` reporting "no flow export configured".
func (c *CLI) SetFlowCollectorHealthFn(fn func() []flowexport.ExporterCollectorHealth) {
	c.flowCollectorHealthFn = fn
}

// SetListenersFn wires the effective management-listener snapshot source for
// `show system services` (#6385). The daemon passes Daemon.effectiveListeners —
// the SAME snapshot the remote gRPC renderer reads — so the local console and
// the remote `cli` report identical, post-bind listener addresses. Nil leaves
// showSystemServices on the documented loopback defaults (offline / unit test).
func (c *CLI) SetListenersFn(fn func() sysservices.Listeners) {
	c.listenersFn = fn
}

// SetBootstrapImportFn wires the recorded day-0 / bootstrap config-import
// outcome for `show system bootstrap-import` (#6496). The daemon passes
// Daemon.BootstrapImportSnapshot — the SAME snapshot /health and the gRPC
// ShowText renderer read — so the console, the remote `cli`, and the health
// probe cannot disagree about whether the day-0 configuration applied. Nil
// leaves the command reporting an unrecorded outcome (offline / unit test).
func (c *CLI) SetBootstrapImportFn(fn func() bootstrapshow.Snapshot) {
	c.bootstrapImportFn = fn
}

// SetKernelUpgradeStatusFn wires the #1930 kernel-channel state for
// `show system kernel-upgrade` (#6495). Before this, the only readout of an
// in-flight kernel roll was a root shell running `xpfd upgrade kernel status`
// or journald — automation had a path (the xpf-deploy orchestrator polls that
// verb over node_exec) and the human operator did not.
func (c *CLI) SetKernelUpgradeStatusFn(fn func() upgrade.ChannelStatus) {
	c.kernelUpgradeStatusFn = fn
}

// SetDDNSOwnedRecordsFn sets a callback for retrieving the DHCP
// dynamic-DNS records this node currently owns (#1387 inc-2).
func (c *CLI) SetDDNSOwnedRecordsFn(fn func() []dhcpserver.DDNSOwnedRecordView) {
	c.ddnsOwnedRecordsFn = fn
}

// SetSurfaceADDNSStatsFn sets a callback for retrieving live Surface A
// (router/interface-address) DDNS counters (#2691 P2). Nil leaves the show
// config-only.
func (c *CLI) SetSurfaceADDNSStatsFn(fn func() *ddnspkg.SurfaceAStats) {
	c.surfaceADDNSStatsFn = fn
}

// SetSurfaceADDNSStatusFn sets a callback for retrieving the Surface A DDNS
// per-scope last-published views for `show services dynamic-dns detail` (#2691
// P2).
func (c *CLI) SetSurfaceADDNSStatusFn(fn func() []ddnspkg.SurfaceAStatusView) {
	c.surfaceADDNSStatusFn = fn
}

// SetSurfaceADDNSForceFn sets the operator force-now / check-now callback for
// `request system dynamic-dns update|check` (#3276).
func (c *CLI) SetSurfaceADDNSForceFn(fn func(force bool) (bool, string)) {
	c.surfaceADDNSForceFn = fn
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

// SetFactoryResetFn wires the daemon's coordinated factory-reset transaction
// (#5871) so the in-process `request system zeroize` runs its wipe under the
// daemon apply gate + terminal reset generation, IDENTICAL to the gRPC zeroize
// path (grpcapi.Config.ZeroizeFn -> daemon.factoryReset — the same function).
// Without it a console zeroize erased state out-of-band, so a concurrent commit
// / HA-sync / reconcile could re-create the just-wiped .configdb SSOT or
// re-render the erased secrets. Leave unset for a CLI spawned outside the daemon
// (offline recovery / unit test): performConsoleZeroize then falls back to an
// ungated direct wipe (no reconcile loop is running to race).
func (c *CLI) SetFactoryResetFn(fn func(ctx context.Context, wipe func() error) error) {
	c.factoryResetFn = fn
}

// SetFabricPeer configures fabric peer dialing for cluster-wide queries.
func (c *CLI) SetFabricPeer(addrFn func() []string, vrfDevice string) {
	c.fabricPeerAddrFn = addrFn
	c.fabricVRFDevice = vrfDevice
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

	// Commit-confirmed timeout rollback ownership (#1922 Item 1a).
	//
	// In daemon mode the in-process CLI routes commit-confirmed through
	// commitConfirmedFn (= d.commitConfirmedAndApply), so the timer is
	// armed inside the daemon's store and xpfd's own rollback executor
	// (d.executeConfirmedRollback, registered via store.SetRollbackExecutor
	// at daemon init) owns the timeout rollback — acquiring the apply
	// semaphore then running store promotion + full reconcile atomically,
	// in ALL modes (gRPC/REST/remote-cli as well as this shell). The old
	// interactive-only, non-atomic SetCentralRollbackHandler path is gone.
	//
	// Standalone mode (commitConfirmedFn nil, e.g. a CLI embedded without
	// a daemon): runCommitConfirmed arms c.store's own timer and there is
	// no daemon executor. Register a minimal store executor here so the
	// timeout still re-applies the rolled-back config to the dataplane —
	// preserving the prior standalone behavior — instead of falling back
	// to the store's store-only performAutoRollback.
	if c.commitConfirmedFn == nil {
		c.store.SetRollbackExecutor(func(gen uint64) {
			prevCfg, ok := c.store.PromoteRollback(gen)
			if !ok || prevCfg == nil {
				return
			}
			if c.applyConfigFn != nil {
				c.applyConfigFn(prevCfg)
			} else if c.dp != nil {
				if err := c.applyToDataplane(prevCfg); err != nil {
					fmt.Fprintf(os.Stderr, "\nwarning: auto-rollback dataplane apply failed: %v\n", err)
				}
			}
			c.reloadSyslog(prevCfg)
			fmt.Fprintf(os.Stderr, "\ncommit confirmed timed out, configuration has been rolled back\n")
		})
	}

	fmt.Println("xpf stateful firewall - Junos-style CLI")
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
			if alarm := c.store.ConfirmAlarm(); alarm != "" {
				fmt.Println("[ALARM: " + alarm + "]")
			}
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
	// The read loop above never falls through — every exit is a `return`
	// (exitCh, io.EOF at operational level, Readline error, or errExit from
	// dispatch). A trailing `return nil` here was unreachable and tripped
	// `go vet` (codex-182 A10-b00-C02); Go accepts the infinite `for {}` as
	// the function's terminating statement, so no return is needed.
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
