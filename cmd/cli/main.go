// cli is the remote CLI client for xpfd.
//
// It connects to the xpfd gRPC API and provides the same Junos-style
// interactive CLI as the embedded console.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/psaab/xpf/pkg/cliterm"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/osident"
	"github.com/psaab/xpf/pkg/policymatch"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

// maxConfigRecvBytes bounds a single gRPC response the CLI will accept. The
// configstore accepts a configuration up to configstore.MaxConfigSize (16 MiB),
// and a ShowConfig response can carry a payload of that size, so the CLI must
// be able to receive it. grpc-Go defaults MaxCallRecvMsgSize to 4 MiB, which
// truncates a large `show configuration` with ResourceExhausted (#5321). Track
// the store ceiling plus 1 MiB of gRPC/proto framing headroom so the two
// bounds cannot drift.
const maxConfigRecvBytes = configstore.MaxConfigSize + (1 << 20)

// dialOpts returns the gRPC dial options the CLI client uses to reach xpfd.
// Kept as a helper (rather than inline) so tests exercise the exact production
// construction: insecure loopback transport plus the raised receive cap that
// lets a large `show configuration` (up to configstore.MaxConfigSize) round
// trip past grpc-Go's 4 MiB default (#5321). extra options (e.g. a bufconn
// dialer) are appended for tests.
func dialOpts(extra ...grpc.DialOption) []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxConfigRecvBytes)),
	}
	return append(opts, extra...)
}

// resolveUsername returns the identity the remote CLI displays in its prompt.
//
// #6701: it is derived from the KERNEL (real uid -> passwd, pkg/osident), never
// from `$USER`. `cli` is an unprivileged client and this is NOT an
// authorization decision — the RBAC boundary lives on the gRPC listener, which
// since #5278 derives the caller's identity server-side from the kernel's
// socket table and enforces the login class there. What is rendered here is the
// prompt, and it is derived the same way so the two agree: a prompt sourced
// from a caller-controlled environment variable renders whatever the caller
// typed (`USER=root cli` printed a root prompt to a read-only operator whose
// RPCs the server would refuse), which is a misleading UI rather than a bypass.
// An unresolvable identity renders as `uid-<n>` rather than the old fabricated
// "remote" placeholder, which read like a real account.
func resolveUsername() string {
	return osident.Current().String()
}

// isLocalOnlyCommand reports whether cmd (the `-c` single-command string) is a
// CLI verb that executes entirely in the client with NO gRPC round-trip, so it
// must run even when xpfd is unreachable. Today the only such verb is the
// offline WireGuard key generator (`request security wireguard
// generate-private-key`, #1434) — a pure-Go X25519 keygen whose whole purpose
// is to be available exactly when the daemon is down (recovery/bootstrap),
// which the pre-dispatch GetStatus probe otherwise defeats (#4909). Matches the
// canonical token form; abbreviated prefixes still take the daemon path.
func isLocalOnlyCommand(cmd string) bool {
	f := strings.Fields(cmd)
	return len(f) == 4 &&
		f[0] == "request" && f[1] == "security" &&
		f[2] == "wireguard" && f[3] == "generate-private-key"
}

func d11ArmAction(runID string, permitEpoch uint64, markerHex string) string {
	return fmt.Sprintf("userspace-attest:arm:%s:%d:%s", runID, permitEpoch, markerHex)
}

func runD11Reattest(
	ctx context.Context,
	client pb.BpfrxServiceClient,
	phase, runID string,
	permitEpoch uint64,
	markerHex string,
) ([]byte, error) {
	switch phase {
	case "arm":
		response, err := client.SystemAction(ctx, &pb.SystemActionRequest{
			Action: d11ArmAction(runID, permitEpoch, markerHex),
		})
		if err != nil {
			return nil, err
		}
		return []byte(response.GetMessage()), nil
	case "ledger":
		response, err := client.GetD11AttestationLedger(ctx, &pb.GetD11AttestationLedgerRequest{})
		if err != nil {
			return nil, err
		}
		return protojson.MarshalOptions{UseProtoNames: true}.Marshal(response)
	default:
		return nil, fmt.Errorf("invalid D11 phase %q (want arm or ledger)", phase)
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "xpfd gRPC address")
	cmdFlag := flag.String("c", "", "run a single command non-interactively and exit")
	d11Mode := flag.Bool("d11-reattest", false, "internal D11 arm/ledger driver")
	d11Phase := flag.String("d11-phase", "", "internal D11 phase: arm or ledger")
	d11RunID := flag.String("d11-run-id", "", "internal D11 run ID")
	d11PermitEpoch := flag.Uint64("d11-permit-epoch", 0, "internal D11 permit epoch")
	d11MarkerHex := flag.String("d11-marker-hex", "", "internal D11 marker selector")
	flag.Parse()
	conn, err := grpc.NewClient(*addr, dialOpts()...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli: connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)

	if *d11Mode {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		output, callErr := runD11Reattest(
			ctx, client, *d11Phase, *d11RunID, *d11PermitEpoch, *d11MarkerHex,
		)
		cancel()
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "cli: D11 %s: %v\n", *d11Phase, callErr)
			os.Exit(1)
		}
		fmt.Println(string(output))
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	username := resolveUsername()

	// A local-only verb (the offline WireGuard key generator) runs entirely in
	// the client with no gRPC round-trip, so it must work when xpfd is DOWN —
	// exactly during recovery/bootstrap. Dispatch it BEFORE the GetStatus
	// reachability probe, which would otherwise exit(1) and make the offline
	// generator unreachable precisely when it is needed (#4909).
	if *cmdFlag != "" && isLocalOnlyCommand(*cmdFlag) {
		c := &ctl{client: client, hostname: hostname, username: username}
		c.startCmd()
		err := c.dispatch(*cmdFlag)
		c.endCmd()
		if err != nil && err != errExit {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	resp, err := client.GetStatus(ctx, &pb.GetStatusRequest{})
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli: cannot reach xpfd at %s: %v\n", *addr, err)
		os.Exit(1)
	}

	c := &ctl{
		client:        client,
		hostname:      hostname,
		username:      username,
		clusterRole:   resp.ClusterRole,
		clusterNodeID: resp.ClusterNodeId,
	}
	// configMode starts false (atomic.Bool zero value).

	if *cmdFlag != "" {
		c.startCmd()
		err := c.dispatch(*cmdFlag)
		c.endCmd()
		if err != nil && err != errExit {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	rc := &remoteCompleter{ctl: c}
	rl, err := readline.NewEx(cliterm.DisableReadlineHistoryAutoSave(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     filepath.Join(os.Getenv("HOME"), ".xpf_cli_history"),
		HistoryLimit:    10000,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    rc,
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		Listener: readline.FuncListener(func(line []rune, pos int, key rune) ([]rune, int, bool) {
			if key != '?' || pos < 1 {
				return line, pos, false
			}
			cleanLine := make([]rune, 0, len(line)-1)
			cleanLine = append(cleanLine, line[:pos-1]...)
			cleanLine = append(cleanLine, line[pos:]...)
			text := string(cleanLine[:pos-1])
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			resp, err := c.client.Complete(ctx, &pb.CompleteRequest{
				Line:       text,
				Pos:        int32(len(text)),
				ConfigMode: c.configMode.Load(),
			})
			if err != nil || len(resp.Candidates) == 0 {
				fmt.Fprintln(c.rl.Stdout(), "  (no help available)")
				rc.helpWritten = true
				return cleanLine, pos - 1, true
			}
			candidates := make([]cmdtree.Candidate, len(resp.Candidates))
			for i, name := range resp.Candidates {
				desc := ""
				if i < len(resp.Descriptions) && resp.Descriptions[i] != "" {
					desc = resp.Descriptions[i]
				} else if strings.Contains(text, "|") {
					desc = pipeFilterDescs[name]
				} else {
					desc = remoteLookupDesc(strings.Fields(text), name, c.configMode.Load())
				}
				candidates[i] = cmdtree.Candidate{Name: name, Desc: desc}
			}
			sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
			cmdtree.WriteHelp(c.rl.Stdout(), candidates)
			rc.helpWritten = true
			return cleanLine, pos - 1, true
		}),
	}))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli: readline: %v\n", err)
		os.Exit(1)
	}
	defer rl.Close()
	c.rl = rl

	fmt.Printf("cli — connected to xpfd (uptime: %s)\n", resp.Uptime)
	fmt.Println("Type '?' for help")
	fmt.Println()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go c.runSignalLoop(sigCh, client, rl.Refresh, func() { os.Exit(0) })
	defer signal.Stop(sigCh)

	for {
		if c.configMode.Load() && confirmPending(client) {
			fmt.Println("[commit confirmed pending - issue 'commit' to confirm]")
		}

		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				if c.configMode.Load() {
					c.configMode.Store(false)
					c.editPath = nil
					exitConfigureBounded(client)
					rl.SetPrompt(c.operationalPrompt())
					fmt.Println("\nExiting configuration mode")
					continue
				}
				break
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		c.startCmd()
		err = c.dispatch(line)
		c.endCmd()
		if err != nil {
			if err == errExit {
				break
			}
			if err == context.Canceled {
				continue
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
	}

	if c.configMode.Load() {
		exitConfigureBounded(client)
	}
}

// exitConfigureTimeout bounds the ExitConfigure control RPC the CLI issues
// when leaving configuration mode from a path that has no cancellable command
// context: the SIGINT double-Ctrl-C handler, an EOF (Ctrl-D) at the prompt,
// and the normal post-loop teardown. These previously used
// context.Background(), so a wedged daemon could hang Ctrl-C cleanup or block
// process exit indefinitely (#5053). A bounded context guarantees the CLI
// still tears down and exits. Sized like the other CLI control RPCs.
const exitConfigureTimeout = 5 * time.Second

// exitConfigureBounded issues a best-effort ExitConfigure with a bounded
// context so a hung daemon cannot wedge CLI teardown. The error is discarded:
// this is cleanup on the way out and there is nothing left to recover.
func exitConfigureBounded(client pb.BpfrxServiceClient) {
	ctx, cancel := context.WithTimeout(context.Background(), exitConfigureTimeout)
	defer cancel()
	_, _ = client.ExitConfigure(ctx, &pb.ExitConfigureRequest{})
}

// confirmPendingTimeout bounds the pre-prompt commit-confirm status poll
// (#5649, C181-C13). The advisory poll runs before Readline with no active
// command context, so a Ctrl-C cannot cancel it.
const confirmPendingTimeout = 2 * time.Second

// confirmPending reports whether a commit-confirmed rollback is armed, using a
// BOUNDED context (#5649, C181-C13). The poll fires before every config-mode
// prompt with no command context to cancel it, so a daemon that accepts the
// connection but never completes GetConfigModeStatus would otherwise wedge the
// interactive client indefinitely before Readline. On timeout/error the prompt
// simply proceeds without the advisory line.
func confirmPending(client pb.BpfrxServiceClient) bool {
	ctx, cancel := context.WithTimeout(context.Background(), confirmPendingTimeout)
	defer cancel()
	st, err := client.GetConfigModeStatus(ctx, &pb.GetConfigModeStatusRequest{})
	return err == nil && st != nil && st.ConfirmPending
}

// interruptWindow is the double-Ctrl-C window: a second interrupt within this
// span of the first exits the CLI.
const interruptWindow = 2 * time.Second

// runSignalLoop is the body of the SIGINT goroutine, extracted from main so
// tests can drive it with an injected channel (#5053). It processes interrupts
// until sigCh is closed: a running command is cancelled; otherwise a first
// Ctrl-C arms a 2s window and a second within it tears down. refresh redraws
// the prompt (rl.Refresh in production; nil in tests). onExit terminates the
// process (os.Exit(0) in production; a recorder in tests) — it is expected not
// to return, so the loop stops after invoking it.
func (c *ctl) runSignalLoop(sigCh <-chan os.Signal, client pb.BpfrxServiceClient, refresh func(), onExit func()) {
	var lastInterrupt time.Time
	for range sigCh {
		if c.cancelCmd() {
			fmt.Fprintln(os.Stderr, "\n^C (command cancelled)")
			continue
		}
		now := time.Now()
		if now.Sub(lastInterrupt) < interruptWindow {
			c.exitOnInterrupt(client, onExit)
			return
		}
		lastInterrupt = now
		fmt.Fprintln(os.Stderr, "\n^C (press again within 2s to exit)")
		if refresh != nil {
			refresh()
		}
	}
}

// exitOnInterrupt performs the double-Ctrl-C teardown: if still in
// configuration mode, release the daemon-side config lock with a bounded
// ExitConfigure, then invoke onExit. configMode is read atomically because the
// main loop mutates it concurrently; a racy read here let a Ctrl-C landing
// during a configure/exit/EOF transition observe stale state and skip the
// ExitConfigure cleanup (#5053).
func (c *ctl) exitOnInterrupt(client pb.BpfrxServiceClient, onExit func()) {
	if c.configMode.Load() {
		exitConfigureBounded(client)
	}
	onExit()
}

// maxConfirmedMinutes bounds `commit confirmed <minutes>` (Junos range
// 1..65535). Kept in sync with configstore.MaxCommitConfirmedMinutes (the
// remote CLI does not import configstore); the daemon re-enforces it.
const maxConfirmedMinutes = 65535

func (c *ctl) handleCommit(args []string) error {
	if len(args) > 0 && args[0] == "check" {
		resp, err := c.client.CommitCheck(c.ctx(), &pb.CommitCheckRequest{})
		if err != nil {
			return fmt.Errorf("commit check failed: %v", err)
		}
		printRemoteConfigWarnings(resp.Warnings)
		fmt.Println("configuration check succeeds")
		return nil
	}

	if len(args) > 0 && args[0] == "comment" {
		if len(args) < 2 {
			return fmt.Errorf("usage: commit comment \"description\"")
		}
		desc := strings.Join(args[1:], " ")
		desc = strings.Trim(desc, "\"'")
		resp, err := c.client.Commit(c.ctx(), &pb.CommitRequest{Comment: desc})
		if err != nil {
			return fmt.Errorf("commit failed: %v", err)
		}
		c.refreshPrompt()
		printRemoteConfigWarnings(resp.Warnings)
		if resp.Summary != "" {
			fmt.Printf("commit complete: %s\n", resp.Summary)
		} else {
			fmt.Println("commit complete")
		}
		return nil
	}

	if len(args) > 0 && args[0] == "confirmed" {
		if len(args) > 2 {
			return fmt.Errorf("usage: commit confirmed [minutes]")
		}
		// #4868: `commit confirmed` is the rollback guard when changing
		// reachability, so a malformed/out-of-range timeout must ERROR rather
		// than silently arming the 10-minute default (junk|0|-1) or truncating a
		// large value through int32 (`4294967297` -> 1). Parse within the
		// int32/Junos range and enforce [1, maxConfirmedMinutes].
		minutes := int32(10)
		if len(args) >= 2 {
			v, err := strconv.ParseInt(args[1], 10, 32)
			if err != nil || v <= 0 {
				return fmt.Errorf("commit confirmed: invalid timeout %q "+
					"(want a positive number of minutes, 1..%d)", args[1], maxConfirmedMinutes)
			}
			if v > maxConfirmedMinutes {
				return fmt.Errorf("commit confirmed: timeout %d exceeds maximum %d minutes",
					v, maxConfirmedMinutes)
			}
			minutes = int32(v)
		}
		resp, err := c.client.CommitConfirmed(c.ctx(), &pb.CommitConfirmedRequest{Minutes: minutes})
		if err != nil {
			return fmt.Errorf("commit confirmed failed: %v", err)
		}
		c.refreshPrompt()
		printRemoteConfigWarnings(resp.Warnings)
		fmt.Printf("commit confirmed will be automatically rolled back in %d minutes unless confirmed\n", minutes)
		return nil
	}

	// #4868: any first token that is not a recognized modifier (e.g. the typo
	// `commit confimed 10`) must NOT fall through to the permanent commit below
	// — that would be a management-stranding change with no rollback timer.
	// Reject it before any mutation. Valid modifiers mirror cmdtree
	// (check / comment / confirmed).
	if len(args) > 0 {
		return fmt.Errorf("commit: unknown option %q (valid: check, comment, confirmed)", args[0])
	}

	resp, err := c.client.Commit(c.ctx(), &pb.CommitRequest{})
	if err != nil {
		return fmt.Errorf("commit failed: %v", err)
	}
	c.refreshPrompt()
	printRemoteConfigWarnings(resp.Warnings)
	if resp.Summary != "" {
		fmt.Printf("commit complete: %s\n", resp.Summary)
	} else {
		fmt.Println("commit complete")
	}
	return nil
}

// printRemoteConfigWarnings mirrors the local CLI's printConfigWarnings
// (pkg/cli/cli_config.go): the daemon ships compile warnings in the
// Commit/CommitCheck/CommitConfirmed responses (#1892 — e.g. the
// retired DPDK-era dataplane knobs), and the remote CLI used to drop
// them on the floor, so the operator never saw them.
func printRemoteConfigWarnings(warnings []string) {
	for _, w := range warnings {
		fmt.Printf("warning: %s\n", w)
	}
}

func (c *ctl) handlePing(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ping <host> [count N] [source IP] [size N] [routing-instance NAME]")
	}
	// #9065: every option here was parsed with its error DISCARDED — a bare
	// `if v, err := strconv.Atoi(...); err == nil` with no else, and an
	// `if i+1 < len(args)` with no else. So `ping host count abc` and
	// `ping host count` both ran a 5-packet ping and said nothing, and the
	// operator got a different ping from the one they typed. Same family as the
	// dropped selectors above: the command succeeds while answering a different
	// question.
	//
	// SCOPED to the four declared options. An UNKNOWN trailing token is still
	// ignored rather than refused — that is a second claim about this loop which
	// this change does not measure, and turning it into an error could refuse a
	// form some script relies on. The silent handling of a KNOWN option's own
	// value is what is fixed.
	req := &pb.PingRequest{Target: args[0], Count: 5}
	takePingValue := func(i *int, kw string) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("missing value for %q", kw)
		}
		*i++
		return args[*i], nil
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "count":
			v, err := takePingValue(&i, "count")
			if err != nil {
				return err
			}
			n, cerr := strconv.Atoi(v)
			if cerr != nil {
				return fmt.Errorf("invalid count %q: must be a number", v)
			}
			req.Count = int32(n)
		case "source":
			v, err := takePingValue(&i, "source")
			if err != nil {
				return err
			}
			req.Source = v
		case "size":
			v, err := takePingValue(&i, "size")
			if err != nil {
				return err
			}
			n, cerr := strconv.Atoi(v)
			if cerr != nil {
				return fmt.Errorf("invalid size %q: must be a number", v)
			}
			req.Size = int32(n)
		case "routing-instance":
			v, err := takePingValue(&i, "routing-instance")
			if err != nil {
				return err
			}
			req.RoutingInstance = v
		}
	}
	ctx, cancel := context.WithTimeout(c.ctx(), 60*time.Second)
	defer cancel()
	stream, err := c.client.Ping(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Output)
	}
	return nil
}

func (c *ctl) handleTraceroute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: traceroute <host> [source IP] [routing-instance NAME]")
	}
	req := &pb.TracerouteRequest{Target: args[0]}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "source":
			if i+1 < len(args) {
				i++
				req.Source = args[i]
			}
		case "routing-instance":
			if i+1 < len(args) {
				i++
				req.RoutingInstance = args[i]
			}
		}
	}
	ctx, cancel := context.WithTimeout(c.ctx(), 60*time.Second)
	defer cancel()
	stream, err := c.client.Traceroute(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Output)
	}
	return nil
}

// readTerminalConfig collects a pasted configuration from readLine until the
// input is COMMITTED by Ctrl-D (io.EOF). A readline.ErrInterrupt (Ctrl-C) or
// any other read error is an ABORT: the partial input is discarded and a
// non-nil error is returned so handleLoad does NOT apply a truncated subset of
// the config as if it were complete (#4883-D).
//
// The implementation moved to pkg/cliterm in #6548. It was duplicated in the
// local console CLI (pkg/cli handleLoad), the copies DIVERGED — #4883-D was
// applied here and never there, so the console kept silently applying
// Ctrl-C-truncated configurations — and a divergence between the two surfaces
// is always a bug. One implementation now serves both; this wrapper keeps the
// call site and the #4883-D regression tests pointed at it.
func readTerminalConfig(readLine func() (string, error)) (string, error) {
	return cliterm.ReadConfig(readLine)
}

func (c *ctl) handleLoad(args []string) error {
	if len(args) < 2 {
		printConfigTreeHelp("load:", "load")
		return nil
	}

	mode := args[0]
	if mode != "override" && mode != "merge" && mode != "set" {
		return fmt.Errorf("load: unknown mode %q (use 'override', 'merge', or 'set')", mode)
	}

	source := args[1]
	var content string

	if source == "terminal" {
		fmt.Println("[Type or paste configuration, then press Ctrl-D on an empty line]")
		var err error
		content, err = readTerminalConfig(c.rl.Readline)
		if err != nil {
			return err
		}
	} else {
		// #6753: bound the READ, not just the post-read length.
		data, err := configstore.ReadBoundedConfigFile(source)
		if err != nil {
			// #7469: %w, not %v — %v flattens the chain, so errors.Is
			// against configstore.ErrExceedsLimit fails on this surface while
			// succeeding on the local CLI. The shared helper was unified; the
			// error handling around it was not.
			return fmt.Errorf("load: %w", err)
		}
		content = string(data)
	}

	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("load: empty input")
	}

	_, err := c.client.Load(c.ctx(), &pb.LoadRequest{
		Mode:    mode,
		Content: content,
	})
	if err != nil {
		return fmt.Errorf("load %s: %v", mode, err)
	}
	fmt.Printf("load %s complete\n", mode)
	return nil
}

func (c *ctl) handleTest(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("test: specify a test command", "test")
		return nil
	}

	switch args[0] {
	case "policy":
		return c.testPolicy(args[1:])
	case "routing":
		return c.testRouting(args[1:])
	case "security-zone":
		return c.testSecurityZone(args[1:])
	default:
		return fmt.Errorf("unknown test command: %s", args[0])
	}
}

func (c *ctl) testPolicy(args []string) error {
	// #3696: parse the selector grammar through the single strict SSOT parser
	// (policymatch.ParseSelectorArgs) shared by all four CLI surfaces + the gRPC
	// test-policy bridge. A value-taking selector present WITHOUT a value, an
	// UNKNOWN selector token, an explicit-empty typed value, and a malformed
	// IP / port / protocol / icmp value are HARD ERRORS instead of silently
	// degrading to the wildcard — the remote CLI no longer builds a
	// silently-widened test-policy topic. Per-value validation (#3116 / #3108 /
	// #3284 / #1711) now lives in the parser.
	sel, err := policymatch.ParseSelectorArgs(args)
	if err != nil {
		return err
	}
	fromZone, toZone, srcIP, dstIP, proto := sel.FromZone, sel.ToZone, sel.SrcIP, sel.DstIP, sel.Protocol
	srcPort, dstPort := sel.SrcPort, sel.DstPort
	icmpType, icmpCode := sel.ICMPType, sel.ICMPCode

	if fromZone == "" || toZone == "" {
		// #3628: shared SSOT selector list (policymatch) so the remote and local
		// surfaces advertise the same complete selector set the parser accepts.
		fmt.Println(policymatch.TestPolicyUsage)
		return nil
	}

	// #3709: the legacy `test-policy:` ShowText topic is a comma/equals-delimited
	// key=value string, so a zone name that itself contains a comma or equals
	// cannot round-trip — the server splits it into bogus segments and rejects
	// or MISPARSES it. Config permits such a zone name (only exact reserved
	// tokens are rejected in compiler_validate_strict.go reservedZoneNames), so
	// rather than silently corrupt the query, fail closed here with a clear
	// error pointing the operator at `show security match-policies`, which uses
	// the typed MatchPolicies RPC and has no delimiter fragility. The local
	// `test policy` (pkg/cli) evaluates such a zone directly and is unaffected.
	for _, z := range []struct{ label, val string }{{"from-zone", fromZone}, {"to-zone", toZone}} {
		if strings.ContainsAny(z.val, ",=") {
			return fmt.Errorf("%s %q contains a comma or equals, which the 'test policy' topic cannot carry; use 'show security match-policies' instead", z.label, z.val)
		}
	}

	topic := fmt.Sprintf("test-policy:from=%s,to=%s", fromZone, toZone)
	if srcIP != "" {
		topic += ",src=" + srcIP
	}
	if dstIP != "" {
		topic += ",dst=" + dstIP
	}
	if srcPort > 0 {
		topic += ",srcport=" + strconv.Itoa(srcPort)
	}
	if dstPort > 0 {
		topic += ",port=" + strconv.Itoa(dstPort)
	}
	if proto != "" {
		topic += ",proto=" + proto
	}
	if icmpType != nil {
		topic += ",ictype=" + strconv.Itoa(int(*icmpType))
	}
	if icmpCode != nil {
		topic += ",iccode=" + strconv.Itoa(int(*icmpCode))
	}
	// #5572: forward the non-first-fragment (l4_present == false) selector to the
	// gRPC test-policy bridge so the remote `test policy` reproduces the #4569
	// fragment-associated deny.
	if sel.NonFirstFragment {
		topic += ",frag=1"
	}
	// #5579: forward the ingress-interface selector so the gRPC test-policy bridge
	// scopes the host-inbound classifier to one interface's effective view. An
	// interface ref (e.g. ge-0/0/0.0) never contains a comma or equals, so it
	// round-trips through the delimiter-based topic; the server validates it.
	if sel.IngressInterface != "" {
		topic += ",iif=" + sel.IngressInterface
	}
	return c.showText(topic)
}

func (c *ctl) testRouting(args []string) error {
	var dest, instance string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "destination":
			if i+1 < len(args) {
				i++
				dest = args[i]
			}
		case "instance":
			if i+1 < len(args) {
				i++
				instance = args[i]
			}
		}
	}

	if dest == "" {
		fmt.Println("usage: test routing destination <ip-or-prefix> [instance <name>]")
		return nil
	}

	topic := "test-routing:dest=" + dest
	if instance != "" {
		topic += ",instance=" + instance
	}
	return c.showText(topic)
}

func (c *ctl) testSecurityZone(args []string) error {
	var ifName string
	for i := 0; i < len(args); i++ {
		if args[i] == "interface" && i+1 < len(args) {
			i++
			ifName = args[i]
		}
	}

	if ifName == "" {
		fmt.Println("usage: test security-zone interface <name>")
		return nil
	}

	return c.showText("test-zone:interface=" + ifName)
}
