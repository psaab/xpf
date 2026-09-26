package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/logging"
)

// traceLogDir is the directory flow-trace files are written to. It is a
// dedicated, root-owned (0700) namespace UNDER /var/log rather than /var/log
// itself (#5038): confining traces to a private directory means an
// operator-supplied trace filename can never resolve onto — or rotate/rename —
// an unrelated privileged system-log inode such as /var/log/auth.log, and the
// 0700 ownership stops a non-root user from pre-planting a symlink/inode the
// root daemon would then open. It is a package var (not a const) only so tests
// can redirect it to a temp dir.
var traceLogDir = "/var/log/xpf-flow-trace"

// sanitizeTraceFilename validates an operator-supplied flow-trace filename.
// The trace file always lives directly under traceLogDir, so only a bare
// basename is accepted: path separators, "." / "..", and absolute paths are
// rejected. Without this a "monitor security flow file ../../etc/x" command
// resolves to traceLogDir/../../etc/x and the daemon appends root-written flow
// telemetry outside the trace directory (#3378 HC-01). Combined with the
// dedicated-directory confinement (#5038) a name can neither traverse out nor
// collide with a system-log inode.
func sanitizeTraceFilename(name string) error {
	if name == "" {
		return fmt.Errorf("trace filename must not be empty")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid trace filename: %q", name)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("trace filename must be a bare name, not a path: %q", name)
	}
	if name != filepath.Base(name) {
		return fmt.Errorf("trace filename must be a bare name, not a path: %q", name)
	}
	return nil
}

// openTraceFile opens the flow-trace file inside traceLogDir with restrictive
// permissions. The dedicated 0700 trace directory is created first, the name is
// sanitized (basename only), the file is opened O_NOFOLLOW so a pre-planted
// symlink under the trace dir cannot redirect the root-written telemetry (#3378
// MC-02), the opened descriptor is verified to be a regular file, and it is
// created mode 0600 rather than world-readable 0644 — flow tuples/zones/policy
// names are audit-grade telemetry (#3378 MC-01). The file-backed monitor verbs
// are additionally gated at PermControl (pkg/cli/permissions.go, #5038) so a
// view-only class cannot trigger this root-privileged write at all.
func openTraceFile(name string) (*os.File, string, error) {
	if err := sanitizeTraceFilename(name); err != nil {
		return nil, "", err
	}
	// Ensure the dedicated, root-owned (0700) trace directory exists before
	// opening into it (#5038). Confining traces to this private namespace — not
	// the shared /var/log — is what prevents a trace filename from ever landing
	// on an unrelated system-log inode, and 0700 keeps non-root users from
	// planting anything the root daemon would open here.
	//
	// #8482: Lstat FIRST, because MkdirAll stats THROUGH a symlink. If
	// traceLogDir is a pre-existing symlink to a directory, MkdirAll succeeds
	// and returns nil — and the O_NOFOLLOW open below then applies to
	// <target>/<name>, a real file at the redirected location rather than a
	// symlink, so it passes too. The file hardening is intact and the parent is
	// what moved. Six prior reviews marked this confinement VERIFIED SAFE and
	// each of them checked the file.
	//
	// Severity, stated so it is not re-filed higher: this is defence in depth,
	// NOT a live escape. Planting that symlink needs write access to /var/log,
	// which is 0755 and root-owned, so the trigger and the write are two
	// different capabilities held by two different parties. What it buys is
	// converting "someone already had write access to /var/log" from a full
	// trace-redirection primitive into a failed open.
	//
	// A DANGLING symlink already failed here (MkdirAll: file exists), so the
	// case this closes is specifically a symlink to an existing directory.
	if fi, err := os.Lstat(traceLogDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, "", fmt.Errorf("trace dir %s is a symlink; refusing to "+
				"write root-owned flow telemetry through it (#8482)", traceLogDir)
		}
		if !fi.IsDir() {
			return nil, "", fmt.Errorf("trace dir %s exists and is not a directory "+
				"(mode %v); refusing to write flow telemetry (#8482)",
				traceLogDir, fi.Mode())
		}
	} else if !os.IsNotExist(err) {
		// Fail closed on any error that is not "absent" — an EACCES or a
		// dangling-link EIO here means we cannot establish what the path is,
		// and MkdirAll would be deciding that for us.
		return nil, "", fmt.Errorf("stat trace dir %s: %w", traceLogDir, err)
	}
	if err := os.MkdirAll(traceLogDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create trace dir %s: %w", traceLogDir, err)
	}
	path := filepath.Join(traceLogDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, path, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, path, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, path, fmt.Errorf("trace target %s is not a regular file", path)
	}
	return f, path, nil
}

// rotateTraceFile closes the current trace file and rolls the generations:
// the oldest archive (name.maxFiles-1) is dropped, name.N shifts to name.N+1,
// the active file becomes name.1, and a fresh active file is opened. maxFiles
// is the total number of generations to keep (active + archives) and is
// clamped to a 2 minimum. It honors the operator's `files` cap so a long
// running trace cannot grow without bound (#3379).
func rotateTraceFile(cur *os.File, name string, maxFiles int) (*os.File, error) {
	// Best-effort close of the old descriptor. A Close error does not gate the
	// cap (the file's bytes are already on disk), so it must not abort the
	// rotation — the rename/remove below are what enforce maxFiles.
	_ = cur.Close()
	if maxFiles < 2 {
		maxFiles = 2
	}
	base := filepath.Join(traceLogDir, name)
	// Drop the oldest archive so the generation count stays within maxFiles. A
	// missing oldest archive is expected (fewer than maxFiles generations have
	// accumulated yet) and is fine; any other Remove failure means the count
	// cap is no longer enforced, so fail closed instead of letting writeLine
	// reset `written` and keep growing on a broken cap (#3379 follow-up).
	if err := os.Remove(fmt.Sprintf("%s.%d", base, maxFiles-1)); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("trace rotate: dropping oldest archive: %w", err)
	}
	// Shift the surviving archives up by one. A missing intermediate
	// generation is expected early in a trace, so skip it, but surface any
	// other failure rather than silently breaking the generation chain.
	for i := maxFiles - 2; i >= 1; i-- {
		if err := os.Rename(fmt.Sprintf("%s.%d", base, i), fmt.Sprintf("%s.%d", base, i+1)); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("trace rotate: shifting archive %d->%d: %w", i, i+1, err)
		}
	}
	// Roll the active file to .1. The active file always exists (we just wrote
	// to it), so a failure here means the size cap did not actually rotate the
	// file; returning the error makes writeLine stop the writer instead of
	// reopening and resetting `written` on top of an un-rotated, over-cap file.
	if err := os.Rename(base, base+".1"); err != nil {
		return nil, fmt.Errorf("trace rotate: rolling active file: %w", err)
	}
	// #9057: ONE directory fsync covering the whole shift — the renames are
	// atomic but the ENTRIES are not durable until the directory is synced.
	// Surfaced rather than swallowed, matching this function's own policy:
	// every other rotation failure here returns, because a caller that keeps
	// writing on top of an un-rotated file is the failure this rotate exists
	// to prevent.
	if err := fsatomic.SyncDir(filepath.Dir(base)); err != nil {
		return nil, fmt.Errorf("trace rotate: syncing the directory after the "+
			"generation shift: %w", err)
	}
	f, _, err := openTraceFile(name)
	return f, err
}

// traceWriter wraps the active flow-trace file and enforces size/count based
// rotation (#3379). A zero maxSize disables rotation (unbounded, the pre-3379
// behavior only when the operator configured no `size`).
type traceWriter struct {
	name     string
	maxSize  int64
	maxFiles int
	f        *os.File
	written  int64
}

func newTraceWriter(name string, f *os.File, maxSize int64, maxFiles int) *traceWriter {
	w := &traceWriter{name: name, maxSize: maxSize, maxFiles: maxFiles, f: f}
	if fi, err := f.Stat(); err == nil {
		w.written = fi.Size()
	}
	return w
}

// writeLine appends one trace line, rotating first if appending it would push
// the active file past maxSize. The byte budget includes the trailing newline.
func (w *traceWriter) writeLine(line string) error {
	if w.maxSize > 0 && w.written > 0 && w.written+int64(len(line))+1 > w.maxSize {
		nf, err := rotateTraceFile(w.f, w.name, w.maxFiles)
		if err != nil {
			return err
		}
		w.f = nf
		w.written = 0
	}
	n, err := fmt.Fprintln(w.f, line)
	w.written += int64(n)
	return err
}

func (w *traceWriter) close() error { return w.f.Close() }

// monitorFlowFilter holds the criteria for a single named flow filter.
type monitorFlowFilter struct {
	Name     string
	SrcIP    *net.IPNet // source prefix
	DstIP    *net.IPNet // destination prefix
	SrcPort  uint16
	DstPort  uint16
	Protocol string // "tcp", "udp", "icmp", etc. or numeric
	Iface    string // interface name
}

// matches returns true if the event record matches this filter.
// An empty filter (no criteria) matches everything.
func (f *monitorFlowFilter) matches(rec *logging.EventRecord) bool {
	if f.SrcIP != nil {
		srcIP := extractIP(rec.SrcAddr)
		if srcIP == nil || !f.SrcIP.Contains(srcIP) {
			return false
		}
	}
	if f.DstIP != nil {
		dstIP := extractIP(rec.DstAddr)
		if dstIP == nil || !f.DstIP.Contains(dstIP) {
			return false
		}
	}
	if f.SrcPort != 0 {
		port := extractPort(rec.SrcAddr)
		if port != f.SrcPort {
			return false
		}
	}
	if f.DstPort != 0 {
		port := extractPort(rec.DstAddr)
		if port != f.DstPort {
			return false
		}
	}
	if f.Protocol != "" {
		if !strings.EqualFold(rec.Protocol, f.Protocol) {
			return false
		}
	}
	if f.Iface != "" {
		if rec.IngressIface != f.Iface {
			return false
		}
	}
	return true
}

// monitorFlowState holds the daemon-side state for "monitor security flow".
type monitorFlowState struct {
	mu       sync.Mutex
	filename string         // trace file name (base name, written to /var/log/)
	fileSize int64          // max file size in bytes
	files    int            // max number of trace files
	match    string         // regex for line filtering (raw pattern, as typed)
	matchRe  *regexp.Regexp // compiled form of match; nil when match is empty
	filters  map[string]*monitorFlowFilter
	active   bool
	cancel   context.CancelFunc // cancel the active monitor goroutine
	sub      *logging.Subscription
	dropped  uint64 // total event-buffer records lost by the current/last trace
	// lastErr records the reason the writer goroutine last stopped on its
	// own (disk-full / permission / rotation failure). It is surfaced by
	// showMonitorSecurityFlow so the operator sees WHY tracing stopped
	// instead of silently reading Inactive, and it is cleared on each fresh
	// start (#4883-B).
	lastErr error
}

func newMonitorFlowState() *monitorFlowState {
	return &monitorFlowState{
		filters: make(map[string]*monitorFlowFilter),
	}
}

// extractIP parses the IP from "addr:port" or bare IP strings.
func extractIP(addrPort string) net.IP {
	// Try host:port first
	host, _, err := net.SplitHostPort(addrPort)
	if err != nil {
		// Might be bare IP (e.g., ICMP)
		host = addrPort
	}
	return net.ParseIP(host)
}

// extractPort parses the port number from "addr:port" strings.
func extractPort(addrPort string) uint16 {
	_, portStr, err := net.SplitHostPort(addrPort)
	if err != nil {
		return 0
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

// traceLineMatches reports whether a formatted trace line should be written
// given the optional compiled match regex (#2288). A nil regex (no `match`
// configured) admits every line; otherwise the line must match the pattern.
func traceLineMatches(line string, re *regexp.Regexp) bool {
	return re == nil || re.MatchString(line)
}

// formatFlowEvent formats an EventRecord into Junos-style flow trace output.
func formatFlowEvent(rec logging.EventRecord) string {
	ts := rec.Time.Format("15:04:05.000000")
	return fmt.Sprintf("%s %s %s->%s %s %s/%s %s policy=%s",
		ts,
		rec.InZoneName+"/"+rec.OutZoneName,
		rec.SrcAddr, rec.DstAddr,
		rec.Protocol,
		rec.InZoneName, rec.OutZoneName,
		rec.Action,
		rec.PolicyName)
}

// formatPacketDropEvent formats an EventRecord into Junos-style packet-drop output.
func formatPacketDropEvent(rec logging.EventRecord) string {
	ts := rec.Time.Format("15:04:05.000000")
	reason := rec.Action
	if rec.ScreenCheck != "" {
		reason = "Dropped by SCREEN:" + rec.ScreenCheck
	} else if rec.Type == "POLICY_DENY" {
		reason = "Dropped by FLOW:Policy deny"
		if rec.PolicyName != "" {
			reason = "Dropped by FLOW:Policy " + rec.PolicyName
		}
	}
	return fmt.Sprintf("%s %s-->%s;%s,%s,%s",
		ts,
		rec.SrcAddr, rec.DstAddr,
		strings.ToLower(rec.Protocol),
		rec.IngressIface,
		reason)
}

// handleMonitorSecurity dispatches monitor security sub-commands.
func (c *CLI) handleMonitorSecurity(args []string) error {
	secTree := operationalTree["monitor"].Children["security"].Children
	if len(args) == 0 {
		fmt.Println("monitor security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(secTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(secTree))
	if err != nil {
		return err
	}

	switch resolved {
	case "flow":
		return c.handleMonitorSecurityFlow(args[1:])
	case "packet-drop":
		return c.handleMonitorSecurityPacketDrop(args[1:])
	default:
		return fmt.Errorf("unknown monitor security target: %s", resolved)
	}
}

// handleMonitorSecurityFlow dispatches flow sub-commands.
func (c *CLI) handleMonitorSecurityFlow(args []string) error {
	flowTree := operationalTree["monitor"].Children["security"].Children["flow"].Children
	if len(args) == 0 {
		fmt.Println("monitor security flow:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(flowTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(flowTree))
	if err != nil {
		return err
	}

	switch resolved {
	case "file":
		return c.handleMonitorSecurityFlowFile(args[1:])
	case "filter":
		return c.handleMonitorSecurityFlowFilter(args[1:])
	case "start":
		return c.handleMonitorSecurityFlowStart()
	case "stop":
		return c.handleMonitorSecurityFlowStop()
	default:
		return fmt.Errorf("unknown monitor security flow target: %s", resolved)
	}
}

// handleMonitorSecurityFlowFile configures the flow trace file.
func (c *CLI) handleMonitorSecurityFlowFile(args []string) error {
	if c.monitorFlow == nil {
		c.monitorFlow = newMonitorFlowState()
	}
	c.monitorFlow.mu.Lock()
	defer c.monitorFlow.mu.Unlock()

	if c.monitorFlow.active {
		fmt.Println("error: stop the active flow monitor before changing the trace file.")
		return nil
	}

	if len(args) == 0 {
		fmt.Println("error: Please specify the trace filename.")
		return nil
	}

	// Parse every token into locals and commit atomically only after all of
	// them validate (#3380 HC-04/MC-07/MC-08). Previously the filename and
	// each option were written into the shared state as they were parsed, so a
	// later failing option (a bad regex, an out-of-range size) left a
	// half-applied config — including a possibly-traversal filename — behind,
	// and unknown tokens / value-less options were silently dropped.
	if err := sanitizeTraceFilename(args[0]); err != nil {
		fmt.Printf("error: %v\n", err)
		return nil
	}
	filename := args[0]
	// Seed from current state so existing size/files/match survive a command
	// that only changes one option.
	fileSize := c.monitorFlow.fileSize
	files := c.monitorFlow.files
	matchPat := c.monitorFlow.match
	matchRe := c.monitorFlow.matchRe

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "size":
			if i+1 >= len(args) {
				fmt.Println("error: size requires a value")
				return nil
			}
			i++
			v, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || v < 10240 || v > 1073741824 {
				fmt.Println("error: size must be 10240..1073741824")
				return nil
			}
			fileSize = v
		case "files":
			if i+1 >= len(args) {
				fmt.Println("error: files requires a value")
				return nil
			}
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 2 || v > 1000 {
				fmt.Println("error: files must be 2..1000")
				return nil
			}
			files = v
		case "match":
			if i+1 >= len(args) {
				fmt.Println("error: match requires a value")
				return nil
			}
			i++
			re, err := regexp.Compile(args[i])
			if err != nil {
				fmt.Printf("error: invalid match regex %q: %v\n", args[i], err)
				return nil
			}
			matchPat = args[i]
			matchRe = re
		default:
			fmt.Printf("error: unknown flow file option: %s\n", args[i])
			return nil
		}
	}

	// All tokens validated: commit.
	c.monitorFlow.filename = filename
	c.monitorFlow.fileSize = fileSize
	c.monitorFlow.files = files
	c.monitorFlow.match = matchPat
	c.monitorFlow.matchRe = matchRe
	return nil
}

// handleMonitorSecurityFlowFilter configures a named flow filter.
func (c *CLI) handleMonitorSecurityFlowFilter(args []string) error {
	if c.monitorFlow == nil {
		c.monitorFlow = newMonitorFlowState()
	}
	c.monitorFlow.mu.Lock()
	defer c.monitorFlow.mu.Unlock()

	if c.monitorFlow.active {
		fmt.Println("error: stop the active flow monitor before editing filters.")
		return nil
	}

	if len(args) == 0 {
		fmt.Println("error: Please specify the filter name.")
		return nil
	}

	// Build into a temporary filter (seeded from the existing one if present)
	// and commit it into the map only after every token validates (#3380
	// HC-03/MC-07/MC-08). Previously the named filter was inserted before any
	// value was parsed, so a command that then failed left an empty filter in
	// the map — and an empty filter matches every event, silently arming broad
	// tracing of all flows. Unknown tokens and value-less options were also
	// dropped, widening collection instead of erroring.
	name := args[0]
	f := &monitorFlowFilter{Name: name}
	if existing, ok := c.monitorFlow.filters[name]; ok {
		fc := *existing
		f = &fc
	}

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "source-prefix":
			if i+1 >= len(args) {
				fmt.Println("error: source-prefix requires a value")
				return nil
			}
			i++
			_, cidr, err := net.ParseCIDR(args[i])
			if err != nil {
				// Try as host address
				ip := net.ParseIP(args[i])
				if ip == nil {
					fmt.Printf("error: invalid source-prefix: %s\n", args[i])
					return nil
				}
				if ip.To4() != nil {
					cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			}
			f.SrcIP = cidr
		case "destination-prefix":
			if i+1 >= len(args) {
				fmt.Println("error: destination-prefix requires a value")
				return nil
			}
			i++
			_, cidr, err := net.ParseCIDR(args[i])
			if err != nil {
				ip := net.ParseIP(args[i])
				if ip == nil {
					fmt.Printf("error: invalid destination-prefix: %s\n", args[i])
					return nil
				}
				if ip.To4() != nil {
					cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			}
			f.DstIP = cidr
		case "source-port":
			if i+1 >= len(args) {
				fmt.Println("error: source-port requires a value")
				return nil
			}
			i++
			p, err := strconv.ParseUint(args[i], 10, 16)
			if err != nil {
				fmt.Printf("error: invalid source-port: %s\n", args[i])
				return nil
			}
			f.SrcPort = uint16(p)
		case "destination-port":
			if i+1 >= len(args) {
				fmt.Println("error: destination-port requires a value")
				return nil
			}
			i++
			p, err := strconv.ParseUint(args[i], 10, 16)
			if err != nil {
				fmt.Printf("error: invalid destination-port: %s\n", args[i])
				return nil
			}
			f.DstPort = uint16(p)
		case "protocol":
			if i+1 >= len(args) {
				fmt.Println("error: protocol requires a value")
				return nil
			}
			i++
			f.Protocol = args[i]
		case "interface":
			if i+1 >= len(args) {
				fmt.Println("error: interface requires a value")
				return nil
			}
			i++
			f.Iface = args[i]
		default:
			fmt.Printf("error: unknown flow filter option: %s\n", args[i])
			return nil
		}
	}

	// Reject a filter with no match criteria: an empty filter matches every
	// event, so silently installing one would fail open into broad tracing of
	// all flows (#3380 HC-03).
	if f.SrcIP == nil && f.DstIP == nil && f.SrcPort == 0 && f.DstPort == 0 &&
		f.Protocol == "" && f.Iface == "" {
		fmt.Println("error: filter requires at least one match criterion.")
		return nil
	}

	// All tokens validated: commit the filter atomically.
	c.monitorFlow.filters[name] = f
	return nil
}

// handleMonitorSecurityFlowStart starts flow tracing.
func (c *CLI) handleMonitorSecurityFlowStart() error {
	// Guard a nil event buffer (#3381). A CLI constructed daemonless /
	// remote (eventBuf == nil) must not panic in Subscribe below; mirror
	// the graceful diagnostic that showSecurityLog and the gRPC/SSE
	// surfaces already return.
	if c.eventBuf == nil {
		fmt.Println("error: event buffer not initialized")
		return nil
	}
	if c.monitorFlow == nil {
		c.monitorFlow = newMonitorFlowState()
	}
	c.monitorFlow.mu.Lock()

	if c.monitorFlow.filename == "" {
		c.monitorFlow.mu.Unlock()
		fmt.Println("error: Please specify the monitor flow trace file.")
		return nil
	}
	if len(c.monitorFlow.filters) == 0 {
		c.monitorFlow.mu.Unlock()
		fmt.Println("error: Please specify monitor security flow filter.")
		return nil
	}
	if c.monitorFlow.active {
		c.monitorFlow.mu.Unlock()
		fmt.Println("error: Flow monitor is already active. Stop it first.")
		return nil
	}

	c.monitorFlow.active = true
	c.monitorFlow.dropped = 0
	// Clear any error recorded by a previous writer-goroutine stop so a
	// fresh start does not surface a stale failure reason (#4883-B).
	c.monitorFlow.lastErr = nil

	// Snapshot the current filters.
	filters := make([]*monitorFlowFilter, 0, len(c.monitorFlow.filters))
	for _, f := range c.monitorFlow.filters {
		fc := *f
		filters = append(filters, &fc)
	}

	// Snapshot the optional match regex (compiled at parse time). Applied
	// as a post-format line filter so the advertised `file <name> match
	// <regex>` filter actually drops non-matching trace lines (#2288).
	matchRe := c.monitorFlow.matchRe

	// Snapshot the rotation limits for the writer (#3379).
	traceName := c.monitorFlow.filename
	maxSize := c.monitorFlow.fileSize
	maxFiles := c.monitorFlow.files

	// Open trace file inside /var/log with a sanitized basename, O_NOFOLLOW,
	// regular-file verification and mode 0600 (#3378).
	logFile, _, err := openTraceFile(c.monitorFlow.filename)
	if err != nil {
		c.monitorFlow.active = false
		c.monitorFlow.mu.Unlock()
		return fmt.Errorf("failed to open trace file: %w", err)
	}

	// Subscribe to event buffer.
	sub := c.eventBuf.Subscribe(256)
	c.monitorFlow.sub = sub

	ctx, cancel := context.WithCancel(context.Background())
	c.monitorFlow.cancel = cancel
	c.monitorFlow.mu.Unlock()

	// Run the monitor goroutine in the background. The writer enforces the
	// configured size/files rotation so the trace cannot grow unbounded under
	// a deny storm or a broad filter (#3379).
	writer := newTraceWriter(traceName, logFile, maxSize, maxFiles)
	go func() {
		defer writer.close()
		var gaps logging.EventGapTracker
		writerFailed := false
		recordWriterError := func(err error) {
			writerFailed = true
			// Rotation or write failed; stop tracing rather than grow the
			// active file without bound. Clear the monitor state under the
			// lock so show stops reporting Active and a fresh start is accepted.
			// Guard on the subscription identity so a concurrent stop/start is
			// not clobbered (#4883-B).
			c.monitorFlow.mu.Lock()
			if c.monitorFlow.sub == sub {
				c.monitorFlow.active = false
				c.monitorFlow.cancel = nil
				c.monitorFlow.sub = nil
				c.monitorFlow.lastErr = err
			}
			c.monitorFlow.mu.Unlock()
		}
		defer func() {
			// Unsubscribe before taking the final count so no producer can add
			// another drop between the snapshot and close.
			sub.Close()
			if lost := gaps.Finish(sub); lost > 0 && !writerFailed {
				if err := writer.writeLine(logging.OverrunLine(lost)); err != nil {
					recordWriterError(err)
				}
			}
			c.monitorFlow.mu.Lock()
			if c.monitorFlow.sub == sub || c.monitorFlow.sub == nil {
				c.monitorFlow.dropped = sub.Dropped()
			}
			c.monitorFlow.mu.Unlock()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case rec := <-sub.C:
				// Record loss before any filters: dropped records may belong to
				// another event type or not match this trace's criteria.
				if lost, gap := gaps.Observe(sub, rec); gap {
					if err := writer.writeLine(logging.OverrunLine(lost)); err != nil {
						recordWriterError(err)
						return
					}
				}
				// Check if any filter matches.
				matched := false
				for _, f := range filters {
					if f.matches(&rec) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
				line := formatFlowEvent(rec)
				if !traceLineMatches(line, matchRe) {
					continue
				}
				if err := writer.writeLine(line); err != nil {
					recordWriterError(err)
					return
				}
			}
		}
	}()

	// Silent success per Junos behavior.
	return nil
}

// handleMonitorSecurityFlowStop stops flow tracing.
func (c *CLI) handleMonitorSecurityFlowStop() error {
	if c.monitorFlow == nil {
		return nil
	}
	c.monitorFlow.mu.Lock()
	defer c.monitorFlow.mu.Unlock()

	if c.monitorFlow.cancel != nil {
		c.monitorFlow.cancel()
		c.monitorFlow.cancel = nil
	}
	if c.monitorFlow.sub != nil {
		c.monitorFlow.dropped = c.monitorFlow.sub.Dropped()
	}
	c.monitorFlow.sub = nil
	c.monitorFlow.active = false
	// Silent success per Junos behavior.
	return nil
}

// showMonitorSecurityFlow displays the current monitor security flow status.
func (c *CLI) showMonitorSecurityFlow() error {
	if c.monitorFlow == nil {
		c.monitorFlow = newMonitorFlowState()
	}
	c.monitorFlow.mu.Lock()
	defer c.monitorFlow.mu.Unlock()

	status := "Inactive"
	if c.monitorFlow.active {
		status = "Active"
	}

	fmt.Printf("  Monitor security flow session status: %s\n", status)
	// Surface why the writer goroutine stopped on its own (disk-full /
	// permission / rotation) so a silently-stopped trace is visible rather
	// than reading Inactive with no explanation (#4883-B).
	if !c.monitorFlow.active && c.monitorFlow.lastErr != nil {
		fmt.Printf("  Monitor security flow last error: %v\n", c.monitorFlow.lastErr)
	}
	if c.monitorFlow.filename != "" {
		fmt.Printf("  Monitor security flow trace file: %s\n", filepath.Join(traceLogDir, c.monitorFlow.filename))
	} else {
		fmt.Printf("  Monitor security flow trace file: (not configured)\n")
	}
	if c.monitorFlow.match != "" {
		fmt.Printf("  Monitor security flow match: %s\n", c.monitorFlow.match)
	}
	fmt.Printf("  Monitor security flow filters: %d\n", len(c.monitorFlow.filters))
	dropped := c.monitorFlow.dropped
	if c.monitorFlow.sub != nil {
		dropped = c.monitorFlow.sub.Dropped()
	}
	fmt.Printf("  Monitor security flow records dropped: %d\n", dropped)

	// Sort filter names for deterministic output.
	names := make([]string, 0, len(c.monitorFlow.filters))
	for name := range c.monitorFlow.filters {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		f := c.monitorFlow.filters[name]
		filterStatus := "Inactive"
		if c.monitorFlow.active {
			filterStatus = "Active"
		}
		fmt.Printf("\n  Filter: %s\n", f.Name)
		fmt.Printf("    Status: %s\n", filterStatus)

		src := "any"
		if f.SrcIP != nil {
			src = f.SrcIP.String()
		}
		if f.SrcPort != 0 {
			src += fmt.Sprintf(" port %d", f.SrcPort)
		}
		fmt.Printf("    Source: %s\n", src)

		dst := "any"
		if f.DstIP != nil {
			dst = f.DstIP.String()
		}
		if f.DstPort != 0 {
			dst += fmt.Sprintf(" port %d", f.DstPort)
		}
		fmt.Printf("    Destination: %s\n", dst)

		if f.Protocol != "" {
			fmt.Printf("    Protocol: %s\n", f.Protocol)
		}
		if f.Iface != "" {
			fmt.Printf("    Interface: %s\n", f.Iface)
		}
	}

	return nil
}

// handleMonitorSecurityPacketDrop streams packet drop events to stdout.
func (c *CLI) handleMonitorSecurityPacketDrop(args []string) error {
	// Guard a nil event buffer (#3381) before Subscribe, mirroring
	// showSecurityLog and the gRPC/SSE surfaces.
	if c.eventBuf == nil {
		fmt.Println("error: event buffer not initialized")
		return nil
	}

	// Parse optional filters.
	var (
		srcIP    *net.IPNet
		dstIP    *net.IPNet
		srcPort  uint16
		dstPort  uint16
		protocol string
		fromZone string
		iface    string
		count    int
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "source-prefix":
			if i+1 >= len(args) {
				fmt.Println("error: source-prefix requires a value")
				return nil
			}
			i++
			_, cidr, err := net.ParseCIDR(args[i])
			if err != nil {
				ip := net.ParseIP(args[i])
				if ip == nil {
					fmt.Printf("error: invalid source-prefix: %s\n", args[i])
					return nil
				}
				if ip.To4() != nil {
					cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			}
			srcIP = cidr
		case "destination-prefix":
			if i+1 >= len(args) {
				fmt.Println("error: destination-prefix requires a value")
				return nil
			}
			i++
			_, cidr, err := net.ParseCIDR(args[i])
			if err != nil {
				ip := net.ParseIP(args[i])
				if ip == nil {
					fmt.Printf("error: invalid destination-prefix: %s\n", args[i])
					return nil
				}
				if ip.To4() != nil {
					cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			}
			dstIP = cidr
		case "source-port":
			if i+1 >= len(args) {
				fmt.Println("error: source-port requires a value")
				return nil
			}
			i++
			p, err := strconv.ParseUint(args[i], 10, 16)
			if err != nil {
				fmt.Printf("error: invalid source-port: %s\n", args[i])
				return nil
			}
			srcPort = uint16(p)
		case "destination-port":
			if i+1 >= len(args) {
				fmt.Println("error: destination-port requires a value")
				return nil
			}
			i++
			p, err := strconv.ParseUint(args[i], 10, 16)
			if err != nil {
				fmt.Printf("error: invalid destination-port: %s\n", args[i])
				return nil
			}
			dstPort = uint16(p)
		case "protocol":
			if i+1 >= len(args) {
				fmt.Println("error: protocol requires a value")
				return nil
			}
			i++
			protocol = args[i]
		case "from-zone":
			if i+1 >= len(args) {
				fmt.Println("error: from-zone requires a value")
				return nil
			}
			i++
			fromZone = args[i]
		case "interface":
			if i+1 >= len(args) {
				fmt.Println("error: interface requires a value")
				return nil
			}
			i++
			iface = args[i]
		case "count":
			if i+1 >= len(args) {
				fmt.Println("error: count requires a value")
				return nil
			}
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 || v > 8192 {
				fmt.Println("error: count must be 1..8192")
				return nil
			}
			count = v
		default:
			fmt.Printf("error: unknown packet-drop option: %s\n", args[i])
			return nil
		}
	}

	fmt.Println("Starting packet drop:")

	// Subscribe to event buffer.
	sub := c.eventBuf.Subscribe(256)
	var gaps logging.EventGapTracker
	defer func() {
		sub.Close()
		if lost := gaps.Finish(sub); lost > 0 {
			fmt.Println(logging.OverrunLine(lost))
		}
		if dropped := sub.Dropped(); dropped > 0 {
			fmt.Printf("dropped=%d\n", dropped)
		}
	}()

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

	seen := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Println() // newline after ^C
			return nil
		case rec := <-sub.C:
			if lost, gap := gaps.Observe(sub, rec); gap {
				fmt.Println(logging.OverrunLine(lost))
			}
			// Only show drops (POLICY_DENY and SCREEN_DROP).
			if rec.Type != "POLICY_DENY" && rec.Type != "SCREEN_DROP" {
				continue
			}

			// Apply filters.
			if srcIP != nil {
				ip := extractIP(rec.SrcAddr)
				if ip == nil || !srcIP.Contains(ip) {
					continue
				}
			}
			if dstIP != nil {
				ip := extractIP(rec.DstAddr)
				if ip == nil || !dstIP.Contains(ip) {
					continue
				}
			}
			if srcPort != 0 && extractPort(rec.SrcAddr) != srcPort {
				continue
			}
			if dstPort != 0 && extractPort(rec.DstAddr) != dstPort {
				continue
			}
			if protocol != "" && !strings.EqualFold(rec.Protocol, protocol) {
				continue
			}
			if fromZone != "" && rec.InZoneName != fromZone {
				continue
			}
			if iface != "" && rec.IngressIface != iface {
				continue
			}

			fmt.Println(formatPacketDropEvent(rec))

			seen++
			if count > 0 && seen >= count {
				return nil
			}
		}
	}
}
