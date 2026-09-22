package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

// requireClearNoScope rejects any trailing operand on a GLOBAL-ONLY clear
// command — one whose backend action can ONLY clear everything and has no
// scoped variant. Such handlers historically recognized a fixed keyword prefix
// and silently DISCARDED the remaining tokens, then issued the unscoped
// mutation, so an operator who typed a scope (e.g. `clear arp 192.0.2.10`) got
// a success message while the ENTIRE cache/table/counter set was wiped (#5811).
// Require exact arity instead: return an error naming the stray tokens and
// stating the command takes no scope, BEFORE any mutation runs. cmd is the full
// command path shown in the message; clears names what it unconditionally
// clears. The wording is kept byte-identical to cmd/cli's copy so both CLIs
// reject the same input the same way.
func requireClearNoScope(cmd, clears string, extra []string) error {
	if len(extra) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected argument(s) %v after %q; this command clears %s "+
		"and takes no scope (per-scope clear is not supported)", extra, cmd, clears)
}

func (c *CLI) handleClear(args []string) error {
	clearTree := operationalTree["clear"].Children
	showHelp := func() {
		fmt.Println("clear:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(clearTree))
	}
	if len(args) < 1 {
		showHelp()
		return nil
	}

	switch args[0] {
	case "arp":
		return c.handleClearArp(args[1:])
	case "ipv6":
		return c.handleClearIPv6(args[1:])
	case "security":
		return c.handleClearSecurity(args[1:])
	case "firewall":
		return c.handleClearFirewall(args[1:])
	case "dhcp":
		return c.handleClearDHCP(args[1:])
	case "interfaces":
		return c.handleClearInterfaces(args[1:])
	case "system":
		return c.handleClearSystem(args[1:])
	default:
		showHelp()
		return nil
	}
}

func (c *CLI) handleClearSystem(args []string) error {
	if len(args) < 1 || args[0] != "config-lock" {
		cmdtree.PrintTreeHelp("clear system:", operationalTree, "clear", "system")
		return nil
	}
	if err := requireClearNoScope("clear system config-lock", "the configuration lock", args[1:]); err != nil {
		return err
	}
	holder, locked := c.store.ConfigHolder()
	if !locked {
		fmt.Println("No configuration lock held")
		return nil
	}
	c.store.ForceExitConfigure()
	fmt.Printf("Configuration lock cleared (was held by %s)\n", holder)
	return nil
}

func (c *CLI) handleClearInterfaces(args []string) error {
	if len(args) >= 1 && args[0] == "statistics" {
		if err := requireClearNoScope("clear interfaces statistics", "all interface statistics", args[1:]); err != nil {
			return err
		}
		fmt.Println("Interface statistics counters noted")
		fmt.Println("(kernel counters are cumulative and cannot be reset)")
		return nil
	}
	cmdtree.PrintTreeHelp("clear interfaces:", operationalTree, "clear", "interfaces")
	return nil
}

func (c *CLI) handleClearArp(args []string) error {
	if err := requireClearNoScope("clear arp", "the ARP cache", args); err != nil {
		return err
	}
	out, err := exec.Command("ip", "-4", "neigh", "flush", "all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("flush ARP: %s", strings.TrimSpace(string(out)))
	}
	fmt.Println("ARP cache cleared")
	return nil
}

func (c *CLI) handleClearIPv6(args []string) error {
	if len(args) < 1 || args[0] != "neighbors" {
		cmdtree.PrintTreeHelp("clear ipv6:", operationalTree, "clear", "ipv6")
		return nil
	}
	if err := requireClearNoScope("clear ipv6 neighbors", "the IPv6 neighbor cache", args[1:]); err != nil {
		return err
	}
	out, err := exec.Command("ip", "-6", "neigh", "flush", "all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("flush IPv6 neighbors: %s", strings.TrimSpace(string(out)))
	}
	fmt.Println("IPv6 neighbor cache cleared")
	return nil
}

func (c *CLI) handleClearSecurity(args []string) error {
	if len(args) < 1 {
		fmt.Println("clear security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["clear"].Children["security"].Children))
		return nil
	}

	switch args[0] {
	case "nat":
		if len(args) >= 3 && args[1] == "source" && args[2] == "persistent-nat-table" {
			if err := requireClearNoScope("clear security nat source persistent-nat-table",
				"the entire persistent NAT table", args[3:]); err != nil {
				return err
			}
			return c.clearPersistentNAT()
		}
		if len(args) >= 2 && args[1] == "statistics" {
			if err := requireClearNoScope("clear security nat statistics",
				"all NAT translation statistics", args[2:]); err != nil {
				return err
			}
			if c.dp == nil || !c.dp.IsLoaded() {
				fmt.Println("dataplane not loaded")
				return nil
			}
			if err := c.dp.ClearNATRuleCounters(); err != nil {
				return fmt.Errorf("clear NAT counters: %w", err)
			}
			fmt.Println("NAT translation statistics cleared")
			return nil
		}
		cmdtree.PrintTreeHelp("clear security nat:", operationalTree, "clear", "security", "nat")
		return nil
	case "flow":
		if len(args) < 2 || args[1] != "session" {
			return fmt.Errorf("usage: clear security flow session [filters...]")
		}
		if c.dp == nil || !c.dp.IsLoaded() {
			fmt.Println("dataplane not loaded")
			return nil
		}
		// Clear uses the selector-only parser: presentation-only tokens
		// (summary/brief/sort-by) are rejected here, so a pasted
		// show-syntax modifier errors instead of falling through to the
		// destructive clear-all path (#5066).
		f := c.parseClearSessionFilter(args[2:])
		if f.hasFilter() {
			return c.clearFilteredSessions(f)
		}
		v4, v6, err := c.dp.ClearAllSessions()
		if err != nil {
			return fmt.Errorf("clear sessions: %w", err)
		}
		fmt.Printf("%d IPv4 and %d IPv6 session entries cleared\n", v4, v6)
		var agg sessionClearErrors
		agg.add("peer clear", c.clearPeerSessions(nil))
		agg.report()
		return nil

	case "policies":
		if len(args) < 2 || args[1] != "hit-count" {
			return fmt.Errorf("usage: clear security policies hit-count")
		}
		if err := requireClearNoScope("clear security policies hit-count",
			"all policy hit counters", args[2:]); err != nil {
			return err
		}
		if c.dp == nil || !c.dp.IsLoaded() {
			fmt.Println("dataplane not loaded")
			return nil
		}
		if err := c.dp.ClearPolicyCounters(); err != nil {
			return fmt.Errorf("clear policy counters: %w", err)
		}
		fmt.Println("policy hit counters cleared")
		return nil

	case "counters":
		if err := requireClearNoScope("clear security counters", "all counters", args[1:]); err != nil {
			return err
		}
		if c.dp == nil || !c.dp.IsLoaded() {
			fmt.Println("dataplane not loaded")
			return nil
		}
		if err := c.dp.ClearAllCounters(); err != nil {
			return fmt.Errorf("clear counters: %w", err)
		}
		fmt.Println("all counters cleared")
		return nil

	default:
		cmdtree.PrintTreeHelp("clear security:", operationalTree, "clear", "security")
		return nil
	}
}

func (c *CLI) clearFilteredSessions(f sessionFilter) error {
	// Operator-input errors must fail the command: an unresolvable
	// zone or pool name would otherwise leave its predicate inert and
	// silently widen (or void) the clear.
	if err := f.validate(); err != nil {
		return err
	}
	// Interface matching needs the zone/egress interface maps; the
	// show path builds them inline, the clear path must do it too —
	// without this an interface-filtered clear matches nothing.
	f.populateIfaceMaps(c)

	var agg sessionClearErrors
	// #4886 A: bound the working set. The pre-#4886 CLI snapshotted EVERY
	// matching forward key + its reverse and DNAT companions (v4 then v6) into
	// growing slices before deleting, so a broad filtered clear on a
	// multi-million-entry table allocated O(matches) up front and could OOM the
	// in-process daemon before making progress. clearFilteredV4Bounded /
	// clearFilteredV6Bounded collect at most cliClearFilteredBatch keys, delete
	// that chunk, and resume (cursor primary; bounded rescan fallback) — peak
	// O(batch). The filter and the f.validate() above are unchanged, so the exact
	// set is cleared and a typo'd predicate still never widens to clear-all (#3439).
	v4Deleted := clearFilteredV4Bounded(c, &f, &agg)
	v6Deleted := clearFilteredV6Bounded(c, &f, &agg)

	fmt.Printf("%d IPv4 and %d IPv6 matching sessions cleared\n", v4Deleted, v6Deleted)
	agg.add("peer clear", c.clearPeerSessions(&f))
	agg.report()
	return nil
}

// cliClearFilteredBatch bounds the forward-key working set per chunk for the
// filtered CLI session clear (#4886). A test seam shrinks it to exercise the
// multi-chunk path on a small table.
var cliClearFilteredBatch = 1024

// cliClearBatchObserver, when non-nil, is invoked once per collected chunk with
// the forward-key count — a test-only seam proving the working set is bounded.
// A revert to the pre-#4886 snapshot-all path reports a single len==matches
// chunk, so the bounded-batch assertion REDs (#4886).
var cliClearBatchObserver func(chunkLen int)

// cliSessionCursor is the cursor-iteration capability (the CLI mirror of
// grpcapi.sessionCursorIterator, #5454). The production dataplane satisfies it,
// so the CLI runs the O(N)-CPU bounded cursor path; only a cursor-less test fake
// falls back to the bounded fresh-rescan. Using the cursor (not a bare rescan)
// keeps a broad clear on a huge table a single O(N) forward pass rather than
// O(N^2), which would trade the memory DoS for a CPU-stall able to starve the HA
// watchdog (#4719) — the same reason the #5454 gRPC path prefers the cursor.
type cliSessionCursor interface {
	IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

// cliClearBatchV4 accumulates one bounded chunk of matching v4 forward keys plus
// each session's reverse companion (keyed on the TRANSLATED tuple val.ReverseKey,
// #2733) and DNAT companion (#2406), mirroring grpcapi.clearBatchV4 (#5454/#4886).
type cliClearBatchV4 struct {
	fwd  []dataplane.SessionKey
	rev  []dataplane.SessionKey
	dnat []dataplane.DNATKey
}

func (b *cliClearBatchV4) reset() { b.fwd = b.fwd[:0]; b.rev = b.rev[:0]; b.dnat = b.dnat[:0] }

// collect appends a matched forward session's keys and returns true once the
// forward chunk is full. Callers must skip reverse entries (val.IsReverse != 0)
// and non-matching keys BEFORE collect, preserving the pre-#4886 CLI semantics.
func (b *cliClearBatchV4) collect(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	b.fwd = append(b.fwd, key)
	if val.ReverseKey.Protocol != 0 {
		b.rev = append(b.rev, val.ReverseKey)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 && val.Flags&dataplane.SessFlagStaticNAT == 0 {
		b.dnat = append(b.dnat, dataplane.DNATKeyForSessionV4(key, val))
	}
	return len(b.fwd) >= cliClearFilteredBatch
}

// deleteAll deletes this chunk's forward keys plus reverse/DNAT companions.
// It returns deleted (forward keys this call actually removed, for the operator
// "N cleared" tally) and removed (forward keys no longer in the map after this
// call = deleted PLUS already-gone/not-found). removed drives the #5948
// rescan no-progress guard: a fresh rescan only shrinks the match set for the
// forward keys that are gone, so removed==0 on a non-empty chunk means the next
// identical rescan would re-collect the same set. A not-found forward key IS
// progress (it will not reappear), so it counts toward removed but not deleted.
func (b *cliClearBatchV4) deleteAll(c *CLI, agg *sessionClearErrors) (deleted, removed int) {
	for _, key := range b.fwd {
		// addExceptNotFound (not add): the cursor path leaves the chunk anchor
		// live and may re-collect it next round, so a benign already-gone
		// forward key must not read as a failure — matching grpcapi #5454.
		if err := c.dp.DeleteSession(key); err != nil {
			agg.addExceptNotFound("v4 forward delete", err)
			if dataplane.IsKeyNotFound(err) {
				removed++ // already gone: not a delete, but still progress
			}
		} else {
			deleted++
			removed++
		}
	}
	for _, key := range b.rev {
		agg.addExceptNotFound("v4 reverse delete", c.dp.DeleteSession(key))
	}
	for _, dk := range b.dnat {
		agg.addExceptNotFound("v4 DNAT companion delete", c.dp.DeleteDNATEntry(dk))
	}
	return deleted, removed
}

// clearFilteredV4Bounded deletes every matching v4 session (plus companions)
// while holding at most O(cliClearFilteredBatch) keys. Cursor primary
// (IterateSessionsFrom from a live anchor, one O(N) pass, deferred anchor
// delete); bounded fresh-rescan fallback for a cursor-less dataplane (#4886).
func clearFilteredV4Bounded(c *CLI, f *sessionFilter, agg *sessionClearErrors) int {
	iterDP, ok := c.dpProbe().(cliSessionCursor)
	if !ok {
		return clearFilteredV4Rescan(c, f, agg)
	}
	deleted := 0
	var a, b cliClearBatchV4
	cur, prev := &a, &b
	prevValid := false
	var cursor *dataplane.SessionKey
	for {
		cur.reset()
		iterErr := iterDP.IterateSessionsFrom(cursor, func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse != 0 {
				return true
			}
			if !f.matchesV4(key, val) {
				return true
			}
			return !cur.collect(key, val)
		})
		agg.add("v4 iterate", iterErr)
		if cliClearBatchObserver != nil {
			cliClearBatchObserver(len(cur.fwd))
		}
		if prevValid {
			// Cursor path terminates unconditionally (the cursor advances every
			// round regardless of delete success), so the removed count is unused
			// here — only the fresh-rescan fallback needs the no-progress guard.
			d, _ := prev.deleteAll(c, agg)
			deleted += d
			prevValid = false
		}
		full := len(cur.fwd) >= cliClearFilteredBatch && iterErr == nil
		if !full {
			d, _ := cur.deleteAll(c, agg)
			deleted += d
			return deleted
		}
		anchor := cur.fwd[len(cur.fwd)-1]
		cursor = &anchor
		cur, prev = prev, cur
		prevValid = true
	}
}

// clearFilteredV4Rescan is the bounded fallback for a cursor-less dataplane
// (test/edge): collect up to cliClearFilteredBatch keys via a fresh iterate,
// delete them, rescan — a deleted (or already-gone) key does not reappear, so a
// fresh scan returns the next chunk, converging while holding only O(chunk) keys
// (#4886). Progress depends on deletes actually removing keys, so a #5948
// no-progress guard breaks the loop if a non-empty chunk removed nothing (every
// forward delete genuinely failed → the same set would be re-collected forever).
// The production cursor path (clearFilteredV4Bounded) does not need this — its
// cursor advances every round regardless of delete success.
func clearFilteredV4Rescan(c *CLI, f *sessionFilter, agg *sessionClearErrors) int {
	deleted := 0
	var b cliClearBatchV4
	for {
		b.reset()
		iterErr := c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse != 0 {
				return true
			}
			if !f.matchesV4(key, val) {
				return true
			}
			return !b.collect(key, val)
		})
		agg.add("v4 iterate", iterErr)
		if cliClearBatchObserver != nil {
			cliClearBatchObserver(len(b.fwd))
		}
		if len(b.fwd) == 0 {
			return deleted
		}
		d, removed := b.deleteAll(c, agg)
		deleted += d
		// #5948 no-progress guard. Unlike the cursor path, this fallback re-scans
		// from the top each round and relies on the just-processed keys being GONE
		// so the next scan returns a smaller set. If removed==0 — every forward key
		// in this non-empty chunk failed to delete with a GENUINE (non-not-found)
		// error, so all remain in the map — the next identical rescan would
		// re-collect the same set forever. Stop with the aggregated delete errors
		// already recorded rather than loop. A not-found key counts as removed (it
		// will not reappear), so a concurrently-drained chunk still makes progress.
		if removed == 0 {
			return deleted
		}
		if len(b.fwd) < cliClearFilteredBatch || iterErr != nil {
			return deleted
		}
	}
}

// cliClearBatchV6 is the IPv6 analogue of cliClearBatchV4.
type cliClearBatchV6 struct {
	fwd  []dataplane.SessionKeyV6
	rev  []dataplane.SessionKeyV6
	dnat []dataplane.DNATKeyV6
}

func (b *cliClearBatchV6) reset() { b.fwd = b.fwd[:0]; b.rev = b.rev[:0]; b.dnat = b.dnat[:0] }

func (b *cliClearBatchV6) collect(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	b.fwd = append(b.fwd, key)
	if val.ReverseKey.Protocol != 0 {
		b.rev = append(b.rev, val.ReverseKey)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 && val.Flags&dataplane.SessFlagStaticNAT == 0 {
		b.dnat = append(b.dnat, dataplane.DNATKeyForSessionV6(key, val))
	}
	return len(b.fwd) >= cliClearFilteredBatch
}

// deleteAll is the IPv6 analogue of cliClearBatchV4.deleteAll, returning the
// same (deleted, removed) pair for the #5948 rescan no-progress guard.
func (b *cliClearBatchV6) deleteAll(c *CLI, agg *sessionClearErrors) (deleted, removed int) {
	for _, key := range b.fwd {
		if err := c.dp.DeleteSessionV6(key); err != nil {
			agg.addExceptNotFound("v6 forward delete", err)
			if dataplane.IsKeyNotFound(err) {
				removed++ // already gone: not a delete, but still progress
			}
		} else {
			deleted++
			removed++
		}
	}
	for _, key := range b.rev {
		agg.addExceptNotFound("v6 reverse delete", c.dp.DeleteSessionV6(key))
	}
	for _, dk := range b.dnat {
		agg.addExceptNotFound("v6 DNAT companion delete", c.dp.DeleteDNATEntryV6(dk))
	}
	return deleted, removed
}

func clearFilteredV6Bounded(c *CLI, f *sessionFilter, agg *sessionClearErrors) int {
	iterDP, ok := c.dpProbe().(cliSessionCursor)
	if !ok {
		return clearFilteredV6Rescan(c, f, agg)
	}
	deleted := 0
	var a, b cliClearBatchV6
	cur, prev := &a, &b
	prevValid := false
	var cursor *dataplane.SessionKeyV6
	for {
		cur.reset()
		iterErr := iterDP.IterateSessionsV6From(cursor, func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse != 0 {
				return true
			}
			if !f.matchesV6(key, val) {
				return true
			}
			return !cur.collect(key, val)
		})
		agg.add("v6 iterate", iterErr)
		if cliClearBatchObserver != nil {
			cliClearBatchObserver(len(cur.fwd))
		}
		if prevValid {
			// Cursor path terminates unconditionally; the removed count is unused
			// here (only the fresh-rescan fallback needs the no-progress guard).
			d, _ := prev.deleteAll(c, agg)
			deleted += d
			prevValid = false
		}
		full := len(cur.fwd) >= cliClearFilteredBatch && iterErr == nil
		if !full {
			d, _ := cur.deleteAll(c, agg)
			deleted += d
			return deleted
		}
		anchor := cur.fwd[len(cur.fwd)-1]
		cursor = &anchor
		cur, prev = prev, cur
		prevValid = true
	}
}

func clearFilteredV6Rescan(c *CLI, f *sessionFilter, agg *sessionClearErrors) int {
	deleted := 0
	var b cliClearBatchV6
	for {
		b.reset()
		iterErr := c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse != 0 {
				return true
			}
			if !f.matchesV6(key, val) {
				return true
			}
			return !b.collect(key, val)
		})
		agg.add("v6 iterate", iterErr)
		if cliClearBatchObserver != nil {
			cliClearBatchObserver(len(b.fwd))
		}
		if len(b.fwd) == 0 {
			return deleted
		}
		d, removed := b.deleteAll(c, agg)
		deleted += d
		// #5948 no-progress guard (see clearFilteredV4Rescan): a non-empty chunk
		// that removed nothing (all forward deletes genuinely failed → keys remain)
		// would be re-collected identically forever; stop with the errors recorded.
		if removed == 0 {
			return deleted
		}
		if len(b.fwd) < cliClearFilteredBatch || iterErr != nil {
			return deleted
		}
	}
}

// sessionClearErrors accumulates per-operation failures during a CLI
// session clear (iterator, forward/reverse/companion deletes, and the
// HA peer-clear RPC) so the operator sees the full failure picture
// instead of a bare success line (#2468). nil errors are ignored.
type sessionClearErrors struct {
	count int
	parts []string
}

func (e *sessionClearErrors) add(op string, err error) {
	if err == nil {
		return
	}
	e.count++
	e.parts = append(e.parts, fmt.Sprintf("%s: %v", op, err))
}

// addExceptNotFound is add() for delete operations whose target key is
// COMPUTED, not enumerated — the reverse-session companion (a naive
// src/dst swap of the forward key) and the DNAT companion entry. For a
// NAT'd session those computed keys frequently do not exist (the real
// reverse companion is keyed on the TRANSLATED tuple val.ReverseKey, not
// the naive swap), so the dataplane returns ebpf.ErrKeyNotExist. That is
// a benign idempotent not-found, NOT a clear failure — counting it would
// make a fully-successful NAT'd-session clear spuriously report a
// failure (#2468). Any OTHER delete error (EIO/EINVAL/...) is a real
// failure and is aggregated. The forward delete uses add() unchanged: a
// forward key came from iteration, so a not-found there is a genuine
// anomaly worth reporting.
func (e *sessionClearErrors) addExceptNotFound(op string, err error) {
	if err == nil || dataplane.IsKeyNotFound(err) {
		return
	}
	e.add(op, err)
}

// report prints a warning line to stdout if any sub-operation failed.
// The cleared-count line is printed by the caller and stays accurate
// for the forward entries that were removed; this adds the honest
// failure tail.
func (e *sessionClearErrors) report() {
	if e.count == 0 {
		return
	}
	fmt.Printf("WARNING: %d clear operation(s) failed: %s\n", e.count, strings.Join(e.parts, "; "))
}

// clearPeerSessions forwards the clear to the HA peer. Returns a
// non-nil error when the peer is unreachable or its clear failed (or
// only partially succeeded) so the caller can report it to the operator
// rather than silently leaving the peer holding the sessions (#2468).
//
// A standalone node (no cluster manager) has no peer and returns nil —
// not a failure.
func (c *CLI) clearPeerSessions(f *sessionFilter) error {
	if c.cluster == nil {
		return nil
	}
	conn := c.dialPeer()
	if conn == nil {
		return fmt.Errorf("peer unreachable")
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := buildPeerClearRequest(f)
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	resp, err := pb.NewBpfrxServiceClient(conn).ClearSessions(ctx, req)
	if err != nil {
		return err
	}
	// The peer reports its own partial-failure tally — propagate it so a
	// local operator learns the peer clear was incomplete.
	if resp != nil && resp.Failures > 0 {
		return fmt.Errorf("peer reported %d failure(s): %s", resp.Failures, resp.FailureSummary)
	}
	return nil
}

// buildPeerClearRequest translates a local session filter into the
// peer-forwarded ClearSessionsRequest. EVERY filter dimension must be
// carried: a dropped filter does not merely widen the peer clear — a
// request with no filters at all is interpreted by the peer as
// clear-all (historically `clear security flow session interface X`
// forwarded an empty request and wiped the peer's session table).
func buildPeerClearRequest(f *sessionFilter) *pb.ClearSessionsRequest {
	req := &pb.ClearSessionsRequest{}
	if f == nil {
		return req
	}
	if f.srcNet != nil {
		req.SourcePrefix = f.srcNet.String()
	}
	if f.dstNet != nil {
		req.DestinationPrefix = f.dstNet.String()
	}
	if f.hasProto {
		switch f.proto {
		case 6:
			req.Protocol = "tcp"
		case 17:
			req.Protocol = "udp"
		case 1:
			req.Protocol = "icmp"
		case dataplane.ProtoICMPv6:
			req.Protocol = "icmpv6"
		default:
			// Numeric protocols, including protocol 0, must never be
			// omitted: an empty protocol field is peer clear-all.
			req.Protocol = strconv.Itoa(int(f.proto))
		}
	}
	req.SourcePort = uint32(f.srcPort)
	req.DestinationPort = uint32(f.dstPort)
	req.Application = f.appName
	req.Zone = f.zoneName
	req.Interface = f.iface
	req.NatOnly = f.natOnly
	req.SourceNatPool = f.snatPool
	return req
}

func (c *CLI) handleClearFirewall(args []string) error {
	if len(args) < 1 || args[0] != "all" {
		cmdtree.PrintTreeHelp("clear firewall:", operationalTree, "clear", "firewall")
		return nil
	}
	if err := requireClearNoScope("clear firewall all", "all firewall filter counters", args[1:]); err != nil {
		return err
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	if err := c.dp.ClearFilterCounters(); err != nil {
		return fmt.Errorf("clear filter counters: %w", err)
	}
	fmt.Println("Firewall filter counters cleared")
	return nil
}

func (c *CLI) handleClearDHCP(args []string) error {
	if len(args) < 1 || args[0] != "client-identifier" {
		cmdtree.PrintTreeHelp("clear dhcp:", operationalTree, "clear", "dhcp")
		return nil
	}

	// A bare `clear dhcp client-identifier` (no selector) is the intentional
	// clear-ALL. But a malformed selector must NOT silently degrade to it:
	// `... interface` (no name), `... interfce ge-0/0/0` (unknown selector),
	// or a stray trailing token used to skip the scoped branch and fall
	// through to ClearAllDUIDs(), wiping EVERY DHCPv6 DUID instead of the one
	// the operator scoped. Validate the selector BEFORE any mutation and
	// reject a malformed one, mirroring the remote CLI's #4883-E guard
	// (cmd/cli/clear.go handleClearDHCP) so both parsers reject the same
	// input the same way (#5896). Validation runs before the c.dhcp==nil
	// check so bad input always errors, regardless of DHCP client state.
	var ifName string
	if len(args) >= 2 {
		if args[1] != "interface" {
			return fmt.Errorf("usage: clear dhcp client-identifier [interface <name>]")
		}
		if len(args) < 3 || args[2] == "" {
			return fmt.Errorf("clear dhcp client-identifier: 'interface' requires a name")
		}
		if len(args) > 3 {
			return fmt.Errorf("clear dhcp client-identifier: unexpected argument %q after interface name", args[3])
		}
		ifName = args[2]
	}

	if c.dhcp == nil {
		fmt.Println("No DHCP clients running")
		return nil
	}

	if ifName != "" {
		if err := c.dhcp.ClearDUID(ifName); err != nil {
			return fmt.Errorf("clear DUID: %w", err)
		}
		fmt.Printf("DHCPv6 DUID cleared for %s\n", ifName)
		return nil
	}

	if err := c.dhcp.ClearAllDUIDs(); err != nil {
		return fmt.Errorf("clear all DUIDs: %w", err)
	}
	fmt.Println("All DHCPv6 DUIDs cleared")
	return nil
}

func (c *CLI) clearPersistentNAT() error {
	// #2114/#6743-F2: one resolution, then operate on the local. Each
	// GetPersistentNAT() is a separate cell load under the daemon's live
	// indirection, so re-reading after the nil-check can hand back nil.
	var table *dataplane.PersistentNATTable
	if c.dp != nil {
		table = c.dp.GetPersistentNAT()
	}
	if table == nil {
		fmt.Println("Persistent NAT table not available")
		return nil
	}
	count := table.Len()
	table.Clear()
	fmt.Printf("Cleared %d persistent NAT bindings\n", count)
	return nil
}
