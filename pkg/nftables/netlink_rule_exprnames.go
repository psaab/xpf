package nftables

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// readRuleExprNames dumps one chain's rules and returns, keyed by rule handle,
// the kernel's expression names in rule order (#18721).
//
// GetRules cannot answer "what expressions does this rule hold?". When
// google/nftables v0.3.0 meets an expression name it has no type for, it skips
// the expression with no trace (expr.exprsFromBytes). byteorder, rt, socket,
// dup and tproxy are all skipped that way, so a rule [rt, cmp, drop] decodes as
// [cmp, drop]. The fence readback must not judge a rule by a decode that drops
// part of it, so it reads the names itself.
//
// The dump dials exactly as c does (its TestDial or its NetNS, otherwise the
// calling thread's namespace), so it reads the same ruleset GetRules read.
func readRuleExprNames(c *nftables.Conn, table *nftables.Table, chain string) (map[uint64][]string, error) {
	conn, err := dialLikeNftConn(c)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")},
	})
	if err != nil {
		return nil, err
	}
	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETRULE),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: append([]byte{byte(table.Family), unix.NFNETLINK_V0, 0, 0}, attrs...),
	})
	if err != nil {
		return nil, fmt.Errorf("dump %s/%s rules: %w", table.Name, chain, err)
	}
	newRule := netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWRULE)
	out := make(map[uint64][]string, len(msgs))
	for _, msg := range msgs {
		if msg.Header.Type != newRule {
			return nil, fmt.Errorf("rule dump returned message type %#x", msg.Header.Type)
		}
		handle, names, err := decodeRuleExprNames(msg.Data)
		if err != nil {
			return nil, err
		}
		if _, dup := out[handle]; dup {
			return nil, fmt.Errorf("rule dump listed handle %d twice", handle)
		}
		out[handle] = names
	}
	return out, nil
}

// decodeRuleExprNames reads the handle and the ordered expression names from
// one NFT_MSG_NEWRULE payload (nfgenmsg header + attributes). Every list
// element must carry a name, or the decode fails.
func decodeRuleExprNames(data []byte) (uint64, []string, error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("short nf_tables rule message (%d bytes)", len(data))
	}
	ad, err := netlink.NewAttributeDecoder(data[4:])
	if err != nil {
		return 0, nil, err
	}
	ad.ByteOrder = binary.BigEndian
	var (
		handle     uint64
		haveHandle bool
		names      []string
	)
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_HANDLE:
			handle, haveHandle = ad.Uint64(), true
		case unix.NFTA_RULE_EXPRESSIONS:
			ad.Nested(func(list *netlink.AttributeDecoder) error {
				for list.Next() {
					if list.Type() != unix.NFTA_LIST_ELEM {
						return fmt.Errorf("rule expression list holds attribute type %d", list.Type())
					}
					name := ""
					list.Nested(func(e *netlink.AttributeDecoder) error {
						for e.Next() {
							if e.Type() == unix.NFTA_EXPR_NAME {
								name = e.String()
							}
						}
						return nil
					})
					if err := list.Err(); err != nil {
						return err
					}
					if name == "" {
						return fmt.Errorf("rule expression without a name")
					}
					names = append(names, name)
				}
				return nil
			})
		}
	}
	if err := ad.Err(); err != nil {
		return 0, nil, fmt.Errorf("decode rule expressions: %w", err)
	}
	if !haveHandle {
		return 0, nil, fmt.Errorf("rule message without a handle")
	}
	return handle, names, nil
}

// dialLikeNftConn opens a raw netfilter netlink socket on the same target as c:
// its TestDial, else its NetNS (0 = the calling thread's namespace), the way
// google/nftables dials (Conn.dialNetlink).
func dialLikeNftConn(c *nftables.Conn) (*netlink.Conn, error) {
	if c.TestDial != nil {
		return nltest.Dial(c.TestDial), nil
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: c.NetNS})
	if err != nil {
		return nil, fmt.Errorf("dial netfilter netlink: %w", err)
	}
	return conn, nil
}

// readNftGeneration returns the namespace's nf_tables ruleset generation
// (NFT_MSG_GETGEN). The kernel bumps it on every committed transaction, so two
// reads that return the same ID bracket a window that no commit published
// into (#18721).
//
// The bracket NARROWS the race; it does not close it. nf_tables_commit
// publishes the new generation (linux v7.0 net/netfilter/nf_tables_api.c:11028,
// smp_store_release of base_seq) BEFORE it switches rule visibility (:11033,
// gencursor = nft_gencursor_next). A commit preempted between those two lines
// is already counted in "before", yet its rule switch can land mid-pass, so
// before == after with mixed views. The kernel's own interrupted-dump check on
// the rules dump has the same residual: nf_tables_dump_rules samples
// cb->seq = nft_base_seq(net) (:3860) and nl_dump_check_consistent (:3833)
// compares against it. Reaching it needs a root writer outside xpf, preempted
// in that two-line gap.
func readNftGeneration(c *nftables.Conn) (uint32, error) {
	conn, err := dialLikeNftConn(c)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETGEN),
			Flags: netlink.Request,
		},
		Data: []byte{unix.AF_UNSPEC, unix.NFNETLINK_V0, 0, 0},
	})
	if err != nil {
		return 0, fmt.Errorf("get nftables generation: %w", err)
	}
	return decodeNftGeneration(msgs)
}

// decodeNftGeneration reads NFTA_GEN_ID from exactly one NFT_MSG_NEWGEN reply.
func decodeNftGeneration(msgs []netlink.Message) (uint32, error) {
	if len(msgs) != 1 {
		return 0, fmt.Errorf("nftables generation reply: %d messages, want 1", len(msgs))
	}
	msg := msgs[0]
	if want := netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWGEN); msg.Header.Type != want {
		return 0, fmt.Errorf("nftables generation reply type %#x, want %#x", msg.Header.Type, want)
	}
	if len(msg.Data) < 4 {
		return 0, fmt.Errorf("short nftables generation reply (%d bytes)", len(msg.Data))
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return 0, err
	}
	ad.ByteOrder = binary.BigEndian
	var (
		id   uint32
		have bool
	)
	for ad.Next() {
		if ad.Type() == unix.NFTA_GEN_ID {
			id, have = ad.Uint32(), true
		}
	}
	if err := ad.Err(); err != nil {
		return 0, fmt.Errorf("decode nftables generation: %w", err)
	}
	if !have {
		return 0, fmt.Errorf("nftables generation reply without NFTA_GEN_ID")
	}
	return id, nil
}

// readAtStableNftGeneration runs read between two generation reads and returns
// read's verdict only if no commit published a new generation in between.
// Otherwise it pauses for the next backoff step and retries: len(backoff)+1
// attempts in all, inside a wall-clock deadline (#18721).
//
// Before each retry it stops when elapsed + the next pause + the SLOWEST pass
// seen so far would exceed deadline. The maximum, not the last pass, is the
// conservative estimate for the next one. The first pass always runs and is
// not bounded by the deadline: one stable pass returns its own verdict however
// long it took. So a readback costs at most deadline + one pass, and the
// deadline is short enough that retries happen only while passes are fast. If
// it runs out of attempts or of deadline, it logs a Warn and fails closed. See
// readNftGeneration for the residual window this cannot see.
//
// The fence readback reads the ruleset several times: the marker object, the
// sets, GetRules, and the raw expression-name dump. A writer outside xpf could
// otherwise replace a rule between GetRules and the dump. NLM_F_REPLACE keeps
// the handle, so both views would describe different rules under one handle,
// and a kind-identical rule with ACCEPT in place of DROP would pass both checks.
func readAtStableNftGeneration(backoff []time.Duration, deadline time.Duration, now func() time.Time, sleep func(time.Duration), gen func() (uint32, error), read func() error) error {
	attempts := len(backoff) + 1
	start := now()
	var first, before, after uint32
	var maxPass time.Duration
	made, stoppedAtDeadline := 0, false
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			pause := backoff[attempt-1]
			if now().Sub(start)+pause+maxPass > deadline {
				stoppedAtDeadline = true
				break
			}
			sleep(pause)
		}
		passStart := now()
		var err error
		if before, err = gen(); err != nil {
			return err
		}
		if attempt == 0 {
			first = before
		}
		verdict := read()
		if after, err = gen(); err != nil {
			return err
		}
		if d := now().Sub(passStart); d > maxPass {
			maxPass = d
		}
		made++
		if before == after {
			return verdict
		}
	}
	// Commits observed over the whole run, pauses included: the generation is
	// a commit counter, so the delta is the number of transactions that landed
	// (uint32 subtraction is wrap-safe).
	commits := after - first
	elapsed := now().Sub(start)
	stop := "attempts exhausted"
	if stoppedAtDeadline {
		stop = fmt.Sprintf("stopped at the %v deadline", deadline)
	}
	slog.Warn("host overlay readback: the nftables ruleset kept changing; failing closed",
		"attempts", made, "commits_observed", commits, "elapsed", elapsed, "stop", stop,
		"first_generation", first, "last_generation", after)
	return fmt.Errorf("host overlay readback: the nftables ruleset changed during each of %d attempts (%d commits observed, generation %d -> %d, %v elapsed, %s); failing closed", made, commits, first, after, elapsed, stop)
}
