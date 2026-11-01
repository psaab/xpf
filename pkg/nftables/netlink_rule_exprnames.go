package nftables

import (
	"encoding/binary"
	"fmt"

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
	var conn *netlink.Conn
	if c.TestDial != nil {
		conn = nltest.Dial(c.TestDial)
	} else {
		var err error
		conn, err = netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: c.NetNS})
		if err != nil {
			return nil, fmt.Errorf("dial netfilter netlink: %w", err)
		}
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
