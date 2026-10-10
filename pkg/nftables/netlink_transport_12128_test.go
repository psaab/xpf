package nftables

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestLargeReplaceRecoversUncertainAck12128(t *testing.T) {
	enterPrivateNetns(t)

	if err := NewNetlinkInstaller().InstallHostInbound(HostInboundSpec{Views: []HostInboundZoneView{{
		Zone: "old", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.1"},
	}}}); err != nil {
		t.Fatalf("install old table: %v", err)
	}

	spec := largeHostInboundSpec12128(512)
	spec.Views[0].UDPFloodThreshold = 100 // Include one screen-flood rule to exercise named-set readback.
	if got := len(HostInboundScreenFloodRules(spec.Views)); got != 1 {
		t.Fatalf("screen-flood rules = %d, want 1 named-set readback case", got)
	}
	var socketDials atomic.Int32
	installer := newNetlinkInstallerConn(func() (*nftables.Conn, error) {
		return nftables.New(nftables.WithSockOptions(func(conn *netlink.Conn) error {
			dial := socketDials.Add(1)
			if err := conn.SetWriteBuffer(2 << 20); err != nil {
				return err
			}
			if err := conn.SetReadBuffer(2 << 20); err != nil {
				return err
			}
			if dial == 2 {
				// The second socket is Flush's ACK receiver. A tiny process-local
				// buffer forces loss without changing any host or namespace sysctl.
				return conn.SetReadBuffer(512)
			}
			return nil
		}))
	})

	var expected *nlPlan
	_, err := installer.replaceTable(HostInboundTableName, hostInboundPriority, func(p *nlPlan) {
		expected = p
		buildHostInboundNetlink(p, spec)
	})
	if err != nil {
		matched, readbackErr := installer.tableMatchesPlan(HostInboundTableName, expected)
		t.Fatalf("large replace with uncertain ACK: %v; explicit readback=(%t, %v), socket dials=%d",
			err, matched, readbackErr, socketDials.Load())
	}
	if len(expected.screenFloodSets) == 0 {
		t.Fatal("replacement plan has no named screen-flood sets to read back")
	}
	if got := socketDials.Load(); got <= 2 {
		t.Fatalf("socket dials = %d; want readback after the Flush socket", got)
	}
	if matched, err := installer.tableMatchesPlan(HostInboundTableName, expected); err != nil || !matched {
		t.Fatalf("large replacement readback = (%t, %v), want complete new plan", matched, err)
	}

	_, err = installer.replaceTable(HostInboundTableName, hostInboundPriority, func(p *nlPlan) {
		p.rule().daddr(famV4, []string{"192.0.2.254"}, false).emit(verdictAccept()...)
		p.c.AddObj(&nftables.CounterObj{Table: p.table, Name: strings.Repeat("x", 300)})
	})
	if err == nil {
		t.Fatal("replacement with an invalid counter name unexpectedly committed")
	}
	if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENAMETOOLONG) && !errors.Is(err, unix.ERANGE) {
		t.Fatalf("invalid counter replacement error = %v, want kernel rejection (EINVAL, ENAMETOOLONG, or ERANGE)", err)
	}
	if matched, readbackErr := installer.tableMatchesPlan(HostInboundTableName, expected); readbackErr != nil || !matched {
		t.Fatalf("rejected replacement changed the previous ruleset: old/new readback=(%t, %v), flush=%v",
			matched, readbackErr, err)
	}
}

func TestNetlinkSocketBufferLimit12128(t *testing.T) {
	enterPrivateNetns(t)
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		t.Fatalf("dial netfilter socket: %v", err)
	}
	defer conn.Close()
	if err := configureNetlinkSocket(conn); err != nil {
		t.Fatalf("configure bounded netlink buffers: %v", err)
	}
	readBuffer, writeBuffer, err := netlinkSocketBuffers(conn)
	if err != nil {
		t.Fatalf("read configured socket buffers: %v", err)
	}
	if readBuffer != netlinkSocketBufferEffective || writeBuffer != netlinkSocketBufferEffective {
		t.Fatalf("effective socket buffers = receive %d/send %d; want %d each",
			readBuffer, writeBuffer, netlinkSocketBufferEffective)
	}
}

func largeHostInboundSpec12128(zones int) HostInboundSpec {
	spec := HostInboundSpec{Views: make([]HostInboundZoneView, 0, zones)}
	for i := range zones {
		spec.Views = append(spec.Views, HostInboundZoneView{
			Zone:           fmt.Sprintf("batch%04d", i),
			SystemServices: []string{"ssh"},
			V4Addrs:        []string{fmt.Sprintf("10.128.%d.%d", i/256, i%256)},
		})
	}
	return spec
}
