package nfqueue

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	harnessUDPPort = 39506
	harnessTable   = "xpf_9506_harness"
)

type trafficHarness struct {
	conn *net.UDPConn
	mu   sync.Mutex
}

var activeTraffic trafficHarness

// requireNetNS runs the current test in an isolated user/network namespace.
// Tests in the child are root in that namespace, so nftables and netlink can
// be used without host privileges. The parent only reports the child result.
func requireNetNS(t *testing.T) {
	t.Helper()
	if os.Getenv("XPF_NFQUEUE_IN_NETNS") != "" {
		bringLoopbackUp(t)
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command("unshare", "-Urn", self,
		"-test.run", "^"+regexp.QuoteMeta(t.Name())+"$", "-test.v")
	cmd.Env = append(os.Environ(), "XPF_NFQUEUE_IN_NETNS=1")
	out, err := cmd.CombinedOutput()
	t.Logf("netns re-exec output:\n%s", out)
	if err != nil {
		t.Fatalf("netns re-exec failed: %v", err)
	}
	t.Skip("netns child completed")
}

func bringLoopbackUp(t *testing.T) {
	t.Helper()
	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find loopback: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bring loopback up: %v", err)
	}
}

// divertTestTraffic installs an inet OUTPUT queue rule for the harness UDP
// destination and opens its local receiver. The synthetic pair exercises the
// NFQUEUE transport through OUTPUT->INPUT; it deliberately does not claim the
// r4 FORWARD/iif==stN XFRM shape, which remains cluster-gated.
func divertTestTraffic(t *testing.T, queueID uint16) (func(), error) {
	bringLoopbackUp(t)
	t.Helper()
	activeTraffic.mu.Lock()
	defer activeTraffic.mu.Unlock()
	if activeTraffic.conn != nil {
		return nil, errors.New("nfqueue harness: traffic receiver already active")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: harnessUDPPort})
	if err != nil {
		return nil, fmt.Errorf("listen UDP4: %w", err)
	}
	c, err := nftables.New()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("nftables.New: %w", err)
	}
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: harnessTable})
	priority := nftables.ChainPriority(0)
	policy := nftables.ChainPolicyAccept
	chain := c.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: &priority,
		Policy:   &policy,
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2, DestRegister: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(harnessUDPPort)},
			&expr.Queue{Num: queueID, Total: 1},
		},
	})
	if err := c.Flush(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("install queue rule: %w", err)
	}
	activeTraffic.conn = conn
	var once sync.Once
	release := func() {
		once.Do(func() {
			activeTraffic.mu.Lock()
			defer activeTraffic.mu.Unlock()
			c.DelTable(table)
			if err := c.Flush(); err != nil {
				t.Errorf("remove queue rule/table: %v", err)
			}
			tables, err := c.ListTables()
			if err != nil {
				t.Errorf("list ruleset after release: %v", err)
			} else if len(tables) != 0 {
				t.Errorf("ruleset not empty after release: %d tables", len(tables))
			}
		})
	}
	return release, nil
}

func closeTestReceiver() {
	activeTraffic.mu.Lock()
	defer activeTraffic.mu.Unlock()
	if activeTraffic.conn != nil {
		_ = activeTraffic.conn.Close()
		activeTraffic.conn = nil
	}
}
func sendTestDatagram(deadline time.Time) error {
	activeTraffic.mu.Lock()
	conn := activeTraffic.conn
	activeTraffic.mu.Unlock()
	if conn == nil {
		return errors.New("nfqueue harness: receiver is not active")
	}
	dialer := net.Dialer{Timeout: time.Until(deadline)}
	udp, err := dialer.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", harnessUDPPort))
	if err != nil {
		return fmt.Errorf("dial UDP4: %w", err)
	}
	defer udp.Close()
	if _, err := udp.Write([]byte("9506-nfqueue-phase0")); err != nil {
		return fmt.Errorf("write UDP4: %w", err)
	}
	return nil
}

func openTestSender() (net.Conn, error) {
	return net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", harnessUDPPort))
}

func sendTestDatagramConn(conn net.Conn, size, index int, deadline time.Time) error {
	if conn == nil {
		return errors.New("nfqueue harness: sender is nil")
	}
	if size < 1 {
		return errors.New("nfqueue harness: invalid datagram size")
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(index + i)
	}
	return sendTestPayloadConn(conn, payload, deadline)
}

func sendTestPayloadConn(conn net.Conn, payload []byte, deadline time.Time) error {
	if conn == nil {
		return errors.New("nfqueue harness: sender is nil")
	}
	if len(payload) < 1 {
		return errors.New("nfqueue harness: empty datagram")
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	n, err := conn.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return fmt.Errorf("short UDP write: %d/%d", n, len(payload))
	}
	return nil
}

func openTestFlowSenders(count int) ([]net.Conn, error) {
	if count <= 0 {
		return nil, errors.New("nfqueue harness: flow count must be positive")
	}
	senders := make([]net.Conn, 0, count)
	for i := 0; i < count; i++ {
		conn, err := openTestSender()
		if err != nil {
			for _, sender := range senders {
				_ = sender.Close()
			}
			return nil, err
		}
		senders = append(senders, conn)
	}
	return senders, nil
}

func sendTestDatagramFlowConn(conn net.Conn, size, flow, index int, deadline time.Time) error {
	if size < 4 {
		return errors.New("nfqueue harness: flow datagram size must be at least 4")
	}
	payload := make([]byte, size)
	binary.BigEndian.PutUint32(payload[:4], uint32(flow))
	for i := 4; i < len(payload); i++ {
		payload[i] = byte(index + i)
	}
	return sendTestPayloadConn(conn, payload, deadline)
}

func awaitTestDatagram(deadline time.Time) error {
	return awaitTestDatagramPayload(deadline, "9506-nfqueue-phase0")
}

func awaitTestDatagramPayload(deadline time.Time, want string) error {
	activeTraffic.mu.Lock()
	conn := activeTraffic.conn
	activeTraffic.mu.Unlock()
	if conn == nil {
		return errors.New("nfqueue harness: receiver is not active")
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != want {
		return fmt.Errorf("unexpected UDP payload %q, want %q", buf[:n], want)
	}
	return nil
}

func assertNoTestDatagram(timeout time.Duration) error {
	activeTraffic.mu.Lock()
	conn := activeTraffic.conn
	activeTraffic.mu.Unlock()
	if conn == nil {
		return errors.New("nfqueue harness: receiver is not active")
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, unix.EAGAIN) {
			return nil
		}
		return err
	}
	return fmt.Errorf("unexpected UDP payload %q", buf[:n])
}
