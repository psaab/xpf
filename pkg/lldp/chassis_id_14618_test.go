package lldp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// chassisTLV14618 extracts the raw Chassis ID TLV value from a built frame.
func chassisTLV14618(t *testing.T, frame []byte) []byte {
	t.Helper()
	if len(frame) < ethHdrLen+2 {
		t.Fatalf("frame too short: %d", len(frame))
	}
	data := frame[ethHdrLen:]
	hdr := binary.BigEndian.Uint16(data[:2])
	if int(hdr>>9) != tlvChassisID {
		t.Fatalf("first TLV type = %d, want chassis %d", hdr>>9, tlvChassisID)
	}
	n := int(hdr & 0x1ff)
	if len(data) < 2+n {
		t.Fatalf("truncated chassis TLV")
	}
	return data[2 : 2+n]
}

// TestChassisIDStableAcrossPorts14618 is the acceptance test for #14618:
// two LLDP sessions on interfaces with different MACs must advertise
// byte-identical Chassis ID TLVs while keeping distinct Ethernet sources
// and Port IDs. RED on the pre-fix per-port chassis derivation (the frames
// carry 02:..:01 vs 02:..:02 as chassis).
func TestChassisIDStableAcrossPorts14618(t *testing.T) {
	systemMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xfe}
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	prevLookup := interfaceByNameFn
	interfaceByNameFn = func(name string) (*net.Interface, error) {
		switch name {
		case "ge-0-0-0":
			return &net.Interface{Index: 1, Name: name, HardwareAddr: macA}, nil
		case "ge-0-0-1":
			return &net.Interface{Index: 2, Name: name, HardwareAddr: macB}, nil
		}
		return nil, errors.New("not found")
	}
	t.Cleanup(func() { interfaceByNameFn = prevLookup })

	var mu sync.Mutex
	peers := map[string]int{}
	prevSess := newIfSessionFn
	newIfSessionFn = func(iface *net.Interface) (*ifSession, error) {
		sess, peer := newSocketpairSession(t, iface)
		mu.Lock()
		peers[iface.Name] = peer
		mu.Unlock()
		return sess, nil
	}
	t.Cleanup(func() {
		newIfSessionFn = prevSess
		mu.Lock()
		for _, fd := range peers {
			unix.Close(fd)
		}
		mu.Unlock()
	})

	m := New()
	cfg := &LLDPConfig{
		ChassisMAC: systemMAC,
		Interfaces: []LLDPInterface{{Name: "ge-0/0/0"}, {Name: "ge-0/0/1"}},
		Interval:   3600,
	}
	if un := m.Apply(context.Background(), cfg); len(un) != 0 {
		t.Fatalf("unresolved = %v", un)
	}
	// txLoop sends one frame immediately per session; read it from each peer.
	frames := make([][]byte, 0, 2)
	for _, name := range []string{"ge-0-0-0", "ge-0-0-1"} {
		mu.Lock()
		fd := peers[name]
		mu.Unlock()
		buf := make([]byte, 2048)
		n, err := unix.Read(fd, buf)
		if err != nil {
			m.Stop()
			t.Fatalf("read transmitted frame on %s: %v", name, err)
		}
		frames = append(frames, append([]byte(nil), buf[:n]...))
	}
	m.Stop()

	c0 := chassisTLV14618(t, frames[0])
	c1 := chassisTLV14618(t, frames[1])
	if !bytes.Equal(c0, c1) {
		t.Fatalf("chassis TLV differs across ports: %x vs %x (per-port MAC chassis, #14618)", c0, c1)
	}
	if want := encodeChassisID(systemMAC); !bytes.Equal(c0, want) {
		t.Fatalf("chassis TLV = %x, want system chassis %x", c0, want)
	}
	if !bytes.Equal(frames[0][6:12], []byte(macA)) {
		t.Fatalf("frame0 Ethernet src = %x, want port MAC %x", frames[0][6:12], []byte(macA))
	}
	if !bytes.Equal(frames[1][6:12], []byte(macB)) {
		t.Fatalf("frame1 Ethernet src = %x, want port MAC %x", frames[1][6:12], []byte(macB))
	}
	n0 := ParseTLVs(frames[0][ethHdrLen:])
	n1 := ParseTLVs(frames[1][ethHdrLen:])
	if n0 == nil || n1 == nil {
		t.Fatalf("ParseTLVs nil: %v %v", n0, n1)
	}
	if n0.PortID == n1.PortID {
		t.Fatalf("port IDs must stay per-port, both %q", n0.PortID)
	}
	if n0.ChassisID != systemMAC.String() || n1.ChassisID != systemMAC.String() {
		t.Fatalf("parsed chassis = %q/%q, want %q on both", n0.ChassisID, n1.ChassisID, systemMAC.String())
	}

	// Control: without an explicit chassis the same two ports must still
	// agree (deterministic fallback), not revert to per-port IDs.
	m2 := New()
	cfg2 := &LLDPConfig{
		Interfaces: []LLDPInterface{{Name: "ge-0/0/0"}, {Name: "ge-0/0/1"}},
		Interval:   3600,
	}
	if un := m2.Apply(context.Background(), cfg2); len(un) != 0 {
		t.Fatalf("fallback unresolved = %v", un)
	}
	var fb [][]byte
	for _, name := range []string{"ge-0-0-0", "ge-0-0-1"} {
		mu.Lock()
		fd := peers[name]
		mu.Unlock()
		// peers map now holds the second generation's fds (overwritten).
		buf := make([]byte, 2048)
		n, err := unix.Read(fd, buf)
		if err != nil {
			m2.Stop()
			t.Fatalf("read fallback frame on %s: %v", name, err)
		}
		fb = append(fb, append([]byte(nil), buf[:n]...))
	}
	m2.Stop()
	if !bytes.Equal(chassisTLV14618(t, fb[0]), chassisTLV14618(t, fb[1])) {
		t.Fatalf("fallback chassis differs across ports: %x vs %x",
			chassisTLV14618(t, fb[0]), chassisTLV14618(t, fb[1]))
	}
	if want := encodeChassisID(macA); !bytes.Equal(chassisTLV14618(t, fb[0]), want) {
		t.Fatalf("fallback chassis = %x, want smallest MAC %x", chassisTLV14618(t, fb[0]), want)
	}
}

// TestChassisIDFallback14618 pins resolveChassisMAC: explicit valid MAC
// wins, a short/invalid explicit value falls back, and the fallback is
// the deterministic smallest usable MAC regardless of interface order.
func TestChassisIDFallback14618(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	ifaces := []*net.Interface{
		{Name: "ge-0-0-0", HardwareAddr: macA},
		{Name: "ge-0-0-1", HardwareAddr: macB},
		{Name: "lo"},
	}
	if got := resolveChassisMAC(nil, ifaces); !bytes.Equal(got, []byte(macB)) {
		t.Fatalf("fallback chassis = %v, want smallest %v", got, macB)
	}
	rev := []*net.Interface{ifaces[1], ifaces[0], ifaces[2]}
	if got := resolveChassisMAC(nil, rev); !bytes.Equal(got, []byte(macB)) {
		t.Fatalf("fallback must be order-independent, got %v want %v", got, macB)
	}
	if got := resolveChassisMAC(nil, nil); got != nil {
		t.Fatalf("no interfaces chassis = %v, want nil", got)
	}
	explicit := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x09}
	if got := resolveChassisMAC(explicit, ifaces); !bytes.Equal(got, []byte(explicit)) {
		t.Fatalf("explicit chassis = %v, want %v", got, explicit)
	}
	if got := resolveChassisMAC(net.HardwareAddr{0x01, 0x02}, ifaces); !bytes.Equal(got, []byte(macB)) {
		t.Fatalf("short explicit must fall back, got %v want %v", got, macB)
	}
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	if got := resolveChassisMAC(zero, ifaces); !bytes.Equal(got, []byte(macB)) {
		t.Fatalf("zero explicit must fall back, got %v want %v", got, macB)
	}
}
