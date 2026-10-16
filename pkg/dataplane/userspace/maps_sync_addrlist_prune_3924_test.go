package userspace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

// newLocalAddressMaps builds real in-memory userspace_local_v4/v6 HASH
// maps sized for the reconcile and injects them into the shim so the test
// can seed keys and Lookup them afterwards.
func newLocalAddressMaps(t *testing.T, m *Manager) (v4, v6 *ebpf.Map) {
	t.Helper()
	var err error
	v4, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceLocalV4Key{})),
		ValueSize:  1,
		MaxEntries: 64,
	})
	if err != nil {
		t.Fatalf("new userspace_local_v4 map: %v", err)
	}
	t.Cleanup(func() { v4.Close() })
	v6, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceShimLocalV6Key{})),
		ValueSize:  1,
		MaxEntries: 64,
	})
	if err != nil {
		t.Fatalf("new userspace_local_v6 map: %v", err)
	}
	t.Cleanup(func() { v6.Close() })
	injectShimMap(t, m.bpfShim, mapNameUserspaceLocalV4, v4)
	injectShimMap(t, m.bpfShim, mapNameUserspaceLocalV6, v6)
	return v4, v6
}

func v4Key(t *testing.T, s string) userspaceLocalV4Key {
	t.Helper()
	ip := net.ParseIP(s).To4()
	if ip == nil {
		t.Fatalf("bad v4 addr %q", s)
	}
	return userspaceLocalV4Key{Addr: binary.BigEndian.Uint32(ip)}
}

func v6Key(t *testing.T, s string) userspaceShimLocalV6Key {
	t.Helper()
	ip := net.ParseIP(s).To16()
	if ip == nil {
		t.Fatalf("bad v6 addr %q", s)
	}
	var k userspaceShimLocalV6Key
	copy(k.Addr[:], ip)
	return k
}

// TestSyncLocalAddressMapsSkipsPruneOnAddrListError is the #3924 RED-on-revert
// guard. A transient netlink AddrList failure yields an INCOMPLETE desired
// set that is missing kernel-owned VRRP VIP addresses. The reconcile MUST
// treat the incomplete enumeration as non-authoritative: it keeps the
// existing VIP/local keys (does NOT prune them), still adds any newly
// config-desired key, and emits an operator-visible warning. Reverting the
// fix re-prunes the VIP keys against the partial set -> VIP/SSH/BGP/IKE
// blackhole -> this test goes RED.
func TestSyncLocalAddressMapsSkipsPruneOnAddrListError(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	m := New()
	localV4Map, localV6Map := newLocalAddressMaps(t, m)

	// Kernel-owned VRRP VIPs that are NOT in the config snapshot. These are
	// exactly the keys buildDesiredLocalAddressSets recovers via AddrList —
	// on a transient AddrList error they are absent from the desired set.
	vipV4 := v4Key(t, "10.0.61.1")   // reth1.0 VIP
	vipV6 := v6Key(t, "2001:db8::1") // reth VIP v6
	if err := localV4Map.Update(vipV4, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed VIP v4: %v", err)
	}
	if err := localV6Map.Update(vipV6, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed VIP v6: %v", err)
	}

	// Inject a transient AddrList failure for BOTH families.
	injectErr := errors.New("transient netlink AddrList ENOBUFS")
	m.addrListForLocalSyncHook = func(_ netlink.Link, _ int) ([]netlink.Addr, error) {
		return nil, injectErr
	}

	// Snapshot carries one config-derived local address that is NOT yet in
	// the map — the reconcile must still add it (adds are safe on partial
	// data).
	newLocal := v4Key(t, "198.51.100.1")
	if err := m.syncLocalAddressMapsLocked(&ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{
			Name: "reth1.0",
			Addresses: []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "198.51.100.1/24",
			}},
		}},
	}); err != nil {
		t.Fatalf("syncLocalAddressMapsLocked returned %v, want nil (transient enum error is non-fatal)", err)
	}

	var got uint8
	// The kernel VIP keys MUST survive — this is the blackhole guard.
	if err := localV4Map.Lookup(vipV4, &got); err != nil {
		t.Fatalf("VRRP VIP v4 key pruned on incomplete enumeration (#3924 blackhole): %v", err)
	}
	if err := localV6Map.Lookup(vipV6, &got); err != nil {
		t.Fatalf("VRRP VIP v6 key pruned on incomplete enumeration (#3924 blackhole): %v", err)
	}
	// The config-derived add must still land.
	if err := localV4Map.Lookup(newLocal, &got); err != nil {
		t.Fatalf("config-derived local add dropped on incomplete enumeration: %v", err)
	}
	// The operator-visible warning must fire (error not silently swallowed).
	if out := buf.String(); !strings.Contains(out, "enumeration incomplete") {
		t.Fatalf("missing incomplete-enumeration warning, got: %q", out)
	}
}

// TestSyncLocalAddressMapsPrunesStaleOnCompleteEnum proves the fix does not
// break the normal reconcile: when AddrList succeeds (enumeration COMPLETE),
// keys that are neither config-desired nor present in the kernel dump are
// pruned as before.
func TestSyncLocalAddressMapsPrunesStaleOnCompleteEnum(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	localV4Map, localV6Map := newLocalAddressMaps(t, m)

	staleV4 := v4Key(t, "192.0.2.99")
	staleV6 := v6Key(t, "2001:db8::dead")
	if err := localV4Map.Update(staleV4, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed stale v4: %v", err)
	}
	if err := localV6Map.Update(staleV6, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed stale v6: %v", err)
	}

	// AddrList succeeds but returns a kernel VIP that the reconcile should
	// preserve (present in the desired set), and NOT the stale keys.
	kernelVIP := net.ParseIP("10.0.61.1")
	m.addrListForLocalSyncHook = func(_ netlink.Link, family int) ([]netlink.Addr, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Addr{{IPNet: &net.IPNet{IP: kernelVIP, Mask: net.CIDRMask(24, 32)}}}, nil
		}
		return nil, nil // empty but successful v6 dump
	}

	newLocal := v4Key(t, "198.51.100.1")
	if err := m.syncLocalAddressMapsLocked(&ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{
			Name: "reth1.0",
			Addresses: []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "198.51.100.1/24",
			}},
		}},
	}); err != nil {
		t.Fatalf("syncLocalAddressMapsLocked: %v", err)
	}

	var got uint8
	// Stale keys removed on complete enumeration.
	if err := localV4Map.Lookup(staleV4, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale v4 key not pruned on complete enumeration: err=%v", err)
	}
	if err := localV6Map.Lookup(staleV6, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale v6 key not pruned on complete enumeration: err=%v", err)
	}
	// Config add + kernel VIP preserved.
	if err := localV4Map.Lookup(newLocal, &got); err != nil {
		t.Fatalf("config-derived local add missing: %v", err)
	}
	if err := localV4Map.Lookup(v4Key(t, "10.0.61.1"), &got); err != nil {
		t.Fatalf("kernel VIP pruned despite being enumerated: %v", err)
	}
}
