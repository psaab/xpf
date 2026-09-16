package daemon

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// natDelta9905 is a string-leg delta with NAT + MACs populated, exercising every
// ParseIP/ParseMAC site in the V4 convert path.
func natDelta9905() dpuserspace.SessionDeltaInfo {
	d := transitOpen9767()
	d.NATSrcIP = "192.0.2.7"
	d.NATDstIP = "198.51.100.9"
	d.NATSrcPort = 23456
	d.NATDstPort = 443
	return d
}

// TestV4ConvertFromDeltaAllocsBudget9905 is a general allocation guard on the
// string-leg V4 convert (NAT+MAC populated): it measures heap allocations per
// conversion and fails on growth. NOTE: it is NOT parse-once evidence —
// net.ParseIP results do not escape, so even the unfixed double-parse
// (value + reverse key) measured 2.0 allocs/op, already under the ceiling.
// Parse-once is pinned structurally instead: NAT resolves once per FromDelta
// into userspaceResolvedV4, and ReverseKey/ForwardWire take the resolved
// carrier or the converted value (no delta re-parse — see
// TestForwardWireAliasNeedsNoDelta9905 and the (key, val) signatures).
func TestV4ConvertFromDeltaAllocsBudget9905(t *testing.T) {
	delta := natDelta9905()
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	if _, _, ok := userspaceSessionFromDeltaV4(delta, zoneIDs); !ok {
		t.Fatal("fixture: delta does not convert, the budget assertion would be vacuous")
	}
	allocs := testing.AllocsPerRun(200, func() {
		if _, _, ok := userspaceSessionFromDeltaV4(delta, zoneIDs); !ok {
			panic("fixture delta stopped converting")
		}
	})
	t.Logf("userspaceSessionFromDeltaV4 (string leg, NAT+MAC): %.1f allocs/op", allocs)
	if allocs > 7 {
		t.Fatalf("userspaceSessionFromDeltaV4 = %.1f allocs/op, want <= 7 (allocation guard, #9905 F-083)", allocs)
	}
}

// TestHandleDeltaZoneMapCachedBudget9905 pins the F-152 fix: the per-delta path
// must not rebuild the zone-id map (and one-element slice) on every delta when
// the active config is unchanged. The delta carries empty IPs so the convert
// drops fast and the measurement isolates the pre-queue overhead: ActiveConfig +
// buildZoneIDs + slice on base, cache lookup after.
func TestHandleDeltaZoneMapCachedBudget9905(t *testing.T) {
	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0, 1),
		store: testStoreWithSetConfig(t, []string{
			"set system dataplane-type userspace",
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key test-cluster-psk-9905",
			"set chassis cluster node 0",
			"set chassis cluster redundancy-group 0 node 0 priority 200",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set security zones security-zone lan",
			"set security zones security-zone wan",
			"set security zones security-zone dmz",
			"set security zones security-zone guest",
		}),
	}
	ss := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil)
	ss.IsPrimaryFn = func() bool { return true }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 0 || rgID == 1 }
	ss.SetConnectedForTesting(true)
	d.sessionSync = ss
	if cfg := d.store.ActiveConfig(); cfg == nil {
		t.Fatal("fixture: no active config, the cache assertion would be vacuous")
	}
	if !d.cluster.IsLocalPrimaryAny() {
		t.Fatal("fixture: node is not primary for any RG")
	}
	if !ss.IsConnected() {
		t.Fatal("fixture: session sync is not connected")
	}
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
		SrcPort:    12345,
		DstPort:    443,
		OwnerRGID:  1,
		// Empty IPs: the convert drops at "v4 address unparseable" before any
		// queue work, isolating the ActiveConfig+buildZoneIDs+slice overhead.
	}
	if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
		t.Fatal("fixture: delta was not handled (withheld), the budget assertion would be vacuous")
	}
	allocs := testing.AllocsPerRun(200, func() {
		if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
			panic("delta handling started withholding")
		}
	})
	t.Logf("handleEventStreamDelta (empty-IP delta, warm cache): %.1f allocs/op", allocs)
	if allocs > 2 {
		t.Fatalf("handleEventStreamDelta = %.1f allocs/op, want <= 2 (zone map cached across deltas, #9905 F-152)", allocs)
	}
}

// NOTE (tripwire, #9905 review): TestHandleDeltaZoneMapCachedBudget9905 lands
// at exactly 2.0 allocs/op on go1.26.4 linux/amd64 — believed to be the
// two netip ParseAddr error boxes on the empty-IP drop path
// (profiler-attributed, not pinned in-repo). Zero headroom is INTENTIONAL: any
// regression that adds even one allocation per delta fails loudly here. Do
// not relax to ≤3 without a measured cause; see docs/log/9905.md.

// binDelta9905 is the binary-leg twin of natDelta9905: the identical session,
// but the strings are empty and the raw bytes ride the #9905 binary fields
// exactly as decodeSessionEvent fills them. Zone names stay string-leg so the
// zone path is exercised identically; only addrs/MACs go binary.
func binDelta9905() dpuserspace.SessionDeltaInfo {
	d := transitOpen9767()
	d.SrcIP, d.DstIP = "", ""
	d.NATSrcIP, d.NATDstIP = "", ""
	d.NeighborMAC, d.SrcMAC = "", ""
	d.SrcAddr = [16]byte{10, 0, 61, 102}
	d.DstAddr = [16]byte{172, 16, 80, 200}
	d.NATSrcAddr = [16]byte{192, 0, 2, 7}
	d.NATDstAddr = [16]byte{198, 51, 100, 9}
	d.BinAddrLen = 4
	d.NATSrcPort = 23456
	d.NATDstPort = 443
	d.NeighborMACBin = [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	d.SrcMACBin = [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08}
	return d
}

// TestBinaryDeltaConvertsWithoutStrings9905 is the F-083 convert-half
// red-green cell: a binary-leg delta (empty strings, binary filled) must
// convert to the same session the string leg produces. RED while convert is
// string-only (drops at unparseable), GREEN after the binary carry-through.
func TestBinaryDeltaConvertsWithoutStrings9905(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	key, val, ok := userspaceSessionFromDeltaV4(binDelta9905(), zoneIDs)
	if !ok {
		t.Fatal("binary-leg delta did not convert (strings empty, binary filled)")
	}
	if key.SrcIP != [4]byte{10, 0, 61, 102} || key.DstIP != [4]byte{172, 16, 80, 200} {
		t.Fatalf("key addrs = %v/%v, want 10.0.61.102/172.16.80.200", key.SrcIP, key.DstIP)
	}
	if val.IngressZone != 1 || val.EgressZone != 2 {
		t.Fatalf("zones = %d/%d, want 1/2", val.IngressZone, val.EgressZone)
	}
	if val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) != dataplane.SessFlagSNAT|dataplane.SessFlagDNAT {
		t.Fatalf("val.Flags = %#x, want SNAT|DNAT set", val.Flags)
	}
	if want := binary.NativeEndian.Uint32([]byte{192, 0, 2, 7}); val.NATSrcIP != want {
		t.Fatalf("val.NATSrcIP = %#x, want %#x", val.NATSrcIP, want)
	}
	if want := binary.NativeEndian.Uint32([]byte{198, 51, 100, 9}); val.NATDstIP != want {
		t.Fatalf("val.NATDstIP = %#x, want %#x", val.NATDstIP, want)
	}
	if val.NATSrcPort != userspaceHostToNetwork16(23456) || val.NATDstPort != userspaceHostToNetwork16(443) {
		t.Fatalf("NAT ports = %#x/%#x, want htons(23456)/htons(443)", val.NATSrcPort, val.NATDstPort)
	}
	if val.FibDmac != [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} || val.FibSmac != [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08} {
		t.Fatalf("FIB MACs = %x/%x, want neighbor/src MACs", val.FibDmac, val.FibSmac)
	}
	rev := val.ReverseKey
	if rev.SrcIP != [4]byte{198, 51, 100, 9} || rev.DstIP != [4]byte{192, 0, 2, 7} {
		t.Fatalf("reverse addrs = %v/%v, want NATDst/NATSrc", rev.SrcIP, rev.DstIP)
	}
	if rev.SrcPort != userspaceHostToNetwork16(443) || rev.DstPort != userspaceHostToNetwork16(23456) {
		t.Fatalf("reverse ports = %#x/%#x, want htons(443)/htons(23456)", rev.SrcPort, rev.DstPort)
	}
	// Binary-leg effective-port fallback: zero NAT port + present NAT addr
	// falls back to the base port, mirroring the string-leg !="" rule.
	d2 := binDelta9905()
	d2.NATSrcPort = 0
	if _, v2, ok := userspaceSessionFromDeltaV4(d2, zoneIDs); !ok {
		t.Fatal("binary-leg delta with zero NAT port did not convert")
	} else if v2.NATSrcPort != userspaceHostToNetwork16(d2.SrcPort) {
		t.Fatalf("fallback NATSrcPort = %#x, want htons(%d)", v2.NATSrcPort, d2.SrcPort)
	}
	// Fabric-redirect forward-wire alias resolves NAT from binary too.
	d3 := binDelta9905()
	d3.FabricRedirect = true
	k3, v3, ok := userspaceSessionFromDeltaV4(d3, zoneIDs)
	if !ok {
		t.Fatal("binary-leg fabric delta did not convert")
	}
	wireKey, _, ok := userspaceForwardWireAliasV4(k3, v3)
	if !ok {
		t.Fatal("binary-leg fabric delta produced no forward-wire alias")
	}
	if wireKey.SrcIP != [4]byte{192, 0, 2, 7} || wireKey.DstIP != [4]byte{198, 51, 100, 9} {
		t.Fatalf("wire addrs = %v/%v, want NATSrc/NATDst", wireKey.SrcIP, wireKey.DstIP)
	}
	// String/binary parity: both legs of the same session convert
	// identically once volatile fields (clock, minted id) are blanked.
	sk, sv, ok := userspaceSessionFromDeltaV4(natDelta9905(), zoneIDs)
	if !ok {
		t.Fatal("fixture: string-leg twin stopped converting")
	}
	sv.Created, sv.LastSeen, sv.SessionID = 0, 0, 0
	bv := val
	bv.Created, bv.LastSeen, bv.SessionID = 0, 0, 0
	if sk != key {
		t.Fatalf("leg keys differ:\n string=%+v\n binary=%+v", sk, key)
	}
	if !reflect.DeepEqual(sv, bv) {
		t.Fatalf("leg values differ:\n string=%+v\n binary=%+v", sv, bv)
	}
}

// TestBinaryDeltaFailClosed9905 pins the whole-struct leg gate: a BinAddrLen
// that is neither 4 nor 16, a family/length mismatch, or a zero binary src
// drops exactly like an unparseable string (no per-field mixing, no partial
// binary use).
func TestBinaryDeltaFailClosed9905(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	cases := map[string]func(*dpuserspace.SessionDeltaInfo){
		"bad length": func(d *dpuserspace.SessionDeltaInfo) { d.BinAddrLen = 9 },
		"v6 family with v4 length": func(d *dpuserspace.SessionDeltaInfo) {
			d.AddrFamily = dataplane.AFInet6
		},
		"v6 length on v4 convert": func(d *dpuserspace.SessionDeltaInfo) { d.BinAddrLen = 16 },
		"zero binary src":         func(d *dpuserspace.SessionDeltaInfo) { d.SrcAddr = [16]byte{} },
		"zero binary dst":         func(d *dpuserspace.SessionDeltaInfo) { d.DstAddr = [16]byte{} },
	}
	for name, mutate := range cases {
		d := binDelta9905()
		mutate(&d)
		if _, _, ok := userspaceSessionFromDeltaV4(d, zoneIDs); ok {
			t.Errorf("%s: converted, want drop (fail closed)", name)
		}
	}
}

// TestBinaryDeltaV6NAT649905 pins the NAT64 pool source on the binary leg:
// Nat64SnatV4Bin must reach val.Nat64SnatV4 so the peer rebuilds the reverse
// (v4->v6) BIB after failover (#4565). The string stays empty on this leg.
func TestBinaryDeltaV6NAT649905(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	d := transitOpenV6_9767()
	d.SrcIP, d.DstIP = "", ""
	d.NeighborMAC, d.SrcMAC = "", ""
	d.Nat64SnatV4 = ""
	src := net.ParseIP("2001:559:8585:bf01::102").To16()
	dst := net.ParseIP("2001:559:8585:80::200").To16()
	if src == nil || dst == nil {
		t.Fatal("fixture: v6 literals do not parse")
	}
	copy(d.SrcAddr[:], src)
	copy(d.DstAddr[:], dst)
	d.BinAddrLen = 16
	d.Nat64 = true
	d.Nat64SnatV4Bin = [4]byte{203, 0, 113, 5}
	key, val, ok := userspaceSessionFromDeltaV6(d, zoneIDs)
	if !ok {
		t.Fatal("binary-leg v6 NAT64 delta did not convert")
	}
	if key.SrcIP != [16]byte(src) || key.DstIP != [16]byte(dst) {
		t.Fatalf("key addrs = %x/%x, want v6 fixtures", key.SrcIP, key.DstIP)
	}
	if val.Nat64SnatV4 != [4]byte{203, 0, 113, 5} {
		t.Fatalf("val.Nat64SnatV4 = %v, want 203.0.113.5", val.Nat64SnatV4)
	}
}

// TestStringLegZeroNATPreserved9905 guards the JSON-leg present-but-zero
// case: NATSrcIP "0.0.0.0" parses (non-nil), so it sets SNAT, stamps a zero
// IP verbatim, overwrites the reverse key with zeros, and trips the
// effective-port fallback. A naive binary-first rewrite keyed on "any
// nonzero byte" would flip this leg from present to absent; this cell pins
// the (bytes, present) semantics instead. Green before and after.
func TestStringLegZeroNATPreserved9905(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	d := transitOpen9767()
	d.NATSrcIP = "0.0.0.0"
	_, val, ok := userspaceSessionFromDeltaV4(d, zoneIDs)
	if !ok {
		t.Fatal("zero-NAT string delta did not convert")
	}
	if val.Flags&dataplane.SessFlagSNAT == 0 {
		t.Fatalf("val.Flags = %#x, want SNAT set for present-but-zero NAT", val.Flags)
	}
	if val.NATSrcIP != 0 {
		t.Fatalf("val.NATSrcIP = %#x, want verbatim 0", val.NATSrcIP)
	}
	if val.ReverseKey.DstIP != [4]byte{} {
		t.Fatalf("reverse DstIP = %v, want zero overwrite", val.ReverseKey.DstIP)
	}
	if val.NATSrcPort != userspaceHostToNetwork16(d.SrcPort) {
		t.Fatalf("NATSrcPort = %#x, want htons(%d) fallback", val.NATSrcPort, d.SrcPort)
	}
}

// zoneCacheDaemon9905 is the TestHandleDeltaZoneMapCachedBudget9905 Daemon
// shape (primary for RG 0/1, connected sync) over a caller-owned store, so a
// test can commit further configs through the same store.
func zoneCacheDaemon9905(t *testing.T, store *configstore.Store) *Daemon {
	t.Helper()
	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0, 1),
		store:   store,
	}
	ss := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil)
	ss.IsPrimaryFn = func() bool { return true }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 0 || rgID == 1 }
	ss.SetConnectedForTesting(true)
	d.sessionSync = ss
	if cfg := d.store.ActiveConfig(); cfg == nil {
		t.Fatal("fixture: no active config")
	}
	return d
}

// commitLines9905 commits one more config on an already-configured store.
// Commit leaves config mode entered, so no second EnterConfigure is needed.
func commitLines9905(t *testing.T, store *configstore.Store, lines []string) {
	t.Helper()
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// TestHandleDeltaZoneMapRebuildsOnCommit9905 is the F-152 behavioral cell the
// alloc budget cannot express: the published cache entry must be STABLE
// across deltas on an unchanged config (pointer identity, not just cost)
// and must REBUILD with new content on every commit. RED until the stream
// handler consults the cache.
func TestHandleDeltaZoneMapRebuildsOnCommit9905(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-9905",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set security zones security-zone lan",
		"set security zones security-zone wan",
		"set security zones security-zone dmz",
		"set security zones security-zone guest",
	})
	d := zoneCacheDaemon9905(t, store)
	drive := func(zone string) {
		t.Helper()
		delta := natDelta9905()
		delta.IngressZone = zone
		if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
			t.Fatalf("zone %q delta withheld, want handled", zone)
		}
	}
	drive("dmz")
	e1 := d.userspaceZoneIDs.Load()
	if e1 == nil {
		t.Fatal("no cache entry after first delta")
	}
	if _, ok := e1.ids["dmz"]; !ok {
		t.Fatal("entry lacks dmz after warmup")
	}
	drive("dmz")
	if e2 := d.userspaceZoneIDs.Load(); e2 != e1 {
		t.Fatal("cache entry rebuilt on unchanged config, want stable identity")
	}
	commitLines9905(t, store, []string{"delete security zones security-zone dmz"})
	drive("dmz")
	e3 := d.userspaceZoneIDs.Load()
	if e3 == e1 {
		t.Fatal("cache entry stable across a commit, want rebuild")
	}
	if _, ok := e3.ids["dmz"]; ok {
		t.Fatal("rebuilt entry still carries removed dmz")
	}
	if e3.gen <= e1.gen {
		t.Fatalf("gen %d -> %d, want monotonic increase", e1.gen, e3.gen)
	}
	// Retained-map: the SUPERSEDED entry must keep its old contents —
	// misses build fresh and swap the pointer, never mutate in place.
	// A fake that wrapped one mutated map would fail here (dmz gone).
	if _, ok := e1.ids["dmz"]; !ok {
		t.Fatal("superseded entry lost dmz: published map was mutated in place")
	}
	commitLines9905(t, store, []string{"set security zones security-zone quarantine"})
	drive("quarantine")
	e4 := d.userspaceZoneIDs.Load()
	if e4 == e3 {
		t.Fatal("cache entry stable across a commit, want rebuild")
	}
	if _, ok := e4.ids["quarantine"]; !ok {
		t.Fatal("rebuilt entry lacks added quarantine")
	}
}

// TestBinaryDeltaDropLogRendersTuple9905 pins the #7171 flow identity on the
// binary leg: a drop log must render the tuple from binary bytes, not empty
// strings. The string-leg control guards the fallback.
func TestBinaryDeltaDropLogRendersTuple9905(t *testing.T) {
	prev := slog.Default()
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	d := binDelta9905()
	d.IngressZone = "nope"
	if _, _, ok := userspaceSessionFromDeltaV4(d, zoneIDs); ok {
		t.Fatal("bad-zone binary delta converted, want drop")
	}
	if got := buf.String(); !strings.Contains(got, "10.0.61.102") || !strings.Contains(got, "172.16.80.200") {
		t.Fatalf("binary-leg drop log lacks tuple: %q", got)
	}
	buf.Reset()
	s := natDelta9905()
	s.IngressZone = "nope"
	if _, _, ok := userspaceSessionFromDeltaV4(s, zoneIDs); ok {
		t.Fatal("bad-zone string delta converted, want drop")
	}
	if got := buf.String(); !strings.Contains(got, "10.0.61.102") || !strings.Contains(got, "172.16.80.200") {
		t.Fatalf("string-leg drop log lacks tuple: %q", got)
	}
}

// TestForwardWireAliasNeedsNoDelta9905 pins the #9905 no-re-resolve shape:
// the wire key derives from the converted value alone (NAT bytes + stamped
// ports + presence flags), so the alias path parses nothing on either leg.
// A hand-built value with no delta in existence proves delta-independence;
// the (key, val) signatures (no delta param) make a regression
// uncompilable.
func TestForwardWireAliasNeedsNoDelta9905(t *testing.T) {
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 2},
		SrcPort:  userspaceHostToNetwork16(1111),
		DstPort:  userspaceHostToNetwork16(2222),
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
		NATSrcIP:   binary.NativeEndian.Uint32([]byte{192, 0, 2, 7}),
		NATDstIP:   binary.NativeEndian.Uint32([]byte{198, 51, 100, 9}),
		NATSrcPort: userspaceHostToNetwork16(23456),
		NATDstPort: userspaceHostToNetwork16(443),
	}
	wireKey, wireVal, ok := userspaceForwardWireAliasV4(key, val)
	if !ok {
		t.Fatal("NAT value produced no alias, want one")
	}
	if wireKey.SrcIP != [4]byte{192, 0, 2, 7} || wireKey.DstIP != [4]byte{198, 51, 100, 9} {
		t.Fatalf("wire addrs = %v/%v, want NATSrc/NATDst", wireKey.SrcIP, wireKey.DstIP)
	}
	if wireKey.SrcPort != userspaceHostToNetwork16(23456) || wireKey.DstPort != userspaceHostToNetwork16(443) {
		t.Fatalf("wire ports = %#x/%#x, want stamped NAT ports", wireKey.SrcPort, wireKey.DstPort)
	}
	if wireVal.NATSrcIP != val.NATSrcIP || wireVal.Flags != val.Flags {
		t.Fatal("alias must carry the base value through")
	}
	if _, _, ok := userspaceForwardWireAliasV4(key, dataplane.SessionValue{}); ok {
		t.Fatal("alias without NAT flags, want none")
	}
	natSrc := net.ParseIP("2001:db8:61::1").To16()
	natDst := net.ParseIP("2001:db8:61::102").To16()
	if natSrc == nil || natDst == nil {
		t.Fatal("fixture: v6 literals do not parse")
	}
	var key6 dataplane.SessionKeyV6
	key6.Protocol = 6
	var val6 dataplane.SessionValueV6
	val6.Flags = dataplane.SessFlagSNAT | dataplane.SessFlagDNAT
	copy(val6.NATSrcIP[:], natSrc)
	copy(val6.NATDstIP[:], natDst)
	val6.NATSrcPort = userspaceHostToNetwork16(54321)
	val6.NATDstPort = userspaceHostToNetwork16(8443)
	wireKey6, _, ok := userspaceForwardWireAliasV6(key6, val6)
	if !ok {
		t.Fatal("NAT v6 value produced no alias, want one")
	}
	if wireKey6.SrcIP != val6.NATSrcIP || wireKey6.DstIP != val6.NATDstIP {
		t.Fatalf("v6 wire addrs = %x/%x, want NATSrc/NATDst", wireKey6.SrcIP, wireKey6.DstIP)
	}
	if wireKey6.SrcPort != userspaceHostToNetwork16(54321) || wireKey6.DstPort != userspaceHostToNetwork16(8443) {
		t.Fatalf("v6 wire ports = %#x/%#x, want stamped NAT ports", wireKey6.SrcPort, wireKey6.DstPort)
	}
	if _, _, ok := userspaceForwardWireAliasV6(key6, dataplane.SessionValueV6{}); ok {
		t.Fatal("v6 alias without NAT flags, want none")
	}
}

// TestNAT64SnatFlagGate9905 pins the per-leg NAT64 gating intent (#9905
// review F2). Base evidence (609433efb): convert had ONE NAT64 site,
// flag-blind `ParseIP(delta.Nat64SnatV4)` at
// daemon_ha_userspace_convert.go:575, through which BOTH string sources
// flowed (strings were the only carrier — no BinAddrLen existed); the
// binary-decoded string was decode-gated on flag && nonzero at
// eventstream.go:1553-1554, while JSON carried producer bytes. Post-change
// equivalence: binary honors the flag explicitly (a flagless bin never
// stamps), string stays flag-blind (legacy fallback).
func TestNAT64SnatFlagGate9905(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	// String leg, flag unset, snat present → stamps (flag-blind legacy).
	s := transitOpenV6_9767()
	s.Nat64 = false
	s.Nat64SnatV4 = "203.0.113.5"
	_, sv, ok := userspaceSessionFromDeltaV6(s, zoneIDs)
	if !ok {
		t.Fatal("string-leg NAT64 delta did not convert")
	}
	if sv.Nat64SnatV4 != [4]byte{203, 0, 113, 5} {
		t.Fatalf("string-leg Nat64SnatV4 = %v, want 203.0.113.5 (flag-blind)", sv.Nat64SnatV4)
	}
	// Binary leg, flag unset, bin present → does NOT stamp (decode gate).
	b := transitOpenV6_9767()
	b.SrcIP, b.DstIP = "", ""
	b.NeighborMAC, b.SrcMAC = "", ""
	b.Nat64SnatV4 = ""
	src := net.ParseIP("2001:559:8585:bf01::102").To16()
	dst := net.ParseIP("2001:559:8585:80::200").To16()
	if src == nil || dst == nil {
		t.Fatal("fixture: v6 literals do not parse")
	}
	copy(b.SrcAddr[:], src)
	copy(b.DstAddr[:], dst)
	b.BinAddrLen = 16
	b.Nat64 = false
	b.Nat64SnatV4Bin = [4]byte{203, 0, 113, 5}
	_, bv, ok := userspaceSessionFromDeltaV6(b, zoneIDs)
	if !ok {
		t.Fatal("binary-leg delta did not convert (addrs valid, want convert)")
	}
	if bv.Nat64SnatV4 != [4]byte{} {
		t.Fatalf("binary-leg Nat64SnatV4 = %v, want zero (flag gate)", bv.Nat64SnatV4)
	}
	// Resolver-level presence pins: a zero final value cannot distinguish
	// absence from copying zero, so assert hasNat64Snat directly, both legs.
	// Binary, flag true + zero bin → absent (zero means no pool source).
	bz := transitOpenV6_9767()
	bz.SrcIP, bz.DstIP = "", ""
	bz.NeighborMAC, bz.SrcMAC = "", ""
	bz.Nat64SnatV4 = ""
	copy(bz.SrcAddr[:], src)
	copy(bz.DstAddr[:], dst)
	bz.BinAddrLen = 16
	bz.Nat64 = true
	bz.Nat64SnatV4Bin = [4]byte{}
	rz := userspaceResolveV6(bz)
	if !rz.ok {
		t.Fatal("binary flag-true/zero delta did not resolve addrs")
	}
	if rz.hasNat64Snat {
		t.Fatal("binary flag-true/zero must be absent (hasNat64Snat=false)")
	}
	// Binary, flag true + nonzero bin → present (positive control).
	bp := bz
	bp.Nat64SnatV4Bin = [4]byte{203, 0, 113, 5}
	rp := userspaceResolveV6(bp)
	if !rp.hasNat64Snat || rp.nat64Snat != [4]byte{203, 0, 113, 5} {
		t.Fatalf("binary flag-true/nonzero presence = (%v,%v), want (true,203.0.113.5)", rp.hasNat64Snat, rp.nat64Snat)
	}
	// String, flag true + empty → absent.
	se := transitOpenV6_9767()
	se.Nat64 = true
	se.Nat64SnatV4 = ""
	re := userspaceResolveV6(se)
	if !re.ok {
		t.Fatal("string flag-true/empty delta did not resolve addrs")
	}
	if re.hasNat64Snat {
		t.Fatal("string flag-true/empty must be absent (hasNat64Snat=false)")
	}
	// String present-but-zero ("0.0.0.0") → present with verbatim zero
	// bytes: presence is ParseIP!=nil, not nonzero. This is the case that
	// proves presence≠nonzero on the string leg.
	sz := transitOpenV6_9767()
	sz.Nat64SnatV4 = "0.0.0.0"
	rz2 := userspaceResolveV6(sz)
	if !rz2.hasNat64Snat {
		t.Fatal(`string "0.0.0.0" must be present (hasNat64Snat=true)`)
	}
	if rz2.nat64Snat != [4]byte{} {
		t.Fatalf("string zero snat bytes = %v, want verbatim zero", rz2.nat64Snat)
	}
}

// TestForwardWireAliasFallsBackToBasePort9905 pins the subtlest from-value
// equivalence (#9905 review F7): with NAT present but a zero raw NAT port,
// the effective port falls back to the base port, and the forward-wire key
// must carry that fallback — wire.SrcPort == htons(base SrcPort).
// Present-but-zero-port NAT on a fabric delta exercises the full chain:
// resolve (fallback) → value stamp → wire derivation, with no delta re-read.
// FabricRedirect on the fixtures is context-only (walk reads it before
// calling Alias; this cell drives Alias directly and passes identically
// without it).
func TestForwardWireAliasFallsBackToBasePort9905(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	d := transitOpen9767()
	d.NATSrcIP = "192.0.2.7"
	d.NATSrcPort = 0 // present address, zero raw port → fallback
	d.FabricRedirect = true
	key, val, ok := userspaceSessionFromDeltaV4(d, zoneIDs)
	if !ok {
		t.Fatal("address-only-NAT delta did not convert")
	}
	if val.NATSrcPort != userspaceHostToNetwork16(d.SrcPort) {
		t.Fatalf("value NATSrcPort = %#x, want htons(%d) fallback", val.NATSrcPort, d.SrcPort)
	}
	wireKey, _, ok := userspaceForwardWireAliasV4(key, val)
	if !ok {
		t.Fatal("address-only-NAT delta produced no alias")
	}
	if wireKey.SrcIP != [4]byte{192, 0, 2, 7} {
		t.Fatalf("wire SrcIP = %v, want NATSrc", wireKey.SrcIP)
	}
	if wireKey.SrcPort != userspaceHostToNetwork16(d.SrcPort) {
		t.Fatalf("wire SrcPort = %#x, want htons(%d) fallback", wireKey.SrcPort, d.SrcPort)
	}
	// V6 mirror.
	d6 := transitOpenV6_9767()
	d6.NATSrcIP = "2001:db8:61::1"
	d6.NATSrcPort = 0
	d6.FabricRedirect = true
	key6, val6, ok := userspaceSessionFromDeltaV6(d6, zoneIDs)
	if !ok {
		t.Fatal("v6 address-only-NAT delta did not convert")
	}
	wireKey6, _, ok := userspaceForwardWireAliasV6(key6, val6)
	if !ok {
		t.Fatal("v6 address-only-NAT delta produced no alias")
	}
	if wireKey6.SrcPort != userspaceHostToNetwork16(d6.SrcPort) {
		t.Fatalf("v6 wire SrcPort = %#x, want htons(%d) fallback", wireKey6.SrcPort, d6.SrcPort)
	}
	var wantNAT [16]byte
	copy(wantNAT[:], net.ParseIP("2001:db8:61::1").To16())
	if wireKey6.SrcIP != wantNAT {
		t.Fatalf("v6 wire SrcIP = %x, want NATSrc", wireKey6.SrcIP)
	}
}

// TestHandleDeltaWithholdsWithoutConfig9905 pins the daemon side of the
// (gen, nil) snapshot shape: a store with no compiled config (fresh boot,
// first-commit rollback target, failed recovery compile) withholds the
// delta so the helper replays, instead of converting against a nil config.
func TestHandleDeltaWithholdsWithoutConfig9905(t *testing.T) {
	d := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0, 1),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config")),
	}
	ss := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil)
	ss.IsPrimaryFn = func() bool { return true }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 0 || rgID == 1 }
	ss.SetConnectedForTesting(true)
	d.sessionSync = ss
	if gen, cfg := d.store.ActiveSnapshot(); gen != 0 || cfg != nil {
		t.Fatalf("fresh store snapshot = (%d,%v), want (0,nil)", gen, cfg)
	}
	delta := natDelta9905()
	delta.IngressZone = "lan"
	if d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
		t.Fatal("delta with no compiled config was handled, want withhold (false)")
	}
	// Warm-cache variant: the same store after a first-commit rollback —
	// snapshot (gen≥1, nil) with a stale-but-pinned warm entry. The
	// handler must still withhold (not convert against nil) and must not
	// clobber the warm entry with a nil build.
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	d2 := &Daemon{
		cluster: clusterManagerPrimaryForRGs(0, 1),
		store:   store,
	}
	ss2 := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil)
	ss2.IsPrimaryFn = func() bool { return true }
	ss2.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 0 || rgID == 1 }
	ss2.SetConnectedForTesting(true)
	d2.sessionSync = ss2
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-9905",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set security zones security-zone lan",
		"set security zones security-zone wan",
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	g1, c1 := store.ActiveSnapshot()
	if g1 == 0 || c1 == nil {
		t.Fatalf("post-confirm snapshot = (%d,%v), want (nonzero,non-nil)", g1, c1)
	}
	dl := natDelta9905()
	dl.IngressZone = "lan"
	if !d2.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, dl) {
		t.Fatal("warmup delta withheld, want handled")
	}
	e1 := d2.userspaceZoneIDs.Load()
	if e1 == nil || e1.gen != g1 {
		t.Fatal("no warm cache entry after handled delta")
	}
	prevCfg, ok := store.PromoteRollback(store.ConfirmGenForTesting())
	if !ok {
		t.Fatal("PromoteRollback: ok=false, want true")
	}
	if prevCfg != nil {
		t.Fatalf("prevCfg = %v, want nil (first-commit rollback)", prevCfg)
	}
	g2, c2 := store.ActiveSnapshot()
	if g2 != g1+1 || c2 != nil {
		t.Fatalf("post-rollback snapshot = (%d,%v), want (%d,nil)", g2, c2, g1+1)
	}
	if d2.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, dl) {
		t.Fatal("delta with nil snapshot was handled, want withhold (false)")
	}
	if e := d2.userspaceZoneIDs.Load(); e != e1 {
		t.Fatal("warm entry clobbered by nil snapshot (want pointer stability)")
	}
}
