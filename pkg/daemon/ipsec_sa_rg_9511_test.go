// #9511: the peer advertises CHILD SA names (ipsec.ActiveConnectionNames), and a
// VPN with traffic-selector entries renders one child `<vpn>-<selector>` per
// selector and no child named `<vpn>`. The #9139 attribution looked names up as
// VPN names only, so every multi-selector VPN fell to RG 0 and BOTH per-RG
// failover answers were wrong:
//
//   - taking the VPN's RG while the peer keeps RG0: attributed to RG0, which this
//     node does not own, so the tunnel is SKIPPED — the #9139 blackhole, still
//     live for these VPNs;
//   - taking RG0 while the peer keeps the VPN's RG: attributed to RG0, which this
//     node does own, so the tunnel is INITIATED — a second IKE SA to the same
//     remote from a different local address.
//
// RG0 is DECLARED in these fixtures on purpose. With RG0 undeclared the first
// case falls through to IsLocalPrimaryAny and initiates by accident, which would
// hide the defect.

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/ipsec"
	"golang.org/x/sync/semaphore"
)

var clusterTwoRethIPsec9511 = []string{
	"set chassis cluster cluster-id 1",
	"set chassis cluster node 0",
	"set chassis cluster authentication-key test-cluster-psk-9511",
	"set chassis cluster ipsec-session-synchronization",
	"set chassis cluster redundancy-group 0 node 0 priority 1",
	"set chassis cluster redundancy-group 1 node 0 priority 200",
	"set chassis cluster redundancy-group 2 node 0 priority 100",
	"set interfaces reth1 redundant-ether-options redundancy-group 1",
	"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
	"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	"set interfaces reth2 redundant-ether-options redundancy-group 2",
	"set interfaces reth2 unit 0 family inet address 10.0.2.1/24",
	"set interfaces ge-0/0/1 gigether-options redundant-parent reth2",
	"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
	"set security ike gateway gw-rg1 address 198.51.100.1",
	"set security ike gateway gw-rg1 external-interface reth1.0",
	"set security ike gateway gw-rg2 address 198.51.100.2",
	"set security ike gateway gw-rg2 external-interface reth2.0",
	"set security ike gateway gw-plain address 198.51.100.3",
	"set security ike gateway gw-plain external-interface ge-0/0/3.0",
}

func multiSelectorIPsecStore9511(t *testing.T) *configstore.Store {
	t.Helper()
	store := testStoreWithSetConfig(t, append(append([]string{}, clusterTwoRethIPsec9511...),
		// The subject: two selectors, anchored on the RG1 reth.
		"set security ipsec vpn vpn-ms ike gateway gw-rg1",
		"set security ipsec vpn vpn-ms traffic-selector ts1 local-ip 10.0.1.0/24",
		"set security ipsec vpn vpn-ms traffic-selector ts1 remote-ip 10.9.1.0/24",
		"set security ipsec vpn vpn-ms traffic-selector ts2 local-ip 10.0.11.0/24",
		"set security ipsec vpn vpn-ms traffic-selector ts2 remote-ip 10.9.2.0/24",
		// Controls: no selector (child name == VPN name) on RG1 and RG2, and an
		// unanchored VPN that follows RG0.
		"set security ipsec vpn vpn-rg1 ike gateway gw-rg1",
		"set security ipsec vpn vpn-rg2 ike gateway gw-rg2",
		"set security ipsec vpn vpn-plain ike gateway gw-plain",
	))
	cfg := store.ActiveConfig()
	vpn := cfg.Security.IPsec.VPNs["vpn-ms"]
	if vpn == nil || len(vpn.TrafficSelectors) != 2 {
		t.Fatalf("FIXTURE: vpn-ms must compile with 2 traffic-selectors, got %+v — "+
			"without them its child names equal its VPN name and every cell below "+
			"passes on the pre-#9511 lookup", vpn)
	}
	if got := ipsecSANameIndex(cfg).VPNs("vpn-ms-ts1"); len(got) != 1 || got[0] != "vpn-ms" {
		t.Fatalf("FIXTURE: vpn-ms-ts1 must be a RENDERED child of vpn-ms, got %v — a "+
			"VPN the renderer skipped would leave the index empty and the cells "+
			"below would measure the fallback", got)
	}
	if !cfg.Chassis.Cluster.IPsecSASync {
		t.Fatal("FIXTURE: ipsec-sa-sync must be on, or the re-initiate leg is gated off")
	}
	return store
}

func clusterOwning9511(t *testing.T, store *configstore.Store, owned ...int) *cluster.Manager {
	t.Helper()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	for _, rg := range []int{0, 1, 2} {
		state := cluster.StateSecondary
		for _, o := range owned {
			if o == rg {
				state = cluster.StatePrimary
			}
		}
		cm.SetGroupStateForTesting(rg, state)
	}
	if _, known := cm.LocalGroupPrimary(0); !known {
		t.Fatal("FIXTURE: RG0 must be declared, or an RG0-attributed tunnel is " +
			"initiated by the undeclared-RG0 fallback and the cell cannot see the defect")
	}
	return cm
}

func TestIPsecConnRedundancyGroupsResolveChildSAName9511(t *testing.T) {
	cfg := multiSelectorIPsecStore9511(t).ActiveConfig()
	idx := ipsecSANameIndex(cfg)
	for _, tc := range []struct {
		conn string
		want int
		why  string
	}{
		{"vpn-ms-ts1", 1, "child of the two-selector VPN anchored on reth1 (RG1)"},
		{"vpn-ms-ts2", 1, "the second child of the same VPN"},
		{"vpn-ms", 1, "the IKE SA name of the same VPN before any child exists"},
		{"vpn-rg1", 1, "CONTROL: no selector, child name == VPN name — unchanged"},
		{"vpn-rg2", 2, "CONTROL: no selector on reth2 — unchanged"},
		{"vpn-plain", 0, "CONTROL: unanchored — RG0 default, unchanged"},
		{"vpn-ms-ts3", 0, "a name no VPN renders keeps the RG0 default"},
	} {
		if got := ipsecConnRedundancyGroups(cfg, idx, tc.conn); len(got) != 1 || got[0] != tc.want {
			t.Errorf("ipsecConnRedundancyGroups(%q) = %v, want [%d] (%s)",
				tc.conn, got, tc.want, tc.why)
		}
	}
}

// Case 1 through the real per-RG MASTER edge: this node takes RG1 while the LIVE
// peer keeps RG0 and RG2. The tunnel anchored on RG1 must come back, and the
// names that reach swanctl must be the CHILD names the peer advertised — the VPN
// name would name no child section and the initiate would fail.
func TestApplyRethServicesForRGReinitiatesMultiSelectorVPN9511(t *testing.T) {
	store := multiSelectorIPsecStore9511(t)
	cm := clusterOwning9511(t, store, 1)

	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-ms-ts1", "vpn-ms-ts2", "vpn-rg2"})
	initiated := make(chan string, 8)
	d := &Daemon{
		cluster:         cm,
		store:           store,
		sessionSync:     ss,
		ipsecInitiateFn: func(name string) error { initiated <- name; return nil },
	}

	d.applyRethServicesForRG(1)

	// The leg runs on its own goroutine. Wait for the EXPECTED count rather than
	// for a quiet period, so a slow scheduler cannot end the wait early; the
	// deadline only bounds the failing case. Then give a late EXTRA initiate
	// (vpn-rg2, or a VPN name) a short window to show up. The synchronous filter
	// cell below pins exactness independently of this timing.
	want := []string{"vpn-ms-ts1", "vpn-ms-ts2"}
	var got []string
	deadline := time.After(5 * time.Second)
collect:
	for len(got) < len(want) {
		select {
		case name := <-initiated:
			got = append(got, name)
		case <-deadline:
			break collect
		}
	}
	settle := time.After(300 * time.Millisecond)
extra:
	for {
		select {
		case name := <-initiated:
			got = append(got, name)
		case <-settle:
			break extra
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("#9511: taking RG1 must initiate exactly the RG1 VPN's CHILD SAs.\n"+
			"  got  %v\n  want %v\n"+
			"  Empty means the child names were attributed to RG0, which the peer "+
			"holds, so the tunnel stays down until the remote initiates. vpn-ms "+
			"(the VPN name) would name no child section. vpn-rg2 belongs to RG2, "+
			"which the live peer still holds.", got, want)
	}
}

// Case 2: this node takes RG0 while the LIVE peer keeps RG1. The multi-selector
// VPN on RG1 must be skipped; the unanchored VPN must be initiated, which is what
// makes an empty answer for vpn-ms observable rather than a filter returning
// nothing at all.
func TestIPsecSAsToReinitiateSkipsMultiSelectorVPNOnRG0Takeover9511(t *testing.T) {
	store := multiSelectorIPsecStore9511(t)
	d := &Daemon{cluster: clusterOwning9511(t, store, 0), store: store}

	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-ms-ts1", "vpn-ms-ts2", "vpn-plain"})
	got := d.ipsecSAsToReinitiate(ss.PeerIPsecSAs())

	if len(got) != 1 || got[0] != "vpn-plain" {
		t.Fatalf("#9511: an RG0 takeover must not initiate a tunnel anchored on RG1, "+
			"which the live peer still holds.\n  got  %v\n  want [vpn-plain]\n"+
			"  vpn-ms-ts* here means the child names fell to the RG0 default: a "+
			"second IKE SA to the same remote from a different local address.", got)
	}
}

// Two VPNs can render the SAME SA name: VPN blue (RG1) with selector red renders
// child blue-red, and VPN blue-red (RG2, no selector) renders a connection and a
// child of that name. Nothing in the name says which one the peer's swanctl
// reported, so a node may initiate it only if it owns BOTH candidates' groups.
// Resolving the exact VPN name first (the first version of this fix) answered
// RG2 alone, and a node owning only RG2 would initiate blue's child as well.
func TestIPsecSANameRenderedByTwoVPNsNeedsEveryCandidateRG9511(t *testing.T) {
	store := testStoreWithSetConfig(t, append(append([]string{}, clusterTwoRethIPsec9511...),
		"set security ipsec vpn blue ike gateway gw-rg1",
		"set security ipsec vpn blue traffic-selector red local-ip 10.0.1.0/24",
		"set security ipsec vpn blue traffic-selector red remote-ip 10.9.1.0/24",
		"set security ipsec vpn blue traffic-selector green local-ip 10.0.21.0/24",
		"set security ipsec vpn blue traffic-selector green remote-ip 10.9.21.0/24",
		"set security ipsec vpn blue-red ike gateway gw-rg2",
	))
	cfg := store.ActiveConfig()
	idx := ipsecSANameIndex(cfg)
	if got := strings.Join(idx.VPNs("blue-red"), ","); got != "blue,blue-red" {
		t.Fatalf("FIXTURE: blue-red must be rendered by both blue and blue-red, got [%s]", got)
	}
	if got := ipsecConnRedundancyGroups(cfg, idx, "blue-red"); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("an SA name two VPNs render must report both groups, got %v, want [1 2]", got)
	}

	for _, tc := range []struct {
		owned []int
		name  string
		want  bool
		why   string
	}{
		{[]int{1}, "blue-red", false, "owns only blue's RG1; the name may be the RG2 VPN the live peer still holds"},
		{[]int{2}, "blue-red", false, "owns only blue-red's RG2; the name may be blue's RG1 child (exact-VPN-name-first answered true here)"},
		{[]int{1, 2}, "blue-red", true, "owns every candidate's group"},
		{[]int{1}, "blue-green", true, "CONTROL: rendered only by blue, so owning RG1 is enough"},
	} {
		d := &Daemon{cluster: clusterOwning9511(t, store, tc.owned...), store: store}
		if got := d.ownsIPsecConn(cfg, idx, tc.name); got != tc.want {
			t.Errorf("owning RGs %v, ownsIPsecConn(%q) = %v, want %v: %s",
				tc.owned, tc.name, got, tc.want, tc.why)
		}
	}
}

// A name whose candidates span RG0 and RG1 with RG0 UNDECLARED: the undeclared-RG0
// fallback ("primary for anything") is not exclusive ownership, so a node holding
// only RG1 must not initiate a name that may be the live peer's unanchored
// tunnel. A UNIQUE unanchored name keeps the historical fallback (the control).
func TestAmbiguousSANameNeedsDeclaredRG0_9511(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-9511",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
		"set security ike gateway gw-rg1 address 198.51.100.1",
		"set security ike gateway gw-rg1 external-interface reth1.0",
		"set security ike gateway gw-plain address 198.51.100.3",
		"set security ike gateway gw-plain external-interface ge-0/0/3.0",
		"set security ipsec vpn blue ike gateway gw-rg1",
		"set security ipsec vpn blue traffic-selector red local-ip 10.0.1.0/24",
		"set security ipsec vpn blue traffic-selector red remote-ip 10.9.1.0/24",
		"set security ipsec vpn blue-red ike gateway gw-plain",
		"set security ipsec vpn lone ike gateway gw-plain",
	})
	cfg := store.ActiveConfig()
	idx := ipsecSANameIndex(cfg)
	if got := ipsecConnRedundancyGroups(cfg, idx, "blue-red"); len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("FIXTURE: blue-red must span RG0 (the unanchored VPN blue-red) and RG1 "+
			"(blue's child), got %v", got)
	}
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	if _, known := cm.LocalGroupPrimary(0); known {
		t.Fatal("FIXTURE: RG0 must be UNDECLARED, or the fallback this cell is about is never reached")
	}
	d := &Daemon{cluster: cm, store: store}

	if d.ownsIPsecConn(cfg, idx, "blue-red") {
		t.Error("#9511: with RG0 undeclared, a node holding only RG1 claimed a name that " +
			"may be the live peer's unanchored tunnel. \"Primary for anything\" is not " +
			"exclusive ownership of RG0.")
	}
	if !d.ownsIPsecConn(cfg, idx, "lone") {
		t.Error("CONTROL: a UNIQUE unanchored name must keep the historical undeclared-RG0 " +
			"fallback (#9139), or every such tunnel stops being re-initiated")
	}
}

// The index is built once per ACTIVE CONFIG. A takeover wave runs one re-initiate
// pass per redundancy group; rebuilding each time would re-render every VPN and
// repeat every warning. A new active config must rebuild, or names would be
// attributed against a VPN set that no longer exists.
func TestCachedIPsecSANameIndexBuildsOncePerActiveConfig9511(t *testing.T) {
	store := multiSelectorIPsecStore9511(t)
	d := &Daemon{store: store}
	cfg := store.ActiveConfig()

	first := d.cachedIPsecSANameIndex(cfg)
	if again := d.cachedIPsecSANameIndex(cfg); fmt.Sprintf("%p", again) != fmt.Sprintf("%p", first) {
		t.Error("the same active config must reuse its index rather than re-render every VPN")
	}
	other := multiSelectorIPsecStore9511(t).ActiveConfig()
	rebuilt := d.cachedIPsecSANameIndex(other)
	if fmt.Sprintf("%p", rebuilt) == fmt.Sprintf("%p", first) {
		t.Error("a new active config must rebuild the index; reusing it would attribute " +
			"names against the previous VPN set")
	}
	if got := rebuilt.VPNs("vpn-ms-ts1"); len(got) != 1 || got[0] != "vpn-ms" {
		t.Errorf("the rebuilt index lost vpn-ms-ts1: %v", got)
	}
	// `other` is not this daemon's ACTIVE config, so the pass above must not
	// have been installed: a pass holding a replaced config evicting the active
	// entry would force the next takeover pass to re-render everything again.
	if back := d.cachedIPsecSANameIndex(cfg); fmt.Sprintf("%p", back) != fmt.Sprintf("%p", first) {
		t.Error("a pass on a config that is not the store's active config evicted the " +
			"active entry; it must be answered without being installed")
	}
}

// A takeover wave starts one re-initiate goroutine per redundancy group, so the
// cache is typically COLD for several concurrent callers at once. Every one of them
// must get the single installed index. Two distinct indexes mean two full renders
// and two copies of every warning, which is what the cache is for.
//
// Detecting UNserialised misses needs the builds to overlap. Round 7 of the #9511
// mutation matrix showed a 40-VPN build is short enough for a loaded machine to run
// the callers one after another, so the mutant with the miss mutex removed escaped.
// The config therefore carries 120 VPNs, which lengthens every build, and the check
// repeats over 10 fresh cold starts, failing on the first one that yields more than one
// index.
func TestCachedIPsecSANameIndexColdMissesBuildOnce9511(t *testing.T) {
	lines := append([]string{}, clusterTwoRethIPsec9511...)
	for i := 0; i < 120; i++ {
		v := fmt.Sprintf("vpn-gen%03d", i)
		lines = append(lines,
			"set security ipsec vpn "+v+" ike gateway gw-rg1",
			fmt.Sprintf("set security ipsec vpn %s traffic-selector a local-ip 10.1.%d.0/24", v, i),
			fmt.Sprintf("set security ipsec vpn %s traffic-selector a remote-ip 10.2.%d.0/24", v, i),
			fmt.Sprintf("set security ipsec vpn %s traffic-selector b local-ip 10.3.%d.0/24", v, i),
			fmt.Sprintf("set security ipsec vpn %s traffic-selector b remote-ip 10.4.%d.0/24", v, i),
		)
	}
	store := testStoreWithSetConfig(t, lines)
	cfg := store.ActiveConfig()
	if got := len(cfg.Security.IPsec.VPNs); got != 120 {
		t.Fatalf("FIXTURE: expected 120 VPNs, got %d", got)
	}

	const callers, trials = 16, 10
	for trial := 0; trial < trials; trial++ {
		d := &Daemon{store: store}
		results := make([]string, callers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i] = fmt.Sprintf("%p", d.cachedIPsecSANameIndex(cfg))
			}(i)
		}
		close(start)
		wg.Wait()

		distinct := map[string]bool{}
		for _, r := range results {
			distinct[r] = true
		}
		if len(distinct) != 1 {
			t.Fatalf("cold start %d: %d concurrent callers built %d distinct indexes; a takeover "+
				"wave would re-render every VPN and repeat every warning once per RG",
				trial, callers, len(distinct))
		}
		if got := d.cachedIPsecSANameIndex(cfg).VPNs("vpn-gen007-b"); len(got) != 1 || got[0] != "vpn-gen007" {
			t.Fatalf("cold start %d: the installed index lost vpn-gen007-b: %v", trial, got)
		}
	}
}

// ── LOADED GENERATION (#9511 option B) ────────────────────────────────────────
//
// A commit is promoted BEFORE its IPsec apply, and a failed render or reload leaves
// the PREVIOUS swanctl generation loaded. The cells below give the daemon a promoted
// config C1 and a loaded generation C0 that differ, and assert that attribution
// follows C0. Scenarios S1 and S2 are the two the narrow check found:
// docs/log/9511.md walks both against master, and S2 was the state where the
// promoted-config index was WORSE than master.

func storeWith9511(t *testing.T, vpnLines ...string) *configstore.Store {
	t.Helper()
	return testStoreWithSetConfig(t, append(append([]string{}, clusterTwoRethIPsec9511...), vpnLines...))
}

var blueOnRG1_9511 = []string{
	"set security ipsec vpn blue ike gateway gw-rg1",
	"set security ipsec vpn blue traffic-selector red local-ip 10.0.1.0/24",
	"set security ipsec vpn blue traffic-selector red remote-ip 10.9.1.0/24",
}

func reinitiatesFor9511(t *testing.T, promoted, loaded *configstore.Store, name string, owned ...int) bool {
	t.Helper()
	d := &Daemon{cluster: clusterOwning9511(t, promoted, owned...), store: promoted}
	if loaded != nil {
		d.ipsecLoadedCfg.Store(loaded.ActiveConfig())
	}
	got := d.ipsecSAsToReinitiate([]string{name})
	return len(got) == 1 && got[0] == name
}

// S1, failed addition: C1 adds VPN blue-red on RG2, but the loaded generation C0 has
// only blue, so blue-red is blue's RG1 child.
func TestIPsecAttributionFollowsLoadedGenerationOnFailedAddition9511(t *testing.T) {
	c0 := storeWith9511(t, blueOnRG1_9511...)
	c1 := storeWith9511(t, append(append([]string{}, blueOnRG1_9511...),
		"set security ipsec vpn blue-red ike gateway gw-rg2")...)
	if !reinitiatesFor9511(t, c1, c0, "blue-red", 1) {
		t.Error("S1: owning RG1 with C0 loaded, blue-red is blue's RG1 child and must be " +
			"re-initiated; the promoted C1 made it ambiguous with a VPN charon never loaded")
	}
	if reinitiatesFor9511(t, c1, c0, "blue-red", 2) {
		t.Error("S1: owning only RG2, blue-red must not be initiated; RG2 has no VPN of " +
			"that name in the loaded generation")
	}
}

// S2, deletion plus failure: C1 deletes VPN blue-red, but the loaded generation C0
// still has it, so blue-red is ambiguous (blue's RG1 child or blue-red's RG2
// tunnel). Owning only RG1 MUST skip. This is the state where attributing from
// the promoted config initiated, and master did not.
func TestIPsecAttributionFollowsLoadedGenerationOnFailedDeletion9511(t *testing.T) {
	c0 := storeWith9511(t, append(append([]string{}, blueOnRG1_9511...),
		"set security ipsec vpn blue-red ike gateway gw-rg2")...)
	c1 := storeWith9511(t, blueOnRG1_9511...)
	if reinitiatesFor9511(t, c1, c0, "blue-red", 1) {
		t.Error("S2: owning only RG1 initiated blue-red, which the LOADED generation " +
			"still renders for blue-red's RG2 tunnel as well; the live peer holds RG2")
	}
	if !reinitiatesFor9511(t, c1, c0, "blue-red", 1, 2) {
		t.Error("S2: owning RG1 and RG2 covers every candidate in the loaded generation " +
			"and must initiate")
	}
}

// Gateway RG move under a failed apply: C1 moves VPN mover from reth1 to reth2, but
// C0 is loaded, so the SA still binds the RG1 address.
func TestIPsecAttributionFollowsLoadedGenerationOnRGMove9511(t *testing.T) {
	c0 := storeWith9511(t, "set security ipsec vpn mover ike gateway gw-rg1")
	c1 := storeWith9511(t, "set security ipsec vpn mover ike gateway gw-rg2")
	if !reinitiatesFor9511(t, c1, c0, "mover", 1) {
		t.Error("RG move: the loaded SA binds reth1 (RG1); owning RG1 must initiate it")
	}
	if reinitiatesFor9511(t, c1, c0, "mover", 2) {
		t.Error("RG move: owning only RG2 must not initiate a tunnel still loaded on RG1")
	}
}

// A name the loaded generation does not render is ROUTINE (the peer loaded a newer
// generation first). It keeps the pre-#9511 lookup and the RG 0 default rather than
// being attributed against the promoted config.
func TestIPsecAttributionAbsentNameKeepsTheRG0Default9511(t *testing.T) {
	c0 := storeWith9511(t, blueOnRG1_9511...)
	c1 := storeWith9511(t, append(append([]string{}, blueOnRG1_9511...),
		"set security ipsec vpn newx ike gateway gw-rg1")...)
	if reinitiatesFor9511(t, c1, c0, "newx", 1) {
		t.Error("newx is not in the loaded generation, so it must take the RG 0 default; " +
			"owning RG1 without RG0 must skip it rather than attribute it through the " +
			"promoted config")
	}
	if !reinitiatesFor9511(t, c1, c0, "newx", 0) {
		t.Error("newx takes the RG 0 default, so owning RG0 must initiate it (pre-#9511 " +
			"behaviour for a name the lookup cannot place)")
	}
}

// The wiring: applyIPsecTracked records the config only when strongSwan LOADED it.
// It is driven through a real ipsec.Manager with a swanctl double. The last case
// is teardown debt after a successful reload, whose Apply error must NOT stop the
// record.
func TestApplyIPsecTrackedRecordsOnlyALoadedGeneration9511(t *testing.T) {
	store := multiSelectorIPsecStore9511(t)
	cfg := store.ActiveConfig()
	m := ipsec.NewWithConfigDir(t.TempDir())
	d := &Daemon{store: store, ipsec: m}

	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			return nil, errors.New("charon vici socket refused")
		}
		return nil, nil
	})
	if err := d.applyIPsecTracked(cfg); err == nil {
		t.Fatal("FIXTURE: the reload must fail")
	}
	if d.ipsecLoadedCfg.Load() != nil {
		t.Error("a failed reload recorded the config as loaded; charon still runs the previous generation")
	}
	if d.ipsecAttributionConfig() != cfg {
		t.Error("before any load in this process, attribution falls back to the promoted " +
			"config (the #9641 residual, the same answer master gives)")
	}

	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) { return nil, nil })
	if err := d.applyIPsecTracked(cfg); err != nil {
		t.Fatalf("FIXTURE: the reload must succeed, got %v", err)
	}
	if d.ipsecLoadedCfg.Load() != cfg {
		t.Fatal("a successful reload must record the config it loaded")
	}

	next := storeWith9511(t, blueOnRG1_9511...).ActiveConfig()
	// Hold the teardown OPEN, as a slow terminate would, and read the attribution
	// source from ANOTHER goroutine meanwhile, the way a failover re-initiation
	// that does not hold applySem would.
	teardownStarted := make(chan struct{}, 1)
	release := make(chan struct{})
	seenDuringTeardown := make(chan *config.Config, 1)
	go func() {
		select {
		case <-teardownStarted:
			seenDuringTeardown <- d.ipsecAttributionConfig()
		case <-time.After(5 * time.Second):
			seenDuringTeardown <- nil
		}
		close(release)
	}()
	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) {
		switch {
		case len(args) > 0 && args[0] == "--list-sas":
			return []byte("vpn-rg1: #1, ESTABLISHED, IKEv2, 8f7c1c8e3a2b1234_i* 4d3c2b1a09876543_r\n"), nil
		case len(args) > 0 && args[0] == "--terminate":
			teardownStarted <- struct{}{}
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			}
			return nil, errors.New("terminate refused")
		}
		return nil, nil
	})
	err := d.applyIPsecTracked(next)
	if err == nil {
		t.Fatal("FIXTURE: dropping the live vpn-rg1 with a refused terminate must return teardown debt")
	}
	if got := <-seenDuringTeardown; got != next {
		t.Error("while the teardown was held open, a concurrent reader still attributed " +
			"against the PREVIOUS generation; charon already ran the new one, and re-initiation " +
			"does not hold applySem")
	}
	if d.ipsecLoadedCfg.Load() != next {
		t.Errorf("teardown debt after a SUCCESSFUL reload still loaded the new generation; "+
			"reading \"loaded\" off Apply's error pinned the previous one (err: %v)", err)
	}
}

// The cache's stale-install guard must key on the ATTRIBUTION config. With a loaded
// generation C0 recorded and a different promoted config C1, every pass attributes
// against C0; a guard keyed on the promoted config would refuse to install C0's
// index, so each pass of a takeover wave would re-render every VPN again.
func TestCachedIPsecSANameIndexReusesTheLoadedGenerationIndex9511(t *testing.T) {
	c0 := storeWith9511(t, blueOnRG1_9511...)
	c1 := storeWith9511(t, append(append([]string{}, blueOnRG1_9511...),
		"set security ipsec vpn newx ike gateway gw-rg1")...)
	d := &Daemon{store: c1}
	d.ipsecLoadedCfg.Store(c0.ActiveConfig())
	src := d.ipsecAttributionConfig()
	if src != c0.ActiveConfig() || src == c1.ActiveConfig() {
		t.Fatal("FIXTURE: attribution must read the loaded generation C0, not the promoted C1")
	}

	first := d.cachedIPsecSANameIndex(src)
	if again := d.cachedIPsecSANameIndex(src); fmt.Sprintf("%p", again) != fmt.Sprintf("%p", first) {
		t.Error("with a loaded generation recorded, repeated passes must reuse its index; " +
			"the install guard compared against the promoted config instead")
	}
	// A pass holding the PROMOTED config is not the attribution source and must not
	// evict the loaded generation's entry.
	_ = d.cachedIPsecSANameIndex(c1.ActiveConfig())
	if back := d.cachedIPsecSANameIndex(src); fmt.Sprintf("%p", back) != fmt.Sprintf("%p", first) {
		t.Error("a pass on the promoted config evicted the loaded generation's index")
	}
}

// ── WIRING (R4-F3) ────────────────────────────────────────────────────────────
//
// applyIPsecTracked is only as good as the call sites that use it. The #4899
// lease-rebind cells replace the apply with the ipsecApply seam, which bypasses the
// tracking, so these cells drive both production call sites through a REAL
// ipsec.Manager with a swanctl double. Reverting either site to an untracked apply
// leaves ipsecLoadedCfg empty and fails the matching cell.

func successfulSwanctl9511(args ...string) ([]byte, error) { return nil, nil }

// The commit/apply path: applyConfigLocked's IPsec step.
func TestApplyConfigLockedRecordsTheLoadedIPsecGeneration9511(t *testing.T) {
	d, cfg := minimalNetworkdDaemon(t, t.TempDir(), &dataplane.ApplyResult{})
	m := ipsec.NewWithConfigDir(t.TempDir())
	m.SetSwanctlForTesting(successfulSwanctl9511)
	d.ipsec = m
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn1": {Gateway: "198.51.100.1"},
	}
	_ = d.applyConfigLocked(context.Background(), cfg) // other tail steps may warn; only the IPsec record is under test
	if d.ipsecLoadedCfg.Load() != cfg {
		t.Error("the commit apply loaded the IPsec config but did not record it; HA " +
			"attribution would keep reading the previous generation (or the promoted " +
			"fallback) after every commit")
	}
}

// The lease-change rebind path, with the test seam unset (production).
func TestIPsecLeaseChangeApplyRecordsTheLoadedGeneration9511(t *testing.T) {
	store := multiSelectorIPsecStore9511(t)
	cfg := store.ActiveConfig()
	m := ipsec.NewWithConfigDir(t.TempDir())
	m.SetSwanctlForTesting(successfulSwanctl9511)
	d := &Daemon{store: store, ipsec: m}
	if err := d.ipsecApplyForLeaseChange(cfg); err != nil {
		t.Fatalf("FIXTURE: the lease-change apply must succeed, got %v", err)
	}
	if d.ipsecLoadedCfg.Load() != cfg {
		t.Error("the lease-change rebind loaded the IPsec config but did not record it")
	}
}

// The #9641 RESIDUAL, pinned on purpose. With nothing loaded by this process (for
// example after an xpfd restart whose boot IPsec apply failed while charon still
// runs C0), attribution falls back to the PROMOTED config C1. Here that makes an RG1
// owner initiate blue-red, which is ambiguous in C0. Master gives the same answer.
// Refusing to re-initiate was not adopted. Whether it could be, given that a failed
// first boot apply is the only way into this state, is an open question on #9641.
// When #9641 lands, the first half of this cell flips DELIBERATELY.
func TestAttributionFallsBackToPromotedConfigBeforeFirstLoad9511(t *testing.T) {
	c0 := storeWith9511(t, append(append([]string{}, blueOnRG1_9511...),
		"set security ipsec vpn blue-red ike gateway gw-rg2")...)
	c1 := storeWith9511(t, blueOnRG1_9511...)
	if got := strings.Join(ipsecSANameIndex(c0.ActiveConfig()).VPNs("blue-red"), ","); got != "blue,blue-red" {
		t.Fatalf("FIXTURE: blue-red must be ambiguous in the charon-held generation C0, got [%s]", got)
	}
	d := &Daemon{cluster: clusterOwning9511(t, c1, 1), store: c1}

	if got := d.ipsecSAsToReinitiate([]string{"blue-red"}); len(got) != 1 || got[0] != "blue-red" {
		t.Errorf("RESIDUAL (#9641) changed: with nothing loaded, attribution is expected to "+
			"fall back to the promoted C1 and initiate blue-red; got %v. If #9641 landed, "+
			"update this cell deliberately.", got)
	}

	d.ipsecLoadedCfg.Store(c0.ActiveConfig())
	if got := d.ipsecSAsToReinitiate([]string{"blue-red"}); len(got) != 0 {
		t.Errorf("once C0 is recorded as loaded, blue-red is ambiguous and needs RG2 too; "+
			"an RG1-only owner must skip it, got %v", got)
	}
}

// The restart/boot path: a fresh daemon's boot apply (applyActiveConfig under
// applySem) must record the generation it loaded, or every restart would leave
// attribution on the promoted fallback until the next commit.
func TestApplyActiveConfigRecordsTheLoadedIPsecGeneration9511(t *testing.T) {
	d, _ := minimalNetworkdDaemon(t, t.TempDir(), &dataplane.ApplyResult{})
	d.applySem = semaphore.NewWeighted(1)
	d.store = testStoreWithSetConfig(t, []string{
		"set security ike gateway gw1 address 198.51.100.1",
		"set security ipsec vpn vpn1 ike gateway gw1",
	})
	m := ipsec.NewWithConfigDir(t.TempDir())
	m.SetSwanctlForTesting(successfulSwanctl9511)
	d.ipsec = m

	d.applyActiveConfig()
	if active := d.store.ActiveConfig(); active == nil || d.ipsecLoadedCfg.Load() != active {
		t.Error("the boot apply loaded the IPsec config but did not record it; after every " +
			"restart attribution would stay on the promoted fallback until the next commit")
	}
}

// ── FAILED-RELOAD WINDOW (#9511 stopgap) ──────────────────────────────────────
//
// THE WINDOW: xpfd writes the new swanctl file, then its reload FAILS. charon keeps
// running the previous generation C0, but the new file C1 stays on disk, and charon's
// own next start or reload (strongswan.service ExecStartPost/ExecReload
// `swanctl --load-all`, Restart=on-abnormal) loads it. A record still naming C0 would
// attribute against a generation charon no longer runs, which is worse than master.
// Inside this window attribution must equal the PROMOTED-config answer, which is
// master's answer and the generation charon will load.
func TestFailedReloadWindowAttributesLikeThePromotedConfig9511(t *testing.T) {
	c0 := storeWith9511(t, append(append([]string{}, blueOnRG1_9511...),
		"set security ipsec vpn blue-red ike gateway gw-rg2")...)
	c1 := storeWith9511(t, blueOnRG1_9511...)
	names := []string{"blue-red", "blue"}

	m := ipsec.NewWithConfigDir(t.TempDir())
	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			return nil, errors.New("charon vici socket refused")
		}
		return nil, nil
	})
	d := &Daemon{cluster: clusterOwning9511(t, c1, 1), store: c1, ipsec: m}
	d.ipsecLoadedCfg.Store(c0.ActiveConfig()) // a previous successful load of C0

	if err := d.applyIPsecTracked(c1.ActiveConfig()); err == nil {
		t.Fatal("FIXTURE: the reload of C1 must fail")
	}
	if got := d.ipsecLoadedCfg.Load(); got != nil {
		t.Fatalf("THE WINDOW: C1 was written and its reload failed, so charon's next "+
			"start or reload loads C1; the record must be cleared, still holds %p", got)
	}

	got := d.ipsecSAsToReinitiate(names)
	master := (&Daemon{cluster: clusterOwning9511(t, c1, 1), store: c1}).ipsecSAsToReinitiate(names)
	sort.Strings(got)
	sort.Strings(master)
	if strings.Join(got, ",") != strings.Join(master, ",") {
		t.Errorf("THE WINDOW: attribution %v must equal the promoted-config answer %v", got, master)
	}
}

// CONTROL: a WRITE failure changes nothing on disk. charon and the file both still hold
// C0, so the record must stay C0; clearing it here would give up a correct answer.
func TestWriteFailureKeepsTheLoadedRecord9511(t *testing.T) {
	c0 := storeWith9511(t, blueOnRG1_9511...)
	c1 := storeWith9511(t, append(append([]string{}, blueOnRG1_9511...),
		"set security ipsec vpn newx ike gateway gw-rg1")...)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := ipsec.NewWithConfigDir(filepath.Join(blocker, "conf.d"))
	reloads := 0
	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			reloads++
		}
		return nil, nil
	})
	d := &Daemon{store: c1, ipsec: m}
	d.ipsecLoadedCfg.Store(c0.ActiveConfig())

	if err := d.applyIPsecTracked(c1.ActiveConfig()); err == nil {
		t.Fatal("FIXTURE: the write into an unwritable config dir must fail")
	}
	if reloads != 0 {
		t.Fatalf("FIXTURE: a write failure must not reach the reload, got %d reloads", reloads)
	}
	if d.ipsecLoadedCfg.Load() != c0.ActiveConfig() {
		t.Error("a write failure left the on-disk config and charon on C0; the record must stay C0")
	}
}
