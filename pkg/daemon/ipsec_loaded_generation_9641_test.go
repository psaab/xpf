package daemon

// #9641: with no in-process record of the loaded generation, HA IPsec attribution reads
// the generation charon reports (its marker pool) and uses it only when charon's loaded
// connections validate it. The swanctl double plays charon: it "loads" the file xpf wrote
// by reading the marker out of it, and it lists connections written by hand from the
// fixture configs, never derived by the code under test.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/ipsec"
)

// What charon lists for the two #9511 fixture VPNs. blue is anchored on reth1 (RG1,
// configured 10.0.1.1) and has one selector "red", so its only child is blue-red.
// blue-red is anchored on reth2 (RG2, configured 10.0.2.1) and has no selector, so its
// child is blue-red too.
const (
	listBlue9641 = "list-conn event {blue {local_addrs=[10.0.1.1] remote_addrs=[198.51.100.1] " +
		"version=IKEv1/2 local-1 {class=pre-shared key groups=[] certs=[]} " +
		"remote-1 {class=pre-shared key groups=[] certs=[]} " +
		"children {blue-red {mode=TUNNEL local-ts=[10.0.1.0/24] remote-ts=[10.9.1.0/24]}}}}\n"
	listBlueRed9641 = "list-conn event {blue-red {local_addrs=[10.0.2.1] remote_addrs=[198.51.100.2] " +
		"version=IKEv1/2 local-1 {class=pre-shared key groups=[] certs=[]} " +
		"remote-1 {class=pre-shared key groups=[] certs=[]} " +
		"children {blue-red {mode=TUNNEL local-ts=[dynamic] remote-ts=[dynamic]}}}}\n"
)

// charon9641 is a swanctl double standing in for charon's loaded state.
type charon9641 struct {
	dir     string // the Manager's config dir, whose file loadFile reads
	marker  string // the generation token charon lists; "" lists no marker pool
	conns   string // the list-conn events charon lists
	listErr error  // returned by every list call (charon unreachable)
	loadErr error  // returned by --load-all
	lists   int    // list-pools and list-conns calls
}

var markerPool9641 = regexp.MustCompile(`(?m)^\s*xpf-gen-([0-9a-z]+) \{`)

// loadFile is charon loading the swanctl file on disk, as its own start or reload does.
// Afterwards it lists the marker that file names.
func (c *charon9641) loadFile(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.dir, ipsec.BPFRXConfFile))
	if err != nil {
		t.Fatalf("FIXTURE: charon cannot read the written file: %v", err)
	}
	m := markerPool9641.FindSubmatch(b)
	if m == nil {
		t.Fatalf("FIXTURE: the written file names no generation:\n%s", b)
	}
	c.marker = string(m[1])
}

func (c *charon9641) swanctl(args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	switch args[0] {
	case "--load-all":
		return nil, c.loadErr
	case "--list-pools":
		c.lists++
		if c.listErr != nil {
			return nil, c.listErr
		}
		if c.marker == "" {
			return []byte("get-pools reply {}\n"), nil
		}
		return []byte("get-pools reply {xpf-gen-" + c.marker + " {base=192.0.2.1 size=1 online=0 offline=0}}\n"), nil
	case "--list-conns":
		c.lists++
		if c.listErr != nil {
			return nil, c.listErr
		}
		return []byte(c.conns + "list-conns reply {}\n"), nil
	}
	return nil, nil
}

// generations9641 commits C0 (blue on RG1) and then C1 (C0 plus blue-red on RG2) into
// ONE store, so C0 is in its history, and returns both digests. Under C0 blue-red is only
// blue's RG1 child; under C1 it is ambiguous with blue-red's RG2 tunnel. So an RG1-only
// owner initiates it under C0 and skips it under C1 (#9511 S1).
func generations9641(t *testing.T) (*configstore.Store, string, string) {
	t.Helper()
	store := storeWith9511(t, blueOnRG1_9511...)
	d0 := store.ActiveDigest()
	commitBlueRed9641(t, store)
	d1 := store.ActiveDigest()
	if d0 == "" || d0 == d1 {
		t.Fatalf("FIXTURE: two distinct generation digests expected, got %q and %q", d0, d1)
	}
	return store, d0, d1
}

// syncApplyC1Plus9641 installs C1 (C0 plus blue-red on RG2) together with any extra
// set lines on the SAME store, so earlier generations stay in its history. C1 renders
// the swanctl SA name blue-red twice, which a commit refuses since #9624, and a commit
// re-validates the whole candidate, so every generation built on C1 has to arrive the
// tolerant way too: synced from a peer, or persisted before the gate. It uses the same
// config-sync ingress as syncedStore9511, including its check that the strict compile
// fails on the #9624 collision and nothing else.
func syncApplyC1Plus9641(t *testing.T, store *configstore.Store, extra ...string) {
	t.Helper()
	lines := append(append(append([]string{}, clusterTwoRethIPsec9511...), blueOnRG1_9511...),
		"set security ipsec vpn blue-red ike gateway gw-rg2")
	lines = append(lines, extra...)
	tr := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("FIXTURE: parse %q: %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("FIXTURE: setpath %q: %v", l, err)
		}
	}
	if _, err := config.CompileConfig(tr.Clone()); err == nil ||
		!strings.Contains(err.Error(), "all render the swanctl SA name") {
		t.Fatalf("FIXTURE: a C1-based generation must fail the strict compile on the #9624 SA-name collision alone, got %v", err)
	}
	if _, err := store.SyncApply(tr.Format(), nil); err != nil {
		t.Fatalf("FIXTURE: SyncApply: %v", err)
	}
}

// commitBlueRed9641 installs C1 on the store (see syncApplyC1Plus9641).
func commitBlueRed9641(t *testing.T, store *configstore.Store) {
	t.Helper()
	syncApplyC1Plus9641(t, store)
}

func initiates9641(d *Daemon, name string) bool {
	got := d.ipsecSAsToReinitiate([]string{name})
	return len(got) == 1 && got[0] == name
}

func daemonAskingCharon9641(t *testing.T, store *configstore.Store, ch *charon9641, owned ...int) *Daemon {
	t.Helper()
	if ch.dir == "" {
		ch.dir = t.TempDir()
	}
	m := ipsec.NewWithConfigDir(ch.dir)
	m.SetSwanctlForTesting(ch.swanctl)
	return &Daemon{cluster: clusterOwning9511(t, store, owned...), store: store, ipsec: m}
}

// THE #9641 STATE. A restarted xpfd whose boot IPsec apply failed has no record, while
// charon still runs C0 from the previous process. Attribution must follow C0, and follow
// C1 once charon loads it. The promoted-config answer (C1) differs, which the FIXTURE
// pins, so the cell can see whether the marker was used.
func TestAttributionFollowsCharonsGenerationAfterARestart9641(t *testing.T) {
	store, d0, d1 := generations9641(t)
	if initiates9641(&Daemon{cluster: clusterOwning9511(t, store, 1), store: store}, "blue-red") {
		t.Fatal("FIXTURE: attributing from the promoted C1 must skip blue-red for an RG1-only owner")
	}
	ch := &charon9641{marker: d0, conns: listBlue9641}
	d := daemonAskingCharon9641(t, store, ch, 1)

	if !initiates9641(d, "blue-red") {
		t.Error("charon runs C0, where blue-red is only blue's RG1 child; an RG1 owner must initiate it")
	}
	ch.marker, ch.conns = d1, listBlue9641+listBlueRed9641
	if initiates9641(d, "blue-red") {
		t.Error("charon now runs C1, where blue-red is ambiguous with RG2; an RG1-only owner must skip it")
	}
}

// THE FAILED-RELOAD WINDOW, end to end through applyIPsecTracked. C0 is applied and
// loaded; C1 is promoted and written, and its reload FAILS. charon still runs C0, and the
// marker it lists is read out of the file xpf wrote for C0, so the cell also binds the
// apply's stamp. The #9511 stopgap alone answered with the promoted C1 here. Then charon's
// own restart loads the file on disk (C1), and attribution follows it.
func TestAttributionFollowsCharonThroughTheFailedReloadWindow9641(t *testing.T) {
	store := storeWith9511(t, blueOnRG1_9511...)
	ch := &charon9641{}
	d := daemonAskingCharon9641(t, store, ch, 1)

	if err := d.applyIPsecTracked(store.ActiveConfig()); err != nil {
		t.Fatalf("FIXTURE: applying C0 must succeed: %v", err)
	}
	ch.loadFile(t)
	ch.conns = listBlue9641

	commitBlueRed9641(t, store)
	ch.loadErr = errors.New("charon vici socket refused")
	if err := d.applyIPsecTracked(store.ActiveConfig()); err == nil {
		t.Fatal("FIXTURE: the reload of C1 must fail")
	}
	if d.ipsecLoadedCfg.Load() != nil {
		t.Fatal("FIXTURE: the failed reload must clear the record (#9511 stopgap)")
	}

	if !initiates9641(d, "blue-red") {
		t.Error("in the window charon still runs C0, where blue-red is blue's RG1 child; an RG1 owner must initiate it")
	}
	ch.loadFile(t) // charon's own restart loads the file on disk
	ch.conns = listBlue9641 + listBlueRed9641
	if initiates9641(d, "blue-red") {
		t.Error("charon loaded C1 from disk, where blue-red is ambiguous with RG2; an RG1-only owner must skip it")
	}
}

// Every case where charon cannot vouch for ONE generation keeps the promoted-config
// answer. In each, trusting charon's listing would give C0's answer instead, so a skipped
// check shows up as an initiate. The first row is the CONTROL: a valid listing is trusted.
func TestAttributionFallbacksKeepThePromotedAnswer9641(t *testing.T) {
	store, d0, _ := generations9641(t)
	control := &charon9641{marker: d0, conns: listBlue9641}
	if !initiates9641(daemonAskingCharon9641(t, store, control, 1), "blue-red") {
		t.Fatal("FIXTURE: a valid C0 listing must be trusted, or no row below can see a skipped check")
	}
	for _, tc := range []struct {
		name string
		ch   charon9641
	}{
		{"charon unreachable", charon9641{marker: d0, conns: listBlue9641,
			listErr: errors.New("connecting to 'unix:///var/run/charon.vici' failed")}},
		{"no marker (a file from an older xpf)", charon9641{conns: listBlue9641}},
		{"unknown marker", charon9641{marker: ipsec.UnknownGeneration, conns: listBlue9641}},
		{"generation not retained on this node", charon9641{marker: strings.Repeat("ab", 32), conns: listBlue9641}},
		{"partial load: marker C0, connections C1", charon9641{marker: d0, conns: listBlue9641 + listBlueRed9641}},
		{"partial load: marker C0, no connections", charon9641{marker: d0}},
		{"marker C0, connection on another local address", charon9641{marker: d0,
			conns: strings.Replace(listBlue9641, "local_addrs=[10.0.1.1]", "local_addrs=[10.0.2.1]", 1)}},
	} {
		ch := tc.ch
		if initiates9641(daemonAskingCharon9641(t, store, &ch, 1), "blue-red") {
			t.Errorf("%s: attribution must keep the promoted C1 answer (skip), but it initiated as if charon ran C0", tc.name)
		}
		if ch.lists == 0 {
			t.Errorf("%s: FIXTURE: charon was never asked, so the row did not reach the marker path", tc.name)
		}
	}
}

// With a record, charon is not asked. The record names exactly the file charon loaded,
// and asking would cost two swanctl calls per pass for no information.
func TestAttributionWithARecordDoesNotAskCharon9641(t *testing.T) {
	store, d0, _ := generations9641(t)
	ch := &charon9641{marker: d0, conns: listBlue9641}
	d := daemonAskingCharon9641(t, store, ch, 1)
	d.ipsecLoadedCfg.Store(store.ActiveConfig())
	if initiates9641(d, "blue-red") {
		t.Error("the record names C1, so blue-red must be skipped for an RG1-only owner")
	}
	if ch.lists != 0 {
		t.Errorf("attribution asked charon %d times although a record was set", ch.lists)
	}
}

// A takeover wave runs one pass per redundancy group. A generation resolved from history
// is compiled once, so every pass gets the same config and the SA name index built for
// it is installed and reused.
func TestCharonsGenerationIsResolvedOncePerWave9641(t *testing.T) {
	store, d0, _ := generations9641(t)
	d := daemonAskingCharon9641(t, store, &charon9641{marker: d0, conns: listBlue9641}, 1)
	first := d.ipsecAttributionConfig()
	if first == nil || first == store.ActiveConfig() {
		t.Fatal("FIXTURE: charon's C0 must resolve from history, not to the promoted config")
	}
	if again := d.ipsecAttributionConfig(); again != first {
		t.Error("a second pass recompiled charon's generation instead of reusing it")
	}
	idx := d.cachedIPsecSANameIndex(first)
	if back := d.cachedIPsecSANameIndex(d.ipsecAttributionConfig()); fmt.Sprintf("%p", back) != fmt.Sprintf("%p", idx) {
		t.Error("the SA name index for charon's generation must be installed and reused, not rebuilt each pass")
	}
}

// The apply names the generation with the store's digest only for the store's ACTIVE
// config. Any other config, even one with identical content, is written as unknown.
func TestApplyIPsecTrackedStampsOnlyTheActiveGeneration9641(t *testing.T) {
	store := storeWith9511(t, blueOnRG1_9511...)
	other := storeWith9511(t, blueOnRG1_9511...)
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"the active config", store.ActiveConfig(), store.ActiveDigest()},
		{"an identical config that is not the active one", other.ActiveConfig(), ipsec.UnknownGeneration},
	} {
		ch := &charon9641{dir: t.TempDir()}
		m := ipsec.NewWithConfigDir(ch.dir)
		m.SetSwanctlForTesting(ch.swanctl)
		d := &Daemon{store: store, ipsec: m}
		if err := d.applyIPsecTracked(tc.cfg); err != nil {
			t.Fatalf("%s: FIXTURE: apply: %v", tc.name, err)
		}
		ch.loadFile(t)
		if ch.marker != tc.want {
			t.Errorf("%s: the written marker names %q, want %q", tc.name, ch.marker, tc.want)
		}
	}
}
