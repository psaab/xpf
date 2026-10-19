package ipsec

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15141 (B02-01): #14589 partial-load recovery accepts a NAME-set match
// as "candidate loaded". When charon refuses a CHANGED EXISTING
// connection (e.g. its new certificate fails to load), the connection
// stays loaded under its OLD content, so ListLoadedConns still reports
// its name. gen1 {a(old),b} -> gen2 {a(rotated),b} is reported partial
// ("loaded 1 of 2, 1 failed"), yet the loaded NAME set {a,b} equals the
// rendered set {a,b}. The full-set shortcut in recoverPartialLoad14589
// returned the candidate hashes, so prevConnHashes["a"] adopted the
// refused rotation, promoteConnNames saw no change, and the SA
// established under the old credentials was never torn down — losing
// the #10878 guarantee. A later gen3 that makes "a" loadable again
// must then still see the gen1->gen3 hash change and enter teardown.
//
// Acceptance (issue): on gen1 -> gen2 (existing conn refused) -> gen3
// (now loadable), gen3 enters the teardown for "a", and after gen2
// prevConnHashes["a"] equals the gen1 hash.

// refusedExistingCharon15141 models charon refusing a changed existing
// connection: while the on-disk candidate carries a's refused rotation
// ("rotated-secret-a"), --load-all reports a partial load and charon
// keeps running the previously loaded set under its old content. Any
// other file loads cleanly and replaces the loaded set. In lied mode
// the first --load-all reports a partial summary even though the full
// candidate actually loaded (summary lied / raced to full).
type refusedExistingCharon15141 struct {
	configPath   string
	refuseSecret string
	refusedOnce  bool
	loadedPSK    map[string]string
	terminated   []string
	liedPartial  bool
	liedDone     bool
}

func (c *refusedExistingCharon15141) run(args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	switch args[0] {
	case "--load-all":
		data, _ := os.ReadFile(c.configPath)
		text := string(data)
		if c.liedPartial && !c.liedDone {
			c.liedDone = true
			c.setLoaded(text)
			return []byte("loaded 1 of 2 connections, 1 failed to load, 0 unloaded\n"), errors.New("exit status 22")
		}
		if c.refuseSecret != "" && !c.refusedOnce && strings.Contains(text, c.refuseSecret) {
			c.refusedOnce = true
			return []byte("loading connection 'a' failed: config discarded\nloaded 1 of 2 connections, 1 failed to load, 0 unloaded\n"), errors.New("exit status 22")
		}
		c.setLoaded(text)
		return nil, nil
	case "--list-conns":
		var b strings.Builder
		for name, psk := range c.loadedPSK {
			b.WriteString("list-conn event {" + name + " {local_addrs=[10.0.1.1] remote_addrs=[10.0.2.1] local-1 {auth=psk id=" + psk + "} children {" + name + " {}}}} \n")
		}
		b.WriteString("list-conns reply {}\n")
		return []byte(b.String()), nil
	case "--list-sas":
		return []byte(liveSA("a", "b")), nil
	case "--terminate":
		c.terminated = append(c.terminated, args[len(args)-1])
		return nil, nil
	}
	return nil, nil
}

// setLoaded records the PSK each connection in text carries, by the
// "secret-<name>" fixture spelling (each VPN's own secret section).
func (c *refusedExistingCharon15141) setLoaded(text string) {
	c.loadedPSK = map[string]string{}
	for _, n := range connNamesInConfigText14589(text) {
		psk := "old"
		switch {
		case strings.Contains(text, "rotated-secret-a") && n == "a":
			psk = "rotated"
		case strings.Contains(text, "fixed-secret-a") && n == "a":
			psk = "fixed"
		}
		c.loadedPSK[n] = psk
	}
}

func terminatedHas15141(ch *refusedExistingCharon15141, name string) bool {
	for _, n := range ch.terminated {
		if n == name {
			return true
		}
	}
	return false
}

func TestPartialLoadRefusedExistingKeepsPriorHash15141(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &refusedExistingCharon15141{configPath: m.configPath, refuseSecret: "rotated-secret-a", loadedPSK: map[string]string{}}
	m.swanctl = ch.run

	// gen1: a,b load cleanly.
	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("gen1 Apply: %v", err)
	}
	gen1Hash := m.prevConnHashes["a"]
	if gen1Hash == "" {
		t.Fatal("gen1 must record a hash for a")
	}

	// gen2: a's PSK rotates but charon refuses the changed existing
	// connection; it stays loaded under the old credentials while the
	// partial summary reports 1 of 2 loaded.
	gen2 := vpnCfg("a", "b")
	gen2.VPNs["a"].PSK = config.Secret("rotated-secret-a")
	ch.terminated = nil
	if err := m.Apply(gen2); err == nil {
		t.Fatal("gen2 partial load must return an error, not success")
	}
	if got := m.prevConnHashes["a"]; got != gen1Hash {
		t.Fatalf("after refused gen2, prevConnHashes[a]=%q must equal the gen1 hash %q (refused candidate hash was promoted)", got, gen1Hash)
	}
	if terminatedHas15141(ch, "a") {
		t.Fatalf("gen2 must not tear down a: charon still runs its old content, terminated=%v", ch.terminated)
	}
	data, rerr := os.ReadFile(m.configPath)
	if rerr != nil {
		t.Fatalf("read on-disk config: %v", rerr)
	}
	if strings.Contains(string(data), "rotated-secret-a") {
		t.Fatalf("refused rotation must not stay on disk after recovery:\n%s", data)
	}

	// gen3: a is now loadable with a new (valid) PSK. The gen1->gen3
	// hash change must enter the teardown for a.
	gen3 := vpnCfg("a", "b")
	gen3.VPNs["a"].PSK = config.Secret("fixed-secret-a")
	ch.terminated = nil
	if err := m.Apply(gen3); err != nil {
		t.Fatalf("gen3 Apply: %v", err)
	}
	if !terminatedHas15141(ch, "a") {
		t.Fatalf("gen3 must terminate the stale SA for a, terminated=%v", ch.terminated)
	}
	if got := m.prevConnHashes["a"]; got == "" || got == gen1Hash {
		t.Fatalf("gen3 must promote a's new hash, got %q (gen1 %q)", got, gen1Hash)
	}
}

// Control: the partial summary lied / raced to full — charon really did
// load the full candidate, including a's rotation. Recovery must still
// promote the candidate hash and tear down a's stale SA on gen2 itself,
// exactly as the pre-fix shortcut did.

func TestPartialLoadSummaryLiedRacedToFullStillPromotes15141(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &refusedExistingCharon15141{configPath: m.configPath, loadedPSK: map[string]string{}}
	m.swanctl = ch.run

	if err := m.Apply(vpnCfg("a", "b")); err != nil {
		t.Fatalf("gen1 Apply: %v", err)
	}
	gen1Hash := m.prevConnHashes["a"]

	gen2 := vpnCfg("a", "b")
	gen2.VPNs["a"].PSK = config.Secret("rotated-secret-a")
	// Arm the lying partial only for gen2's load.
	ch.liedPartial = true
	ch.liedDone = false
	ch.terminated = nil
	if err := m.Apply(gen2); err == nil {
		t.Fatal("gen2 partial summary must return an error, not success")
	}
	if got := m.prevConnHashes["a"]; got == "" || got == gen1Hash {
		t.Fatalf("raced-to-full gen2 must promote a's candidate hash, got %q (gen1 %q)", got, gen1Hash)
	}
	if !terminatedHas15141(ch, "a") {
		t.Fatalf("raced-to-full gen2 must tear down a's stale SA, terminated=%v", ch.terminated)
	}
	data, rerr := os.ReadFile(m.configPath)
	if rerr != nil {
		t.Fatalf("read on-disk config: %v", rerr)
	}
	if !strings.Contains(string(data), "rotated-secret-a") {
		t.Fatalf("raced-to-full candidate must stay on disk:\n%s", data)
	}
}
