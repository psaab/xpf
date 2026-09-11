package ipsec

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9641: the generation marker and its validation. The marker cells drive a real Manager
// writing into a temp dir. The validation cells compare ExpectedLoadedConns with REAL
// strongSwan 6.0.5 `--list-conns --raw` captures (list_conns_9641_test.go).

const gen9641 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func applyAndRead9641(t *testing.T, apply func(m *Manager) error) string {
	t.Helper()
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	if err := apply(m); err != nil {
		t.Fatalf("FIXTURE: apply: %v", err)
	}
	b, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read the written config: %v", err)
	}
	return string(b)
}

// The written file names its generation as an INERT pool: exactly one pool, named for the
// generation, holding one TEST-NET-1 address, and referenced by no connection. What
// precedes it is byte-for-byte the render every other consumer reads.
func TestApplyGenerationWritesAnInertMarkerPool9641(t *testing.T) {
	cfg := proofConfig9641()
	written := applyAndRead9641(t, func(m *Manager) error {
		return m.ApplyGeneration(cfg, gen9641, ApplyHooks{})
	})
	doc := parseSwanctlDoc(t, written)
	pools := doc.at(t, "pools")
	if got := pools.childNames(); len(got) != 1 || got[0] != "xpf-gen-"+gen9641 {
		t.Fatalf("pools = %v, want exactly the marker xpf-gen-%s", got, gen9641)
	}
	pools.at(t, "xpf-gen-"+gen9641).requireSetting(t, "addrs", "192.0.2.1/32")
	conns := doc.at(t, "connections").childNames()
	if len(conns) == 0 {
		t.Fatal("FIXTURE: the written config must carry connections, or no reference could be seen")
	}
	for _, conn := range conns {
		doc.at(t, "connections", conn).hasNoSetting(t, "pools")
	}
	if render := (&Manager{}).generateConfig(cfg); !strings.HasPrefix(written, render) {
		t.Error("the written file must be the render followed by the marker; the render the " +
			"SA name index and ExpectedLoadedConns read would differ from the file")
	}
}

// A plain Apply, and any generation that is not a lowercase hex digest, write the UNKNOWN
// marker. The token is an unquoted section name, so a tampered generation must never
// reach the file.
func TestApplyGenerationWritesUnknownForAnythingButADigest9641(t *testing.T) {
	cfg := proofConfig9641()
	for _, tc := range []struct {
		name  string
		apply func(m *Manager) error
	}{
		{"Apply", func(m *Manager) error { return m.Apply(cfg) }},
		{"ApplyWithHooks", func(m *Manager) error { return m.ApplyWithHooks(cfg, ApplyHooks{}) }},
		{"empty", func(m *Manager) error { return m.ApplyGeneration(cfg, "", ApplyHooks{}) }},
		{"uppercase", func(m *Manager) error { return m.ApplyGeneration(cfg, strings.ToUpper(gen9641), ApplyHooks{}) }},
		{"injection", func(m *Manager) error {
			return m.ApplyGeneration(cfg, gen9641+" {\n  }\n}\nconnections {", ApplyHooks{})
		}},
	} {
		doc := parseSwanctlDoc(t, applyAndRead9641(t, tc.apply))
		if got := doc.at(t, "pools").childNames(); len(got) != 1 || got[0] != "xpf-gen-unknown" {
			t.Errorf("%s: pools = %v, want [xpf-gen-unknown]", tc.name, got)
		}
	}
}

// The empty-config clear path removes the file, so charon lists NO marker afterwards,
// never a stale one naming the previous generation.
func TestApplyGenerationClearPathLeavesNoMarker9641(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = func(args ...string) ([]byte, error) { return nil, nil }
	if err := m.ApplyGeneration(proofConfig9641(), gen9641, ApplyHooks{}); err != nil {
		t.Fatalf("FIXTURE: apply: %v", err)
	}
	if err := m.ApplyGeneration(&config.IPsecConfig{}, gen9641, ApplyHooks{}); err != nil {
		t.Fatalf("FIXTURE: clear: %v", err)
	}
	if _, err := os.Stat(m.configPath); !os.IsNotExist(err) {
		t.Errorf("the clear path must remove the file and its marker, stat err = %v", err)
	}
}

func poolsSwanctl9641(out string, err error) func(args ...string) ([]byte, error) {
	return func(args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "--list-pools" && args[1] == "--raw" {
			return []byte(out), err
		}
		return nil, fmt.Errorf("unexpected swanctl call %v", args)
	}
}

// The real 6.0.5 capture reads back. Its proof pool name is not a digest, so it reads as
// UNKNOWN. Renamed to a digest it reads as that generation, and a foreign pool beside
// the marker does not disturb it.
func TestLoadedGenerationReadsTheRealFixture9641(t *testing.T) {
	raw := readFixture9641(t, "swanctl_list_pools_raw_9641.txt")
	if !strings.Contains(raw, "xpf-gen-proof9641 {") {
		t.Fatal("FIXTURE: the capture must hold the proof marker pool")
	}
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = poolsSwanctl9641(raw, nil)
	if got, err := m.LoadedGeneration(); err != nil || got != UnknownGeneration {
		t.Errorf("the capture's non-digest marker: got (%q, %v), want (%q, nil)", got, err, UnknownGeneration)
	}
	named := strings.Replace(raw, "proof9641", gen9641, 1)
	m.swanctl = poolsSwanctl9641(named, nil)
	if got, err := m.LoadedGeneration(); err != nil || got != gen9641 {
		t.Errorf("got (%q, %v), want (%q, nil)", got, err, gen9641)
	}
	withForeign := strings.Replace(named, "get-pools reply {", "get-pools reply {vips {base=10.3.0.1 size=254 online=0 offline=0} ", 1)
	m.swanctl = poolsSwanctl9641(withForeign, nil)
	if got, err := m.LoadedGeneration(); err != nil || got != gen9641 {
		t.Errorf("with a foreign pool beside the marker: got (%q, %v), want (%q, nil)", got, err, gen9641)
	}
}

// Every outcome that cannot name ONE generation is an error, never a generation: charon
// unreachable, no marker (an older xpf's file, or no xpf config loaded), two markers.
func TestLoadedGenerationRefusesWhatItCannotName9641(t *testing.T) {
	pool := func(name string) string {
		return name + " {base=192.0.2.1 size=1 online=0 offline=0}"
	}
	for _, tc := range []struct {
		name string
		out  string
		err  error
		want error
	}{
		{"unreachable", "", errors.New("connecting to 'unix:///var/run/charon.vici' failed"), nil},
		{"no pools", "get-pools reply {}\n", nil, ErrNoGenerationMarker},
		{"foreign pool only", "get-pools reply {vips {base=10.3.0.1 size=254 online=0 offline=0}}\n", nil, ErrNoGenerationMarker},
		{"two markers", "get-pools reply {" + pool("xpf-gen-"+gen9641) + " " + pool("xpf-gen-unknown") + "}\n", nil, ErrAmbiguousGenerationMarker},
		{"malformed", "get-pools reply {" + pool("xpf-gen-"+gen9641) + "\n", nil, nil},
	} {
		m := NewWithConfigDir(t.TempDir())
		m.swanctl = poolsSwanctl9641(tc.out, tc.err)
		got, err := m.LoadedGeneration()
		if err == nil {
			t.Errorf("%s: must be an error, got generation %q", tc.name, got)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

// localAddrProofConfig9641 rebuilds the config behind the local_addrs capture.
func localAddrProofConfig9641() *config.IPsecConfig {
	return &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"proof-la": {Name: "proof-la", Gateway: "198.51.100.63", LocalAddr: "192.0.2.61",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: "10.63.1.0/24", RemoteIP: "10.64.1.0/24"},
				}},
		},
	}
}

func describe9641(c LoadedConns) string {
	parts := make([]string, 0, len(c))
	for name, lc := range c {
		if lc == nil {
			lc = &LoadedConn{}
		}
		parts = append(parts, fmt.Sprintf("%s{children=%v local=%v remote=%v}", name, lc.Children, lc.LocalAddrs, lc.RemoteAddrs))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// THE VALIDATION PRIMITIVE, against real charon. Each config is first proven to render
// byte-for-byte to the file charon loaded. Its expected loaded connections must then
// EQUAL what charon listed, endpoint lists included (%any for an unrendered local_addrs).
func TestExpectedLoadedConnsEqualsWhatCharonLoaded9641(t *testing.T) {
	for _, tc := range []struct {
		cfg         *config.IPsecConfig
		source, raw string
	}{
		{proofConfig9641(), "swanctl_list_conns_source_9641.conf", "swanctl_list_conns_raw_9641.txt"},
		{localAddrProofConfig9641(), "swanctl_list_conns_localaddr_source_9641.conf", "swanctl_list_conns_localaddr_raw_9641.txt"},
	} {
		text, _, err := (&Manager{}).renderConfig(tc.cfg)
		if err != nil {
			t.Fatalf("%s: render: %v", tc.source, err)
		}
		if src := readFixture9641(t, tc.source); text != src {
			t.Fatalf("FIXTURE %s: the rebuilt config no longer renders to the file charon loaded:\n%s", tc.source, text)
		}
		loaded, err := parseListConnsRaw(readFixture9641(t, tc.raw))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.raw, err)
		}
		want, err := expectedLoadedConns(tc.cfg, nil)
		if err != nil {
			t.Fatalf("%s: expectedLoadedConns: %v", tc.source, err)
		}
		if !loaded.Equal(want) {
			t.Errorf("%s: expected %s\ncharon loaded %s", tc.raw, describe9641(want), describe9641(loaded))
		}
	}
}

// THE DISCRIMINATOR. A generation whose gateway moved to another local address keeps
// every connection and child name, so only the endpoint list tells the two apart, and
// validation must refuse the generation charon did not load.
func TestExpectedLoadedConnsRefusesAMovedLocalAddress9641(t *testing.T) {
	loaded, err := parseListConnsRaw(readFixture9641(t, "swanctl_list_conns_localaddr_raw_9641.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	moved := localAddrProofConfig9641()
	moved.VPNs["proof-la"].LocalAddr = "192.0.2.62"
	want, err := expectedLoadedConns(moved, nil)
	if err != nil {
		t.Fatalf("expectedLoadedConns: %v", err)
	}
	if sortedSANames9641(want) != sortedSANames9641(loaded) {
		t.Fatal("FIXTURE: the moved generation must render the same names, or a name set alone would already refuse it")
	}
	if loaded.Equal(want) {
		t.Errorf("validation accepted a generation with a different local address: expected %s, charon loaded %s",
			describe9641(want), describe9641(loaded))
	}
}

func sortedSANames9641(c LoadedConns) string {
	var out []string
	for n := range c.SANames() {
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestLoadedConnsEqualIsOrderInsensitiveAndFieldExact9641(t *testing.T) {
	base := func() LoadedConns {
		return LoadedConns{
			"a": {Children: []string{"a-1", "a-2"}, LocalAddrs: []string{"%any"}, RemoteAddrs: []string{"198.51.100.1", "198.51.100.2"}},
			"b": {Children: []string{"b"}, LocalAddrs: []string{"192.0.2.1"}, RemoteAddrs: []string{"%any"}},
		}
	}
	reordered := base()
	reordered["a"].Children = []string{"a-2", "a-1"}
	reordered["a"].RemoteAddrs = []string{"198.51.100.2", "198.51.100.1"}
	if !base().Equal(reordered) {
		t.Error("charon's listing order is not a contract; a reordered listing must be equal")
	}
	for _, tc := range []struct {
		name   string
		mutate func(LoadedConns)
	}{
		{"extra connection", func(c LoadedConns) { c["c"] = &LoadedConn{Children: []string{"c"}} }},
		{"missing connection", func(c LoadedConns) { delete(c, "b") }},
		{"renamed connection", func(c LoadedConns) { c["b2"] = c["b"]; delete(c, "b") }},
		{"child differs", func(c LoadedConns) { c["a"].Children = []string{"a-1", "a-3"} }},
		{"extra child", func(c LoadedConns) { c["b"].Children = []string{"b", "b-2"} }},
		{"duplicated child", func(c LoadedConns) { c["b"].Children = []string{"b", "b"} }},
		{"local differs", func(c LoadedConns) { c["b"].LocalAddrs = []string{"192.0.2.9"} }},
		{"remote differs", func(c LoadedConns) { c["a"].RemoteAddrs = []string{"198.51.100.1"} }},
	} {
		c := base()
		tc.mutate(c)
		if base().Equal(c) || c.Equal(base()) {
			t.Errorf("%s: must not be equal", tc.name)
		}
	}
}

// Local addresses resolved at apply time from the kernel or through DNS cannot be
// replayed for a stored generation, so validation must REFUSE rather than guess. An
// explicit or configured address is exact and stays validatable.
func TestExpectedLoadedConnsRefusesApplyTimeLocalAddresses9641(t *testing.T) {
	withHost := func(cfg *config.Config, host string) *config.Config {
		gw := cfg.Security.IPsec.Gateways["gw"]
		gw.Address, gw.DynamicHostname = "", host
		return cfg
	}
	withVPNLocal := func(cfg *config.Config, addr string) *config.Config {
		cfg.Security.IPsec.VPNs["tun"].LocalAddr = addr
		return cfg
	}
	for _, tc := range []struct {
		name      string
		cfg       *config.Config
		wantLocal string // "" means unvalidatable
	}{
		{"DHCP unit with no configured address", dhcpBoundConfig("wan0.0", "", "", true), ""},
		{"dynamic hostname whose family needs DNS", withHost(dhcpBoundConfig("wan0.0", "", "192.0.2.10/24", false), "peer.example.net"), ""},
		{"configured unit address", dhcpBoundConfig("wan0.0", "", "192.0.2.10/24", false), "192.0.2.10"},
		{"explicit gateway local-address", dhcpBoundConfig("wan0.0", "192.0.2.20", "", true), "192.0.2.20"},
		{"IP-literal dynamic hostname", withHost(dhcpBoundConfig("wan0.0", "", "192.0.2.10/24", false), "203.0.113.9"), "192.0.2.10"},
		{"VPN local-address over a runtime gateway", withVPNLocal(dhcpBoundConfig("wan0.0", "", "", true), "192.0.2.30"), "192.0.2.30"},
	} {
		_, rendered, err := (&Manager{}).renderConfig(&tc.cfg.Security.IPsec)
		if err != nil || !rendered["tun"] {
			t.Fatalf("%s: FIXTURE: tun must render, or validation has nothing to refuse (rendered %v, err %v)", tc.name, rendered, err)
		}
		got, err := ExpectedLoadedConns(tc.cfg)
		if tc.wantLocal == "" {
			if !errors.Is(err, ErrGenerationUnvalidatable) {
				t.Errorf("%s: want ErrGenerationUnvalidatable, got %s (err %v)", tc.name, describe9641(got), err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: must be validatable, got %v", tc.name, err)
			continue
		}
		if lc := got["tun"]; lc == nil || strings.Join(lc.LocalAddrs, ",") != tc.wantLocal {
			t.Errorf("%s: expected %s, want local [%s]", tc.name, describe9641(got), tc.wantLocal)
		}
	}
}

// prepareConfigFromConfig must agree with PrepareConfig wherever it claims an answer. A
// dual-stack interface separates the family hints: a v6 peer must get the v6 address,
// and a hint that ignored the peer's family would hand it the v4 one.
func TestPrepareConfigFromConfigAgreesWithPrepareConfig9641(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {Name: "wan0", Units: map[int]*config.InterfaceUnit{
					0: {Addresses: []string{"fe80::5/64", "192.0.2.10/24", "2001:db8::10/64"}},
				}},
			},
		},
		Security: config.SecurityConfig{IPsec: config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"v4":        {Name: "v4", Address: "203.0.113.1", ExternalIface: "wan0.0"},
				"v6":        {Name: "v6", Address: "2001:db8:ffff::1", ExternalIface: "wan0.0"},
				"v6literal": {Name: "v6literal", DynamicHostname: "2001:db8:ffff::2", ExternalIface: "wan0"},
				"responder": {Name: "responder", ResponderOnly: true, ExternalIface: "wan0.0"},
			},
		}},
	}
	prod := PrepareConfig(cfg)
	replay, runtime := prepareConfigFromConfig(cfg)
	if prod.Gateways["v6"].LocalAddress == prod.Gateways["v4"].LocalAddress {
		t.Fatal("FIXTURE: the v4 and v6 peers must resolve to different local addresses")
	}
	for name := range cfg.Security.IPsec.Gateways {
		if runtime[name] {
			t.Errorf("%s: resolves from configuration, but was reported as apply-time", name)
			continue
		}
		if got, want := replay.Gateways[name].LocalAddress, prod.Gateways[name].LocalAddress; got != want {
			t.Errorf("%s: replayed local address %q, PrepareConfig resolved %q", name, got, want)
		}
	}
}
