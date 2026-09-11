package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9641 END TO END ON REAL CHARON. The source fixture is the file ApplyGeneration wrote
// (connections, secrets, then the marker pool). strongSwan 6.0.5 loaded it with
// `swanctl --load-all --noprompt` (rc 0; negative control rejected; capture procedure in
// docs/log/9641.md), and the other fixtures are what charon then listed. The writer, the
// reader and the validator must all agree with that capture: the marker names the
// generation, the loaded connections equal the expectation, and the marker is neither a
// connection nor an SA.

func combinedProofConfig9641() (*config.IPsecConfig, string) {
	return &config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
		"proof-gen": {Name: "proof-gen", Gateway: "198.51.100.64", LocalAddr: "192.0.2.64",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"ts1": {Name: "ts1", LocalIP: "10.65.1.0/24", RemoteIP: "10.66.1.0/24"},
			}},
	}}, "9641" + strings.Repeat("0", 60)
}

func TestWrittenGenerationFileAsCharonLoadedIt9641(t *testing.T) {
	cfg, gen := combinedProofConfig9641()
	written := applyAndRead9641(t, func(m *Manager) error { return m.ApplyGeneration(cfg, gen, ApplyHooks{}) })
	if written != readFixture9641(t, "swanctl_generation_combined_source_9641.conf") {
		t.Fatalf("FIXTURE: ApplyGeneration no longer writes the file charon loaded; the capture "+
			"describes a different file:\n%s", written)
	}

	m := NewWithConfigDir(t.TempDir())
	m.swanctl = poolsSwanctl9641(readFixture9641(t, "swanctl_generation_combined_pools_raw_9641.txt"), nil)
	if got, err := m.LoadedGeneration(); err != nil || got != gen {
		t.Errorf("LoadedGeneration on charon's listing = (%q, %v), want (%q, nil)", got, err, gen)
	}

	loaded, err := parseListConnsRaw(readFixture9641(t, "swanctl_generation_combined_conns_raw_9641.txt"))
	if err != nil {
		t.Fatalf("parse charon's connections: %v", err)
	}
	want, err := expectedLoadedConns(cfg, nil)
	if err != nil {
		t.Fatalf("expectedLoadedConns: %v", err)
	}
	if !loaded.Equal(want) {
		t.Errorf("charon loaded %s, the validation expected %s", describe9641(loaded), describe9641(want))
	}
	for name := range loaded {
		if strings.HasPrefix(name, generationMarkerPrefix) {
			t.Errorf("the marker %q appears as a loaded CONNECTION; it must be a pool only", name)
		}
	}
	if sas := readFixture9641(t, "swanctl_generation_combined_sas_raw_9641.txt"); strings.Contains(sas, generationMarkerPrefix) || strings.Contains(sas, "proof-gen") {
		t.Errorf("charon lists an SA after loading the marker file: %s", sas)
	}
}
