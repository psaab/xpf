package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #17797: systemSyslogSeedCacheIfEmpty mapped EVERY installed client
// onto EVERY host key (the inner loop assigned each client to the
// current host's key, so the last installed client won every key).
// Adoption must key each pre-installed client by ITS OWN destination:
// host A's key must hold the client dialed to host A, never host B's.
//
// These cells drive the real seed entry point with real loopback UDP
// clients planted on the handler — the exact pre-installed state the
// seed exists for (a client planted before the cache existed).

func seedPlantClient17797(t *testing.T, port int, sourceAddr string) *logging.SyslogClient {
	t.Helper()
	c, err := logging.NewSyslogClientWithSource("127.0.0.1", port, sourceAddr)
	if err != nil {
		t.Fatalf("plant client 127.0.0.1:%d src %q: %v", port, sourceAddr, err)
	}
	if c == nil {
		t.Fatalf("plant client 127.0.0.1:%d src %q: nil client", port, sourceAddr)
	}
	return c
}

func seedSnapshot17797(d *Daemon) (map[string]*logging.SyslogClient, map[string]string) {
	d.systemSyslogBuiltMu.Lock()
	defer d.systemSyslogBuiltMu.Unlock()
	byKey := make(map[string]*logging.SyslogClient, len(d.systemSyslogBuiltByKey))
	for k, v := range d.systemSyslogBuiltByKey {
		byKey[k] = v
	}
	fps := make(map[string]string, len(d.systemSyslogBuiltFP))
	for k, v := range d.systemSyslogBuiltFP {
		fps[k] = v
	}
	return byKey, fps
}

func TestSystemSyslogSeedCachePerHost17797(t *testing.T) {
	d := newSystemSyslogDaemon16767(t)
	portA, _ := udpSink16767(t)
	portB, _ := udpSink16767(t)
	hostA := &config.SyslogHostConfig{Address: "127.0.0.1", Port: portA}
	hostB := &config.SyslogHostConfig{Address: "127.0.0.1", Port: portB}
	cfg := systemSyslogCfg16767(hostA, hostB)

	clientA := seedPlantClient17797(t, portA, "")
	clientB := seedPlantClient17797(t, portB, "")
	if clientA == clientB {
		t.Fatal("premise: planted clients must be distinct pointers")
	}
	// Reversed install order: under the nested-loop defect every key
	// ends with the LAST installed client regardless of destination.
	d.slogHandler.SetClients([]*logging.SyslogClient{clientB, clientA})

	d.systemSyslogSeedCacheIfEmpty(cfg)

	byKey, fps := seedSnapshot17797(d)
	keyA, keyB := systemSyslogHostKey(hostA), systemSyslogHostKey(hostB)
	if keyA == keyB {
		t.Fatal("premise: hosts must have distinct cache keys")
	}
	if len(byKey) != 2 {
		t.Fatalf("#17797: seeded %d cache entries, want exactly 2 (one per host): %v", len(byKey), byKey)
	}
	if got := byKey[keyA]; got != clientA {
		t.Fatalf("#17797: host A key adopted client %p, want host A's own client %p (RemoteAddr %q)",
			got, clientA, clientA.RemoteAddr())
	}
	if got := byKey[keyB]; got != clientB {
		t.Fatalf("#17797: host B key adopted client %p, want host B's own client %p (RemoteAddr %q) — last-installed-wins mis-adoption",
			got, clientB, clientB.RemoteAddr())
	}
	// Adoption must never vouch for construction inputs: seeded
	// fingerprints stay empty so the next vetted apply re-dials once.
	if fps[keyA] != "" || fps[keyB] != "" {
		t.Fatalf("#17797: seeded fingerprints must stay empty, got A=%q B=%q", fps[keyA], fps[keyB])
	}
}

func TestSystemSyslogSeedCacheControls17797(t *testing.T) {
	t.Run("single-host adopts its own client", func(t *testing.T) {
		d := newSystemSyslogDaemon16767(t)
		portA, _ := udpSink16767(t)
		hostA := &config.SyslogHostConfig{Address: "127.0.0.1", Port: portA}
		clientA := seedPlantClient17797(t, portA, "")
		d.slogHandler.SetClients([]*logging.SyslogClient{clientA})

		d.systemSyslogSeedCacheIfEmpty(systemSyslogCfg16767(hostA))

		byKey, fps := seedSnapshot17797(d)
		keyA := systemSyslogHostKey(hostA)
		if len(byKey) != 1 || byKey[keyA] != clientA {
			t.Fatalf("single-host seed = %v, want exactly {%q: %p}", byKey, keyA, clientA)
		}
		if fps[keyA] != "" {
			t.Fatalf("single-host seeded fingerprint = %q, want empty", fps[keyA])
		}
	})

	t.Run("foreign clients are not adopted", func(t *testing.T) {
		d := newSystemSyslogDaemon16767(t)
		portA, _ := udpSink16767(t)
		portOther, _ := udpSink16767(t)
		hostA := &config.SyslogHostConfig{Address: "127.0.0.1", Port: portA}

		// Same address, wrong port; right address:port, wrong source.
		foreign := seedPlantClient17797(t, portOther, "")
		wrongSource := seedPlantClient17797(t, portA, "127.0.0.2")
		d.slogHandler.SetClients([]*logging.SyslogClient{foreign, wrongSource})

		d.systemSyslogSeedCacheIfEmpty(systemSyslogCfg16767(hostA))

		byKey, _ := seedSnapshot17797(d)
		if len(byKey) != 0 {
			t.Fatalf("#17797: seed adopted foreign clients %v, want no entries for host A", byKey)
		}
	})

	t.Run("duplicate host keys share their one client", func(t *testing.T) {
		d := newSystemSyslogDaemon16767(t)
		portA, _ := udpSink16767(t)
		hostA := &config.SyslogHostConfig{Address: "127.0.0.1", Port: portA}
		clientA := seedPlantClient17797(t, portA, "")
		d.slogHandler.SetClients([]*logging.SyslogClient{clientA})

		d.systemSyslogSeedCacheIfEmpty(systemSyslogCfg16767(hostA, hostA))

		byKey, _ := seedSnapshot17797(d)
		keyA := systemSyslogHostKey(hostA)
		if len(byKey) != 1 || byKey[keyA] != clientA {
			t.Fatalf("duplicate-host seed = %v, want exactly {%q: %p}", byKey, keyA, clientA)
		}
	})
	t.Run("ambiguous installed destinations are not adopted", func(t *testing.T) {
		d := newSystemSyslogDaemon16767(t)
		portA, _ := udpSink16767(t)
		hostA := &config.SyslogHostConfig{Address: "127.0.0.1", Port: portA}
		clientA := seedPlantClient17797(t, portA, "")
		clientB := seedPlantClient17797(t, portA, "")
		if clientA == clientB {
			t.Fatal("premise: same-destination clients must be distinct pointers")
		}
		d.slogHandler.SetClients([]*logging.SyslogClient{clientA, clientB})

		d.systemSyslogSeedCacheIfEmpty(systemSyslogCfg16767(hostA))

		byKey, _ := seedSnapshot17797(d)
		if len(byKey) != 0 {
			t.Fatalf("#17797: seed arbitrarily adopted one of two matching clients %v, want no ambiguous entry", byKey)
		}
	})
}
