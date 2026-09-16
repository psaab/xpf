package daemon

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// TestConfigApplyReconcilesConnectionAuth6628 binds the CALL SITE.
//
// #6628's whole mechanism hangs off one line in the apply tail. Every test in
// pkg/cluster drives ReconcileConnectionAuth directly, so deleting that line
// leaves all of them green while no commit ever upgrades anything in
// production — the exact shape of the bind-the-wiring defect this campaign has
// hit repeatedly.
//
// It also cannot be folded into the #5078 sibling in this package. That test
// asserts the apply tail does NOT restart comms on a key commit; this one
// asserts the apply tail DOES reconcile connection auth. They are opposite
// halves of the same decision and both have to hold: the connection must
// survive the commit AND be upgraded in place.
//
// FAIL-ON-REVERT: remove `ss.ReconcileConnectionAuth("config-apply")` from
// step 20 and this reds on the read deadline.
func TestConfigApplyReconcilesConnectionAuth6628(t *testing.T) {
	installFakeNetworkctl(t)

	d := &Daemon{
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		networkd:  networkd.NewInDir(t.TempDir()),
		vrrpMgr:   vrrp.NewManager(),
		cluster:   cluster.NewManager(0, 1),
		daemonCtx: context.Background(),
		opts:      Options{NoDataplane: true},
	}

	const psk = "apply-tail-upgrade-psk-6628"
	ss := cluster.NewSessionSync(":0", "10.99.1.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	ss.InstallUnauthenticatedConnForTest(local)
	ss.SetAuthProvider(d.cluster)

	d.clusterCommsMu.Lock()
	d.sessionSync = ss
	d.clusterCommsMu.Unlock()

	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:          1,
		NodeID:             0,
		ControlInterface:   "em0",
		PeerAddress:        "10.99.0.2",
		FabricInterface:    "fab0",
		FabricPeerAddress:  "10.99.1.2",
		ControlLinkAuthKey: config.Secret(psk),
	}
	// Comms are "already up" on this transport, so step 20 runs its body
	// without restarting (the auth key is excluded from the transport key —
	// #5078 — which is exactly why the in-place upgrade is needed at all).
	d.activeClusterTransport = clusterTransportFromConfig(cfg)
	// The cluster manager must hold the key before the tail runs: the upgrade
	// reads the LIVE key through the auth provider.
	d.cluster.UpdateConfig(cfg.Chassis.Cluster)

	got := make(chan uint8, 1)
	go func() {
		hdr := make([]byte, 12)
		if _, err := io.ReadFull(peer, hdr); err != nil {
			got <- 0
			return
		}
		length := binary.LittleEndian.Uint32(hdr[8:12])
		if length > 0 {
			body := make([]byte, length)
			if _, err := io.ReadFull(peer, body); err != nil {
				got <- 0
				return
			}
		}
		got <- hdr[4]
	}()

	// The tail returns reconcile errors in this stripped-down harness; the
	// assertion is on what step 20 puts on the wire.
	go func() {
		_ = d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	}()

	select {
	case typ := <-got:
		if typ != cluster.SyncMsgAuthUpgradeHelloForTest {
			t.Fatalf("the apply tail must start an in-place auth upgrade on the established "+
				"connection; got frame type %d, want %d. Without this line a committed key "+
				"never reaches an existing session-sync stream and #6628 is reopened with "+
				"every pkg/cluster test still green",
				typ, cluster.SyncMsgAuthUpgradeHelloForTest)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the apply tail put nothing on the wire: no in-place auth upgrade was started")
	}
}
