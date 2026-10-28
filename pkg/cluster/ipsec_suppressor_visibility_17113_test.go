package cluster

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func captureWarn17113(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// #17113: the IPsec-discriminator suppressor must count and warn once per
// incarnation like its five siblings, instead of silently setting only debt.
func TestIpsecDiscriminatorSuppressorCountsAndWarnsOnce17113(t *testing.T) {
	logs := captureWarn17113(t)
	ss := fenceSync9752()
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagInstallTableIdentity))
	if !ss.peerCapabilitiesLearned() || ss.IpsecTunnelDiscriminatorCapable() {
		t.Fatal("FIXTURE: peer must be learned and IPsec-incapable")
	}
	const ipsecTag = uint64(3)<<32 | 71
	if !ss.suppressIpsecDiscriminatorInstallForIncapablePeer(ipsecTag, "session_v4") {
		t.Fatal("class-3 IPsec install must be withheld from an incapable peer")
	}
	if !ss.suppressIpsecDiscriminatorInstallForIncapablePeer(ipsecTag, "session_v4") {
		t.Fatal("second class-3 IPsec install must also be withheld")
	}
	if got := ss.stats.InstallsSuppressedIpsecDiscriminator.Load(); got != 2 {
		t.Errorf("InstallsSuppressedIpsecDiscriminator = %d, want 2", got)
	}
	if got := ss.Stats().InstallsSuppressedIpsecDiscriminator; got != 2 {
		t.Errorf("Stats().InstallsSuppressedIpsecDiscriminator = %d, want 2", got)
	}
	if !ss.peerIncarnationState().ipsecDiscriminatorSuppressDebt.Load() {
		t.Error("suppression must still record cold-prime debt")
	}
	if got := strings.Count(logs.String(), "withholding IPsec discriminator session installs"); got != 1 {
		t.Errorf("IPsec suppression Warn count = %d, want exactly 1 per incarnation:\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "S9.4") {
		t.Errorf("IPsec suppression Warn must name the S9.4 capability:\n%s", logs.String())
	}
}

// Controls: a capable peer and non-IPsec tags are never counted or warned.
func TestIpsecDiscriminatorSuppressorCapableAndNonIpsecControls17113(t *testing.T) {
	logs := captureWarn17113(t)
	ss := fenceSync9752()
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagIpsecTunnelDiscriminator))
	const ipsecTag = uint64(3)<<32 | 71
	if ss.suppressIpsecDiscriminatorInstallForIncapablePeer(ipsecTag, "session_v4") {
		t.Fatal("capable peer must receive IPsec installs")
	}
	if ss.suppressIpsecDiscriminatorInstallForIncapablePeer(uint64(1)<<32|100, "session_v4") {
		t.Fatal("GRE-class tag must not be withheld by the IPsec suppressor")
	}
	if ss.suppressIpsecDiscriminatorInstallForIncapablePeer(0, "session_v4") {
		t.Fatal("untagged install must not be withheld by the IPsec suppressor")
	}
	if ss.suppressIpsecDiscriminatorInstallForIncapablePeer(uint64(3)<<32, "session_v4") {
		t.Fatal("class-3 tag with zero if_id must not be withheld")
	}
	if got := ss.stats.InstallsSuppressedIpsecDiscriminator.Load(); got != 0 {
		t.Errorf("InstallsSuppressedIpsecDiscriminator = %d, want 0 for controls", got)
	}
	if logs.Len() != 0 {
		t.Errorf("controls must not warn:\n%s", logs.String())
	}
}

// #17113: a bulk aborted by the IPsec fence must name the S9.4 capability,
// not claim the peer lacks install-table identity.
func TestIpsecBulkFenceNamesIpsecCapability17113(t *testing.T) {
	logs := captureWarn17113(t)
	senderSS, _ := newBulk6031Primary(t)
	receiverSS, _ := newBulk6031Standby(t)
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 47912, DstPort: 5203}
	senderSS.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: key, Value: dataplane.SessionValue{
				State: dataplane.SessStateEstablished, IngressZone: 5,
				SessionID: 77, RTFlowSessionID: 77,
				TunnelDiscriminator: uint64(3)<<32 | 71,
			}},
		}}, nil
	}
	senderSS.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagInstallTableIdentity))

	sendErr, bulkEnd := pumpBulkFenced9752(t, senderSS, receiverSS)
	if !errors.Is(sendErr, errBulkFencedForIpsecPeer) {
		t.Fatalf("doBulkSync error = %v, want the IPsec fence sentinel", sendErr)
	}
	if errors.Is(sendErr, errBulkFencedForPeer) {
		t.Fatalf("IPsec-fenced bulk must not report the install-table sentinel: %v", sendErr)
	}
	if !strings.Contains(sendErr.Error(), "IPsec") || !strings.Contains(sendErr.Error(), "S9.4") {
		t.Fatalf("IPsec bulk error must name the S9.4 IPsec discriminator capability: %v", sendErr)
	}
	if strings.Contains(sendErr.Error(), "install-table identity") {
		t.Fatalf("IPsec bulk error must not blame install-table identity: %v", sendErr)
	}
	if bulkEnd {
		t.Fatal("an IPsec-fenced bulk completed its window")
	}
	if !senderSS.peerIncarnationState().bulkFencedForIpsecPeer.Load() {
		t.Error("IPsec fence abort did not latch bulkFencedForIpsecPeer")
	}
	if got := senderSS.stats.InstallsSuppressedIpsecDiscriminator.Load(); got != 1 {
		t.Errorf("InstallsSuppressedIpsecDiscriminator = %d, want 1 for the bulk abort row", got)
	}
	if got := strings.Count(logs.String(), "withholding IPsec discriminator session installs"); got != 1 {
		t.Errorf("bulk IPsec suppression Warn count = %d, want 1:\n%s", got, logs.String())
	}
}

// The latched IPsec refusal (no walk) must also name the S9.4 capability.
func TestIpsecBulkFenceLatchedNamesIpsecCapability17113(t *testing.T) {
	ss := fenceSync9752()
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagInstallTableIdentity))
	ss.peerIncarnationState().bulkFencedForIpsecPeer.Store(true)
	err := ss.BulkSync()
	if !errors.Is(err, errBulkFencedForIpsecPeer) {
		t.Fatalf("latched BulkSync error = %v, want the IPsec fence sentinel", err)
	}
	if errors.Is(err, errBulkFencedForPeer) {
		t.Fatalf("latched IPsec bulk must not report the install-table sentinel: %v", err)
	}
}

func TestIpsecSuppressionCountersVisibleInStatistics17113(t *testing.T) {
	ss := &SessionSync{}
	ss.stats.InstallsSuppressedIpsecDiscriminator.Add(7)
	if got := ss.Stats().InstallsSuppressedIpsecDiscriminator; got != 7 {
		t.Fatalf("Stats().InstallsSuppressedIpsecDiscriminator = %d, want 7", got)
	}
	m := NewManager(0, 1)
	m.SetSyncStats(ss)
	if out := m.FormatInformation(); !strings.Contains(out, "Installs suppressed (peer lacks IPsec discriminator support): 7") {
		t.Errorf("FormatInformation does not expose the IPsec suppression counter:\n%s", out)
	}
	if out := m.FormatStatistics(); !strings.Contains(out, "Installs suppressed (peer lacks IPsec discriminator support)") {
		t.Errorf("FormatStatistics does not expose the IPsec suppression counter:\n%s", out)
	}
}
