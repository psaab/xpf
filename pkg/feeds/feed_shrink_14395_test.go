package feeds

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// epochRotationBody14395 builds a canonical body from prefix strings already
// in canonical form.
func epochBody14395(prefixes []string) string {
	var b strings.Builder
	for _, p := range prefixes {
		b.WriteString(p)
		b.WriteString("\n")
	}
	return b.String()
}

func epochPrefixes14395(octet2 byte, start, count int) []string {
	out := make([]string, 0, count)
	for i := start; i < start+count; i++ {
		out = append(out, fmt.Sprintf("198.%d.%d.%d/32", octet2, i>>8, i&0xff))
	}
	return out
}

// TestMultiStepRotationRefusedAgainstEpochBaseline14395 is the decisive
// DR8-H5 / #14395 regression: three successive 51%-retained equal-count
// rotations, each retaining 51% of its immediate predecessor while dropping
// surviving originals first, must not fully replace the epoch set without a
// refusal. Step 1 installs (51% of epoch retained); step 2 retains only 2
// originals (2% of epoch) and must be refused against the epoch baseline,
// leaving the installed set unchanged and naming epoch content overlap.
func TestMultiStepRotationRefusedAgainstEpochBaseline14395(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	m, server, fs := newShrinkFeed11059(t, "epoch-rotation-feed", retainForever, nil)

	originals := epochPrefixes14395(18, 0, 100) // P1..P100
	server.set(epochBody14395(originals), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 {
		t.Fatalf("seed installed %d prefixes, want 100", got)
	}
	seedInfo := m.AllFeeds()[fs.name]

	// Step 1: retain P1..P51, add A1..A49 (198.19.*). Installs.
	step1 := append(append([]string{}, originals[:51]...), epochPrefixes14395(19, 0, 49)...)
	server.set(epochBody14395(step1), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 || m.AllFeeds()[fs.name].ShrinkRefused {
		t.Fatalf("single 51%%-retained rotation did not install: installed=%d info=%+v", got, m.AllFeeds()[fs.name])
	}
	step1Info := m.AllFeeds()[fs.name]
	if step1Info.Hash == seedInfo.Hash {
		t.Fatal("step 1 did not change installed content")
	}

	// Step 2: retain 51 of step-1 set: only P1,P2 originals + all 49 A
	// prefixes, add B1..B49 (198.20.*). Retains 51% of predecessor but only
	// 2% of epoch -> must be refused no later than here.
	step2 := append(append([]string{}, originals[:2]...), epochPrefixes14395(19, 0, 49)...)
	step2 = append(step2, epochPrefixes14395(20, 0, 49)...)
	server.set(epochBody14395(step2), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	info := m.AllFeeds()[fs.name]
	if !info.ShrinkRefused {
		t.Fatalf("second rotation (2%% of epoch) was not refused: installed=%d info=%+v logs=%s", len(m.GetPrefixes(fs.name)), info, logs.String())
	}
	if got := len(m.GetPrefixes(fs.name)); got != 100 || info.Hash != step1Info.Hash {
		t.Fatalf("epoch refusal changed installed set: installed=%d info=%+v want hash %s", got, info, step1Info.Hash)
	}
	if info.ShrinkCandidateOldCount != 100 {
		t.Fatalf("epoch churn refusal old count = %d, want epoch 100: %+v", info.ShrinkCandidateOldCount, info)
	}
	if info.ShrinkBaselineHash != seedInfo.Hash {
		t.Fatalf("epoch churn refusal baseline hash = %q, want epoch hash %q: %+v", info.ShrinkBaselineHash, seedInfo.Hash, info)
	}
	if !strings.Contains(info.ShrinkCandidateReason, "epoch") || !strings.Contains(info.ShrinkCandidateReason, "overlap") {
		t.Fatalf("refusal reason does not name epoch content overlap: %q", info.ShrinkCandidateReason)
	}
	if !strings.Contains(info.LastError, "epoch") {
		t.Fatalf("refusal error does not name epoch baseline: %q", info.LastError)
	}
	if !strings.Contains(logs.String(), "content-churn") {
		t.Fatalf("epoch churn refusal not audited as content-churn:\n%s", logs.String())
	}

	// Step 3 candidate (0 originals) also refused while epoch stands; the
	// already-refused step-2 candidate remains the pinned refusal if step 3
	// is a different candidate it becomes the new refusal — either way the
	// installed set must stay at step 1.
	step3 := append(append([]string{}, epochPrefixes14395(19, 0, 51)...), epochPrefixes14395(21, 0, 49)...)
	server.set(epochBody14395(step3), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	info = m.AllFeeds()[fs.name]
	if !info.ShrinkRefused || len(m.GetPrefixes(fs.name)) != 100 || info.Hash != step1Info.Hash {
		t.Fatalf("third rotation installed or cleared epoch refusal: installed=%d info=%+v", len(m.GetPrefixes(fs.name)), info)
	}
}

// TestAcknowledgedEpochChurnRebasesEpoch14395: acknowledging the exact
// epoch-churn candidate installs it and rebases the epoch, so a subsequent
// 51%-retained rotation against the NEW epoch installs.
func TestAcknowledgedEpochChurnRebasesEpoch14395(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "epoch-ack-feed", retainForever, nil)
	originals := epochPrefixes14395(18, 0, 100)
	server.set(epochBody14395(originals), http.StatusOK)
	m.fetchFeed(context.Background(), fs)

	step1 := append(append([]string{}, originals[:51]...), epochPrefixes14395(19, 0, 49)...)
	server.set(epochBody14395(step1), http.StatusOK)
	m.fetchFeed(context.Background(), fs)

	step2 := append(append([]string{}, originals[:2]...), epochPrefixes14395(19, 0, 49)...)
	step2 = append(step2, epochPrefixes14395(20, 0, 49)...)
	server.set(epochBody14395(step2), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	info := m.AllFeeds()[fs.name]
	if !info.ShrinkRefused {
		t.Fatalf("fixture: epoch churn was not refused: %+v", info)
	}
	if err := m.AcknowledgeFeedShrink(fs.name, info.ShrinkRefusalID,
		info.ShrinkCandidateHash, info.ShrinkBaselineHash,
		info.ShrinkCandidateOldCount, info.ShrinkCandidateNewCount,
		"operator=alice", "provider confirmed epoch rotation"); err != nil {
		t.Fatalf("acknowledging epoch churn: %v", err)
	}
	m.fetchFeed(context.Background(), fs)
	installed := m.AllFeeds()[fs.name]
	if installed.ShrinkRefused || installed.Hash != info.ShrinkCandidateHash || len(m.GetPrefixes(fs.name)) != 100 {
		t.Fatalf("acknowledged epoch candidate did not install: %+v", installed)
	}

	// A 51%-retained rotation of the NEW epoch (retain 51 of step2) must
	// install — proving the epoch rebased. Keep 51 step2 entries, add 49 new.
	newEpoch := m.GetPrefixes(fs.name)
	if len(newEpoch) != 100 {
		t.Fatalf("new epoch size %d, want 100", len(newEpoch))
	}
	next := append(append([]string{}, newEpoch[:51]...), epochPrefixes14395(22, 0, 49)...)
	server.set(epochBody14395(next), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 || m.AllFeeds()[fs.name].ShrinkRefused {
		t.Fatalf("51%% rotation of rebased epoch did not install: installed=%d info=%+v", got, m.AllFeeds()[fs.name])
	}
}

// TestEpochContentSurvivesColdRestart14395: the epoch prefix set persists in
// the shrink-history snapshot and is restored, so a cold restart does not
// re-bootstrap the epoch to a rotated set.
func TestEpochContentSurvivesColdRestart14395(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "epoch-cold-feed", retainForever, nil)
	originals := epochPrefixes14395(18, 0, 100)
	server.set(epochBody14395(originals), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	step1 := append(append([]string{}, originals[:51]...), epochPrefixes14395(19, 0, 49)...)
	server.set(epochBody14395(step1), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if m.AllFeeds()[fs.name].ShrinkRefused {
		t.Fatal("fixture: step1 should install")
	}

	snap := m.ShrinkHighWaterSnapshot()
	if len(snap) != 1 || len(snap[0].Prefixes) != 100 {
		t.Fatalf("snapshot does not carry epoch prefixes: %+v", snap)
	}
	epochSet := map[string]bool{}
	for _, p := range snap[0].Prefixes {
		epochSet[p] = true
	}
	for _, p := range originals {
		if !epochSet[p] {
			t.Fatalf("snapshot epoch missing original %s", p)
		}
	}

	// Cold restart via the Apply path (mirrors TestColdRestartRestoresHighWater11755):
	// a fresh manager restored from the snapshot, fed the rotated step1 set
	// as its first fetch, must still refuse the 2%-of-epoch step2 rotation.
	// #14994: the first cold fetch is now compared with the restored epoch
	// (step1 retains 51%, so it installs without rebasing the epoch); the
	// pre-#14994 http URL is also https here because #14385 refuses
	// plaintext-http feed registration on master (pre-existing failure of
	// this fixture on master, unrelated to the guard change).
	cfg := func() *config.DynamicAddressConfig {
		return &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
			"server": {Name: "server", URL: "https://127.0.0.1:1/feed", FeedName: "epoch-cold-feed", UpdateInterval: 3600},
		}}
	}
	m2 := New(nil)
	m2.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m2.RestoreShrinkHighWater(snap)
	m2.Apply(ctx, cfg())
	m2.mu.RLock()
	fs2 := m2.feeds["epoch-cold-feed"]
	m2.mu.RUnlock()
	if fs2 == nil {
		t.Fatal("Apply did not create cold feed")
	}
	select {
	case <-fs2.done:
	case <-time.After(time.Second):
		t.Fatal("cancelled cold feed producer did not exit")
	}
	// #14994: the first cold fetch is compared with the restored epoch.
	// Feeding the original epoch set first installs it (identical to the
	// restored epoch) without rebasing; step1 then installs as an ordinary
	// 51%-retained rotation against the still-standing epoch, and step2
	// (2% of epoch) is refused below.
	origRes, err := parseFeed(strings.NewReader(epochBody14395(originals)))
	if err != nil {
		t.Fatal(err)
	}
	m2.installSnapshot(fs2, origRes)
	if len(m2.GetPrefixes("epoch-cold-feed")) != 100 || m2.AllFeeds()["epoch-cold-feed"].ShrinkRefused {
		t.Fatalf("cold install of restored epoch set was refused: %+v", m2.AllFeeds()["epoch-cold-feed"])
	}
	step1Res, err := parseFeed(strings.NewReader(epochBody14395(step1)))
	if err != nil {
		t.Fatal(err)
	}
	m2.installSnapshot(fs2, step1Res)
	if len(m2.GetPrefixes("epoch-cold-feed")) != 100 || m2.AllFeeds()["epoch-cold-feed"].ShrinkRefused {
		t.Fatalf("cold 51%% rotation of restored epoch did not install: %+v", m2.AllFeeds()["epoch-cold-feed"])
	}
	step2 := append(append([]string{}, originals[:2]...), epochPrefixes14395(19, 0, 49)...)
	step2 = append(step2, epochPrefixes14395(20, 0, 49)...)
	step2Res, err := parseFeed(strings.NewReader(epochBody14395(step2)))
	if err != nil {
		t.Fatal(err)
	}
	m2.installSnapshot(fs2, step2Res)
	info := m2.AllFeeds()["epoch-cold-feed"]
	if !info.ShrinkRefused || info.Hash != step1ResHash(step1Res) {
		t.Fatalf("cold-restarted epoch did not refuse 2%% rotation: %+v", info)
	}
}

func step1ResHash(r fetchResult) string { return fmt.Sprintf("%x", r.hash) }
