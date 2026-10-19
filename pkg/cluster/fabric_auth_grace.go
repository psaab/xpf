package cluster

// Fabric rollout-grace first-keyed anchor persistence (#15262).
//
// The #11676 grace was anchored at the in-memory no-key -> key transition
// in UpdateConfig (group_state.go). Every xpfd process start satisfies
// that transition — a fresh Manager has no key — so a long-keyed node
// re-opened up to five minutes of tokenless read-only fabric RPCs
// (GetSessions, GetSessionSummary, GetZonePairSummary, MonitorInterface,
// safe ShowText) on EVERY restart, until the peer next authenticated and
// armed enforcement. The exposure is bounded per start, but it recurs
// deterministically and needs no operator action to trigger.
//
// This file persists the first-keyed instant, scoped to the accepted-key
// set, in durable node state next to the HA boot epoch
// (/var/lib/xpf/fabric-auth-grace). The record is:
//
//	<first-keyed unix-nanos> <accepted-set digest>\n
//
// The digest is HMAC-SHA256 over a domain tag keyed by each accepted key
// (primary then additional), concatenated — see controlAuthKeySetDigest.
// It never contains key bytes and, like controlLinkKeyID, is a keyed
// digest rather than a plain hash, so the file is not an offline oracle
// beyond what the 32-bit operator key-id already publishes. Scoping by
// the SET (not the signing key alone) is what the acceptance requires in
// both directions:
//
//   - a restart under an UNCHANGED accepted set restores the original
//     first-keyed time, so the grace keeps running from first keying and
//     is already expired five minutes later — no fresh window;
//   - a NEW key (rotation: signing key changed, or the additional key
//     added/retired) is a different set, so it re-anchors and still gets
//     its rollout grace, which is the grace's legitimate purpose.
//
// Failure posture is fail-closed for the grace and fail-open for the
// daemon: a persist failure only logs — UpdateConfig must never fail a
// config apply over an auxiliary state file, and on a healthy node the
// write lands. If the record is missing/corrupt/mismatched, the caller
// treats the apply as a fresh first keying (today's behaviour); the
// residual is a node whose /var/lib/xpf was wiped, which is indistinguish-
// able from a genuinely new keying without a stronger identity for the
// file. A backwards clock step is handled by keeping the earliest valid
// first-keyed time for the digest (see UpdateConfig).
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// fabricAuthGraceStatePath is where the first-keyed anchor is persisted.
// /var/lib/xpf is the persistent runtime-state root xpf already uses for
// the HA boot epoch (bootEpochPath) and SNMPv3 engineBoots. A package var
// so tests can redirect it, mirroring bootEpochPath.
var fabricAuthGraceStatePath = "/var/lib/xpf/fabric-auth-grace"

// fabricAuthGraceNow is the wall clock the anchor is stamped and compared
// with. A var so cluster tests can pin an instant across a simulated
// restart (two Managers) without sleeping; production never replaces it.
// The grpcapi tests do not need it: they derive their fabric clock from
// ControlLinkAuthKeyConfiguredAt itself.
var fabricAuthGraceNow = func() time.Time { return time.Now() }

// fabricAuthGraceStateTag domain-separates the accepted-set digest from
// every other HMAC computed with the control-link PSK (heartbeat frame
// MAC, fabric bearer token, controlLinkKeyID). Versioned so a future
// digest-layout change gets a distinct value for free.
var fabricAuthGraceStateTag = []byte("xpf fabric-auth grace anchor v1")

// controlAuthKeySetDigest derives a stable identifier for an accepted-key
// SET: HMAC-SHA256(primary, tag) || HMAC-SHA256(additional, tag) when the
// additional key is present, hex-encoded. Either key may be empty only
// when the whole set is empty, in which case the digest is "".
//
// Keying each component (rather than hashing the raw keys) means the
// persisted file holds no value an attacker can dictionary-test faster
// than they can already test a captured heartbeat/fabric MAC, and the
// domain tag keeps the digest from being confused with any other value
// derived from the same PSK. Concatenation (rather than hashing the pair
// under one key) keeps the digest defined when only the additional key
// is configured, and makes A+B distinct from B+A in the two slots — the
// signing slot and the accept-only slot are different postures.
func controlAuthKeySetDigest(primary, additional []byte) string {
	if len(primary) == 0 && len(additional) == 0 {
		return ""
	}
	var b strings.Builder
	for _, k := range [][]byte{primary, additional} {
		if len(k) == 0 {
			continue
		}
		mac := hmac.New(sha256.New, k)
		mac.Write(fabricAuthGraceStateTag)
		b.WriteString(hex.EncodeToString(mac.Sum(nil)))
	}
	return b.String()
}

func loadFabricAuthGraceAnchor(path, digest string) time.Time {
	if digest == "" {
		return time.Time{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) != 2 || fields[1] != digest {
		return time.Time{}
	}
	nanos, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || nanos <= 0 {
		return time.Time{}
	}
	at := time.Unix(0, nanos).UTC()
	if at.After(fabricAuthGraceNow()) {
		return time.Time{}
	}
	return at
}

// persistFabricAuthGraceAnchor durably records at as the first-keyed time
// for digest. Best-effort: a failure is logged and otherwise ignored (see
// the file header for why a failed write must not fail the config apply).
// A post-rename fsync failure means the record IS visible to the next
// read, so it is not reported as a failure to persist.
func persistFabricAuthGraceAnchor(path, digest string, at time.Time) {
	if digest == "" || at.IsZero() {
		return
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("cluster: fabric rollout-grace anchor state dir create failed; "+
			"a restart under an unchanged key will re-open the tokenless read-only grace (#15262)",
			"path", path, "err", err)
		return
	}
	body := strconv.FormatInt(at.UnixNano(), 10) + " " + digest + "\n"
	if err := fsatomic.WriteFileDurable(path, []byte(body), 0o644); err != nil {
		var postRename *fsatomic.PostRenameSyncError
		if errors.As(err, &postRename) {
			slog.Warn("cluster: fabric rollout-grace anchor persisted but its durability is UNKNOWN "+
				"(the post-rename directory fsync failed; the value IS visible to the next read)",
				"path", path, "err", err)
			return
		}
		slog.Warn("cluster: fabric rollout-grace anchor persist failed; "+
			"a restart under an unchanged key will re-open the tokenless read-only grace (#15262)",
			"path", path, "err", err)
	}
}

// SetFabricAuthGraceStatePathForTesting redirects the first-keyed anchor
// file (#15262) to path and returns a restore function. Test-only,
// mirroring the bootEpochPath redirection pattern; not for production
// callers. It exists so a simulated restart (a second Manager over the
// same path) can prove the persisted anchor is honoured.
func SetFabricAuthGraceStatePathForTesting(path string) func() {
	orig := fabricAuthGraceStatePath
	fabricAuthGraceStatePath = path
	return func() { fabricAuthGraceStatePath = orig }
}
