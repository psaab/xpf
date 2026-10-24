package cluster

// Control-link PSK rotation overlap (#6630).
//
// THE DEFECT. Before this, rotating the control-link PSK was a PLANNED-OUTAGE
// operation. There is one key, and a node verifies every control frame against
// exactly that key, so the moment one node is committed to the new key each end
// receives a present-but-invalid HMAC from the other. `admitFrame` rejects
// those frames WITHOUT refreshing `lastSeen`, so after
// `heartbeat-interval x heartbeat-threshold` — 200 ms x 5 = ~1 s at the shipped
// cluster settings — BOTH nodes declare the peer dead and BOTH take over their
// redundancy groups: dual-master with duplicate VIPs on the wire for the whole
// window between the two commits.
//
// The workaround pkg/cluster/README.md used to document — clear both keys,
// then set the new one — does not work either: `validateClusterAuthKeyStrict`
// (#6611) expressly refuses to commit a cluster with no key, so the documented
// rotation path is rejected by the very gate that requires the key.
//
// THE MECHANISM. `additional-authentication-key` is a second key a node
// ACCEPTS and never SIGNS with. Because signing is unchanged, a rotation never
// has two signers and the two commits can be separated in time:
//
//	1. node0: set additional-authentication-key B   (signs A, accepts A+B)
//	2. node1: set additional-authentication-key B   (signs A, accepts A+B)
//	3. node0: set authentication-key B
//	          set additional-authentication-key A   (signs B, accepts B+A)
//	4. node1: same                                  (signs B, accepts B+A)
//	5. both:  delete additional-authentication-key  (signs B, accepts B)
//
// At every step each node accepts what the other is signing, so liveness is
// never lost. Step 5 is the explicit FINALIZE: it is an operator commit, not a
// timer, so the overlap ends when the operator says so and is never permanent.
//
// #16029: "never permanent" relied on the operator remembering step 5. A
// forgotten finalize left the retired key accepted indefinitely — no
// expiry, no age, no alarm. The window now records when it opened
// (Manager.controlLinkRotationOpenedAt, stamped in UpdateConfig when the
// additional key's identity changes) and the status line renders its age;
// past controlLinkRotationStaleAfter (7 days) the line carries an ALARM
// naming the window by key ID. It still never auto-finalizes: retiring a
// key the peer still signs with reopens the dual-master window, so the
// remedy stays an operator commit — now a prompted one.
//
// WHY AN OVERLAP AND NOT A COORDINATED CUTOVER. The two nodes have no channel
// to agree a cutover instant on that does not itself depend on the key being
// rotated. Once the PSK becomes provisioning-time node-local state — the
// eventual posture recorded in pkg/cluster/README.md under "The three-way
// incompatibility" — there is not even a config-sync push to carry a
// coordinated plan. A bounded dual-accept window is therefore FORCED, not
// preferred: it is the only rotation that keeps heartbeat liveness.
//
// WHY A DERIVED ID AND NOT A KEY ID ON THE WIRE. #6630 asks for a key
// identifier in the frame so a receiver knows which key to verify against
// rather than trying both. The receiver already learns which key verified, for
// free, by trying them — two HMACs over a ~52-byte frame at 5 Hz is not a cost
// worth a wire change, and a wire change on the heartbeat is a mixed-version
// hazard on the one channel whose failure mode is dual-master. The PROPERTY
// the identifier was for is "the operator can answer: has the peer moved to
// the new key, is it safe to finalize?", and that is answered by recording
// which accepted key last verified a peer frame and surfacing its id in
// `show chassis cluster statistics`. Same answer, no new bytes on the wire,
// and nothing about the key exposed to an observer that they could not already
// compute if they held it.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// controlLinkKeyIDTag domain-separates the key-id derivation from every other
// HMAC this package computes with the same PSK (the heartbeat frame MAC, the
// fabric bearer token, the session-sync frame key). Without it a key id and a
// frame MAC would be the same construction over different inputs, and a
// published id would be a chosen-input oracle on the key.
var controlLinkKeyIDTag = []byte("xpf cluster control-link key-id v1")

// controlLinkKeyIDLen is how many hex characters of the derived digest form
// the id. 8 hex chars = 32 bits: enough that an operator comparing two ids by
// eye is not misled by a collision during a rotation (there are two keys, not
// a population), and short enough to sit in a `show` line.
const controlLinkKeyIDLen = 8

// controlLinkKeyID derives a short, stable, operator-facing identifier for a
// control-link key. Empty for an absent key.
//
// It is HMAC-SHA256(key, tag), truncated — NOT a hash of the key, and not the
// key. Truncation to 32 bits means the id is not a practical target for
// recovering the key, and the domain-separation tag means it cannot be
// confused with, or used as an oracle for, any other value derived from the
// same PSK. Two nodes holding the same key derive the same id with no
// exchange, which is the whole point: the operator compares ids across a
// `show` on each node.
//
// It is safe to log and to render. Everything else about the key is not.
func controlLinkKeyID(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(controlLinkKeyIDTag)
	return hex.EncodeToString(mac.Sum(nil))[:controlLinkKeyIDLen]
}

// controlLinkRotationStaleAfter is the #16029 age at which an open rotation
// window stops reading as routine and starts reading as forgotten. The
// normal procedure (README "Procedure — rotate A to B") is five commits
// usually separated by minutes; even a cautious maintenance that stages one
// node per day finishes inside a week. Seven days is therefore well past
// any legitimate in-flight rotation, while still naming the exposure —
// the retired key remains accepted — long before it becomes permanent.
// It alarms only; it NEVER retires the additional key itself, because
// finalizing while the peer still signs the old key reopens the
// dual-master window (see ControlLinkRotationSafeToFinalize).
const controlLinkRotationStaleAfter = 7 * 24 * time.Hour

// controlLinkRotationNow is the wall clock rotation-open stamps and age
// comparisons read. A var so tests can pin an instant across applies
// without sleeping, mirroring fabricAuthGraceNow; production never
// replaces it.
var controlLinkRotationNow = func() time.Time { return time.Now() }

// controlLinkRotationAge reports how long the current additional-key
// window has been open and whether one is open at all. A closed window,
// or a future-dated open stamp (wall clock stepped backwards), reports
// not-open/zero rather than a negative age: the alarm must never fire on
// clock noise, and a backwards step must not suppress it forever — the
// age simply restarts from zero at the stepped clock.
func (m *Manager) controlLinkRotationAge() (time.Duration, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.controlLinkRotationAgeLocked()
}

// controlLinkRotationAgeLocked is controlLinkRotationAge for callers
// already holding m.mu (read or write).
func (m *Manager) controlLinkRotationAgeLocked() (time.Duration, bool) {
	if len(m.controlAuthKeyAlt) == 0 || m.controlLinkRotationOpenedAt.IsZero() {
		return 0, false
	}
	if age := controlLinkRotationNow().Sub(m.controlLinkRotationOpenedAt); age > 0 {
		return age, true
	}
	return 0, true
}

// ControlLinkRotationOpenSince returns the wall-clock instant the current
// additional-key window opened, or the zero Time when no window is open.
// Zero also after a daemon restart until the first config apply re-anchors
// it (the anchor is in-memory; see Manager.controlLinkRotationOpenedAt).
func (m *Manager) ControlLinkRotationOpenSince() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.controlAuthKeyAlt) == 0 {
		return time.Time{}
	}
	return m.controlLinkRotationOpenedAt
}

// ControlLinkRotationStale reports the #16029 forgotten-rotation alarm
// state: a rotation window is open and has been open longer than
// controlLinkRotationStaleAfter, so the retired key has remained accepted
// far past any legitimate in-flight rotation. The returned duration is
// the window's current age (0 when not stale). Naming the window is the
// status line's job (controlLinkRotationStatus); this predicate is the
// machine-readable half for tests and other renderers.
func (m *Manager) ControlLinkRotationStale() (time.Duration, bool) {
	age, open := m.controlLinkRotationAge()
	if !open || age <= controlLinkRotationStaleAfter {
		return 0, false
	}
	return age, true
}

// notePeerControlKeyID records the id of the accepted key that last verified a
// peer control frame (#6630).
//
// This is the observation a rotation needs and nothing else provides. "Both
// nodes are committed to key B" is a statement about two config files; "the
// peer is currently SIGNING with B" is a statement about the running system,
// and only the second one makes finalizing safe. Retiring the old key while
// the peer still signs with it re-opens the dual-master window the overlap
// exists to close.
//
// Written on every accepted authenticated frame — a plain string store under
// the manager lock, at heartbeat rate, so it costs nothing measurable — and
// deliberately NOT sticky: if the peer moves back to the old key (a rollback,
// or a node replaced from an older config drive), the operator must see that,
// not the high-water mark of what it once used.
func (m *Manager) notePeerControlKeyID(id string) {
	if id == "" {
		return
	}
	m.mu.Lock()
	if m.peerControlKeyID != id {
		m.peerControlKeyID = id
	}
	m.mu.Unlock()
}

// PeerControlKeyID returns the id of the accepted key the peer's last verified
// control frame was signed with, or "" if no authenticated frame has been
// accepted. Safe to render.
func (m *Manager) PeerControlKeyID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerControlKeyID
}

// ControlLinkKeyIDs returns the id of the key this node SIGNS with and the id
// of the additional key it merely ACCEPTS (empty when no rotation window is
// open). Safe to render.
func (m *Manager) ControlLinkKeyIDs() (signing, additional string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return controlLinkKeyID(m.controlAuthKey), controlLinkKeyID(m.controlAuthKeyAlt)
}

// ControlLinkRotationSafeToFinalize reports whether retiring the additional
// key would keep the peer authenticated: a rotation window is open, and the
// peer's last verified frame was signed with the key this node SIGNS with
// rather than the additional one.
//
// False when no window is open (nothing to finalize), and false when no
// authenticated peer frame has been seen at all — absence of evidence is not
// evidence that the peer has moved, and this is the direction where being
// wrong costs a dual-master window.
func (m *Manager) ControlLinkRotationSafeToFinalize() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.controlAuthKeyAlt) == 0 || len(m.controlAuthKey) == 0 {
		return false
	}
	if m.peerControlKeyID == "" {
		return false
	}
	return m.peerControlKeyID == controlLinkKeyID(m.controlAuthKey)
}
