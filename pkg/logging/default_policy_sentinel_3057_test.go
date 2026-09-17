package logging

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #3057: the implicit default-policy deny/reject carries a reserved sentinel
// policy ID (dataplane.DefaultPolicySentinelID) that can never equal a real
// configured policy ID. Before the fix it emitted 0, which aliased the FIRST
// configured policy (also ID 0); when that first policy is a permit, a default
// deny logged with the permit's name — an actively misleading audit trail.

// TestResolvePolicyNameSentinelRendersDefaultPolicy proves the sentinel resolves
// to "default-policy" and that id 0 resolves to something DISTINCT from it —
// the two no longer collide, which is the #3057 property.
//
// SUPERSEDED IN PART by #4626/#6851. This test originally also asserted that a
// genuine policy ID 0 "still resolves to the first configured policy". That
// claim was retired deliberately: id 0 is ALSO the id stamped on every session
// no policy admitted (host-inbound, neighbour-seed, fabric, tunnel, pre-#3056,
// and everything synced from an older HA peer), so the wire value is genuinely
// ambiguous and naming a real rule is the more dangerous of the two possible
// errors — see dataplane.UnattributedPolicyName. The six session-row surfaces
// were routed through that guard by #4626; #6851 routed this RT_FLOW resolver
// through it too, because a syslog record ships off-box and its attribution is
// durable.
//
// The #3057 property this test exists for is UNAFFECTED and is asserted in both
// directions below: the sentinel must not render as the first policy, and id 0
// must not render as the default-policy. What changed is only the third value —
// id 0 now under-claims as "unattributed" instead of naming allow-web.
func TestResolvePolicyNameSentinelRendersDefaultPolicy(t *testing.T) {
	er := NewEventReader(nil, NewEventBuffer(16))
	// The first configured policy is a PERMIT at real runtime ID 0 — exactly
	// the value the implicit default used to borrow.
	er.SetPolicyNames(map[uint32]string{0: "allow-web"})

	if got := er.resolvePolicyName(dataplane.DefaultPolicySentinelID); got != dataplane.DefaultPolicyName {
		t.Fatalf("sentinel resolved to %q, want %q (must NOT alias the first policy)", got, dataplane.DefaultPolicyName)
	}
	if got := er.resolvePolicyName(dataplane.DefaultPolicySentinelID); got == "allow-web" {
		t.Fatalf("sentinel resolved to the first policy name %q — the #3057 collision", got)
	}
	// #4626/#6851: id 0 under-claims rather than naming the first policy.
	if got := er.resolvePolicyName(0); got != dataplane.UnattributedPolicyName {
		t.Fatalf("policy ID 0 resolved to %q, want %q — id 0 is overloaded and must "+
			"not name the first configured policy (#4626/#6851)",
			got, dataplane.UnattributedPolicyName)
	}
	// The #3057 non-collision, asserted in the OTHER direction too: id 0 must
	// not be rendered as the implicit default either. A "fix" that collapsed
	// both reserved ids onto one name would satisfy the assertion above and
	// re-create exactly the aliasing #3057 removed.
	if got := er.resolvePolicyName(0); got == dataplane.DefaultPolicyName {
		t.Fatalf("policy ID 0 resolved to %q — the two RESERVED ids must stay "+
			"distinct from each other (#3057)", got)
	}
}

// rawPolicyDenyFrame builds a POLICY_DENY raw event frame (eventType 3) with the
// given policy ID stamped at the wire policy_id slot [44:48].
func rawPolicyDenyFrame(policyID uint32) []byte {
	data := make([]byte, rawEventWireSize)
	data[40] = 0x30 // src port 12345
	data[41] = 0x39
	data[42] = 0x01 // dst port 443
	data[43] = 0xbb
	binary.LittleEndian.PutUint32(data[44:48], policyID)
	data[52] = eventTypePolicyDeny
	data[53] = 6 // TCP
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("203.0.113.7").To4())
	copy(data[24:28], net.ParseIP("8.8.8.8").To4())
	return data
}

// TestDefaultPolicyDenyDoesNotMisattributeToFirstPermit is the exact
// misleading-audit case: the first configured policy is a PERMIT (real ID 0),
// and a packet matching no policy is denied by the implicit default. The
// structured RT_FLOW_SESSION_DENY record MUST show policy-name="default-policy",
// NOT the permit policy's name.
func TestDefaultPolicyDenyDoesNotMisattributeToFirstPermit(t *testing.T) {
	er := NewEventReader(nil, NewEventBuffer(16))
	er.SetPolicyNames(map[uint32]string{0: "allow-web"}) // first policy is a permit

	if ok := er.ProcessRawEvent(rawPolicyDenyFrame(dataplane.DefaultPolicySentinelID)); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}
	recs := er.buffer.Latest(16)
	if len(recs) != 1 {
		t.Fatalf("buffer has %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Type != "POLICY_DENY" {
		t.Fatalf("record type = %q, want POLICY_DENY", rec.Type)
	}
	if rec.PolicyName != dataplane.DefaultPolicyName {
		t.Fatalf("default-deny record PolicyName = %q, want %q (must not borrow the first permit's name)", rec.PolicyName, dataplane.DefaultPolicyName)
	}

	structured := formatStructuredMsg(rec, 6)
	if !strings.Contains(structured, `policy-name="default-policy"`) {
		t.Fatalf("structured RT_FLOW missing default-policy:\n%s", structured)
	}
	if strings.Contains(structured, `policy-name="allow-web"`) {
		t.Fatalf("structured RT_FLOW mis-attributes the default deny to the first permit:\n%s", structured)
	}
}

// TestUnattributedPolicyDenyRendersUnattributed exercises the other reserved
// policy id through the actual raw POLICY_DENY decoder. A deny produced before
// policy evaluation (such as #6682's unzoned-ingress guard) must render as
// "unattributed", not as the implicit default-policy and not as a configured
// policy that happens to occupy runtime id 0.
func TestUnattributedPolicyDenyRendersUnattributed(t *testing.T) {
	er := NewEventReader(nil, NewEventBuffer(16))
	er.SetPolicyNames(map[uint32]string{0: "allow-web"}) // real id 0 must not win

	if ok := er.ProcessRawEvent(rawPolicyDenyFrame(dataplane.UnattributedPolicyID)); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}
	recs := er.buffer.Latest(16)
	if len(recs) != 1 {
		t.Fatalf("buffer has %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Type != "POLICY_DENY" {
		t.Fatalf("record type = %q, want POLICY_DENY", rec.Type)
	}

	if rec.PolicyID != dataplane.UnattributedPolicyID {
		t.Fatalf("unattributed-deny record PolicyID = %d, want %d",
			rec.PolicyID, dataplane.UnattributedPolicyID)
	}
	if rec.PolicyName != dataplane.UnattributedPolicyName {
		t.Fatalf("unattributed-deny record PolicyName = %q, want %q",
			rec.PolicyName, dataplane.UnattributedPolicyName)
	}

	structured := formatStructuredMsg(rec, 6)
	if !strings.Contains(structured, `policy-name="unattributed"`) {
		t.Fatalf("structured RT_FLOW missing unattributed policy name:\n%s", structured)
	}
	if strings.Contains(structured, `policy-name="default-policy"`) ||
		strings.Contains(structured, `policy-name="allow-web"`) {
		t.Fatalf("structured RT_FLOW mis-attributed the unzoned deny:\n%s", structured)
	}
}

// TestDefaultPolicySentinelLockstepWithRust is the cross-language contract test:
// the Go dataplane.DefaultPolicySentinelID MUST byte-for-byte equal the Rust
// DEFAULT_POLICY_SENTINEL_ID in userspace-dp/src/policy.rs. The value travels in
// the shared policy_id u32 wire field; a drift would silently mis-render (or, at
// the extreme, re-collide) the implicit default-policy. The test reads the Rust
// source and parses the constant rather than hard-coding it, so a change to
// either side that forgets the other fails here.
func TestDefaultPolicySentinelLockstepWithRust(t *testing.T) {
	// pkg/logging -> repo root is ../../
	src := filepath.Join("..", "..", "userspace-dp", "src", "policy.rs")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	re := regexp.MustCompile(`(?m)const\s+DEFAULT_POLICY_SENTINEL_ID\s*:\s*u32\s*=\s*([A-Za-z0-9_:]+)\s*;`)
	m := re.FindSubmatch(body)
	if m == nil {
		t.Fatalf("could not find DEFAULT_POLICY_SENTINEL_ID in %s", src)
	}
	rustExpr := string(m[1])
	var rustVal uint64
	switch rustExpr {
	case "u32::MAX":
		rustVal = 0xFFFFFFFF
	default:
		// Accept a numeric/hex literal form too (strip Rust underscores).
		clean := strings.ReplaceAll(rustExpr, "_", "")
		parsed, perr := strconv.ParseUint(strings.TrimPrefix(clean, "0x"), hexOrDec(clean), 64)
		if perr != nil {
			t.Fatalf("unrecognized DEFAULT_POLICY_SENTINEL_ID expression %q: %v", rustExpr, perr)
		}
		rustVal = parsed
	}
	if uint64(dataplane.DefaultPolicySentinelID) != rustVal {
		t.Fatalf("Go DefaultPolicySentinelID=0x%X must equal Rust DEFAULT_POLICY_SENTINEL_ID=%s (0x%X) "+
			"(lockstep, see userspace-dp/src/policy.rs)", dataplane.DefaultPolicySentinelID, rustExpr, rustVal)
	}
}

// TestUnattributedPolicyIDLockstepWithRust is the #9989 counterpart of the
// #3057 sentinel lockstep above: Go dataplane.UnattributedPolicyID MUST
// byte-for-byte equal Rust UNATTRIBUTED_POLICY_ID in
// userspace-dp/src/policy.rs. Both are zero today, so a hard-coded assertion
// would stay green if the Rust side drifted to a fresh reserved value while Go
// kept 0 (or vice versa) — parsing the Rust literal binds the two sides so a
// one-sided change fails here.
func TestUnattributedPolicyIDLockstepWithRust(t *testing.T) {
	// pkg/logging -> repo root is ../../
	src := filepath.Join("..", "..", "userspace-dp", "src", "policy.rs")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	re := regexp.MustCompile(`(?m)const\s+UNATTRIBUTED_POLICY_ID\s*:\s*u32\s*=\s*([A-Za-z0-9_:]+)\s*;`)
	m := re.FindSubmatch(body)
	if m == nil {
		t.Fatalf("could not find UNATTRIBUTED_POLICY_ID in %s", src)
	}
	rustExpr := string(m[1])
	var rustVal uint64
	switch rustExpr {
	case "u32::MIN":
		rustVal = 0
	default:
		// Accept a numeric/hex literal form too (strip Rust underscores).
		clean := strings.ReplaceAll(rustExpr, "_", "")
		parsed, perr := strconv.ParseUint(strings.TrimPrefix(clean, "0x"), hexOrDec(clean), 64)
		if perr != nil {
			t.Fatalf("unrecognized UNATTRIBUTED_POLICY_ID expression %q: %v", rustExpr, perr)
		}
		rustVal = parsed
	}
	if uint64(dataplane.UnattributedPolicyID) != rustVal {
		t.Fatalf("Go UnattributedPolicyID=0x%X must equal Rust UNATTRIBUTED_POLICY_ID=%s (0x%X) "+
			"(lockstep, see userspace-dp/src/policy.rs)", dataplane.UnattributedPolicyID, rustExpr, rustVal)
	}
}

func hexOrDec(s string) int {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return 16
	}
	return 10
}
