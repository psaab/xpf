package config

import (
	"fmt"
	"strings"
)

// validateClusterAuthKeyStrict hard-rejects, at commit / commit-check, a
// `chassis cluster` stanza that configures no `authentication-key` (#6611).
//
// Three independent control-channel authentication mechanisms exist — fabric
// gRPC auth (#4357), heartbeat HMAC + anti-replay (#4326), and session-sync
// challenge/response + per-frame HMAC (#4369) — and ALL THREE key off the same
// `chassis cluster authentication-key` PSK. Each one deliberately fails OPEN
// when that PSK is absent, so the cluster keeps forming during a rolling
// upgrade:
//
//	pkg/grpcapi/fabric_auth.go  fabricAuthDecision:    !keyConfigured -> accept
//	pkg/cluster/heartbeat.go    heartbeatAuthDecision: !keyConfigured -> accept
//	pkg/cluster/sync_auth.go    performSyncHandshake:  no key -> no handshake
//
// An unkeyed cluster therefore runs the fabric gRPC listener, the heartbeat and
// the session-sync channel with NO authentication at all — allowlist-only. Any
// host that can reach the control segment can drive failover, read and clear
// sessions, and inject synthetic sessions. Before this gate, an unkeyed cluster
// committed silently: nothing in the configuration layer even mentioned it.
//
// STRICT applies to EVERY caller of compileTreeStrict, which is more than the
// operator commit. All three of these refuse an unkeyed cluster:
//
//	Store.Commit / CommitCheck / CommitConfirmed — the operator commit. A
//	  rejection here is inert for traffic: the active config and the dataplane
//	  are untouched, so the cluster keeps running while the operator adds a key.
//	daemon.bootstrapFromFile (daemon_apply_commit.go) — the UNATTENDED first-boot
//	  import of /etc/xpf/xpf.conf, taken whenever the config DB has no active
//	  config (daemon_run_bringup.go). A rejection here leaves the node with NO
//	  active config — it does not boot with a warning. This is the path a
//	  reimaged / replaced / DR-restored node takes, and the path
//	  test/incus/cluster-setup.sh takes on every cluster-deploy (it wipes
//	  /etc/xpf/.configdb).
//	configstore.CheckText — `xpfd check-config`, wired into
//	  scripts/deploy/xpf-deploy.py, scripts/image/make_config_drive.py and the
//	  first-boot loader scripts/image/xpf-day0-config (which falls back to the
//	  factory bootstrap on reject).
//	pkg/eventengine — AUTONOMOUS remediation (CommitCheck + the daemon commit
//	  closure). On a leniently-booted unkeyed cluster every `change-configuration`
//	  policy silently fails until the cluster is keyed; no operator is present to
//	  see it.
//
// So the migration order matters and is documented in pkg/cluster/README.md:
// key the RUNNING cluster first (that commit is accepted), and only then
// re-provision, reimage, or rebuild a day-0 drive.
//
// Lenient on load / peer-sync (opts.lenientClusterAuthKey): an already-persisted
// or peer-synced unkeyed config still BOOTS with a warning (#1960 no-brick).
// That is what preserves the IN-PLACE upgrade path — a cluster that was unkeyed
// before the upgrade keeps its config DB, loads it through CompileConfigLenient,
// comes up, and keeps forwarding. The heartbeat and fabric gRPC dual-accept
// grace means a key can then be rolled out one node at a time without dropping
// the cluster. SESSION SYNC is the exception: #5078 removed its dual-accept, so
// a keyed node rejects an unkeyed peer and session sync stays DOWN until both
// nodes are keyed AND both have restarted. pkg/cluster/README.md -> "Rolling it
// onto a live unkeyed cluster" marks the old sequence STALE (#6881).
//
// The key is compared only for emptiness and is never echoed into the error —
// the whole point of Secret (compiler_system.go) is that it never reaches a log
// or a CLI render.
func validateClusterAuthKeyStrict(cfg *Config) error {
	return validateClusterAuthKeyStrictWithCurrent(cfg, nil)
}

// validateClusterAuthKeyStrictWithCurrent is validateClusterAuthKeyStrict
// with the persisted/current signing primary supplied by the candidate
// pipeline (#16025 fold 2). currentPrimary is the trimmed primary of the
// config active immediately before the candidate, or nil when there is
// no such state (fresh candidate, day-0 check, direct CompileConfig).
func validateClusterAuthKeyStrictWithCurrent(cfg *Config, currentPrimary *string) error {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	// TrimSpace normalizes emptiness: a whitespace-only key IS "configured" to
	// the runtime's len(key) > 0 test but is not a key, so trimming here makes
	// this gate deliberately STRICTER than the runtime rather than identical to
	// it — the right direction on the strict path. (The difference stays
	// observable on the tolerant path; see pkg/cluster/README.md "Key
	// strength".) #16025: this is also an ENTROPY floor on the strict path —
	// a non-empty primary key shorter than MinAdvisedControlLinkKeyLen is
	// rejected here, because the heartbeat/fabric/session-sync HMAC over
	// known frame bodies is an offline dictionary oracle for a short PSK.
	// The tolerant path downgrades this rejection to a warning
	// (lenientClusterAuthKey), so a persisted weak key still boots with a
	// warning and never bricks.
	//
	// ROTATION EXCEPTION (#16025 folds 1-2): an EXISTING short primary may
	// remain temporarily on the strict path while a distinct additional
	// key of at least the floor is staged. That is step 1/2 of the
	// documented no-outage #6630 rotation: the node still signs with the
	// existing primary, accepts the staged replacement, and can then swap
	// the primary in steps 3/4 without either peer rejecting its frames.
	//
	// Fold 2 gates the exception on persisted/current state, not on the
	// candidate's shape alone. A fresh candidate can author the identical
	// short-primary + strong-additional pair, so candidate-only proof
	// would let any new cluster commit a weak signing key indefinitely
	// by staging a strong accept-only key beside it. The exception opens
	// only when currentPrimary — the trimmed primary of the config active
	// immediately before this candidate, supplied by configstore from
	// its compiled active config — is present, is itself below the floor,
	// and EQUALS the candidate primary (the same old key being migrated,
	// not a newly chosen short one). Nil current (fresh store, day-0
	// CheckText, direct CompileConfig) keeps the exception closed. A
	// short or identical additional key never satisfies it.
	if key := strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal()); key != "" {
		if len(key) >= MinAdvisedControlLinkKeyLen {
			return nil
		}
		alt := strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKeyAlt.Reveal())
		persistedShortPrimary := currentPrimary != nil &&
			len(*currentPrimary) < MinAdvisedControlLinkKeyLen &&
			len(*currentPrimary) > 0 && *currentPrimary == key
		if persistedShortPrimary && len(alt) >= MinAdvisedControlLinkKeyLen && alt != key {
			return nil
		}
		return fmt.Errorf("chassis cluster: `authentication-key` is %d "+
			"characters; at least %d are required on commit — a short PSK "+
			"can be dictionary-guessed offline from a captured heartbeat "+
			"or fabric frame and then used to forge the control channel; "+
			"generate a replacement with `openssl rand -base64 32`, stage it as "+
			"`chassis cluster additional-authentication-key <key>` on both nodes, "+
			"then rotate it into `authentication-key` using the #6630 overlap",
			len(key), MinAdvisedControlLinkKeyLen)
	}
	if strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKeyAlt.Reveal()) != "" {
		// #6630: the additional key is ACCEPTED, never SIGNED with, so a
		// cluster carrying only it signs nothing and is exactly as fail-open
		// as an unkeyed one. Say so specifically rather than letting the
		// generic message send an operator to re-add the leaf they already
		// have.
		return fmt.Errorf("chassis cluster: `additional-authentication-key` is set but " +
			"`authentication-key` is not — the additional key is only ever VERIFIED " +
			"against, never signed with, so this node would sign nothing and the control " +
			"channel would fail OPEN exactly as if unkeyed; set `chassis cluster " +
			"authentication-key <key>` to the key this node should sign with")
	}
	return fmt.Errorf("chassis cluster: no authentication-key configured — the " +
		"cluster control channel (fabric gRPC, heartbeat, and session sync) " +
		"authenticates with a shared PSK and fails OPEN when none is set, so " +
		"any host able to reach the control segment could drive failover, read " +
		"or clear sessions, and inject sessions; set `chassis cluster " +
		"authentication-key <key>` to the SAME value on both nodes (generate " +
		"one with `openssl rand -base64 32`)")
}

// validateStrictSessionAuthNeedsKeyStrict rejects `chassis cluster
// strict-session-auth` on a node with no control-link PSK — #7441.
//
// The posture is INERT without a key: the runtime rule is "while this node is
// keyed AND the posture is declared, an un-upgraded session-sync connection is
// dropped", so with no key nothing is ever evicted. An operator who sets the
// leaf and believes the hole is closed is worse off than one who is told.
//
// WHY IT IS ORDERED BEFORE validateClusterAuthKeyStrict, which already rejects
// a keyless cluster on its own: that gate's message is about the control
// channel failing open and sends the operator to add a key, saying nothing
// about the posture leaf they just set. Both messages are true; this one
// describes what the operator actually did. Ordering it first is the whole
// reason it is reachable at all on the strict path.
//
// It honours the SAME lenient downgrade (#1960 no-brick) as its siblings. A
// config already on disk, or pushed from a peer, must still boot: an inert
// posture leaf is no more dangerous at runtime than not setting it, so
// refusing to load one would brick a node over a no-op.
func validateStrictSessionAuthNeedsKeyStrict(cfg *Config) error {
	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.StrictSessionAuth {
		return nil
	}
	// TrimSpace for the same reason validateClusterAuthKeyStrict trims: a
	// whitespace-only key is "configured" to the runtime's len(key) > 0 test
	// but is not a key. Deliberately stricter than the runtime here.
	if strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal()) != "" {
		return nil
	}
	return fmt.Errorf("chassis cluster: `strict-session-auth` is set but " +
		"`authentication-key` is not — the posture only evicts an unauthenticated " +
		"session-sync connection while this node HOLDS a key, so as written it does " +
		"nothing at all and the #6628 residual it is meant to close stays open; set " +
		"`chassis cluster authentication-key <key>` (the SAME value on both nodes), " +
		"or remove `strict-session-auth`")
}

// validateClusterAuthKeyOverlapStrict rejects a rotation overlap that is not
// one (#6630).
//
// `additional-authentication-key` exists so a PSK rotation can roll node by
// node: each node ACCEPTS both keys while the pair is mid-rotation, so neither
// end ever receives a present-but-invalid HMAC and heartbeat liveness is never
// lost. Setting it to the SAME value as `authentication-key` accepts exactly
// one key — no overlap at all — while reading, in the config and in
// `show chassis cluster statistics`, as though a rotation window were open.
// That is worse than not setting it: the operator would proceed to the next
// commit believing they were protected, which is precisely the dual-master
// window the leaf exists to close.
//
// Whitespace-normalised on both sides for the same reason the emptiness gate
// is: a key differing only in surrounding whitespace is the same key to
// anything that matters, and the runtime compares raw bytes, so a
// trim-equal pair is an overlap that isn't.
func validateClusterAuthKeyOverlapStrict(cfg *Config) error {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	alt := strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKeyAlt.Reveal())
	if alt == "" {
		return nil
	}
	if alt != strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal()) {
		return nil
	}
	// Neither key is echoed — the whole point of Secret.
	return fmt.Errorf("chassis cluster: `additional-authentication-key` is identical to " +
		"`authentication-key`, so this node accepts exactly ONE key and there is no " +
		"rotation overlap; the config and `show chassis cluster statistics` would " +
		"nonetheless read as though a rotation window were open, and proceeding to the " +
		"next commit on that belief is the dual-master window the leaf exists to close. " +
		"Set it to the OTHER key of the rotation, or remove it to finalize")
}

// validateClusterAuthKeyTransitionStrict rejects a candidate whose
// SIGNING key the active config does not already ACCEPT (#16858,
// R3-B04-02).
//
// The stateless gates above judge a config in isolation. They cannot see
// the defect this gate closes: from active {A} (signs A, accepts {A}) a
// one-shot `set chassis cluster authentication-key B` yields candidate
// {B} (signs B, accepts {B}). Each node, once committed, signs a key the
// peer's still-active config does not accept, so every heartbeat from
// the committed node is a present-but-invalid HMAC at the peer. admitFrame
// rejects those without refreshing lastSeen; after the heartbeat
// threshold plus the 5s sync-recency suppression cap both nodes declare
// the peer lost and take over their redundancy groups — the dual-master
// window #6630's overlap exists to close. The same shape arises on
// `rollback N` from a finalized {B} config to a pre-rotation {A} config,
// and on `load override` staging the same candidate; all three reach
// this gate through the strict candidate pipeline, because rollback and
// load override only stage the candidate and commit is what promotes it.
//
// The rule is local and asymmetrical, mirroring the runtime acceptance
// relation: the CANDIDATE's signing (primary) key must already be a
// member of the ACTIVE config's accepted set {active primary, active
// additional}. It need not be the active signing key — step 3/4 of the
// #6630 procedure (`authentication-key B`, `additional-authentication-key
// A` from active {signs A, accepts A+B}) signs B, and B is accepted by
// the active config exactly because steps 1/2 staged it. Conversely the
// candidate's accepted set is irrelevant to the peer's ability to verify
// THIS node: what the peer must accept is what this node will sign.
//
// Cases that pass, by construction:
//   - No active cluster config (current == nil, or no cluster stanza, or
//     no active key): first keying of a cluster. There is no peer-held
//     accepted set to violate; the README "rolling onto a live unkeyed
//     cluster" path keys the running cluster this way.
//   - Candidate removes the cluster stanza, or removes its key: the
//     candidate signs nothing new. Removing the key while keeping the
//     stanza is refused by validateClusterAuthKeyStrictWithCurrent; the
//     transition gate does not second-guess it.
//   - Candidate signing key == active primary (routine commits, steps
//     1/2 which change only the additional key, step 5 finalize which
//     drops it, and the #16025 staged exception which keeps the old
//     primary while staging its replacement).
//   - Candidate signing key == active additional (steps 3/4).
//
// Cases refused: any candidate whose primary is neither the active
// primary nor the active additional — the one-shot rotation and the
// rollback-past-finalize above, whether the candidate's own additional
// key names the old key or not. A candidate {signs B, accepts B+A} from
// active {A} is still refused: this node accepting A does not make the
// peer accept B, and it is the peer's rejection of this node's B-signed
// frames that loses liveness.
//
// Current state comes only from configstore's candidate pipeline
// (s.compiled, the config active immediately before the candidate),
// exactly like the #16025 fold-2 exception. Fresh/day-0/CheckText and
// direct CompileConfig have no active config and keep the gate closed —
// there is no transition to judge. The peer-strict pipeline (#9619)
// passes the same current, so a shared commit is judged on the peer
// view against the same active accepted set. On the tolerant path the
// rejection downgrades to a warning (#1960 no-brick): a persisted or
// peer-synced config whose key differs from a notional predecessor must
// still boot; SyncApply never supplies a current config, so in practice
// the warning fires only if a future tolerant caller does.
//
// Neither key is echoed — the whole point of Secret. The message names
// the five-step procedure so the operator is sent to the overlap rather
// than to a re-typed key.
// clusterAcceptedKeys16858 is the active config's accepted key set: the
// signing primary plus the accept-only additional key (#6630), trimmed.
// It is the smallest state the #16858 interlock needs, carried in
// compileOpts so the gate never holds the whole active *Config. Held
// only for equality checks and never logged or rendered.
type clusterAcceptedKeys16858 struct {
	primary    string
	additional string
}

func validateClusterAuthKeyTransitionStrict(cfg *Config, active *clusterAcceptedKeys16858) error {
	if cfg == nil || cfg.Chassis.Cluster == nil || active == nil {
		return nil
	}
	candidateSigning := strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal())
	if candidateSigning == "" {
		return nil
	}
	if active.primary == "" && active.additional == "" {
		return nil
	}
	if candidateSigning == active.primary || candidateSigning == active.additional {
		return nil
	}
	return fmt.Errorf("chassis cluster: `authentication-key` changes the signing key to one the " +
		"active configuration does not already accept — the peer still runs the active " +
		"configuration, so it will reject this node's heartbeats as present-but-invalid " +
		"HMACs until it commits the matching key, and past the heartbeat threshold both " +
		"nodes take over (dual-master); rotate through the overlap instead: on BOTH nodes " +
		"first `set chassis cluster additional-authentication-key <new-key>`, then on both " +
		"nodes `set chassis cluster authentication-key <new-key>` with " +
		"`set chassis cluster additional-authentication-key <old-key>`, then on both nodes " +
		"`delete chassis cluster additional-authentication-key` (#16858)")
}

// MinAdvisedControlLinkKeyLen is the length below which
// ClusterAuthKeyStrengthWarnings flags a control-link PSK as weak. The PSK
// backs HMAC-SHA256 on the heartbeat, the fabric bearer token, the session-sync
// frame MAC and the duplicate-identity beacon; 16 characters is the floor at
// which a key is worth more than a dictionary guess, and `openssl rand -base64
// 32` (the documented generator) produces 44.
const MinAdvisedControlLinkKeyLen = 16

// clusterAuthKeyPlaceholderMarkers are substrings that identify a key copied
// verbatim from a reference config in this repository. Those values are
// PUBLISHED, so a config carrying one satisfies validateClusterAuthKeyStrict
// while remaining trivially forgeable by anyone who has read the repo.
var clusterAuthKeyPlaceholderMarkers = []string{"change-me", "example-only"}

// ClusterAuthKeyStrengthWarnings reports control-link PSK weaknesses: a
// key that is short, or one copied verbatim from a shipped reference
// config. Placeholder weakness remains warning-only on both paths. Short
// PRIMARY keys are rejected on strict commit by
// validateClusterAuthKeyStrict unless a distinct replacement of at least
// MinAdvisedControlLinkKeyLen is staged as additional-authentication-key
// for the #6630 migration (persisted primary only, fold 2); on the tolerant path, and during that staged
// rotation, short keys warn rather than refusing the config. A short
// additional key likewise warns on both paths (it is accept-only and the
// staged value must be replaced before it becomes the signing primary,
// at which point the strict floor applies).
//
// The warning never renders the key. It reports the LENGTH only, and for a
// placeholder it says that one matched WITHOUT naming which.
//
// Naming the marker was the obvious thing and it was wrong. The rationale was
// that a marker is a literal from this repository rather than operator key
// material — true right up until the two coincide. A key of exactly
// `change-me` makes the marker AND the key the same string, so printing the
// marker printed the whole key into the commit output and the log. That is the
// disclosure this advisory exists to warn about, produced by the advisory
// itself. The operator does not need to be told which placeholder they used;
// they need to be told to replace it.
func ClusterAuthKeyStrengthWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	var out []string
	// #6630: the ADDITIONAL key is checked on the same terms. A node accepts
	// frames signed with it, so a weak or published value there forges the
	// control channel exactly as a weak primary does — and it is the more
	// likely place for one, because a rotation is when an operator reaches
	// for a throwaway. Each leaf is named in its own warning so the operator
	// knows which to replace, which costs nothing: the NAME is not the secret.
	out = append(out, clusterKeyStrengthWarnings(
		"authentication-key", cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal())...)
	out = append(out, clusterKeyStrengthWarnings(
		"additional-authentication-key", cfg.Chassis.Cluster.ControlLinkAuthKeyAlt.Reveal())...)
	return out
}

// clusterKeyStrengthWarnings reports the length and placeholder advisories for
// one control-link key leaf. Single-sourced across the primary and the #6630
// additional key: a divergence between how the two are judged is always a bug,
// since both are verified against with the same HMAC.
func clusterKeyStrengthWarnings(leaf, raw string) []string {
	key := strings.TrimSpace(raw)
	if key == "" {
		return nil // absence is validateClusterAuthKeyStrict's business
	}
	var out []string
	if len(key) < MinAdvisedControlLinkKeyLen {
		out = append(out, fmt.Sprintf("chassis cluster %s is %d "+
			"characters; %d or more is advised: a weak PSK can be guessed and "+
			"used to forge the heartbeat, fabric bearer token, session-sync frame "+
			"MAC, or duplicate-identity beacon — generate one with "+
			"`openssl rand -base64 32`",
			leaf, len(key), MinAdvisedControlLinkKeyLen))
	}
	lower := strings.ToLower(key)
	for _, marker := range clusterAuthKeyPlaceholderMarkers {
		if strings.Contains(lower, marker) {
			// Deliberately does NOT name the marker: when the key IS the
			// marker, naming it prints the key.
			out = append(out, fmt.Sprintf("chassis cluster %s matches a "+
				"published placeholder from a reference config; those values are "+
				"in this repository, so the control channel and duplicate-identity "+
				"beacon are forgeable by anyone who has read it — replace it with "+
				"a key generated by `openssl rand -base64 32`", leaf))
			break
		}
	}
	return out
}

// ValidateClusterAuthKeyOverlapForTest exposes validateClusterAuthKeyOverlapStrict
// to pkg/cluster's #6630 rotation fixtures, which must assert that the
// degenerate overlap is refused at COMMIT rather than merely being harmless at
// runtime. Exported for the test seam only; production callers use the strict
// gate in compiler_uniformgates_cluster_zone.go.
func ValidateClusterAuthKeyOverlapForTest(cfg *Config) error {
	return validateClusterAuthKeyOverlapStrict(cfg)
}
