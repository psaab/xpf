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
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	// TrimSpace normalizes emptiness: a whitespace-only key IS "configured" to
	// the runtime's len(key) > 0 test but is not a key, so trimming here makes
	// this gate deliberately STRICTER than the runtime rather than identical to
	// it — the right direction on the strict path. (The difference stays
	// observable on the tolerant path; see pkg/cluster/README.md "Key
	// strength".) This is an EMPTINESS floor, not an entropy floor — a
	// one-character key passes here. Key strength is a continuum and is
	// surfaced by ClusterAuthKeyStrengthWarnings rather than rejected, so a
	// weak-but-real key never becomes a new brick class for an operator who
	// already did the right thing.
	if strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal()) != "" {
		return nil
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

// MinAdvisedControlLinkKeyLen is the length below which
// ClusterAuthKeyStrengthWarnings flags a control-link PSK as weak. The PSK
// backs HMAC-SHA256 on the heartbeat, the fabric bearer token and the
// session-sync frame MAC; 16 characters is the floor at which a key is worth
// more than a dictionary guess, and `openssl rand -base64 32` (the documented
// generator) produces 44.
const MinAdvisedControlLinkKeyLen = 16

// clusterAuthKeyPlaceholderMarkers are substrings that identify a key copied
// verbatim from a reference config in this repository. Those values are
// PUBLISHED, so a config carrying one satisfies validateClusterAuthKeyStrict
// while remaining trivially forgeable by anyone who has read the repo.
var clusterAuthKeyPlaceholderMarkers = []string{"change-me", "example-only"}

// ClusterAuthKeyStrengthWarnings reports control-link PSK weaknesses that are
// real but do not justify refusing the config: a key that is short, or one
// copied verbatim from a shipped reference config. These are WARNINGS on both
// the strict and tolerant paths — unlike absence, which is binary and is
// rejected, key strength is a continuum, and hard-rejecting a short key would
// brick a commit (and, via bootstrapFromFile, a provision) for an operator who
// already configured authentication.
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
			"characters; %d or more is advised (the PSK backs HMAC-SHA256 on the "+
			"heartbeat, the fabric bearer token and the session-sync frame MAC) — "+
			"generate one with `openssl rand -base64 32`",
			leaf, len(key), MinAdvisedControlLinkKeyLen))
	}
	lower := strings.ToLower(key)
	for _, marker := range clusterAuthKeyPlaceholderMarkers {
		if strings.Contains(lower, marker) {
			// Deliberately does NOT name the marker: when the key IS the
			// marker, naming it prints the key.
			out = append(out, fmt.Sprintf("chassis cluster %s matches a "+
				"published placeholder from a reference config; those values are "+
				"in this repository, so the control channel is forgeable by "+
				"anyone who has read it — replace it with a key generated by "+
				"`openssl rand -base64 32`", leaf))
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
