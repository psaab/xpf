# Codex — HOSTILE plan review, round 1 (#5078)

Model: codex-cli 0.144.0 (GPT-5-class). Framing: defensive design review
(first attempt was blocked by the Codex cyber-content guardrail with the
offensive-attacker framing; re-run succeeded with a defensive framing —
per feedback_codex_infra_must_retry). Verdict at bottom.

```
The narrow v2 cryptographic construction is sound, but the plan is not a complete security fix. Two release-blocking paths still permit active compromise:

1. A locally keyed daemon can still be forced into unauthenticated dual-accept before its sticky guard arms.
2. A transparent relay can read config sync, learn the control-link PSK itself, then forge authenticated traffic.

## 1. Channel binding

For one correctly configured channel with distinct endpoints, the proposed construction closes both reflection vectors.

One wording correction is important: the honest initiator and responder must derive the same transcript. The role byte makes their proofs different. What must differ are the two attacker-created transcripts where the same victim is initiator on one connection and responder on another:

- Victim initiator: `(ep_i=local, ep_r=peer)`
- Victim responder: `(ep_i=peer, ep_r=local)`

That role reversal is what defeats cross-connection reflection in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/5078-research/docs/research/5078-syncauth-reflection/plan.md:191).

The “lowest address is always dialer” rule does not mean that node cannot accept. Both nodes always run listeners; only outbound dialing is conditional. An attacker can therefore make the nominal dialer act as responder. Role must come from the actual `Dial`/`Accept` path, as proposed, not from node identity or address comparison. See [sync_conn.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/sync_conn.go:573) and [sync_conn.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/sync_conn.go:590).

Missing requirements:

- Reject canonical `localEndpoint == peerEndpoint`. The plan assumes they differ, but does not enforce it. If they collapse to identical bytes, reversing the slots no longer changes the attack transcript.
- Protect against dual-fabric collisions. For example, fab0 `(local=A, peer=B)` and fab1 `(local=B, peer=A)` can produce the same role-ordered tuple when the victim has opposite roles. Bind a stable, mutually agreed channel ID, or validate that all per-fabric role contexts are unique and no endpoint pair is reused in reverse. Raw `fabricIdx` is safe only if same-index topology is enforced on both nodes.
- Consider binding the configured cluster ID to prevent cross-cluster proof-oracle use where PSKs and RFC1918 layouts are reused.
- Do not include “optional” node IDs in a fixed v2 format. Either omit them or specify an exact mandatory HELLO field and authoritative source. Heartbeat-learned peer IDs are asynchronous and peer-asserted.

## 2. Nonce handling

Fresh 32-byte `crypto/rand` nonces plus both nonces in the transcript are sufficient. No timestamp or persistent replay database is needed: one fresh honest nonce makes a captured proof and old frame key unusable on reconnect.

Equal-peer-nonce rejection is good early reflection defense. All-zero rejection is useful RNG-failure hygiene, but is not a general entropy test. Also:

- Reject an all-zero locally generated nonce.
- Require exact HELLO length, not “at least 34 bytes.”
- Require `keyed` to be exactly `0` or `1`.
- Require exact proof length.
- Fail closed on malformed or trailing fields.

A global cache of prior peer nonces is not required under the normal CSPRNG assumption.

## 3. Ordering

Responder-validates-first is safe once the full transcript and role are correctly bound. The initiator proof is not reusable on another correctly bound connection.

It does expose a public offline verifier for PSK guesses: all HMAC inputs are observable. That is inherent in this HMAC challenge-response, not caused specifically by sending first. The PSK therefore must be randomly generated and high entropy; the current configuration accepts an unrestricted string with no strength policy.

Keep the three-second deadline over the entire exchange. Ordering is defense-in-depth, not a replacement for the role-reversed, cross-fabric adversarial tests.

## 4. Directional frame keys

The proposed derivation is correct:

```text
k_i2r = HMAC(PSK, frameTag || 0x00 || transcript)
k_r2i = HMAC(PSK, frameTag || 0x01 || transcript)
```

With the stated assignment, an echoed outbound frame is checked with the opposite key and fails. Tests must prove:

- Initiator send key equals responder receive key.
- Responder send key equals initiator receive key.
- The two direction keys differ.
- A reflected frame fails.
- Both legitimate directions succeed.

`authConn.authed()` should require two correctly sized keys.

Separately, the current receiver accepts any increasing sequence rather than the next sequence ([sync_auth.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/sync_auth.go:196)). A TCP-terminating relay can delete one complete frame and forward a later frame undetected. Requiring sequence `1` initially and then exactly `previous+1` would convert selective deletion into a detected disconnect.

These directional keys cease to protect anything once the relay learns the PSK through plaintext config sync, discussed below.

## 5. Compatibility

The v2-versus-v1 keyed flag-day is correct. There is no safe automatic fallback to the reflectable v1 proof. The documented mixed-version outage is acceptable only with:

- A maintenance-window upgrade.
- Preflight version checks.
- Persistent per-fabric degraded status.
- An explicit prohibition on failover until v2 sync is re-established.

A two-phase deployment can reduce operational risk: first deploy v2-capable binaries, then explicitly activate a configured minimum version/strict mode on both nodes. It remains vulnerable until activation; that is operational staging, not secure interoperability.

The release-blocking problem is the retained keyed-local-to-unkeyed/legacy dual-accept path. Before `syncAuthedEver` or `HeartbeatPeerAuthSeen` arms, an attacker can answer with `keyed=0` or send a normal frame instead of HELLO. The current decision accepts that unauthenticated connection ([sync_auth.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/sync_auth.go:265), [sync_auth.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/sync_auth.go:361)).

Worse, a normal first frame is executed before connection installation ([sync_conn.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/sync_conn.go:493)). It can be `syncMsgFence`, which disables RGs ([sync_conn.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/sync_conn.go:1657)). The pass-through connection is then installed and may displace the legitimate peer. Later guard arming does not evict it.

Therefore:

- Local PSK configured must mean “require authenticated v2,” regardless of the unauthenticated peer’s claimed `keyed` bit.
- Preserve byte-identical legacy behavior only when the local node itself has no PSK.
- Any keyed-to-unkeyed migration mode must be explicit, default-off, time-limited, and clearly described as disabling authentication.
- Recheck policy immediately before installation, execute no pending control frame before final admission, and evict existing unauthenticated connections when enforcement activates. These close races but do not make automatic dual-accept secure.

## 6. Legitimate-path transcript mismatches

| Input | Concrete risk | Required rule |
|---|---|---|
| Transport | Session sync prefers the control link and only falls back to fabric; the plan repeatedly says “fabric endpoints.” | Bind the actual selected sync transport endpoints. See [daemon_ha_sync.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/daemon/daemon_ha_sync.go:478). |
| Local address | `s.localAddr` is selected from live kernel interface addresses, not copied directly from one configured endpoint. Multiple same-family addresses or enumeration changes can select a different value. | Pin the selected endpoint at construction and validate reciprocal configuration. See [daemon_cluster_bind.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/daemon/daemon_cluster_bind.go:132). |
| Peer address | Peer-address leaves are currently untyped strings; hostnames may reach `net.Dial` but fail `netip.ParseAddrPort`. | Require literal IP addresses at commit, or define a different stable identity scheme. Do not use DNS results as transcript identity. |
| Encoding | “16-byte address + u16 port” does not specify IPv4-mapped IPv6, family, zones, or port byte order. | Use an explicit family byte, 4/16 address bytes, fixed byte order, and reject zones/wildcards/unspecified addresses. |
| Reciprocity | NAT, aliases, or differently chosen reachable addresses can let TCP connect while the two configured views differ. | Either declare such topologies unsupported and validate them, or provision a separate shared logical endpoint identity. |
| Dual fabric | `localAddr/peerAddr` versus `localAddr1/peerAddr1` and role may differ per link. | Pass role, selected endpoint pair, and channel context explicitly; test fab0 and fab1 independently. |
| Endpoint collision | Equal endpoints or reverse-reused fab0/fab1 pairs reopen cross-reflection. | Reject them or bind a stable agreed channel identifier. |
| Node ID | Local/peer values can be sourced differently or observed at different times; “optional” changes transcript layout. | Omit from v2, or fully specify presence, range, source, and endianness. |
| Version/wire layout | Extra HELLO bytes, future negotiation, or inconsistent version selection can produce ambiguous transcripts. | Exact v2 encoding; future negotiation must bind both advertised versions. |
| Key epoch | A handshake can finish under a key replaced during the exchange. | Snapshot one immutable key plus generation and verify the generation before installation. |

The failover test must explicitly force fab0 down and prove a fresh authenticated fab1 handshake and bidirectional sealed traffic. Ordinary RG failover may never exercise the secondary endpoint pair.

## 7. Other issues

- Reconnect replay is closed if every connection gets fresh nonces. Directional counters may reset because the keys change.
- Key rotation is not complete. Existing connections retain old derived keys, and auth-key changes do not restart cluster communications because the key is absent from `clusterTransportKey` ([daemon_ha_sync.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/daemon/daemon_ha_sync.go:995)). Immediate teardown can also strand the peer before it receives the new key. Rotation needs staged dual-key handling or an explicitly coordinated out-of-band procedure.
- `HeartbeatPeerAuthSeen` is process/receiver-local and initially false ([peer_state.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/peer_state.go:29)). It is not a secure first-contact policy.
- Status can report “unauthenticated frames rejected” based on heartbeat state while an earlier unauthenticated sync connection remains installed ([status.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/status.go:422)).
- The accept path creates an unbounded goroutine per connection, while the pre-auth parser permits a 16 MiB allocation per connection ([sync_conn.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/sync_conn.go:1180), [sync_auth.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/cluster/sync_auth.go:289)). A three-second timeout bounds duration, not aggregate memory or goroutines. Add a small per-fabric handshake semaphore and header-first, exact-size parsing.

## 8. Option A versus TLS/Noise

Option A is not sufficient for this codebase because the claimed “passive-only plaintext residual” destroys authentication.

When configuration synchronization is enabled, the daemon sends `Store.ShowActive()` over this stream ([daemon_ha_sync.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/daemon/daemon_ha_sync.go:327)). `ShowActive()` returns the raw tree ([store_format.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/configstore/store_format.go:31)); its documentation explicitly says the cleartext form backs HA config sync and retains real secrets ([store_format.go](/home/ps/git/bpfrx/.claude/worktrees/5078-research/pkg/configstore/store_format.go:297)). That includes the same control-link PSK, deliberately config-synced between nodes, plus other operational secrets.

A transparent relay can therefore:

1. Relay the legitimate v2 handshake between the real nodes.
2. Read the plaintext config frame because sealing only appends an HMAC.
3. Recover the control-link PSK.
4. Reconstruct the visible transcript and derive both directional keys.
5. Forge frames on the current connection or authenticate a new one.
6. Potentially attack the heartbeat and fabric-gRPC channels that reuse the PSK.

This directly contradicts the SMR assertion that the relay cannot inject because it lacks the PSK ([claude-smr-plan-r1.md](/home/ps/git/bpfrx/.claude/worktrees/5078-research/docs/research/5078-syncauth-reflection/claude-smr-plan-r1.md:52)).

The complete fix should use an encrypted, mutually authenticated standard transport—TLS 1.3 external PSK with ephemeral key exchange where supported, or a carefully selected Noise pattern—with strict no-fallback policy and out-of-band PSK provisioning. Adding directional AEAD records to Option A could be an emergency intermediate, but it becomes another custom secure-transport design and still requires the dual-accept and channel-context fixes above.

VERDICT: PLAN-REJECT — automatic keyed-local dual-accept remains a direct PSK-less impersonation/injection path, and plaintext config sync reveals the very PSK protecting the stream, allowing a transparent relay to become an active forger.
```
