# Antigravity (AGY) — HOSTILE plan review, round 1 (#5078)

Tool: agy 1.1.0. First two attempts misparsed the CLI flags (the --print
flag consumes the prompt as its value); this run used the correct
ordering. Verdict at bottom.

```
Here is the hostile review of the proposed cryptographic protocol changes in `docs/research/5078-syncauth-reflection/plan.md` and the self-review in `docs/research/5078-syncauth-reflection/claude-smr-plan-r1.md`.

---

## 1. Hostname/DNS-based Bypass of Endpoint Binding (Vector B Exploit)
The plan proposes binding the parsed `netip.AddrPort` bytes of the configured endpoints (`s.localAddr`/`s.peerAddr`) to separate the transcripts of the initiator and responder connections. However, if the operator configures DNS hostnames (e.g., `localAddr = "node1.cluster.local:7000"`, `peerAddr = "node2.cluster.local:7000"`), `netip.ParseAddrPort` will fail. 

If the implementation handles parsing errors by falling back to a default value (e.g., zeroed bytes or empty strings), `ep_initiator` and `ep_responder` will both be represented identically (e.g., `0.0.0.0:0`). This completely neutralizes the role-ordered endpoint binding, allowing an attacker to equalize the transcripts on two connections and perform a cross-connection reflection (Vector B).

### Byte-Level Trace of the Bypass
Assume the victim $V$ has hostnames configured, causing `netip.ParseAddrPort` to fail and return an 18-byte zero array (`0x00...00`). Let the PSK be `key`.

1. **Connection- $\beta$ (Outbound dial from $V$ to Attacker):**
   * $V$ acts as **Initiator**, generating fresh nonce `nonce_I` (`0x1111...11`).
   * $V$ sends `HELLO{v=2, keyed=1, nonce_I}`.
   * $V$ expects `proof_responder` from the peer.
2. **Connection- $\alpha$ (Inbound connection from Attacker to $V$'s listener):**
   * $V$ accepts and acts as **Responder**, generating fresh nonce `nonce_R` (`0x2222...22`).
   * $V$ sends `HELLO{v=2, keyed=1, nonce_R}`.
   * $V$ expects `proof_initiator` from the peer.
3. **Attacker Equalizes Nonces:**
   * On Connection- $\beta$, the attacker sends `HELLO` containing `peerNonce = nonce_R` (`0x2222...22`).
   * On Connection- $\alpha$, the attacker sends `HELLO` containing `peerNonce = nonce_I` (`0x1111...11`).
4. **Initiator Proof Extraction:**
   * $V$-initiator on Connection- $\beta$ computes the initiator transcript:
     $$\text{transcript}_\beta = \text{SHA256}(\text{LP}(\text{tag}) \mathbin{\Vert} \text{u8}(2) \mathbin{\Vert} \text{LP}(0\text{x}1111...11) \mathbin{\Vert} \text{LP}(0\text{x}2222...22) \mathbin{\Vert} \text{LP}(\text{zeros}) \mathbin{\Vert} \text{LP}(\text{zeros}))$$
   * $V$-initiator sends $\text{proof\_initiator}_\beta = \text{HMAC}(\text{key}, \text{proofTag} \mathbin{\Vert} 0\text{x}00 \mathbin{\Vert} \text{transcript}_\beta)$.
5. **Replay on Connection- $\alpha$:**
   * The attacker intercepts $\text{proof\_initiator}_\beta$ from Connection- $\beta$ and replays it to $V$-responder on Connection- $\alpha$.
   * $V$-responder on Connection- $\alpha$ expects a proof over:
     $$\text{transcript}_\alpha = \text{SHA256}(\text{LP}(\text{tag}) \mathbin{\Vert} \text{u8}(2) \mathbin{\Vert} \text{LP}(0\text{x}1111...11) \mathbin{\Vert} \text{LP}(0\text{x}2222...22) \mathbin{\Vert} \text{LP}(\text{zeros}) \mathbin{\Vert} \text{LP}(\text{zeros}))$$
   * Since $\text{transcript}_\alpha == \text{transcript}_\beta$, the replayed proof verifies perfectly. The attacker authenticates on Connection- $\alpha$ without holding the PSK.

---

## 2. Wildcard Listening Address Asymmetry (Production Outage Vector)
If the operator configures a wildcard address for local listening (e.g., `localAddr = "0.0.0.0:7000"`) but configures the unicast IP for the peer (e.g., `peerAddr = "10.0.0.2:7000"`), the endpoints in the transcripts will mismatch:
* Node A (dialing Node B) binds: $\text{ep\_initiator} = \text{"0.0.0.0:7000"}$, $\text{ep\_responder} = \text{"10.0.0.2:7000"}$
* Node B (accepting Node A) binds: $\text{ep\_initiator} = \text{"10.0.0.1:7000"}$, $\text{ep\_responder} = \text{"0.0.0.0:7000"}$

These transcripts will never match, causing the legitimate handshake to fail closed and inducing a permanent production sync outage.

---

## 3. Equal-Nonce & Related-Nonce Verification
Checking `peerNonce == localNonce` and `peerNonce == all-zeros` is cryptographically sufficient to kill the single-connection mirror (Vector A). Near-equal or related nonces (e.g., `peerNonce = localNonce ^ 1`) do not expose the PSK or allow proof forgery because SHA-256 is collision-resistant and HMAC-SHA256 acts as a secure pseudorandom function (PRF). However, equal-nonce checks do not prevent Vector B, which relies entirely on the robustness of the role-ordered endpoint binding.

---

## 4. Initiator Proof Harvesting (Ordering Oracle)
Since the initiator transmits its proof first, an attacker acting as a responder can always harvest $\text{proof\_initiator}$ for the nonces exchanged.
* If the endpoint binding is functioning correctly, this harvested proof is useless because the endpoint order is reversed for the target connection role, resulting in a different transcript.
* If the endpoint binding fails (e.g., via the hostname parse failure to zero-bytes), the initiator proof-first transmission acts as a direct signing oracle for the attacker to complete the reflection on the responder connection.

---

## 5. Directional Keys Residual Risk
Deriving directional keys ($k_{i2r} \neq k_{r2i}$) successfully prevents reflection of a node's own frames back onto the *same* connection. However, if the handshake transcripts are equalized (e.g., via the hostname zero-byte bypass), the attacker can perform **cross-connection frame reflection**:
* A frame sealed by $V$ on Connection- $\alpha$ (using $k_{r2i}$) can be replayed to $V$ on Connection- $\beta$ (which verifies using $recvKey = k_{r2i}$). 
Thus, directional keys do not replace the need for robust endpoint/role separation in the transcript.

---

## 6. Flag-Day / Downgrade Risks & Operational Asymmetries
* **Downgrade Safety:** Fail-closed on version < 2 is downgrade-safe since any version modification on the wire by a MITM forces a connection abort.
* **Transitional Upgrades:** A hard fail-closed flag-day forces a session-sync outage during the rolling upgrade window, risking dropped flows if a failover occurs mid-upgrade. Dismissing a temporary, opt-in transitional downgrade knob (e.g., `allow-legacy-sync-auth`) ignores the high operational risk of traffic disruption in large fleets.
* **Dial Loops:** If `shouldInitiateFabricDial` fails to parse hostnames on both sides, both nodes will evaluate it to `true` and dial concurrently, leading to rapid connection thrashing where each node constantly closes its active connection to accept the new inbound one.

---

## 7. Additional Missed Vectors
* **Dual-Fabric index mapping:** If the fabric index is not bound to the transcript, or if the secondary fabric is mismapped to use the primary fabric's config strings, an attacker can reflect a proof from `fab0` to `fab1`.
* **RNG failure:** If `rand.Read` fails, the error is handled, but if it degrades silently (e.g., predictable entropy under virtualization), the nonces become predictable, allowing pre-computation attacks.

---

## Verdict

### **PLAN-SOUND-WITH-CHANGES**

### Required Changes:
1. **Canonical Endpoint Derivation from Active Sockets:** Instead of binding static configuration strings (which are prone to hostname resolution failures and `0.0.0.0` wildcard mismatches), bind the **actual IPs** of the established connection retrieved from the socket via `conn.LocalAddr()` and `conn.RemoteAddr()`. 
   * Normalize the endpoints by stripping the ephemeral port of the initiator and replacing it with a canonical value (e.g. `0` or the configured listener port).
   * Map the resolved IP addresses to the role: $\text{ep\_initiator}$ always uses the initiator's socket IP, and $\text{ep\_responder}$ always uses the responder's socket IP.
2. **Dual-Fabric Binding:** Bind the `fabricIdx` (0 or 1) explicitly into the transcript to prevent cross-fabric proof replay.
3. **Optional Transitional Mode:** Add a temporary, operator-gated config flag (`allow-legacy-sync-auth`, defaulting to `false`) to allow zero-downtime rolling upgrades in critical environments, accompanied by a persistent degraded-state alarm.
```
