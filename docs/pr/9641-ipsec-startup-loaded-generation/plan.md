# #9641 plan (revision 3b): READ which generation charon loaded, and VALIDATE it

Revisions 1 and 2 inferred charon's generation from what it loaded and got PLAN NO twice
(P1, P4, P5; docs/log/9641.md). Per the lead's decision, revision 3 makes identity READ,
not inferred.

## Problem

HA IPsec re-initiation must attribute against the generation charon RUNS. Two states
defeat any record kept inside xpfd:
- **Restart window (#9641):** after an xpfd restart whose boot IPsec apply fails, there
  is no in-process record, so the promoted fallback names a config charon did not take.
- **Charon-side reload (the #9511 regression, stopgapped):** a failed xpfd reload leaves
  the new file on disk, and strongSwan's own start or reload loads it.

## Design

### 1. The marker: an inert, unreferenced address pool

Every swanctl config xpf renders appends:

```
pools {
  xpf-gen-<digest> {
    addrs = 192.0.2.1/32
  }
}
```

- **Address:** 192.0.2.1 is TEST-NET-1.
- **Inert:** no connection references the pool (no `pools = xpf-gen-...` in any
  `connections` section), so no IKE SA can draw from it or negotiate against it. A pool
  is not a connection: charon cannot initiate or respond with it. `swanctl --list-pools`
  reports it.
- **Atomic with its connections:** the pool sits in the same file, and `swanctl
  --load-all` loads conns, pools and secrets from that file together. So whatever file
  charon loaded, its marker names that file's generation. That includes charon's own
  restart or reload of a file whose xpfd reload failed.
- **To measure before implementation:** that 6.0.5 loads an unreferenced pool with
  `--load-all` and lists it in `--list-pools` (text and `--raw`). The fixture is
  captured under the cluster lock with the verified procedure. If a pool cannot carry
  the identity, fall back to a connection marker that is PROVABLY inert: loopback on
  both ends, no children, no `start_action`, and auth that cannot match. That proof goes
  in this plan, and every xpf path enumerating conns filters the marker, with a cell.
- **No existing collision:** xpf renders no swanctl `pools` section today, and nothing
  in xpf calls `--list-pools`. The only pool code is NAT pools, unrelated.

### 2. The digest: the xpf config generation, per node

- `<digest>` identifies the xpf config TREE generation that was applied:
  `configTextDigest(tree.Format())`, the same function as `Store.ActiveDigest()`
  (`pkg/configstore/store.go:925`, `:971`). It is not a digest of the rendered swanctl
  text, which depends on `PrepareConfig`'s runtime address and DNS resolution and could
  not be recomputed for an older generation.
- At apply time the daemon supplies the digest of the config it is applying:
  `store.ActiveDigest()` when `cfg` is the store's active compiled config. Otherwise it
  supplies an "unknown" marker digest, which attributes via the fallback.
- **Per node:** each node renders and applies its own node-effective config, and looks up
  the digest charon reports among ITS OWN retained trees. Cross-node render determinism
  is NOT required. Two nodes carrying different digests for the "same" config is fine,
  because nothing compares digests across nodes.

### 3. Lookup, on every re-initiation pass

1. `swanctl --list-pools --raw` through the stdout-only seam, bounded by
   `swanctlTimeout`. Take the pool named `xpf-gen-<digest>`.
2. Find the tree among the node's retained generations: the store's active tree plus
   ALL of `Store.ListHistory()` (`NewHistory(50)`), matching `configTextDigest`.
   Compile it leniently, cached per digest and off the failover path.
3. Attribute from that compiled config with #9511's machinery (SA name index,
   every-candidate-RG rule, undeclared-RG0 exclusivity).

### 4. Fallbacks: all routine, all master's answer (the promoted config)

- Charon unreachable, or the query fails or times out.
- Marker absent: charon started from a file written by an OLDER xpf with no marker
  (mixed-version upgrade), or no xpf config loaded at all.
- Marker digest unknown: older than the retained history, or supplied as "unknown".

Each fallback logs once per episode and is re-evaluated on the next pass. None is cached.

### 5. What the stopgap becomes (implemented order, revision 3c)

The #9511 stopgap (`ApplyHooks.Written` clears the record, `Loaded` sets it) stays, and
attribution resolves in this order:

1. **The in-process record**, when set. Written clears it whenever the file on disk
   changes, so a set record names exactly the file charon loaded and would reload. Asking
   charon could then only return that generation, or a mismatch that falls back to it,
   so the query (two swanctl calls per pass) is skipped.
2. **The validated marker**, when the record is empty: after an xpfd restart whose boot
   IPsec apply failed, and in the failed-reload window.
3. **The promoted config** otherwise, which is the pre-#9641 answer.

## Revision 3b: validate the marker (Codex round 3, atomicity)

`swanctl --load-all` is NOT a transaction. It runs separate loaders, with pools before
connections in the 6.0.5 capture. xpf's own `Manager.reload()` is `swanctl --load-all`,
so the marker loads with the file. But a partial or interrupted load can leave the marker
and the connections at different generations. The marker is therefore IDENTITY ONLY, and
it is accepted only when charon's loaded connections validate it:

1. **Loaded fingerprint:** `swanctl --list-conns --raw` gives, per connection, its
   children plus `local_addrs` and `remote_addrs` (the existing parser).
2. **Candidate fingerprint** of the generation the marker names, from its lenient-compiled
   `*config.Config`:
   - Render as a whole. A render error disqualifies the candidate, and a skipped VPN is
     excluded.
   - For each rendered VPN take children, `remote_addrs` (as rendered) and a local
     address resolved WITHOUT `PrepareConfig`: `vpn.LocalAddr`, else
     `gw.LocalAddress`, else the gateway external-interface's CONFIGURED unit address
     (`resolveConfiguredInterfaceAddress`, config-only). A family hint comes from a
     literal gateway address.
   - An empty local address matches charon's `%any`.
   - If any local address would need the kernel lookup or a DNS family hint, the
     candidate is UNVALIDATABLE.
3. **Accept** the marker's generation only if the fingerprints are EQUAL. On a mismatch
   (e.g. a partial load) or an unvalidatable candidate, fall back to master's answer.
   There is no wildcard.

## Residual, documented

A reload landing between the marker query and the initiate calls attributes against
the generation read at query time. Master attributes from the promoted config read at
attribution time, so it has the same window. This is master-equivalent, not a
regression.

A render-IDENTICAL RG move (explicit local-address unchanged) combined with a pools-only
partial load: the loaded connections are byte-identical across the two generations, so
validation cannot tell them apart. Documented, not solved; it needs a partial load AND a
render-identical RG change.

## Tests

- **Render:** the marker pool is present with the supplied digest, and no connection
  references it (parsed swanctl doc).
- **Parser:** `--list-pools --raw` from a real 6.0.5 fixture (to capture).
- **Charon restart loads the written-but-failed file:** the marker reports that file's
  digest, and attribution uses that generation, not the in-process record.
- **Unknown digest:** falls back to the promoted config.
- **Marker absent** (the mixed-version or older-xpf cell): falls back.
- **Charon unreachable:** falls back, uncached, and re-asks next pass.
- **Marker inert:** it never appears in `ActiveConnectionNames`, in `show security
  ipsec`, or in any initiate call.
- **Query-to-initiate race:** documented as master-equivalent in a cell comment.
- **Mutation matrix:** marker presence, digest source, lookup candidates, and each
  fallback.

## Review

A SHORT Codex plan check on this revision, focused on marker inertness and fallbacks
(the lead's instruction), after the pool fixture is captured.
