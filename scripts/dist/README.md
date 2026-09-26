# xpf signed distribution tooling (#1924)

Mechanism for a signed, hosted appliance distribution. Spec:
`docs/research/1924-signed-hosted-dist/plan.md`. Operator runbook:
`docs/distribution.md`.

## Files

| File | Role |
|---|---|
| `sign.py` | minisign sign/verify + per-version manifest helpers (shared by bake/validate/deploy/publish) |
| `build-apt-repo.sh` | builds a flat signed apt repo (default) or reprepro (opt-in) |
| `install.sh` | Tailscale-style one-command installer (validate-all-inputs → keyring + apt source + install, with cleanup-on-failure). Ships with `%%…%%` markers baked at publish time. |
| `publish.py` | fail-closed publish gate + `XPF_PUBLISH_CMD` dispatch. `stamp-installer` bakes the real archive key + apt base URL + channel into `install.sh` (substitute-then-sign); the gate REQUIRES a stamped+signed `install.sh` unless `--no-installer`. The apt base URL is VALIDATED before it is baked (`validate_apt_url`, #5685/M40): it must be a strict `https://` URL with no shell metacharacter / whitespace / control byte / userinfo / query / fragment / percent-escape, so a lower-trust value cannot cross the signing boundary into `install.sh`'s single-quoted literal and become signed, root-executed shell — a malformed value fails the release CLOSED. Also REQUIRES each image's signed `xpf-<ver>.manifest` provenance to say `validated: true` (#4904 A — a `--skip-validate` bake is refused) AND `base_image_pinned: true` (#5815 — an `XPF_ALLOW_UNPINNED_BASE=1` bake signs `base_image_pinned: false`, i.e. its own authenticated metadata says the Ubuntu base was not anchored to a reviewed digest; that image is refused, fail-CLOSED on a missing key too, with no override). When an upload will happen it snapshots the tree into a private immutable staging dir and gates+dispatches ONLY that snapshot (#4904 C — the bytes gated are the bytes uploaded, closing a TOCTOU where a concurrent writer swapped an artifact/installer after the gate). |
| `xpf-image.pub.placeholder` | PLACEHOLDER minisign public key (see below) |
| `xpf-archive-keyring.asc.placeholder` | PLACEHOLDER OpenPGP apt archive key (see below) |

## The two operator inputs (OPEN QUESTIONS — not wired to real values here)

This tooling is complete as a MECHANISM. Going live needs two operator
decisions, supplied at release time as config inputs (never hardcoded):

1. **Hosting target** — `XPF_IMAGE_BASE_URL` (images + `install.sh` +
   `latest.json`; any static host incl. GitHub Releases) and
   `XPF_APT_BASE_URL` (the `dists/`+`pool/` apt tree; needs a
   directory-serving host — NOT GitHub Releases flat assets). Plus the
   retention policy and channel layout (`stable`/`edge`).
2. **Signing identity** — the minisign keypair (images) and the OpenPGP
   archive key (apt): who holds the secret keys, rotation cadence, and where
   the public keys are pinned/published.

## Placeholder keys — replace before any real publish

`xpf-image.pub.placeholder` and `xpf-archive-keyring.asc.placeholder` are
generated placeholders whose SECRET keys were shredded at generation and are
held by NO ONE. They exist so the mechanism + tests have a concrete pubkey
path shape, and so the repo never ships a key that anyone can sign for.

To go live (engineer/release time, after OQ-2 is decided):

1. Generate the real image keypair on the signing host:
   `minisign -G -p xpf-image.pub -s xpf-image.sec` (keep `.sec` OFF the repo
   and off CI unless OQ-4 chooses CI signing).
2. Generate the real OpenPGP archive key; export the public key to
   `xpf-archive-keyring.asc`.
3. Commit the real PUBLIC keys as `scripts/dist/xpf-image.pub` and
   `scripts/dist/xpf-archive-keyring.asc` (drop the `.placeholder` suffix).
   These public files are the pinned trust roots; their authenticity comes
   from the in-repo git copy, NOT from any hosting URL. During image-key
   rotation, commit both active public keys and retain both in the trust set
   until operators have updated; keep both signing secrets outside the repo.
   Keep the old signer first so the canonical `.minisig` stays valid for
   legacy checkouts; publish later keys as `.minisig.<key-id>` sidecars.
4. Point signing at the secret key by PATH: `XPF_SIGN_SECKEY=/secure/xpf-image.sec`
   for the bake, and the OpenPGP key id for `build-apt-repo.sh`.

The signing secret key is referenced by PATH only. It is NEVER committed,
logged, or embedded. Tests use a throwaway keypair generated in a temp dir.

## Roundtrip (the local gate — no hosting, no real key)

```bash
scripts/dist/selftest.sh     # generates a throwaway key, signs, verifies,
                             # proves tamper-detection, builds a flat repo,
                             # and dry-runs install.sh
```
