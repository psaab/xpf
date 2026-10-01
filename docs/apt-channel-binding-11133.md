# Persistent APT channel binding (#11133)

**Design:** v1, converged for implementation  
**Base:** `9eb57798568b23b7bdb0323012e9ec700f44de2a`  
**Issue:** [#11133](https://github.com/psaab/xpf/issues/11133), follow-up to #11126

## Problem and evidence

`scripts/dist/install.sh` writes a source with `Suites: $CHANNEL` and calls
`verify_channel` after `apt-get update` but before the install in that one
installer run. It requires the signed Release `Suite` and `Codename` to equal
`stable` or `edge`. A later standalone `apt upgrade` never calls this shell
check. APT verifies the Release signature but accepts a signed Release whose
Suite differs from the source's requested suite, with a warning; that index can
still supply package candidates. Clearing APT's lists does not restore the
install-time check.

Step-0 evidence on the current installer:

- `python3 -m unittest scripts.dist.test_install_apt_channel_10767 -v` passed
  all 4 existing cells for first-install binding.
- A hermetic local file repository had `dists/stable/InRelease` signed by a
  throwaway OpenPGP key but advertised `Suite: edge` and `Codename: edge`.
  With isolated APT state/lists, `apt-get update` returned 0 and warned
  `Conflicting distribution ... (expected stable but got edge)`. `apt-cache
  policy xpf-appliance` selected `99.0~edge` at priority 500 over the installed
  `1.0`, and `apt-get -s upgrade` proposed `Inst xpf-appliance [1.0]
  (99.0~edge xpf:edge [amd64])`. This reproduces the post-install bypass.
- On local APT 3.3.1, an isolated signed-repository check of the proposed
  preferences below gave both current binary packages (`xpf` and
  `xpf-appliance`) priority 990 when the Release matched `stable/stable`. After
  clearing the lists and fetching a signed `edge/edge` Release from the same
  `stable` source path, both edge versions had priority -1 and the simulated
  upgrade contained no `Inst` lines. The temporary repository and key were
  removed after the check.

## Decision

Persist the selected channel as an installer-managed APT preference file at
`/etc/apt/preferences.d/xpf-channel.pref`. Generate the selected-channel rule
first, then catch-all deny rules for XPF packages from releases outside the
selected pair, including a Release that omits one of its identity fields:

```text
# xpf appliance channel pin; Managed by install.sh (#11133)

Package: xpf*
Pin: release a=<channel>,n=<channel>
Pin-Priority: 990

Package: xpf*
Pin: release a=*
Pin-Priority: -1

Package: xpf*
Pin: release n=*
Pin-Priority: -1
```

`a` is APT's Archive/Suite field and `n` is its Codename field; the comma in
the positive rule requires both to match. The separate negative rules deny a
release when either identity field is present but the selected pair does not
match. The selected-channel rule must come first so a valid stable or edge
Release receives priority 990 instead of the later deny rules. `stable` and
`edge` are the only accepted channel values in the installer and repository
builder. The binary packages in `debian/control` are `xpf` and
`xpf-appliance`; the `xpf*` glob covers both and future packages in the same
namespace without pinning the appliance's ordinary Debian dependencies. The
pin is based on the signed Release identity, not a mirror hostname or a
signing-key fingerprint.

An APT fixture showed that putting the deny rule first leaves even a matching
stable package at the installed version; selected-first produces the intended
990 priority. Priority 990 is above APT's ordinary installed-package priority
and lets a selected-channel upgrade win, but deliberately remains below the
threshold that forces downgrades. This preserves APT's no-automatic-downgrade
behavior: rebinding from edge to stable blocks future edge candidates, but an
already-installed newer edge version is not silently downgraded. An operator
who intentionally wants that rollback must explicitly use APT's
`--allow-downgrades` after reviewing it.


### Installer ordering and failure behavior

Keep the existing first-install check. After `verify_channel` accepts the
signed metadata, write the preferences file atomically (temporary file in the
same directory, mode 0644, then rename) and before `apt-get install`. Thus the
installer's package selection is pinned too, including if another APT update
replaces lists between verification and installation. A mismatching initial
Release fails before a new pin is written.

The installer refuses an existing unmarked `xpf-channel.pref` rather than
silently replacing administrator-authored policy. An existing file carrying
the installer marker may be replaced. If installation fails after a pin
replacement, restore the prior marked file byte-for-byte (or remove the new
file if none existed); clear the backup on success. This keeps a failed
channel rebind from leaving a new pin behind. As with the existing installer,
root/admin changes to APT configuration are outside the threat model.

The preference file is not a dpkg payload file or conffile: the installer owns
it, so package upgrades do not prompt or overwrite it. Extend `debian/xpf.postrm`
to remove it on `remove`/`purge` only when its management marker is present,
mirroring the existing cleanup for the installer-written `xpf.sources`. Leave
an unmarked file untouched. A downgrade to a pre-#11133 package followed by
removal may leave the marked preference behind because that old maintainer
script cannot know about it; the leftover rule is fail-closed for other XPF
candidates and can be removed by rerunning the current installer or deleting
the marked file deliberately.

### Channel and key rotation

A normal `apt upgrade` reads the preference file without invoking
`install.sh`; it remains effective after the lists are cleared and refetched.
To change channels, rerun the installer with an explicit `XPF_CHANNEL` (or a
newly stamped installer for that channel). The installer verifies the new
signed Release before replacing the pin. Because the priority is 990, channel
rebinding does not force a package downgrade; such a downgrade is an explicit
operator action.

The pin contains no key material and does not change during archive-key
rotation. The existing rotation mechanism remains authoritative: the installer
writes the keyring to `/usr/share/keyrings`, the `xpf` package ships that
package-owned non-conffile keyring, and a dual-sign overlap lets `apt upgrade`
deliver the new key before the old signer retires. Suite/Codename remain
`stable`/`edge`; changing those identities requires a coordinated installer
and repository change before operators rebind.

## Threat model and limits

Protected: a network mirror or CDN that can serve an already-signed edge tree
from the stable path, including after local list caches are deleted. APT may
still download that validly signed Release and warn about the mismatch, but the
preferences prevent its `xpf*` versions from being candidates; the selected
stable/edge Release remains installable at priority 990. The existing
installer-side exact Suite/Codename check still rejects a mismatch on first
install.

If both `Suite` and `Codename` are absent, APT cannot associate the Release
with the configured source suite and cannot use it to produce package
candidates. If either field is present, the corresponding negative rule also
catches a mismatched or malformed identity.

Not protected: root or an administrator removing/overriding the preference,
a compromised trusted archive signing key, a trusted signer publishing edge
payload under the selected stable Suite/Codename, denial of service from a
mirror withholding the selected suite, or non-XPF packages from other APT
sources. An already-installed non-selected version is not removed automatically;
the pin prevents its future upgrades from a non-selected Release.

## Alternatives considered

- Keeping only the installer check is the reproduced defect: later APT runs do
  not execute the installer.
- Per-channel archive signing keys could separate trust cryptographically, but
  would change the current shared-key release process, operator inputs, and
  dual-sign rotation protocol. It is unnecessary for the stated signed-Release
  mismatch when APT can pin both signed channel identity fields.
- `NotAutomatic`/`ButAutomaticUpgrades` publisher metadata changes affect all
  consumers of a suite and do not provide a host-persisted binding to the
  operator's selected channel.
- A hostname pin is not sufficient: the mirror/CDN identity is not the
  signed channel identity, and an untrusted mirror may serve the same host/path.

## Validation plan

1. Keep the four #11126 install-time cells: matching stable accepted; a signed
   edge Release at a stable source rejected; a codename-only mismatch rejected;
   missing XPF index target fails closed.
2. Add a hermetic integration test using a throwaway GPG key and isolated
   `sources.list`, status, cache, preferences, and lists. With a stable source
   pointed at a signed edge Release, prove APT update warns but succeeds and
   the unpinned baseline selects/upgrades both `xpf` and `xpf-appliance`.
   Clear the isolated lists and repeat with the generated pin; prove both edge
   versions are -1/no simulated upgrade. A signed stable Release must remain
   priority 990/upgradable. Also test a signed malformed Release served at the
   stable path with `Suite: edge` but no Codename: APT must visibly warn, every
   XPF candidate from it must be -1, and no XPF package may be installed from
   it. Include an unrelated package to prove the deny rules do not pin Debian
   dependencies.
3. Exercise the real installer functions with fake `apt-get`/`indextargets`:
   write the pin only after successful channel verification and before install;
   preserve an unmarked preferences file; replace a marked pin; restore/remove
   it on install failure.
4. Exercise `xpf.postrm` cleanup for a marked pin on remove/purge and
   preservation of an unmarked file.
5. Run the new tests, existing distribution tests/selftest, `sh -n`, and
   `shellcheck` for changed shell scripts (accounting for only known baseline
   diagnostics).

## Open policy questions

None for the current contract: only `stable`/`edge` are supported, the Release
must already match both names, the XPF binary package namespace is `xpf*`, and
APT's default no-downgrade behavior is retained on channel rebind. The choices
above do not change the trusted key, release format, or first-install channel
contract.