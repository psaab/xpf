#!/usr/bin/env bash
# #19084: a ROOT run under testguard-run.sh cannot change host state in the
# trees it covers (/etc, /var/lib, /var/log, /run), yet the command still
# reads back what it wrote, in-process and from a child process. Both root
# paths are exercised: the user-namespace path (no VM proof) and the VM-proof
# path. The VM proof's prior state is restored on exit.
#
# Root only. It refuses (exit 2) otherwise, so a non-root invocation never
# reads as a pass. Wired into `make vm-test-root` (test-testguard-overlay).
set -u
here=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" != 0 ]; then
	echo "testguard-overlay-selftest: must run as root, in the disposable VM leg (make vm-test-root)" >&2
	exit 2
fi
pass=0 fail=0
ok() { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

tag="xpf-overlay-selftest.$$"
proof=/run/xpf-testguard-vm-boot-id
W=$(mktemp -d "${TMPDIR:-/tmp}/tg-overlay.XXXXXX")
had_proof=0
[ -e "$proof" ] && { had_proof=1; cp -p "$proof" "$W/proof.saved"; }
cleanup() {
	rm -rf "/etc/$tag.seed" "/etc/$tag.new" "/var/lib/$tag" "/var/log/$tag.log" "/run/$tag"
	if [ "$had_proof" = 1 ]; then
		cp -p "$W/proof.saved" "$proof"
	else
		rm -f "$proof"
	fi
	rm -rf "$W"
}
trap cleanup EXIT

# The stand-in command writes a new file in each covered tree, rewrites and
# chmods a seeded /etc file, and deletes a seeded /var/lib file. It then reads
# each change back, in its own process and from a child process, and exits 7
# if any is not visible: the overlay must not hide a test's own writes.
cat >"$W/fake" <<EOT
#!/bin/sh
set -e
printf 'new\n' > /etc/$tag.new
mkdir -p /var/lib/$tag/sub && printf 'new\n' > /var/lib/$tag/sub/new
printf 'new\n' > /var/log/$tag.log
mkdir -p /run/$tag && printf 'new\n' > /run/$tag/new
printf 'rewritten\n' > /etc/$tag.seed
chmod 0640 /etc/$tag.seed
rm -f /var/lib/$tag/seed
[ "\$(cat /etc/$tag.new)" = new ] || exit 7
[ "\$(sh -c 'cat /var/lib/$tag/sub/new')" = new ] || exit 7
[ "\$(sh -c 'cat /var/log/$tag.log /run/$tag/new')" = "\$(printf 'new\nnew')" ] || exit 7
[ "\$(cat /etc/$tag.seed)" = rewritten ] || exit 7
[ "\$(stat -c %a /etc/$tag.seed)" = 640 ] || exit 7
[ ! -e /var/lib/$tag/seed ] || exit 7
echo "ok  	fake	0.001s"
EOT
chmod +x "$W/fake"

run_case() { # $1 label
	local label=$1 out rc
	mkdir -p "/var/lib/$tag"
	printf 'seed-etc\n' >"/etc/$tag.seed"
	printf 'seed-lib\n' >"/var/lib/$tag/seed"
	chmod 0600 "/etc/$tag.seed" "/var/lib/$tag/seed"
	local before
	before=$(stat -c '%a %s %Y %n' "/etc/$tag.seed" "/var/lib/$tag/seed"; sha256sum "/etc/$tag.seed" "/var/lib/$tag/seed")
	out=$(bash "$here/testguard-run.sh" "$W/fake" 2>&1)
	rc=$?
	if [ "$rc" = 0 ]; then
		ok "$label: the command saw every write it made (in-process and from a child) and exited 0"
	else
		bad "$label: testguard-run exited $rc (7 = a write was not visible inside): $out"
	fi
	local after
	after=$(stat -c '%a %s %Y %n' "/etc/$tag.seed" "/var/lib/$tag/seed" 2>&1; sha256sum "/etc/$tag.seed" "/var/lib/$tag/seed" 2>&1)
	if [ "$before" = "$after" ]; then
		ok "$label: the seeded host files are byte-, mode- and mtime-identical"
	else
		bad "$label: a seeded host file changed: before [$before] after [$after]"
	fi
	local leaked=
	for p in "/etc/$tag.new" "/var/lib/$tag/sub" "/var/log/$tag.log" "/run/$tag"; do
		[ -e "$p" ] && leaked="$leaked $p"
	done
	if [ -z "$leaked" ]; then
		ok "$label: nothing the command created reached the host"
	else
		bad "$label: created on the host:$leaked"
	fi
	rm -rf "/etc/$tag.seed" "/var/lib/$tag"
}

rm -f "$proof"
run_case "user-namespace path (no VM proof)"
bash "$here/mark-test-vm.sh" || bad "could not establish the VM proof for the second path"
if [ -e "$proof" ]; then
	run_case "VM-proof path"
fi

# Detector control: the residue check still FAILS a root run that changes a
# state path the overlay does not cover (a temp dir added through
# XPF_RESIDUE_EXTRA_STATE_PATHS), so a clean result above is the overlay's
# doing, not a blind detector.
mkdir -p "$W/state"
printf 'seed\n' >"$W/state/xpf.sources"
printf '#!/bin/sh\nrm -f %s\necho "ok  \tfake\t0.001s"\n' "$W/state/xpf.sources" >"$W/uncovered"
chmod +x "$W/uncovered"
XPF_RESIDUE_EXTRA_STATE_PATHS="$W/state" bash "$here/testguard-run.sh" "$W/uncovered" >/dev/null 2>&1
rc=$?
if [ "$rc" = 1 ]; then
	ok "detector control: a root run that deletes an uncovered state file FAILS (exit 1)"
else
	bad "detector control: exit $rc, want 1"
fi

printf '\ntestguard-overlay-selftest: passed=%d failed=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
