#!/usr/bin/env bash
# #19084: a ROOT run under testguard-run.sh executes in a throwaway view of
# the whole root filesystem (scripts/testguard-root-view.sh). This selftest
# drives both root paths, the user-namespace path (no VM proof) and the
# VM-proof path, with stand-in commands, and checks the host before and after:
#
#   [seeds]        rewrites, chmods, deletes and creations in /etc, /var/lib,
#                  /var/log, /run, /srv, /opt, /root and /tmp are all visible
#                  to the command (in-process and from a child) and none
#                  reaches the host (R18 R2);
#   [F1-symlink]   the same through a directory symlink in /var/log that
#                  resolves to /srv (Codex F1);
#   [F2-cwd]       a command started in a host directory runs in that
#                  directory INSIDE the view: a relative write stays private;
#   [F2-fds]       descriptors the caller left open are closed before exec;
#   [pass-through] writes under TMPDIR do reach the host (build output must
#                  not land in the tmpfs upper);
#   [read-only]    a vfat mount (overlayfs cannot take it as a lower layer)
#                  is read-only in the view; skipped when there is none;
#   [F3-id]        an `id` that fails refuses the run (exit 2, no command);
#   [F4-vm]        on a non-VM this selftest refuses before touching the VM
#                  proof or seeding anything;
#   [unsupported]  a mount of a type the wrapper cannot place refuses the run;
#   [R1-detach]    on the VM-proof path, a command that detaches the root
#                  view FAILS the run; on the user-namespace path it cannot;
#   [detector]     the residue check still FAILS a run that changes a
#                  watched state path through the writable pass-through.
#
# Root only. Otherwise it exits 77 (SKIP, with the reason) so a non-root run
# never reads as a pass: scripts/run-selftests.sh reports it as a named SKIP,
# and `make vm-test-root` (test-testguard-overlay) runs it as root, where the
# Makefile target fails on anything but 0. It seeds host trees and rewrites
# the VM proof (restoring both on exit), so it refuses (exit 2) on anything
# that is not a VM, checked read-only BEFORE any of that (Codex F4).
set -u
here=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" != 0 ]; then
	echo "SKIP: testguard-overlay-selftest needs root; it runs in the disposable VM leg (make vm-test-root)"
	exit 77
fi
# #19084 Codex F4: VM eligibility first, read-only. The same predicate as
# scripts/mark-test-vm.sh, which this selftest calls later.
virt=$(systemd-detect-virt --vm 2>/dev/null || true)
if [ -z "$virt" ] || [ "$virt" = none ]; then
	echo "testguard-overlay-selftest: REFUSED: not a virtual machine (systemd-detect-virt --vm: '${virt:-}'); it seeds host trees and rewrites the VM proof, so it runs only in a disposable VM (#19084)" >&2
	exit 2
fi
# Every host mutation below is announced here first. The [F4-vm] cell runs
# this script nested on a "non-VM" and requires the trace to stay empty.
trace() { [ -z "${TG_SELFTEST_TRACE:-}" ] || printf '%s\n' "$*" >>"$TG_SELFTEST_TRACE"; }

pass=0 fail=0
ok() { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

export TMPDIR=${TMPDIR:-/var/tmp}
tag="tg-sel.$$"
proof=/run/xpf-testguard-vm-boot-id
W=$(mktemp -d "$TMPDIR/tg-overlay.XXXXXX")
seeds="/etc/$tag.seed /var/lib/$tag /var/log/$tag.log /run/$tag /srv/$tag /opt/$tag /root/$tag /tmp/$tag
/etc/$tag.new /var/log/$tag-f1 /srv/$tag-f1 /etc/$tag-cwd /srv/$tag-fd /srv/$tag-unsup /boot/efi/$tag"
had_proof=0
trace proof-save
[ -e "$proof" ] && { had_proof=1; cp -p "$proof" "$W/proof.saved"; }
cleanup() {
	for p in $seeds; do rm -rf "$p"; done
	if [ "$had_proof" = 1 ]; then
		cp -p "$W/proof.saved" "$proof"
	else
		rm -f "$proof"
	fi
	rm -rf "$W"
}
trap cleanup EXIT

# host_state: type, mode, size, mtime and sha256 of every path given, so a
# chmod, a same-size rewrite or an unlink on the host all show.
host_state() {
	for p in "$@"; do
		if [ -e "$p" ] || [ -L "$p" ]; then
			stat -c '%F %a %s %Y %n' "$p"
			[ -f "$p" ] && sha256sum "$p"
		else
			echo "absent $p"
		fi
	done 2>&1
}

mkfake() { # $1 name, then the body; exits 7 if a check inside fails
	local f="$W/$1"
	shift
	printf '#!/bin/sh\nfail() { echo "CHECK: $*" >&2; exit 7; }\n%s\n' "$*" >"$f"
	chmod +x "$f"
}

# ── [seeds] ──────────────────────────────────────────────────────────────
seed_files="/etc/$tag.seed /var/lib/$tag/seed /srv/$tag/seed /opt/$tag/seed /root/$tag/seed /tmp/$tag/seed"
seed_new="/etc/$tag.new /var/lib/$tag/sub /var/log/$tag.log /run/$tag /srv/$tag/new /opt/$tag/new /root/$tag/new /tmp/$tag/new"
mkfake seeds "
for f in $seed_files; do
	[ \"\$(cat \$f)\" = seed ] || fail \"\$f: the host's content is not readable in the view\"
	printf 'rewritten\n' > \$f && chmod 0640 \$f || fail \"\$f: cannot rewrite\"
done
rm -f /var/lib/$tag/seed
printf 'new\n' > /etc/$tag.new
mkdir -p /var/lib/$tag/sub /run/$tag && printf 'new\n' > /var/lib/$tag/sub/new && printf 'new\n' > /run/$tag/new
printf 'new\n' > /var/log/$tag.log
for d in /srv/$tag /opt/$tag /root/$tag /tmp/$tag; do printf 'new\n' > \$d/new || fail \"\$d: cannot create\"; done
[ ! -e /var/lib/$tag/seed ] || fail 'the unlink is not visible'
for f in /etc/$tag.seed /srv/$tag/seed /opt/$tag/seed /root/$tag/seed /tmp/$tag/seed; do
	[ \"\$(sh -c \"cat \$f\")\" = rewritten ] || fail \"\$f: a child does not see the rewrite\"
	[ \"\$(stat -c %a \$f)\" = 640 ] || fail \"\$f: the chmod is not visible\"
done
for f in /etc/$tag.new /var/lib/$tag/sub/new /run/$tag/new /var/log/$tag.log /srv/$tag/new /tmp/$tag/new; do
	[ \"\$(sh -c \"cat \$f\")\" = new ] || fail \"\$f: a child does not see the new file\"
done"
seed_hosts() {
	mkdir -p "/var/lib/$tag" "/srv/$tag" "/opt/$tag" "/root/$tag" "/tmp/$tag"
	for f in $seed_files; do printf 'seed\n' >"$f"; chmod 0600 "$f"; done
}

# ── [F1-symlink] ─────────────────────────────────────────────────────────
mkfake f1 "
f=/var/log/$tag-f1/target.log
[ \"\$(cat \$f)\" = orig ] || fail 'the symlinked target is not readable'
chmod 0600 \$f && printf 'more\n' >> \$f && printf 'new\n' > /var/log/$tag-f1/new || fail 'cannot write through the symlink'
[ \"\$(stat -c %a \$f)\" = 600 ] || fail 'the chmod through the symlink is not visible'
[ \"\$(sh -c \"cat /var/log/$tag-f1/new\")\" = new ] || fail 'a child does not see the new file'"
seed_f1() {
	mkdir -p "/srv/$tag-f1"
	printf 'orig\n' >"/srv/$tag-f1/target.log"
	chmod 0644 "/srv/$tag-f1/target.log"
	ln -sfn "/srv/$tag-f1" "/var/log/$tag-f1"
}

# ── [F2-cwd] ─────────────────────────────────────────────────────────────
# The relative writes come FIRST, before any check can exit: a cwd that still
# names the host directory must show up as a host change, not only as a
# wrong pwd.
mkfake cwd "
seen=\$(cat ./seed)
printf 'rewritten\n' > ./seed && printf 'new\n' > ./new || fail 'cannot write relative to the cwd'
[ \"\$(pwd -P)\" = /etc/$tag-cwd ] || fail \"the command runs in \$(pwd -P), not in /etc/$tag-cwd\"
[ \"\$seen\" = cwd-seed ] || fail 'a relative read does not see the host file'
[ \"\$(cat ./new)\" = new ] || fail 'the relative write is not visible'"

# ── [F2-fds] ─────────────────────────────────────────────────────────────
mkfake fds "
for n in 6 7; do [ ! -e /proc/self/fd/\$n ] || { echo leaked >&7; fail \"descriptor \$n from the caller is still open\"; }; done"

# ── [pass-through] ───────────────────────────────────────────────────────
mkfake pass "
printf 'kept\n' > $W/pass.out && [ \"\$(cat $W/pass.out)\" = kept ] || fail 'cannot write under TMPDIR'"

# ── [read-only] ──────────────────────────────────────────────────────────
vfat=$(findmnt -rn -t vfat -o TARGET 2>/dev/null | head -n 1)
mkfake ro "
ls '$vfat' >/dev/null || fail 'the vfat mount is not readable'
if touch '$vfat/$tag' 2>/dev/null; then fail 'the vfat mount is writable in the view'; fi"

run_tg() { # $1 cwd, then the command; sets out and rc
	out=$(cd "$1" && shift && bash "$here/testguard-run.sh" "$@" 2>&1)
	rc=$?
}

branch_cases() { # $1 label
	local b=$1 before after
	trace "seed $b"

	seed_hosts
	before=$(host_state $seed_files $seed_new)
	run_tg / "$W/seeds"
	[ "$rc" = 0 ] && ok "[seeds] $b: every change was visible to the command and a child" ||
		bad "[seeds] $b: testguard-run exited $rc (7 = a change was not visible): $out"
	after=$(host_state $seed_files $seed_new)
	[ "$before" = "$after" ] && ok "[seeds] $b: the host's seeds in /etc /var/lib /srv /opt /root /tmp are unchanged and nothing new appeared" ||
		bad "[seeds] $b: the host changed: $(diff <(echo "$before") <(echo "$after") | grep '^[<>]' | tr '\n' ' ')"
	for p in $seed_files $seed_new; do rm -rf "$p"; done

	seed_f1
	before=$(host_state "/srv/$tag-f1/target.log" "/srv/$tag-f1/new")
	run_tg / "$W/f1"
	[ "$rc" = 0 ] && ok "[F1-symlink] $b: writes through /var/log/$tag-f1 -> /srv were visible inside" ||
		bad "[F1-symlink] $b: testguard-run exited $rc: $out"
	after=$(host_state "/srv/$tag-f1/target.log" "/srv/$tag-f1/new")
	[ "$before" = "$after" ] && ok "[F1-symlink] $b: the symlink's host target kept its mode, bytes and mtime" ||
		bad "[F1-symlink] $b: the host target changed: before [$before] after [$after]"
	rm -rf "/var/log/$tag-f1" "/srv/$tag-f1"

	mkdir -p "/etc/$tag-cwd"
	printf 'cwd-seed\n' >"/etc/$tag-cwd/seed"
	before=$(host_state "/etc/$tag-cwd/seed" "/etc/$tag-cwd/new")
	run_tg "/etc/$tag-cwd" "$W/cwd"
	[ "$rc" = 0 ] && ok "[F2-cwd] $b: the command ran in its cwd inside the view" ||
		bad "[F2-cwd] $b: testguard-run exited $rc: $out"
	after=$(host_state "/etc/$tag-cwd/seed" "/etc/$tag-cwd/new")
	[ "$before" = "$after" ] && ok "[F2-cwd] $b: relative writes from a host cwd stayed private" ||
		bad "[F2-cwd] $b: the host cwd changed: before [$before] after [$after]"
	rm -rf "/etc/$tag-cwd"

	mkdir -p "/srv/$tag-fd"
	printf 'fd-seed\n' >"/srv/$tag-fd/file"
	before=$(host_state "/srv/$tag-fd/file")
	out=$(bash -c 'exec 7>>"$1" 6<"$2"; shift 2; exec bash "$@"' _ "/srv/$tag-fd/file" "/srv/$tag-fd" "$here/testguard-run.sh" "$W/fds" 2>&1)
	rc=$?
	[ "$rc" = 0 ] && ok "[F2-fds] $b: descriptors 6 and 7 from the caller were closed before exec" ||
		bad "[F2-fds] $b: testguard-run exited $rc: $out"
	after=$(host_state "/srv/$tag-fd/file")
	[ "$before" = "$after" ] && ok "[F2-fds] $b: nothing was written through an inherited descriptor" ||
		bad "[F2-fds] $b: the host file changed: before [$before] after [$after]"
	rm -rf "/srv/$tag-fd"

	rm -f "$W/pass.out"
	run_tg / "$W/pass"
	if [ "$rc" = 0 ] && [ "$(cat "$W/pass.out" 2>/dev/null)" = kept ]; then
		ok "[pass-through] $b: a write under TMPDIR reached the host"
	else
		bad "[pass-through] $b: rc $rc, host file: '$(cat "$W/pass.out" 2>&1)': $out"
	fi

	if [ -n "$vfat" ]; then
		run_tg / "$W/ro"
		if [ "$rc" = 0 ] && [ ! -e "$vfat/$tag" ]; then
			ok "[read-only] $b: $vfat is read-only in the view"
		else
			bad "[read-only] $b: rc $rc, host $vfat/$tag exists: $([ -e "$vfat/$tag" ] && echo yes || echo no): $out"
		fi
		rm -f "$vfat/$tag"
	else
		echo "  skip [read-only] $b: no vfat mount on this host"
	fi
}

# ── user-namespace path: no VM proof ─────────────────────────────────────
trace proof-remove
rm -f "$proof"
branch_cases "user-namespace path"

# [R1-detach] control: there the inherited mounts are locked, so the command
# cannot detach the view, and the run passes.
mkfake detach 'umount -l / 2>/dev/null; exit 0'
run_tg / "$W/detach"
[ "$rc" = 0 ] && ok "[R1-detach] user-namespace path: a command cannot detach the locked view; the run passes" ||
	bad "[R1-detach] user-namespace path: exit $rc, want 0: $out"

# ── [F3-id]: an `id` that fails refuses the run ──────────────────────────
mkdir -p "$W/badid"
printf '#!/bin/sh\nexit 1\n' >"$W/badid/id"
chmod +x "$W/badid/id"
mkfake marker "touch $W/f3.marker"
rm -f "$W/f3.marker"
out=$(PATH="$W/badid:$PATH" bash "$here/testguard-run.sh" "$W/marker" 2>&1)
rc=$?
if [ "$rc" = 2 ] && [ ! -e "$W/f3.marker" ]; then
	ok "[F3-id] a failing id refuses the run (exit 2) and the command never runs"
else
	bad "[F3-id] exit $rc (want 2), command ran: $([ -e "$W/f3.marker" ] && echo yes || echo no): $out"
fi

# ── [unsupported]: a mount the wrapper cannot place refuses the run ──────
trace "seed unsupported"
mkdir -p "/srv/$tag-unsup"
rm -f "$W/f3.marker"
out=$(unshare -m --propagation private bash -c 'mount -t ramfs tg-unsupported "$1" || exit 99; shift; exec bash "$@"' _ \
	"/srv/$tag-unsup" "$here/testguard-run.sh" "$W/marker" 2>&1)
rc=$?
if [ "$rc" = 2 ] && [ ! -e "$W/f3.marker" ] && [[ $out == *"/srv/$tag-unsup is ramfs"* ]]; then
	ok "[unsupported] a ramfs mount the wrapper cannot place refuses the run (exit 2), naming it"
else
	bad "[unsupported] exit $rc (want 2; 99 = fixture mount failed), command ran: $([ -e "$W/f3.marker" ] && echo yes || echo no): $out"
fi
rm -rf "/srv/$tag-unsup"

# ── [F4-vm]: on a non-VM this selftest touches nothing ───────────────────
if [ -z "${TG_SELFTEST_NESTED:-}" ]; then
	mkdir -p "$W/nonvm"
	printf '#!/bin/sh\necho none\nexit 1\n' >"$W/nonvm/systemd-detect-virt"
	chmod +x "$W/nonvm/systemd-detect-virt"
	before=$(host_state "$proof")
	out=$(PATH="$W/nonvm:$PATH" TG_SELFTEST_NESTED=1 TG_SELFTEST_TRACE="$W/f4.trace" bash "$0" 2>&1)
	rc=$?
	after=$(host_state "$proof")
	if [ "$rc" = 2 ] && [ ! -s "$W/f4.trace" ] && [ "$before" = "$after" ]; then
		ok "[F4-vm] on a non-VM the selftest refuses (exit 2) before touching the proof or seeding"
	else
		bad "[F4-vm] exit $rc (want 2), host actions before the refusal: [$(tr '\n' ' ' <"$W/f4.trace" 2>/dev/null)], proof [$before] -> [$after]: $out"
	fi
fi

# ── VM-proof path ────────────────────────────────────────────────────────
trace proof-mark
bash "$here/mark-test-vm.sh" || bad "could not establish the VM proof for the second path"
if [ -e "$proof" ]; then
	branch_cases "VM-proof path"
	run_tg / "$W/detach"
	if [ "$rc" = 1 ] && [[ $out == *"root view is no longer mounted"* ]]; then
		ok "[R1-detach] VM-proof path: a command that detaches the root view FAILS the run (exit 1)"
	else
		bad "[R1-detach] VM-proof path: exit $rc, want 1 with the root-view FAIL: $out"
	fi
fi

# ── [detector]: the residue check still sees a pass-through state change ─
mkdir -p "$W/state"
printf 'seed\n' >"$W/state/xpf.sources"
mkfake uncovered "rm -f $W/state/xpf.sources"
XPF_RESIDUE_EXTRA_STATE_PATHS="$W/state" bash "$here/testguard-run.sh" "$W/uncovered" >/dev/null 2>&1
rc=$?
[ "$rc" = 1 ] && ok "[detector] a root run that deletes a watched state file through the pass-through FAILS (exit 1)" ||
	bad "[detector] exit $rc, want 1"

printf '\ntestguard-overlay-selftest: passed=%d failed=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
