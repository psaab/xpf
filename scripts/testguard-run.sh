#!/usr/bin/env bash
# Run a command with private net+mount namespaces and an observable PID 1
# baseline for internal/testguard. The parent PID 1 keeps the original
# namespaces; the child enters both namespaces before exec. Host residue is
# measured read-only before and after and reported without cleanup.
set -euo pipefail
if (($# == 0)); then
	echo "usage: testguard-run.sh command [args...]" >&2
	exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)
shim_dir="$root/test/support/host-bin-shims"
real_path=
IFS=: read -r -a path_entries <<<"$PATH"
for entry in "${path_entries[@]}"; do
	[[ -n "$entry" && "$entry" != "$shim_dir" ]] || continue
	real_path="${real_path:+$real_path:}$entry"
done
if [[ -n "$real_path" ]]; then
	PATH="$shim_dir:$real_path"
else
	PATH="$shim_dir"
fi
export PATH
# #19084 Codex F3: the effective UID decides whether the run gets the root
# view below, so it is resolved ONCE and validated. An `id` that fails, prints
# nothing or disagrees with the shell's own EUID is not read as "unprivileged":
# that would run a real-root command with no protection at all.
euid=$(id -u 2>/dev/null) || euid=
if [[ ! $euid =~ ^[0-9]+$ || $euid != "$EUID" ]]; then
	echo "testguard-run: REFUSED: cannot determine the effective UID (id -u gave '$euid', the shell says $EUID); refusing rather than treat the run as unprivileged (#19084)" >&2
	exit 2
fi
# The caller's working directory, re-established inside the root view.
cwd=$(pwd -P 2>/dev/null) || cwd=
# #19066: inside these namespaces a further private namespace is always
# creatable, so a test that could not get one has a broken mechanism, not an
# unlucky environment. Netns cells report that through
# testguard.NetnsUnavailable, which FAILS under XPF_REQUIRE_NETNS instead of
# skipping. Before this, 10 re-exec cells skipped as "netns unavailable" on
# every run while the package guard was refusing their child.
export XPF_REQUIRE_NETNS=1
# #19090 R13-a/R4: a caller that names a file in XPF_TESTGUARD_STATE_VERDICT
# learns whether this run changed production state, independently of the exit
# status (which a timeout VOID or a baseline comparison would otherwise
# reinterpret). One line "state-changed" is appended when the state check
# below fails. The variable is consumed here and NOT passed to the command, so
# a nested testguard-run.sh records into its own caller's file, never this
# one's.
state_verdict=${XPF_TESTGUARD_STATE_VERDICT:-}
unset XPF_TESTGUARD_STATE_VERDICT

command=$1
shift
if [[ "$command" == go || "$command" == "$shim_dir/go" ]]; then
	go_bin=$(PATH="$real_path" command -v go) || {
		echo "testguard-run: real Go binary not found" >&2
		exit 127
	}
	set -- "$go_bin" "$@"
else
	set -- "$command" "$@"
fi
# #19084: a root run's pass-through (the TMPDIR scratch among it) may not be,
# or lie below, a host system tree (R19 F4: exact roots alone let /etc/x
# through): a top-level root itself, or anything at or below /etc, /usr,
# /boot, /bin, /sbin, /lib*, /var/lib, /var/log, /proc, /sys, /dev or /run.
# Below /home, /root, /srv, /opt, /var and /mnt is allowed (GOMODCACHE in a
# home, GOCACHE in /root/.cache, a /var/tmp scratch), and so is /tmp itself as
# a declared TMPDIR scratch.
system_tree() {
	case $1 in
	/ | /home | /root | /srv | /opt | /var | /mnt | /media | \
		/etc | /etc/* | /usr | /usr/* | /boot | /boot/* | /bin | /bin/* | /sbin | /sbin/* | \
		/lib | /lib/* | /lib32 | /lib32/* | /lib64 | /lib64/* | /var/lib | /var/lib/* | \
		/var/log | /var/log/* | /proc | /proc/* | /sys | /sys/* | /dev | /dev/* | /run | /run/*)
		return 0
		;;
	esac
	return 1
}
scratch=${TMPDIR:-/var/worktrees/.cache/tmpdir}
# The scratch is created HERE, long before the pass-through loop below checks
# it, so a root run checks it first: TMPDIR=/etc/new-cache was refused, but
# only after this mkdir had left /etc/new-cache on the host (Codex P2 on
# 468f7d2371).
# The VALIDATED canonical path is what gets created, not the caller's
# spelling: `mkdir -p /etc/new-cache/../../var/tmp` creates /etc/new-cache
# while it walks the components, although the path normalizes to an allowed
# /var/tmp (Codex P2 on 26517e7917).
if [[ $euid == 0 ]]; then
	lexical=$(realpath -m "$scratch" 2>/dev/null) || lexical=
	if [[ -z $lexical ]] || system_tree "$lexical"; then
		echo "testguard-run: REFUSED: pass-through directory '$scratch' (TMPDIR) would expose a host system tree; point TMPDIR elsewhere (#19084)" >&2
		exit 2
	fi
	scratch=$lexical
fi
mkdir -p "$scratch"
work=$(mktemp -d "$scratch/testguard-run.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
"$root/scripts/host-residue-snapshot.sh" "$work/before.txt"
set +e
proof=/run/xpf-testguard-vm-boot-id
current_boot=$(cat /proc/sys/kernel/random/boot_id)
proof_boot=
if [[ -f "$proof" && ! -L "$proof" ]] &&
	[[ $(stat -c '%u %a' "$proof" 2>/dev/null || true) == "0 444" ]]; then
	proof_boot=$(cat "$proof")
fi
# #19084 R19 F3: XPF_TESTGUARD_NO_VM_PROOF=1 makes this run ignore the VM
# proof and take the user-namespace path. It can only LOWER privilege, so it
# is honoured from any caller, and a caller that needs the unprivileged path
# (the overlay selftest) never has to delete the runner's shared proof, which
# other lanes' root legs depend on.
if [[ ${XPF_TESTGUARD_NO_VM_PROOF:-} == 1 ]]; then
	proof_boot=
fi
# #18559: inside the private net namespace, bring loopback UP before the
# command runs. A fresh namespace starts with `lo` DOWN and every package of
# one `go test ./...` shares it, so before this a cell that serves or dials
# 127.0.0.1 passed or failed by TEST ORDER: it passed only if a fixture that
# raises lo itself (pkg/cluster's ensureLoopbackRoutable18038,
# #18952/#18960; pkg/daemon's sync-pair repairs, #18933/#18935) had already
# run. Loopback is private
# to the namespace, so isolation from the host is unchanged. A failure to
# raise it is reported, not hidden.
#
# #19049: also allow unprivileged ICMP datagram ("ping") sockets in the
# namespace. A fresh network namespace starts with net.ipv4.ping_group_range
# at the kernel default "1 0" (no group), so icmp.ListenPacket("udp4"/"udp6")
# fails with EACCES for every caller, uid 0 included — the check is by group,
# not capability. A systemd host gets "0 2147483647" from systemd's own
# 50-default.conf (the Ubuntu appliance image is one); xpf itself pins no
# value (it ships no sysctl.d file for it). The product's ICMP prober
# (pkg/cluster ip-monitoring) and tunnel keepalive (pkg/routing) open
# exactly these sockets, so under the old
# namespace the real prober could not open a socket at all and its cells read
# "probe not completed": TestIPMonitorPrimaryDualStackDemotes16425 was red on
# every testguard run. The sysctl is per network namespace, so the host's
# value is untouched. The full range is written first; inside an unprivileged
# user namespace only the mapped gid is valid, so the fallback is the
# caller's own gid. A failure is reported, not hidden.
inner='ip link set lo up 2>/dev/null || echo "testguard-run: could not bring loopback up in the test namespace" >&2; { echo "0 2147483647" >/proc/sys/net/ipv4/ping_group_range || echo "$(id -g) $(id -g)" >/proc/sys/net/ipv4/ping_group_range; } 2>/dev/null || echo "testguard-run: could not allow ICMP datagram sockets (ping_group_range) in the test namespace" >&2; exec "$@"'
# #19084: a ROOT run executes inside a throwaway view of the WHOLE root
# filesystem (scripts/testguard-root-view.sh). A private mount namespace alone
# isolates nothing on disk: a root test that writes or unlinks /etc/... does it
# on the host's root filesystem. Redirecting production paths one by one
# missed some (R18's 46-file seeded probe: 7 deleted or rewritten after the
# redirects), and so did covering a fixed list of trees: a directory symlink
# in a covered tree that resolved outside it, or any uncovered tree (/srv,
# /opt, /root, /tmp, ...), still reached the host (Codex F1, R18 R2 on
# 11eaccc637). So "/" itself is an overlay whose lower layer is the host's
# root filesystem and whose upper layer is a tmpfs that exists only in this
# namespace; every other mount is overlaid too, bound in read-only, bound in
# as a pseudo filesystem, or the run is refused (exit 2). Tests still READ
# the host's files and read back what they write, in-process and from child
# processes. The only writable host storage is the pass-through allowlist
# below. Host daemons are outside the namespace and keep the real files.
#
# The view is built by real root BEFORE any user namespace exists: inside the
# user namespace of the no-VM-proof path the inherited mounts are locked, and
# overlayfs cannot clone a lower tree with locked submounts (/run has several).
# Non-root runs are unchanged: they cannot write the host's system trees.
# The residue check below stays as the detector.
cover=()
inner_cmd=$inner
if [[ $euid == 0 ]]; then
	[[ -n $cwd ]] || { echo "testguard-run: REFUSED: cannot resolve the working directory for the root view (#19084)" >&2; exit 2; }
	# The writable pass-through: the checkout, the TMPDIR scratch (and this
	# run's work dir in it), and Go's build cache, module cache and build
	# temp. Nothing else on the host is writable from inside the view.
	pass_raw=("$root" "$scratch")
	go_vars=()
	if gobin=$(PATH="$real_path" command -v go 2>/dev/null); then
		mapfile -t go_vars < <(PATH="$real_path" "$gobin" env GOCACHE GOMODCACHE GOTMPDIR 2>/dev/null)
	fi
	pass_raw+=("${GOCACHE:-${go_vars[0]:-}}" "${GOMODCACHE:-${go_vars[1]:-}}" "${GOTMPDIR:-${go_vars[2]:-}}")
	pass=()
	# A pass-through may not be, or lie below, a host system tree
	# (system_tree, above). Checked on the lexical path BEFORE the mkdir, so a
	# refused path is never created on the host, and again after symlinks
	# resolve.
	for p in "${pass_raw[@]}"; do
		[[ -n $p && $p != off ]] || continue
		lexical=$(realpath -m "$p" 2>/dev/null) || lexical=
		if [[ -z $lexical ]] || system_tree "$lexical"; then
			echo "testguard-run: REFUSED: pass-through directory '$p' would expose a host system tree; point TMPDIR/GOCACHE/GOMODCACHE/GOTMPDIR elsewhere (#19084)" >&2
			exit 2
		fi
		mkdir -p "$lexical" 2>/dev/null && p=$(realpath -e "$lexical" 2>/dev/null) || {
			echo "testguard-run: REFUSED: cannot resolve the pass-through directory '$p' (#19084)" >&2
			exit 2
		}
		if system_tree "$p"; then
			echo "testguard-run: REFUSED: pass-through directory $p (after symlinks) would expose a host system tree; point TMPDIR/GOCACHE/GOMODCACHE/GOTMPDIR elsewhere (#19084)" >&2
			exit 2
		fi
		pass+=("$p")
	done
	# #19084 (Codex P1 on 70ba89c39f): the pass-through must be DISJOINT from
	# the production state the overlay protects. A production symlink that
	# resolves INTO a writable pass-through (/var/log/xpf -> /var/tmp/xpf-log
	# with TMPDIR=/var/tmp) turns an accidental append to /var/log/xpf/... into
	# a write to the host file through the pass-through bind; nodev does not
	# stop ordinary writes. Refuse such a layout before anything runs. The scan
	# covers the overlay-protected production trees, one filesystem each,
	# depth-bounded, and resolves every symlink in one realpath pass.
	mapfile -d '' -t prod_links < <(find /etc /var/lib /var/log /run -xdev -maxdepth 8 -type l -print0 2>/dev/null)
	if ((${#prod_links[@]})); then
		mapfile -d '' -t prod_targets < <(printf '%s\0' "${prod_links[@]}" | xargs -0 realpath -m -z -- 2>/dev/null)
		# realpath -m resolves a missing target or a symlink loop without
		# failing (coreutils 9.12 on the runner), so the arrays stay aligned;
		# every target is compared either way.
		for i in "${!prod_links[@]}"; do
			for p in "${pass[@]}"; do
				t=${prod_targets[i]:-}
				if [[ -n $t && ($t == "$p" || $t == "$p"/*) ]]; then
					echo "testguard-run: REFUSED: production symlink ${prod_links[i]} resolves to $t, inside the writable pass-through $p; an accidental write there would reach the host. Move the pass-through (TMPDIR/GOCACHE/GOMODCACHE/GOTMPDIR, the checkout) or the symlink (#19084)" >&2
					exit 2
				fi
			done
		done
	fi
	mkdir -p "$work/overlay"
	cover=(unshare -m --propagation private bash "$root/scripts/testguard-root-view.sh" "$work/overlay" "$cwd" "${pass[@]}" --)
	# R18 R1: in the VM-proof branch the command keeps real root, so it can
	# detach mounts in its own namespace. The host's root filesystem is not
	# attached there (the view pivoted away from it), but a detached view is
	# no longer the run's view, so after the command the run's namespace must
	# still have the testguard root overlay at "/", or the run FAILS.
	# Detection only: a command with real root can also mount host block
	# devices or enter host namespaces, which no check here can stop.
	# It brings loopback up and sets ping_group_range exactly as $inner does
	# (#19049).
	inner_cmd='ip link set lo up 2>/dev/null || echo "testguard-run: could not bring loopback up in the test namespace" >&2; { echo "0 2147483647" >/proc/sys/net/ipv4/ping_group_range || echo "$(id -g) $(id -g)" >/proc/sys/net/ipv4/ping_group_range; } 2>/dev/null || echo "testguard-run: could not allow ICMP datagram sockets (ping_group_range) in the test namespace" >&2; "$@"; rc=$?; grep -qE "^[^ ]+ [^ ]+ [^ ]+ / / .* - overlay testguard-root( |\$)" /proc/self/mountinfo 2>/dev/null || { echo "testguard-run: FAIL: the root view is no longer mounted at / in the run'"'"'s namespace after the command (the command detached it?); its writes may not have been contained (#19084 R18 R1)" >&2; [ "$rc" -eq 0 ] && rc=1; }; exit "$rc"'
fi
if [[ $euid == 0 && -n "$current_boot" && "$proof_boot" == "$current_boot" ]]; then
	# The VM proof permits the privileged lane to retain its VM capabilities
	# (for BPF/memlock tests); namespace identity is still independently
	# checked by testguard in the child.
	XPF_SACRIFICIAL_HOST=1 "${cover[@]}" \
		unshare -pf --fork --mount-proc sh -c '(unshare -nm sh -c "$0" testguard-run "$@")' "$inner_cmd" "$@"
else
	# A caller-supplied intent sentinel is not proof; do not propagate it on
	# the workstation path.
	env -u XPF_SACRIFICIAL_HOST "${cover[@]}" \
		unshare -Urp --fork --mount-proc sh -c '(unshare -nm sh -c "$0" testguard-run "$@")' "$inner_cmd" "$@"
fi
rc=$?
set -e
"$root/scripts/host-residue-snapshot.sh" "$work/after.txt"
# #19090 R3: every harness diagnostic goes to STDERR. stdout is the command's
# own stream, and for go-test-json.sh's side-file path that is the
# `go test -json` event stream: a plain-text report there corrupted the JSON
# file, made jq fail and turned the run's verdict into a stream error (2).
if ! cmp -s "$work/before.txt" "$work/after.txt"; then
	{
		echo "HOST RESIDUE DIFFERENCE (report-only; no cleanup performed):"
		diff -u "$work/before.txt" "$work/after.txt" || true
	} >&2
fi
# #19066: a difference in the production state paths FAILS the run, with
# status 1 when the tests themselves passed. NOT 3: go-test-json.sh,
# go-test-watch.sh and the Makefile read 3 as VOID (a go-test timeout), which
# would turn a host mutation into "undetermined", and a rerun would come back
# clean because the files are already gone (#19066 R18). The rest of the
# report stays report-only (systemd session scopes come and go with other
# users of the host). A difference in these paths is a test that wrote or
# deleted production state, or another writer on the same host (#19090
# R13-b): since #19084 a concurrent ROOT run of this wrapper writes only its
# own copy-on-write view, so on a shared runner the remaining candidates are a
# process outside any testguard run (a package upgrade, a hand-run test) and
# paths added through XPF_RESIDUE_EXTRA_STATE_PATHS that sit in a writable
# pass-through. The diff printed above names what changed; it cannot name
# whose run changed it.
state_sections() { awk '/^--- state(-content)? /{on=1} /^--- / && !/^--- state(-content)? /{on=0} on' "$1"; }
if ! cmp -s <(state_sections "$work/before.txt") <(state_sections "$work/after.txt"); then
	echo "testguard-run: FAIL: the run changed production state paths on the host (no cleanup performed):" >&2
	diff -u <(state_sections "$work/before.txt") <(state_sections "$work/after.txt") >&2 || true
	[[ "$rc" -eq 0 ]] && rc=1
	if [[ -n $state_verdict ]] && ! printf 'state-changed\n' >>"$state_verdict"; then
		echo "testguard-run: could not record the state change in $state_verdict; the caller cannot see it apart from the exit status" >&2
	fi
fi
exit "$rc"
