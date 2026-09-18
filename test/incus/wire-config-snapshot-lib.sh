#!/usr/bin/env bash
# shellcheck shell=bash
#
# Normalize the output envelope from the remote CLI without discarding the
# configuration body. The CLI may render `display set` as flat `set` commands
# or, when its pipe is not applied, as a hierarchical brace tree. Interactive
# framing is not configuration and is removed; all configuration lines are
# preserved verbatim so a runner cannot turn a real snapshot into empty text.
wire_snapshot_payload() {
    awk '
        /^cli .*connected to xpfd/ { next }
        /^Type .*for help$/ { next }
        !started && NF == 0 { next }
        { started = 1; print }
    '
}
