#!/bin/sh
# Container entrypoint: when VIGIE_LINK_OVERRIDES=1 (api, pipeline), make
# $VIGIE_DATA_DIR/overrides.db a symlink to the separate overrides volume, then exec the command.
#
# Why: the api and the pipeline both derive overrides.db from VIGIE_DATA_DIR (no separate
# setting), but overrides.db lives on its own volume so that ingest never mounts it and so it can
# be backed up on its own. SQLite names -wal/-shm after the resolved path, so they land on the
# overrides volume too.
#
# Safety: never replaces anything. An existing symlink must already point at the right target;
# a regular file at that path (human labels created by an earlier layout) makes the container
# refuse to start rather than be shadowed or deleted.
set -eu

DATA_DIR="${VIGIE_DATA_DIR:-/var/lib/vigie}"
TARGET="${VIGIE_OVERRIDES_TARGET:-/overrides/overrides.db}"
LINK="$DATA_DIR/overrides.db"

if [ "${VIGIE_LINK_OVERRIDES:-0}" = 1 ]; then
	if [ ! -L "$LINK" ] && [ ! -e "$LINK" ]; then
		# Two containers may race here; "File exists" from the loser is fine, re-checked below.
		ln -s "$TARGET" "$LINK" 2>/dev/null || true
	fi
	if [ ! -L "$LINK" ]; then
		echo "vigie-entrypoint: refusing: $LINK exists and is not a symlink to $TARGET" >&2
		exit 70
	fi
	if [ "$(readlink "$LINK")" != "$TARGET" ]; then
		echo "vigie-entrypoint: refusing: $LINK points at $(readlink "$LINK"), expected $TARGET" >&2
		exit 70
	fi
fi

exec "$@"
