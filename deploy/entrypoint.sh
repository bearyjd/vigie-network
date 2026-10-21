#!/bin/sh
# Container entrypoint. With VIGIE_GUARD_OVERRIDES=1 (api, pipeline) it checks, before exec'ing the
# command, that nothing ingest can write could stand in for the trusted overrides.db.
#
# Why: api and pipeline trust overrides.db (identity links, rules, API tokens). They address it
# directly through VIGIE_OVERRIDES_PATH on its own volume, which ingest never mounts. If a file or
# symlink named overrides.db existed in a directory ingest CAN write (the raw/data volume or the
# inventory volume), a compromised ingest could plant something there, and anything that still
# resolved the default <data dir>/overrides.db would trust it. So the container refuses to start:
#   - VIGIE_OVERRIDES_PATH is unset (the code would fall back to <data dir>/overrides.db), or
#   - VIGIE_OVERRIDES_PATH lies inside the data dir or the inventory dir, or
#   - overrides.db exists AT ALL (file, symlink, even a dangling one) in either of those.
# Nothing is ever deleted or repaired here; a human removes the stale entry.
set -eu

DATA_DIR="${VIGIE_DATA_DIR:-/var/lib/vigie}"
INVENTORY_DIR=$(dirname -- "${VIGIE_INVENTORY_PATH:-$DATA_DIR/inventory.db}")

refuse() {
	echo "vigie-entrypoint: refusing: $1" >&2
	exit 70
}

if [ "${VIGIE_GUARD_OVERRIDES:-0}" = 1 ]; then
	OVERRIDES="${VIGIE_OVERRIDES_PATH:-}"
	[ -n "$OVERRIDES" ] || refuse "VIGIE_OVERRIDES_PATH is not set"
	for dir in "$DATA_DIR" "$INVENTORY_DIR"; do
		case "$OVERRIDES" in
		"$dir"/*) refuse "VIGIE_OVERRIDES_PATH ($OVERRIDES) is inside $dir, which ingest can write" ;;
		esac
		if [ -e "$dir/overrides.db" ] || [ -L "$dir/overrides.db" ]; then
			refuse "$dir/overrides.db exists (stale file or link); remove it by hand"
		fi
	done
fi

exec "$@"
