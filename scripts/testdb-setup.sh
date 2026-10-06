#!/usr/bin/env bash
# Prepares the database that the database backed Go tests need.
#
# Those tests connect and assume the schema exists. None of them run a migration.
# That requirement used to live only in prose, which meant a fresh machine produced
# six silent skips and a green suite. This script makes it executable: it creates
# the database when it is absent, applies the embedded migrations through the
# authority's own migration runner, and then checks that the tables the tests touch
# are actually there.
#
# Safe to run repeatedly. Creating an existing database is skipped and the
# migration runner treats no change as success.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/scripts/lib/checks.sh"
[ -r "$LIB" ] || { echo "shared check library unreachable at $LIB" >&2; exit 1; }
# shellcheck source=lib/checks.sh
. "$LIB"

# An unset variable is not an error. The url holds no secret, so the library
# carries a default and the variable only overrides it.
URL="$(ck_test_db_url)"
echo "connection url from $(ck_test_db_origin)"

for tool in psql python3 go; do
	command -v "$tool" >/dev/null || { echo "required tool not found: $tool" >&2; exit 1; }
done

DBNAME=$(python3 "$ROOT/scripts/lib/dburl.py" "$URL" dbname) || exit 1
MAINT=$(python3 "$ROOT/scripts/lib/dburl.py" "$URL" maintenance) || exit 1

echo "test database: $DBNAME"

# Readiness gate. A cluster that has just started refuses connections with "the
# database system is starting up", and WSL stops its VM when idle, so the server is
# frequently a few seconds old when this runs. A single attempt would report a down
# cluster for a server that is merely busy booting, so readiness gets a budget.
# Every test run in this project is expected to come through here first.
ready=no
for _ in $(seq 1 "${DB_READY_BUDGET:-60}"); do
	if psql "$MAINT" -tAc 'select 1' >/dev/null 2>&1; then ready=yes; break; fi
	sleep 1
done
if [ "$ready" != yes ]; then
	echo "the server did not become ready. Is the cluster running?" >&2
	echo "  pg_isready: $(pg_isready 2>&1)" >&2
	echo "  pg_lsclusters:" >&2
	pg_lsclusters 2>&1 | sed 's/^/    /' >&2
	exit 1
fi
echo "server ready: $(pg_isready 2>&1)"

# A test binary killed mid run leaves its per package database behind, so leftovers
# are swept before every run. The pattern requires the trailing underscore that the
# template name does not have, so the template can never match it. The underscores are
# escaped because LIKE treats a bare underscore as a single character wildcard.
#
# The listing keeps its errors. Discarding them turned a failed query into an empty
# list and an untroubled "no leftover per package databases", which is a clean report
# of a check that never ran.
leftovers=$(psql "$MAINT" -tAc \
	"select datname from pg_database where datname like 'darkrouter\\_test\\_%'" 2>&1)
if [ $? -ne 0 ]; then
	echo "listing leftover databases failed, so the sweep cannot run:" >&2
	printf '%s\n' "$leftovers" | sed 's/^/    /' >&2
	exit 1
fi

if [ -z "$leftovers" ]; then
	echo "no leftover per package databases"
else
	removed=0
	survivors=''
	while IFS= read -r db; do
		[ -z "$db" ] && continue
		case "$db" in
		darkrouter_test_*) ;;
		*)
			echo "refusing to drop '$db': outside the darkrouter_test_ namespace" >&2
			survivors="$survivors $db"
			continue
			;;
		esac

		out=$(psql "$MAINT" -q -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)" 2>&1)
		if [ $? -ne 0 ]; then
			out=$(psql "$MAINT" -q -c "DROP DATABASE IF EXISTS \"$db\"" 2>&1)
		fi

		# The effect, not the exit status. A drop that reported success while the
		# database is still listed would otherwise be counted as removed.
		still=$(psql "$MAINT" -tAc \
			"select count(*) from pg_database where datname = '$db'" 2>&1)
		if [ $? -ne 0 ]; then
			echo "could not confirm whether '$db' was removed:" >&2
			printf '%s\n' "$still" | sed 's/^/    /' >&2
			survivors="$survivors $db"
		elif [ "$still" = 0 ]; then
			removed=$((removed + 1))
		else
			echo "leftover database '$db' is still present after the drop:" >&2
			[ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' >&2
			survivors="$survivors $db"
		fi
	done <<< "$leftovers"

	echo "removed $removed leftover per package database(s)"
	if [ -n "$survivors" ]; then
		echo "these leftover databases survived the sweep:$survivors" >&2
		exit 1
	fi
fi

exists=$(psql "$MAINT" -tAc "select 1 from pg_database where datname = '$DBNAME'" 2>/dev/null)
if [ "$exists" = "1" ]; then
	echo "database already present, leaving it alone"
else
	# Quoted so a name needing quoting is still created correctly, and the role
	# running this becomes the owner, which is what the tests connect as.
	psql "$MAINT" -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$DBNAME\"" >/dev/null || {
		echo "creating database $DBNAME failed" >&2; exit 1; }
	echo "database created"
fi

echo "applying the embedded migrations"
# The url is passed explicitly. The library resolved it, possibly from the default,
# so it may not be in the environment at all, and cmd/testdb reads the environment.
( cd "$ROOT/authority" && TEST_DATABASE_URL="$URL" go run ./cmd/testdb ) || exit 1

# Enumerated from the tables the gated tests read and write, not from whatever the
# database happens to contain, so a migration that stops creating one of them is a
# failure here rather than a confusing failure inside a test.
REQUIRED='subscribers sessions subscriptions relay_nodes circuit_assignments token_issuance_events'
missing=''
for t in $REQUIRED; do
	have=$(psql "$URL" -tAc "select 1 from information_schema.tables where table_schema = 'public' and table_name = '$t'" 2>/dev/null)
	[ "$have" = "1" ] || missing="$missing $t"
done
if [ -n "$missing" ]; then
	echo "the schema is incomplete after migrating, missing:$missing" >&2
	exit 1
fi

echo "schema verified, all 6 required tables present"
echo "ready: go test ./... in authority/ will now run the database backed tests"
