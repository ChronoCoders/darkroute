#!/usr/bin/env bash
# Shared check library for gate.sh and the git hooks under scripts/hooks, so the
# gate and the hooks cannot drift apart. ARCHITECTURE 11 forbids any automated
# pipeline, which makes these local checks the only enforcement that exists.
#
# Two patterns here are written so this file does not match itself. The tooling
# name is a split character class. The dash class is assembled at run time from
# escapes, so the source stays pure ascii and the sweep does not flag the one file
# that defines what it looks for. It is matched as characters under a UTF-8 locale
# rather than as bytes, because a byte level class matches the 0xE2 lead byte that
# U+2010 shares with U+2192 and would flag every arrow in the tree.
#
# Every pattern has a self test that proves it still matches the literal it is
# meant to catch and still rejects a near miss. A pattern that silently stops
# matching turns its check into an unconditional pass, which is the failure mode
# these self tests exist to catch.

CK_NAME_PAT='c[l]aude'
CK_ADDR_PAT='noreply@anthropi[c]\.com'
CK_DASH_CLASS="[$(printf '\u2010\u2011\u2012\u2013\u2014\u2015')]"
CK_MSG_PREFIX='^(feat|fix|docs|test|refactor|chore)(\([a-z0-9._-]+\))?: .+'
CK_CLEANUP_WORDS='formatting|whitespace|punctuation|typo|trailing space|indentation|em dash|en dash|reformat'

# The project author. Every commit that leaves this machine carries this identity
# as both author and committer. It is already in every commit in the published
# history, so naming it here exposes nothing new, and a rule that lives only in a
# instruction file is a rule the next session can forget.
CK_AUTHOR_NAME='ChronoCoders'
CK_AUTHOR_EMAIL='altug@bytus.io'

# The test database url carries nothing secret: peer authentication over the unix
# socket, so no password, no host and no port appear in it. That is why the default
# lives here as a constant instead of in a shell profile that every fresh shell has
# to have sourced. TEST_DATABASE_URL overrides it when a different database is
# wanted. The database check still fails loudly when the cluster is down or the
# schema is missing. It just no longer fails merely because nobody exported a
# variable.
CK_TEST_DB_DEFAULT='postgres:///quiethop_test?host=/var/run/postgresql&sslmode=disable'

ck_test_db_url() {
	printf '%s' "${TEST_DATABASE_URL:-$CK_TEST_DB_DEFAULT}"
}

ck_test_db_origin() {
	if [ -n "${TEST_DATABASE_URL:-}" ]; then printf 'TEST_DATABASE_URL'; else printf 'the built in default'; fi
}

CK_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
CK_ACCEPTED="$CK_ROOT/scripts/accepted-advisories.txt"

CK_STEP=0
CK_FAILED=0

# Tool lookup that also searches where cargo and go install, because neither
# location is reliably on PATH in a non-login shell.
ck_tool() {
	local n="$1" p d
	p=$(command -v "$n" 2>/dev/null) && { printf '%s' "$p"; return 0; }
	for d in "$(go env GOPATH 2>/dev/null)/bin" "$HOME/go/bin" "$HOME/.cargo/bin"; do
		[ -x "$d/$n" ] && { printf '%s' "$d/$n"; return 0; }
	done
	return 1
}

ck_require() {
	local n missing=0
	for n in "$@"; do
		ck_tool "$n" >/dev/null || { echo "required tool not found: $n" >&2; missing=1; }
	done
	return $missing
}

# Run an external tool, failing with a message that names it when it is absent.
# A missing tool has to read as a failure: a skipped check and a passing check
# look identical in the output otherwise.
ck_run() {
	ck_require "$1" || return 1
	"$@"
}

ck_run_in() {
	local dir="$1"; shift
	cd "$CK_ROOT/$dir" || return 1
	ck_require "$1" || return 1
	"$@"
}

ck_gofmt() {
	ck_require gofmt || return 1
	local out
	out=$(cd "$CK_ROOT/authority" && gofmt -l . 2>&1) || return 1
	[ -z "$out" ] && return 0
	echo "these files are not gofmt clean:" >&2
	printf '%s\n' "$out" | sed 's/^/    /' >&2
	return 1
}

ck_step() {
	local label="$1"; shift
	local out rc
	CK_STEP=$((CK_STEP + 1))
	out=$("$@" 2>&1); rc=$?
	if [ "$rc" -eq 0 ]; then
		printf 'PASS  %2d  %s\n' "$CK_STEP" "$label"
		if [ -n "${CK_VERBOSE:-}" ] && [ -n "$out" ]; then
			printf '%s\n' "$out" | sed 's/^/          /'
		fi
	else
		printf 'FAIL  %2d  %s\n' "$CK_STEP" "$label"
		printf '%s\n' "$out" | tail -30 | sed 's/^/          /'
		CK_FAILED=$((CK_FAILED + 1))
	fi
	return 0
}

ck_naming_self_test() {
	local probe probe2
	probe=$(printf 'c%saude' l)
	printf '%s\n' "$probe" | grep -qi -e "$CK_NAME_PAT" || {
		echo "name pattern no longer matches the literal" >&2; return 1; }
	probe2=$(printf 'noreply@anthropi%s.com' c)
	printf '%s\n' "$probe2" | grep -qi -e "$CK_ADDR_PAT" || {
		echo "address pattern no longer matches the literal" >&2; return 1; }
	if printf '%s\n' "an ordinary line of prose" | grep -qi -e "$CK_NAME_PAT" -e "$CK_ADDR_PAT"; then
		echo "name pattern matches text it should not" >&2; return 1
	fi
	echo "name and address patterns match their literals and reject a near miss"
}

# Text arrives as an argument rather than through a pipeline, because a grep that
# finds nothing exits non-zero and that must not be read as a violation.
ck_naming_scan() {
	local label="$1" text="$2" hits
	[ -z "$text" ] && return 0
	hits=$(printf '%s\n' "$text" | grep -n -i -e "$CK_NAME_PAT" -e "$CK_ADDR_PAT" || true)
	[ -z "$hits" ] && return 0
	printf 'REJECT %s: the tooling name or address appears here\n' "$label" >&2
	printf '%s\n' "$hits" | head -8 | sed 's/^/    /' >&2
	return 1
}

ck_naming_scan_paths() {
	local text="$1" hits
	[ -z "$text" ] && return 0
	hits=$(printf '%s\n' "$text" | grep -i -e "$CK_NAME_PAT" || true)
	[ -z "$hits" ] && return 0
	printf 'REJECT path: a path carries the tooling name\n' >&2
	printf '%s\n' "$hits" | head -8 | sed 's/^/    /' >&2
	return 1
}

ck_naming_staged() {
	local rc=0 v
	ck_naming_scan_paths "$(git diff --cached --name-only --diff-filter=ACMR || true)" || rc=1
	ck_naming_scan "staged content" "$(git diff --cached --diff-filter=ACMR -U0 | grep '^+' | grep -v '^+++' || true)" || rc=1
	for v in "$(git config user.name || true)" "$(git config user.email || true)"; do
		if printf '%s\n' "$v" | grep -qi -e "$CK_NAME_PAT" -e "$CK_ADDR_PAT"; then
			echo "REJECT identity: user.name or user.email carries the tooling name" >&2; rc=1
		fi
	done
	return $rc
}

# Author and committer on every commit in a range. The naming scan over the same
# fields only rejects an identity carrying the tooling name, which leaves every
# other wrong identity through, so this is a separate rule rather than a widening
# of that one.
ck_identity_commits() { # revs
	local revs="$1" rc=0 line sha rest an ae cn ce checked=0 total
	total=$(git rev-list --count "$revs" 2>/dev/null || echo 0)
	# Only commits that have not reached a remote yet. 8a68505 in this history was
	# made through the GitHub web interface, so it carries that interface's
	# committer, and a rule applied to the whole reachable history would refuse
	# every push forever over a commit that was published long before the rule
	# existed. What has already left the machine cannot be stopped from leaving.
	while IFS= read -r line; do
		[ -z "$line" ] && continue
		checked=$((checked + 1))
		sha=${line%% *}
		rest=${line#* }
		IFS='|' read -r an ae cn ce <<< "$rest"
		if [ "$an" != "$CK_AUTHOR_NAME" ] || [ "$ae" != "$CK_AUTHOR_EMAIL" ]; then
			printf 'REJECT identity: %s author is "%s <%s>", expected "%s <%s>"\n' \
				"${sha:0:8}" "$an" "$ae" "$CK_AUTHOR_NAME" "$CK_AUTHOR_EMAIL" >&2
			rc=1
		fi
		if [ "$cn" != "$CK_AUTHOR_NAME" ] || [ "$ce" != "$CK_AUTHOR_EMAIL" ]; then
			printf 'REJECT identity: %s committer is "%s <%s>", expected "%s <%s>"\n' \
				"${sha:0:8}" "$cn" "$ce" "$CK_AUTHOR_NAME" "$CK_AUTHOR_EMAIL" >&2
			rc=1
		fi
	done < <(git log --format="%H %an|%ae|%cn|%ce" "$revs" --not --remotes 2>/dev/null)
	if [ "${total:-0}" -eq 0 ]; then
		echo "the range held no commit at all, so the identity check proved nothing" >&2
		return 1
	fi
	if [ $rc -eq 0 ]; then
		if [ "$checked" -eq 0 ]; then
			echo "all $total commit in this range are already on a remote, none left to check"
		else
			echo "$checked of $total commit are unpublished and carry the project identity"
		fi
	fi
	return $rc
}

ck_identity_config() {
	local n e rc=0
	n=$(git -C "$CK_ROOT" config user.name || true)
	e=$(git -C "$CK_ROOT" config user.email || true)
	[ "$n" = "$CK_AUTHOR_NAME" ] || { echo "user.name is '$n', expected '$CK_AUTHOR_NAME'" >&2; rc=1; }
	[ "$e" = "$CK_AUTHOR_EMAIL" ] || { echo "user.email is '$e', expected '$CK_AUTHOR_EMAIL'" >&2; rc=1; }
	[ $rc -eq 0 ] && echo "the configured identity is $n <$e>"
	return $rc
}

# The control builds a scratch repository, never the working tree, and proves the
# rule rejects a wrong author and a wrong committer separately as well as
# accepting a correct commit. Checking a predicate in isolation says nothing about
# whether anything calls it, so the hook case lives in the hook controls and this
# covers the rule itself.
ck_identity_self_test() {
	local tmp rc=0
	tmp=$(mktemp -d) || return 1
	(
		cd "$tmp" || exit 1
		git init -q .
		git config user.name "$CK_AUTHOR_NAME"
		git config user.email "$CK_AUTHOR_EMAIL"
		git config commit.gpgsign false
		printf 'x\n' > f
		git add f
		git commit -q -m 'chore: a commit'
	) >/dev/null 2>&1
	( cd "$tmp" && ck_identity_commits HEAD ) >/dev/null 2>&1 || {
		echo "control failed: a correct commit was rejected" >&2; rc=1; }

	( cd "$tmp" && git -c user.name='Someone Else' -c user.email='someone@example.invalid' \
		commit -q --allow-empty -m 'chore: a commit with the wrong author' ) >/dev/null 2>&1
	if ( cd "$tmp" && ck_identity_commits HEAD~1..HEAD ) >/dev/null 2>&1; then
		echo "control failed: a commit with the wrong author and committer was accepted" >&2; rc=1
	fi

	( cd "$tmp" && GIT_COMMITTER_NAME='Someone Else' GIT_COMMITTER_EMAIL='someone@example.invalid' \
		git commit -q --allow-empty -m 'chore: a commit with the wrong committer' ) >/dev/null 2>&1
	if ( cd "$tmp" && ck_identity_commits HEAD~1..HEAD ) >/dev/null 2>&1; then
		echo "control failed: a commit with only the committer wrong was accepted" >&2; rc=1
	fi

	rm -rf "$tmp"
	[ $rc -eq 0 ] || return 1
	echo "the identity rule accepts the project identity and rejects a wrong author or committer"
}

ck_naming_tracked() {
	local rc=0 f hits=''
	ck_naming_scan_paths "$(git ls-files || true)" || rc=1
	while IFS= read -r f; do
		[ -f "$f" ] || continue
		if grep -I -q -i -e "$CK_NAME_PAT" -e "$CK_ADDR_PAT" "$f" 2>/dev/null; then
			hits="$hits$f"$'\n'
		fi
	done < <(git ls-files)
	if [ -n "$hits" ]; then
		echo "REJECT tracked content: these tracked files carry the tooling name or address" >&2
		printf '%s' "$hits" | head -12 | sed 's/^/    /' >&2
		rc=1
	fi
	ck_naming_scan_paths "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)" || rc=1
	return $rc
}

ck_dash_self_test() {
	local cp bad=0
	for cp in 2010 2011 2012 2013 2014 2015; do
		if ! printf "x\\u${cp}y\n" | LC_ALL=C.UTF-8 grep -q "$CK_DASH_CLASS"; then
			echo "dash class no longer matches U+$cp" >&2; bad=1
		fi
	done
	# U+2192 shares a lead byte with the dash block. A class matched as bytes would
	# match here, which is the specific defect this rejects.
	if printf 'a\u2192b\n' | LC_ALL=C.UTF-8 grep -q "$CK_DASH_CLASS"; then
		echo "dash class matches U+2192, so it is matching bytes and not characters" >&2; bad=1
	fi
	if printf 'a-b\n' | LC_ALL=C.UTF-8 grep -q "$CK_DASH_CLASS"; then
		echo "dash class matches an ascii hyphen" >&2; bad=1
	fi
	[ $bad -eq 0 ] || return 1
	echo "dash class matches U+2010 through U+2015 and rejects U+2192 and the ascii hyphen"
}

ck_dash_text() {
	local label="$1" text="$2" hits
	[ -z "$text" ] && return 0
	hits=$(printf '%s\n' "$text" | LC_ALL=C.UTF-8 grep -n "$CK_DASH_CLASS" || true)
	[ -z "$hits" ] && return 0
	printf 'REJECT %s: an em dash or en dash appears here\n' "$label" >&2
	printf '%s\n' "$hits" | head -8 | sed 's/^/    /' >&2
	return 1
}

ck_dash_tracked() {
	local f h hits=''
	while IFS= read -r f; do
		[ -f "$f" ] || continue
		h=$(LC_ALL=C.UTF-8 grep -I -n "$CK_DASH_CLASS" "$f" 2>/dev/null | head -3 || true)
		if [ -n "$h" ]; then
			hits="$hits$(printf '%s\n' "$h" | sed "s|^|$f:|")"$'\n'
		fi
	done < <(git ls-files)
	[ -z "$hits" ] && return 0
	echo "REJECT tracked content: these tracked files carry an em dash or en dash" >&2
	printf '%s' "$hits" | head -20 | sed 's/^/    /' >&2
	return 1
}

ck_dash_staged() {
	ck_dash_text "staged content" "$(git diff --cached --diff-filter=ACMR -U0 | grep '^+' | grep -v '^+++' || true)"
}

# The private documents. ARCHITECTURE.md and SECURITY_MODEL.md are the governing
# specs and SESSION_LOG.md is the running record, all three deliberately kept out
# of the published repository. They are excluded through .git/info/exclude, which
# is local and does not survive a fresh clone, so the hook is what actually stops
# them from being committed.
CK_PRIVATE_PATHS='^(ARCHITECTURE\.md|SECURITY_MODEL\.md|SESSION_LOG\.md|STATUS_REPORT\.md|docs/DECISIONS\.md|authority/\.env|authority/keys/)'
# authority/.env.example is deliberately tracked: .gitignore ignores .env and
# .env.* and then re-includes it, because it documents the variables the service
# needs. The pattern above stays broad, so authority/.env.local and
# authority/.env.production are still refused, and the one tracked template is
# excepted by name rather than by narrowing the rule.
CK_PRIVATE_ALLOW='^authority/\.env\.example$'

ck_private_staged() {
	local hits
	hits=$(git diff --cached --name-only --diff-filter=ACMR \
		| grep -E "$CK_PRIVATE_PATHS" \
		| grep -vE "$CK_PRIVATE_ALLOW" || true)
	[ -z "$hits" ] && return 0
	echo "REJECT staged path: these stay untracked and must not be committed" >&2
	printf '%s\n' "$hits" | sed 's/^/    /' >&2
	return 1
}

# Formatters run over the staged paths only, so an unrelated file in the working
# tree cannot block a commit.
ck_fmt_staged() {
	local rs go
	rs=$(git diff --cached --name-only --diff-filter=ACMR -- '*.rs' || true)
	go=$(git diff --cached --name-only --diff-filter=ACMR -- 'authority/*.go' || true)
	local rc=0 out
	if [ -n "$rs" ]; then
		ck_require cargo || return 1
		out=$(cd "$CK_ROOT" && printf '%s\n' "$rs" | xargs cargo fmt -- --check 2>&1) || {
			echo "REJECT format: staged rust is not rustfmt clean" >&2
			printf '%s\n' "$out" | head -20 | sed 's/^/    /' >&2
			rc=1; }
	fi
	if [ -n "$go" ]; then
		ck_require gofmt || return 1
		out=$(cd "$CK_ROOT" && printf '%s\n' "$go" | xargs gofmt -l 2>&1) || true
		if [ -n "$out" ]; then
			echo "REJECT format: staged go is not gofmt clean" >&2
			printf '%s\n' "$out" | sed 's/^/    /' >&2
			rc=1
		fi
	fi
	return $rc
}

# Crate roots are derived from the workspace members in Cargo.toml rather than
# listed here, so a crate added later is covered without editing this file.
ck_crate_roots() {
	local m r
	sed -n '/^members *= *\[/,/\]/p' "$CK_ROOT/Cargo.toml" |
		grep -o '"[^"]*"' | tr -d '"' |
	while IFS= read -r m; do
		[ -z "$m" ] && continue
		for r in "$m/src/lib.rs" "$m/src/main.rs"; do
			[ -f "$CK_ROOT/$r" ] && printf '%s\n' "$r"
		done
	done
}

# Both attributes are checked, not only unsafe_code. forbid(unsafe_code) is
# enforced by every build, but nothing asserts the line is still on the file:
# delete it and the crate still compiles with unsafe allowed again. The rule and
# its application need testing separately, and this is the rule.
ck_attr_file() {
	local f="$1" rc=0 a
	[ -f "$f" ] || { echo "crate root missing: $f" >&2; return 1; }
	for a in 'deny(warnings)' 'forbid(unsafe_code)'; do
		grep -qF "#![$a]" "$f" || { echo "$f does not carry #![$a]" >&2; rc=1; }
	done
	return $rc
}

ck_attr_roots() {
	local rc=0 r n=0
	while IFS= read -r r; do
		[ -z "$r" ] && continue
		n=$((n + 1))
		ck_attr_file "$CK_ROOT/$r" || rc=1
	done < <(ck_crate_roots)
	if [ "$n" -eq 0 ]; then
		echo "no crate roots were found, so this check proved nothing" >&2
		return 1
	fi
	echo "$n crate roots carry both attributes"
	return $rc
}

# The control runs against copies in a scratch directory, never the working tree,
# and it proves the checker rejects a root with either attribute removed as well
# as accepting one that is intact.
# Path construction must never resolve a name and must never seed its generator.
#
# SECURITY_MODEL 5.3 puts it plainly: no hostname is resolved anywhere in path
# construction, because a resolver that saw those lookups would learn the path.
# The client works from the address literals the registry publishes. Asserting
# that a parser rejects a hostname tests the rule; this tests that no code on
# the path calls a resolver in the first place, which is the separate half.
#
# The generator half is here for the same reason. Selection must be uniform over
# valid paths, and a fixed seed in production would make every client pick the
# same path while every statistical test still passed.
CK_RESOLVER_PATTERN='to_socket_addrs|ToSocketAddrs|lookup_host'
CK_FIXED_SEED_PATTERN='seed_from_u64|from_seed'

ck_path_files() {
	printf '%s\n' client/src/path.rs client/src/dial.rs client/src/circuits.rs
}

# Everything above the test module. A seeded generator is correct in a test and
# wrong in production, so the two halves are not interchangeable.
ck_non_test_part() {
	awk '/^#\[cfg\(test\)\]/{exit} {print}' "$1"
}

ck_path_file_clean() {
	local f="$1" rc=0 hits
	hits=$(ck_non_test_part "$f" | grep -nE "$CK_RESOLVER_PATTERN")
	if [ -n "$hits" ]; then
		echo "name resolution in $f:" >&2
		printf '%s\n' "$hits" | sed 's/^/    /' >&2
		rc=1
	fi
	hits=$(ck_non_test_part "$f" | grep -nE "$CK_FIXED_SEED_PATTERN")
	if [ -n "$hits" ]; then
		echo "a seeded generator outside tests in $f:" >&2
		printf '%s\n' "$hits" | sed 's/^/    /' >&2
		rc=1
	fi
	return $rc
}

ck_path_self_test() {
	local tmp rc=0 f
	f=$(ck_path_files | head -1)
	tmp=$(mktemp -d) || return 1
	cp "$CK_ROOT/$f" "$tmp/intact.rs"
	ck_path_file_clean "$tmp/intact.rs" >/dev/null 2>&1 || {
		echo "control failed: the intact file was rejected" >&2; rc=1; }

	# A planted resolver call must be caught.
	{ echo 'fn planted(a: &str) { let _ = a.to_socket_addrs(); }'; cat "$tmp/intact.rs"; } > "$tmp/resolver.rs"
	if ck_path_file_clean "$tmp/resolver.rs" >/dev/null 2>&1; then
		echo "control failed: a planted to_socket_addrs call was accepted" >&2; rc=1
	fi

	# A planted fixed seed must be caught.
	{ echo 'fn planted() { let _ = StdRng::seed_from_u64(7); }'; cat "$tmp/intact.rs"; } > "$tmp/seed.rs"
	if ck_path_file_clean "$tmp/seed.rs" >/dev/null 2>&1; then
		echo "control failed: a planted fixed seed was accepted" >&2; rc=1
	fi

	# A seed below the test marker must be allowed, or the check would ban the
	# uniformity test it exists alongside.
	printf 'fn ok() {}\n#[cfg(test)]\nmod t { fn s() { let _ = StdRng::seed_from_u64(7); } }\n' > "$tmp/testonly.rs"
	ck_path_file_clean "$tmp/testonly.rs" >/dev/null 2>&1 || {
		echo "control failed: a seed inside the test module was rejected" >&2; rc=1; }

	rm -rf "$tmp"
	[ $rc -eq 0 ] || return 1
	echo "the check accepts intact path code, catches a planted resolver call and a planted fixed seed, and allows a seed inside tests"
}

ck_path_no_resolution() {
	local rc=0 f n=0
	while IFS= read -r f; do
		[ -z "$f" ] && continue
		if [ ! -r "$CK_ROOT/$f" ]; then
			echo "path file missing, so this check proved nothing: $f" >&2
			return 1
		fi
		n=$((n + 1))
		ck_path_file_clean "$CK_ROOT/$f" || rc=1
	done < <(ck_path_files)
	if [ "$n" -eq 0 ]; then
		echo "no path files were checked, so this check proved nothing" >&2
		return 1
	fi
	echo "$n path files resolve no name and seed no generator outside tests"
	return $rc
}

ck_attr_self_test() {
	local tmp first rc=0
	first=$(ck_crate_roots | head -1)
	[ -n "$first" ] || { echo "no crate root to build a control from" >&2; return 1; }
	tmp=$(mktemp -d) || return 1
	cp "$CK_ROOT/$first" "$tmp/intact.rs"
	ck_attr_file "$tmp/intact.rs" >/dev/null 2>&1 || {
		echo "control failed: an intact crate root was rejected" >&2; rc=1; }
	grep -v 'forbid(unsafe_code)' "$tmp/intact.rs" > "$tmp/stripped.rs"
	if ck_attr_file "$tmp/stripped.rs" >/dev/null 2>&1; then
		echo "control failed: a root with forbid(unsafe_code) removed was accepted" >&2; rc=1
	fi
	grep -v 'deny(warnings)' "$tmp/intact.rs" > "$tmp/nowarn.rs"
	if ck_attr_file "$tmp/nowarn.rs" >/dev/null 2>&1; then
		echo "control failed: a root with deny(warnings) removed was accepted" >&2; rc=1
	fi
	rm -rf "$tmp"
	[ $rc -eq 0 ] || return 1
	echo "the attribute check accepts an intact root and rejects one with either attribute removed"
}

ck_toolchain_pins() {
	local rc=0 c t
	c=$(grep -oP 'channel\s*=\s*"\K[^"]+' "$CK_ROOT/rust-toolchain.toml" 2>/dev/null || true)
	if [ -z "$c" ]; then
		echo "rust-toolchain.toml carries no channel, so the rust toolchain is unpinned" >&2; rc=1
	else
		echo "rust channel pinned to $c"
	fi
	t=$(grep -oP '^toolchain \Kgo[0-9.]+' "$CK_ROOT/authority/go.mod" 2>/dev/null || true)
	if [ -z "$t" ]; then
		echo "authority/go.mod carries no toolchain directive, so the go toolchain is unpinned" >&2; rc=1
	else
		echo "go toolchain pinned to $t"
	fi
	return $rc
}

ck_hooks_installed() {
	local p rc=0 h
	p=$(git -C "$CK_ROOT" config --get core.hooksPath || true)
	if [ "$p" != "scripts/hooks" ]; then
		echo "core.hooksPath is '${p:-unset}', not scripts/hooks. Run: git config core.hooksPath scripts/hooks" >&2
		rc=1
	fi
	for h in pre-commit commit-msg pre-push; do
		if [ ! -f "$CK_ROOT/scripts/hooks/$h" ]; then
			echo "scripts/hooks/$h is missing" >&2; rc=1
		elif [ ! -x "$CK_ROOT/scripts/hooks/$h" ]; then
			echo "scripts/hooks/$h is not executable" >&2; rc=1
		fi
	done
	[ $rc -eq 0 ] && echo "core.hooksPath is scripts/hooks and all three hooks are executable"
	return $rc
}

# Accepted ids come from the file, never from what an auditor happened to print,
# so an advisory that stops being reported does not silently keep its exemption.
ck_accepted_ids() {
	[ -r "$CK_ACCEPTED" ] || return 1
	grep -v '^[[:space:]]*#' "$CK_ACCEPTED" | grep -v '^[[:space:]]*$' |
		awk -F ' \\| ' '{gsub(/^[ \t]+|[ \t]+$/, "", $1); print $1}'
}

ck_accepted_file_self_test() {
	local n bad
	[ -r "$CK_ACCEPTED" ] || { echo "accepted advisory file unreadable at $CK_ACCEPTED" >&2; return 1; }
	n=$(ck_accepted_ids | grep -c . || true)
	if [ "${n:-0}" -eq 0 ]; then
		echo "the accepted advisory file parsed to zero ids, so every advisory would fail" >&2
		return 1
	fi
	bad=$(grep -v '^[[:space:]]*#' "$CK_ACCEPTED" | grep -v '^[[:space:]]*$' |
		awk -F ' \\| ' 'NF != 5 { print NR": "$1 }' || true)
	if [ -z "$bad" ]; then
		bad=$(ck_accepted_ids | grep -vE '^(RUSTSEC|GHSA|CVE)-' || true)
	fi
	if [ -n "$bad" ]; then
		echo "the accepted advisory file has malformed records:" >&2
		printf '%s\n' "$bad" | head -6 | sed 's/^/    /' >&2
		return 1
	fi
	echo "$n accepted advisory records parsed, all with five fields and a recognised id"
}

ck_cargo_audit() {
	ck_require cargo cargo-audit python3 || return 1
	[ -r "$CK_ACCEPTED" ] || { echo "accepted advisory file unreadable at $CK_ACCEPTED" >&2; return 1; }
	local json
	json=$(cd "$CK_ROOT" && cargo audit --json 2>/dev/null) || true
	[ -n "$json" ] || { echo "cargo audit produced no json output" >&2; return 1; }
	printf '%s' "$json" | ACCEPTED="$(ck_accepted_ids)" \
		python3 "$CK_ROOT/scripts/lib/audit_filter.py" cargo
}

ck_npm_audit() {
	ck_require npm python3 || return 1
	[ -r "$CK_ACCEPTED" ] || { echo "accepted advisory file unreadable at $CK_ACCEPTED" >&2; return 1; }
	local json
	json=$(cd "$CK_ROOT/dashboard" && npm audit --omit=dev --json 2>/dev/null) || true
	[ -n "$json" ] || { echo "npm audit produced no json output" >&2; return 1; }
	printf '%s' "$json" | ACCEPTED="$(ck_accepted_ids)" \
		python3 "$CK_ROOT/scripts/lib/audit_filter.py" npm
}

# The tables the database backed tests read and write, enumerated from those tests
# rather than from whatever the database happens to contain, so a migration that
# stops creating one of them fails here instead of inside a test.
CK_TEST_DB_TABLES='subscribers sessions subscriptions relay_nodes circuit_assignments token_issuance_events'

ck_test_db() {
	ck_require psql python3 || return 1
	local url origin dbname missing t have version
	url="$(ck_test_db_url)"
	origin="$(ck_test_db_origin)"
	dbname=$(python3 "$CK_ROOT/scripts/lib/dburl.py" "$url" dbname) || return 1

	if ! psql "$url" -tAc 'select 1' >/dev/null 2>&1; then
		echo "cannot reach the test database '$dbname' (url from $origin)" >&2
		echo "  pg_isready: $(pg_isready 2>&1)" >&2
		echo "  the cluster may be down, or the database may not exist yet" >&2
		echo "  fix: scripts/testdb-setup.sh" >&2
		return 1
	fi

	missing=''
	for t in $CK_TEST_DB_TABLES; do
		have=$(psql "$url" -tAc \
			"select 1 from information_schema.tables where table_schema = 'public' and table_name = '$t'" \
			2>/dev/null)
		[ "$have" = 1 ] || missing="$missing $t"
	done
	if [ -n "$missing" ]; then
		echo "the test database '$dbname' is missing tables:$missing" >&2
		echo "  fix: scripts/testdb-setup.sh applies the embedded migrations" >&2
		return 1
	fi

	version=$(psql "$url" -tAc 'select version from schema_migrations' 2>/dev/null)
	echo "test database '$dbname' reachable (url from $origin), schema complete at migration ${version:-unknown}"
}

# The control for the step above. It runs the same check against a socket directory
# that holds no server. If that passes, the check cannot tell a missing database
# from a present one, and a green gate would mean nothing.
ck_test_db_control() {
	if ( TEST_DATABASE_URL='postgres:///quiethop_test?host=/var/empty&sslmode=disable'
		ck_test_db ) >/dev/null 2>&1; then
		echo "the database check passed against a dead socket, so it detects nothing" >&2
		return 1
	fi
	echo "the database check fails when no server is listening"
}

# go test with the database url supplied, and a skip is treated as a failure. The
# whole point of the database step is that six tests used to skip silently and the
# suite still reported success.
ck_go_test() {
	ck_require go || return 1
	local out rc skips passes
	out=$(cd "$CK_ROOT/authority" && TEST_DATABASE_URL="$(ck_test_db_url)" \
		go test -count=1 -v ./... 2>&1)
	rc=$?
	if [ $rc -ne 0 ]; then
		printf '%s\n' "$out" | grep -E '^--- FAIL|^[[:space:]]+[a-z_]+\.go:[0-9]+:' | head -20 >&2
		return 1
	fi
	skips=$(printf '%s\n' "$out" | grep -c '^--- SKIP' || true)
	if [ "${skips:-0}" -ne 0 ]; then
		echo "the suite reported success but skipped $skips test(s). A skip is not a pass." >&2
		printf '%s\n' "$out" | grep '^--- SKIP' | sed 's/^/    /' >&2
		return 1
	fi
	passes=$(printf '%s\n' "$out" | grep -c '^--- PASS' || true)
	echo "$passes tests passed, 0 skipped"
}

# Commit message shape. Used by the commit-msg hook, and kept here so the gate
# and the hook share one definition of it.
ck_msg_shape() {
	local file="$1" rc=0 subject
	subject=$(head -1 "$file")
	if grep -v '^#' "$file" | sed '/^[[:space:]]*$/d' | tail -n +2 | grep -q .; then
		echo "REJECT message: the message has a body. Commit messages are one line." >&2; rc=1
	fi
	printf '%s\n' "$subject" | grep -qE "$CK_MSG_PREFIX" || {
		echo "REJECT message: the subject needs a conventional prefix, one of feat fix docs test refactor chore" >&2
		rc=1; }
	if grep -qiE '^([A-Za-z][A-Za-z0-9-]*-by|signed-off-by|cc|c[l]aude-session): ' "$file"; then
		echo "REJECT message: the message carries a trailer" >&2; rc=1
	fi
	if printf '%s\n' "$subject" | grep -qiE "$CK_CLEANUP_WORDS"; then
		echo "REJECT message: a subject describing a formatting or whitespace cleanup is not allowed on its own" >&2
		rc=1
	fi
	ck_dash_text "commit message" "$(cat "$file")" || rc=1
	ck_naming_scan "commit message" "$(cat "$file")" || rc=1
	return $rc
}
