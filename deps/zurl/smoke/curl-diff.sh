#!/usr/bin/env bash
#
# The differential oracle: the same request through curl and through zurl,
# and one answer.
#
# This is rule 4's discipline one level up. The fuzz oracle says a parse must
# not depend on how the transport split the bytes; this says a REQUEST must
# not depend on which client sent it. curl is what everyone else is measured
# against, so a disagreement is a finding either way — and `zig build
# tls-smoke` already proved the idea by matching curl byte for byte on one
# URL. This generalises that to a corpus.
#
# A live gate, deliberately not part of `zig build test`: it needs a network
# and a real origin, and a unit test that fails when DNS is down is a gate
# people learn to ignore.
#
# WHAT IS COMPARED, and what is not:
#
#   compared      the response body, byte for byte
#                 the status code, via -w
#                 the process exit code
#                 individual header values a caller acts on
#
#   not compared  response header BYTES. zurl reconstructs the head from
#                 parsed name/value pairs, so it has no status line and no
#                 original casing or ordering to reproduce. Demanding byte
#                 identity there would test the reconstruction, not the
#                 client.
#
#                 timings. Two clients differ there by construction, so a
#                 comparison could only ever produce false failures.

set -u

zurl_bin="${1:?usage: curl-diff.sh <path-to-zurl> [base-url]}"
base="${2:-https://example.com}"

command -v curl >/dev/null || { echo "curl-diff: curl not on PATH"; exit 2; }
[ -x "$zurl_bin" ] || { echo "curl-diff: no zurl binary at $zurl_bin"; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

passed=0
failed=0

# Run one flag set through both and compare body, status and exit code.
#
# Arguments go to BOTH verbatim, which is the point: a flag zurl spells
# differently is a difference the oracle should surface, not one the harness
# should paper over.
check() {
  local name="$1"; shift

  # REMOVED, not truncated. Whether a client creates the output file at all is
  # itself a difference — `-f` makes curl leave it absent where zurl once made
  # it empty, which is a defect this oracle found. Pre-creating both files
  # would erase exactly that signal while still fixing the stale-body problem,
  # so existence is compared instead of assumed.
  rm -f "$work/curl.body" "$work/zurl.body"

  curl -s -o "$work/curl.body" -w '%{http_code}' "$@" > "$work/curl.code" 2>/dev/null
  local curl_exit=$?
  "$zurl_bin" -s -o "$work/zurl.body" -w '%{http_code}' "$@" > "$work/zurl.code" 2>/dev/null
  local zurl_exit=$?

  local problems=""
  local curl_code zurl_code
  curl_code=$(cat "$work/curl.code")
  zurl_code=$(cat "$work/zurl.code")

  if [ "$curl_exit" != "$zurl_exit" ]; then
    problems="$problems exit(curl=$curl_exit zurl=$zurl_exit)"
  fi
  if [ "$curl_code" != "$zurl_code" ]; then
    problems="$problems status(curl=$curl_code zurl=$zurl_code)"
  fi

  local curl_has=no zurl_has=no
  [ -e "$work/curl.body" ] && curl_has=yes
  [ -e "$work/zurl.body" ] && zurl_has=yes
  if [ "$curl_has" != "$zurl_has" ]; then
    problems="$problems output-file(curl=$curl_has zurl=$zurl_has)"
  elif [ "$curl_has" = yes ] && ! cmp -s "$work/curl.body" "$work/zurl.body"; then
    problems="$problems body($(wc -c <"$work/curl.body") vs $(wc -c <"$work/zurl.body") bytes)"
  fi

  if [ -z "$problems" ]; then
    printf '  ok   %s\n' "$name"
    passed=$((passed + 1))
  else
    printf '  FAIL %s —%s\n' "$name" "$problems"
    printf '       args: %s\n' "$*"
    failed=$((failed + 1))
  fi
}

# Status and exit only, for cases whose OUTPUT is the reconstructed head
# rather than a body: `-I` writes headers to `-o`, and those bytes are not
# comparable for the reason at the top of this file.
check_status() {
  local name="$1"; shift

  curl -s -o /dev/null -w '%{http_code}' "$@" > "$work/curl.code" 2>/dev/null
  local curl_exit=$?
  "$zurl_bin" -s -o /dev/null -w '%{http_code}' "$@" > "$work/zurl.code" 2>/dev/null
  local zurl_exit=$?

  local curl_code zurl_code
  curl_code=$(cat "$work/curl.code")
  zurl_code=$(cat "$work/zurl.code")

  if [ "$curl_exit" = "$zurl_exit" ] && [ "$curl_code" = "$zurl_code" ]; then
    printf '  ok   %s (status %s)\n' "$name" "$curl_code"
    passed=$((passed + 1))
  else
    printf '  FAIL %s — curl=%s/%s zurl=%s/%s\n' \
      "$name" "$curl_code" "$curl_exit" "$zurl_code" "$zurl_exit"
    failed=$((failed + 1))
  fi
}

# One header's VALUE, since the head's bytes are not comparable.
#
# An EMPTY value from both is not agreement, it is two failures agreeing to
# say nothing — no network, DNS down, a bad flag. Comparing only the values
# would print `ok` for that, so a header this asks about must actually be
# present, and both clients must have exited zero.
check_header() {
  local name="$1" header="$2"; shift 2

  rm -f "$work/zurl.head"

  local curl_value zurl_value curl_exit zurl_exit
  curl_value=$(curl -s -o /dev/null -D - "$@" 2>/dev/null |
    grep -i "^$header:" | head -1 | cut -d: -f2- | tr -d ' \r')
  curl_exit=$?
  "$zurl_bin" -s -o /dev/null -D "$work/zurl.head" "$@" >/dev/null 2>&1
  zurl_exit=$?
  zurl_value=$(grep -i "^$header:" "$work/zurl.head" 2>/dev/null |
    head -1 | cut -d: -f2- | tr -d ' \r')

  if [ "$curl_exit" != 0 ] || [ "$zurl_exit" != 0 ]; then
    printf '  FAIL %s — a client failed (curl=%s zurl=%s), not a comparison\n' \
      "$name" "$curl_exit" "$zurl_exit"
    failed=$((failed + 1))
  elif [ -z "$curl_value" ]; then
    printf '  FAIL %s — curl reported no %s, so there is nothing to compare\n' "$name" "$header"
    failed=$((failed + 1))
  elif [ "$curl_value" = "$zurl_value" ]; then
    printf '  ok   %s (%s: %s)\n' "$name" "$header" "$curl_value"
    passed=$((passed + 1))
  else
    printf '  FAIL %s — %s: curl=[%s] zurl=[%s]\n' "$name" "$header" "$curl_value" "$zurl_value"
    failed=$((failed + 1))
  fi
}

http_base=$(printf '%s' "$base" | sed 's|^https|http|')
missing="$base/nonexistent-$$"

echo "curl-diff: $(curl --version | head -1)"
echo "curl-diff: base $base"
echo

check        "GET https"              "$base/"
check        "GET http"               "$http_base/"
check_status "HEAD via -I"            -I "$base/"
check        "HEAD via -X"            -X HEAD "$base/"
check        "404 body"               "$missing"
check        "404 with -f"            -f "$missing"
check        "custom request header"  -H 'X-Diff: 1' "$base/"
check        "custom user-agent"      -A 'curl-diff/1' "$base/"
check        "redirects followed"     -L "$base/"
check        "max-time generous"      --max-time 30 "$base/"
check        "basic auth accepted"    -u 'user:pass' "$base/"
# `--max-time 0` means "no timeout" to curl and the largest bound here, which
# is the same observable answer against a responsive origin.
#
# Two cases the reviewer named are NOT here, and their absence is deliberate:
#
#   -X get   curl sends the method verbatim, so a strict origin answers 400.
#            zurl cannot express a non-canonical method at all -- its request
#            type is an enum -- so it refuses with a usage error. A permanent
#            disagreement is not a test, it is a known limitation, and
#            docs/SCOPE.md carries it.
#
#   -o -     this harness supplies its own `-o` to capture the body, so a
#            case adding a second one tests argument precedence rather than
#            either client. Covered by a parser test instead.
check        "--max-time 0"           --max-time 0 "$base/"

check_header "content-type"          content-type "$base/"
check_header "server"                server "$base/"

echo
if [ "$failed" -eq 0 ]; then
  echo "curl-diff: $passed/$passed agree"
  exit 0
fi
echo "curl-diff: $failed of $((passed + failed)) DISAGREE"
exit 1
