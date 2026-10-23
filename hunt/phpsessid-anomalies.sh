#!/usr/bin/env bash
# phpsessid-anomalies.sh: find PHPSESSID response cookies that cannot be a
# real session ID (the PHP2Shell memory-disclosure fingerprint,
# CVE-2026-109618 / CVE-2026-109619).
#
# The disclosure variant makes PHP URL-encode whatever sits in a freed heap
# slot into the next response's PHPSESSID cookie. A real session ID has a
# fixed length and a fixed alphabet; a leaked one usually has the wrong
# length, percent-encoding (%XX never appears in a real ID) or other bytes.
#
# Input: a log that records the Set-Cookie response header, for example the
# temporary nginx format in ../nginx/php2shell-setcookie-logging.conf.
# Default access logs do NOT contain response headers.
#
# usage: phpsessid-anomalies.sh [-l LENGTHS] LOG [LOG ...]
#   -l  comma-separated session-ID lengths your servers issue (default 26,32;
#       32 is PHP's default, 26 the php.ini-production value up to PHP 8.3).
#       Run it on a known-clean day first and adjust until it is quiet.
# Read-only. exit: 0 nothing anomalous, 1 anomalies printed, 2 usage error
set -u

lengths="26,32"
while getopts "l:" o; do
  case "$o" in
    l) lengths="$OPTARG" ;;
    *) echo "usage: $0 [-l 26,32] LOG [LOG ...]" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -gt 0 ] || { echo "usage: $0 [-l 26,32] LOG [LOG ...]" >&2; exit 2; }
case "$lengths" in *[!0-9,]*|"") echo "-l takes numbers separated by commas" >&2; exit 2 ;; esac

out=$(for f in "$@"; do
  case "$f" in *.gz) zcat -f -- "$f" ;; *) cat -- "$f" ;; esac 2>/dev/null
done | awk -v lens="$lengths" '
  BEGIN { n = split(lens, L, ","); for (i = 1; i <= n; i++) ok[L[i]] = 1 }
  /PHPSESSID=/ {
    rest = $0
    while ((p = index(rest, "PHPSESSID=")) > 0) {
      rest = substr(rest, p + 10)
      v = rest
      sub(/[;" \t].*$/, "", v)            # value ends at ; quote or whitespace
      why = ""
      if (!(length(v) in ok))       why = why "length " length(v) " "
      if (v ~ /%/)                  why = why "percent-encoded "
      if (v !~ /^[A-Za-z0-9,-]*$/)  why = why "unexpected characters "
      if (why != "") { print "[" why "] " $0; break }
    }
  }')

if [ -z "$out" ]; then
  echo "no anomalous PHPSESSID values (allowed lengths: $lengths)"
  exit 0
fi
echo "== $(printf '%s\n' "$out" | wc -l | tr -d ' ') suspicious response(s); correlate each with the multipart POST just before it"
printf '%s\n' "$out"
exit 1
