#!/usr/bin/env bash
# oom-fatal-bursts.sh: hunt for the PHP2Shell trigger signature
# (CVE-2026-109618 / CVE-2026-109619).
#
# Every exploitation attempt has to force an out-of-memory fatal while PHP
# parses a multipart request, so attempts leave
#   "Allowed memory size of N bytes exhausted (tried to allocate M bytes)"
# in PHP, PHP-FPM or Apache error logs. One such line is ordinary; a burst of
# them, lined up with multipart POSTs, is the signal.
#
# usage: oom-fatal-bursts.sh [LOG ...]
#   With no arguments it reads the usual Debian/Ubuntu/RHEL locations,
#   including rotated .gz files. Read-only.
# exit:  0 no matches, 1 matches found, 2 no readable log
set -u

logs=("$@")
if [ ${#logs[@]} -eq 0 ]; then
  for f in /var/log/php*-fpm.log* /var/log/php-fpm/*.log* /var/log/php*/*.log* \
           /var/log/apache2/error.log* /var/log/httpd/error_log* /var/log/nginx/error.log*; do
    [ -r "$f" ] && logs+=("$f")
  done
fi
[ ${#logs[@]} -gt 0 ] || { echo "no readable log found; pass the paths explicitly" >&2; exit 2; }

pat='Allowed memory size of [0-9]+ bytes exhausted'
read_log() { case "$1" in *.gz) zcat -f -- "$1" ;; *) cat -- "$1" ;; esac 2>/dev/null; }

hits=$(for f in "${logs[@]}"; do read_log "$f" | grep -E "$pat" | sed "s|^|${f##*/}: |"; done)
if [ -z "$hits" ]; then
  echo "no OOM fatals in ${#logs[@]} log file(s)"
  exit 0
fi

n=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
echo "== $n OOM fatal line(s) in ${#logs[@]} log file(s)"
printf '%s\n' "$hits" | tail -n 20
echo
echo "== per minute (busiest first). Timestamps understood:"
echo "   [23-Oct-2026 07:43:12 ...] (PHP/FPM) and [Fri Oct 23 07:43:12.123 2026] (Apache)"
printf '%s\n' "$hits" \
  | grep -oE '\[[0-9]{2}-[A-Za-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}|\[[A-Za-z]{3} [A-Za-z]{3} [ 0-9][0-9] [0-9]{2}:[0-9]{2}' \
  | sed 's/^\[//' | sort | uniq -c | sort -rn | head -n 15
echo
echo "Next: correlate the busiest minutes with multipart POSTs in the access log,"
echo "and check child-crashes.sh for worker deaths in the same window."
exit 1
