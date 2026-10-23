#!/usr/bin/env bash
# child-crashes.sh: PHP worker deaths that PHP2Shell attempts leave behind
# (CVE-2026-109618 / CVE-2026-109619).
#
#   Apache (mod_php):  "child pid N exit signal Aborted (6)" or
#                      "child pid N exit signal Segmentation fault (11)"
#   PHP-FPM:           "child N exited on signal 6|11 (SIGABRT|SIGSEGV)"
#
# A burst of signal deaths on POST-heavy endpoints is worth an investigation.
# PHP-FPM "exited with code 70" lines are printed separately: on a patched
# build that is the controlled recycle after a fatal, i.e. the fix working.
#
# usage: child-crashes.sh [LOG ...]   (default: usual Apache and PHP-FPM logs; .gz included)
# Read-only. exit: 0 no signal deaths, 1 signal deaths found, 2 no readable log
set -u

logs=("$@")
if [ ${#logs[@]} -eq 0 ]; then
  for f in /var/log/apache2/error.log* /var/log/httpd/error_log* \
           /var/log/php*-fpm.log* /var/log/php-fpm/*.log*; do
    [ -r "$f" ] && logs+=("$f")
  done
fi
[ ${#logs[@]} -gt 0 ] || { echo "no readable log found; pass the paths explicitly" >&2; exit 2; }

read_log() { case "$1" in *.gz) zcat -f -- "$1" ;; *) cat -- "$1" ;; esac 2>/dev/null; }
grab() { for f in "${logs[@]}"; do read_log "$f" | grep -E "$1" | sed "s|^|${f##*/}: |"; done; }

deaths=$(grab 'exit signal (Aborted|Segmentation fault)|exited on signal (6|11)\b')
recycles=$(grab 'exited with code 70')

if [ -n "$recycles" ]; then
  echo "== $(printf '%s\n' "$recycles" | wc -l | tr -d ' ') FPM 'exited with code 70' recycle(s): expected on patched builds after a fatal"
  printf '%s\n' "$recycles" | tail -n 5
  echo
fi
if [ -z "$deaths" ]; then
  echo "no signal deaths (SIGABRT/SIGSEGV) in ${#logs[@]} log file(s)"
  exit 0
fi
echo "== $(printf '%s\n' "$deaths" | wc -l | tr -d ' ') worker death(s) by signal"
printf '%s\n' "$deaths" | tail -n 30
exit 1
