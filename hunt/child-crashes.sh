#!/usr/bin/env bash
# child-crashes.sh: PHP worker deaths and exits that PHP2Shell attempts leave
# behind (CVE-2026-109618 / CVE-2026-109619).
#
#   Apache (mod_php):  "child pid N exit signal Aborted (6)" or
#                      "child pid N exit signal Segmentation fault (11)"
#   PHP-FPM:           "child N exited on signal 6|11 (SIGABRT|SIGSEGV)"
#
# A burst of signal deaths on POST-heavy endpoints is worth an investigation.
#
# PHP-FPM exits are printed separately, and they are NOT a patch indicator:
#   "exited with code 70"   PHP-FPM ends a worker with code 70 whenever request
#                           startup fails (FPM_EXIT_SOFTWARE), on patched and
#                           unpatched builds alike. A burst lined up with
#                           multipart POSTs is an attempt signal.
#   "exited with code 137"  patched builds only: the new hard memory limit ends
#                           the worker with _exit(137). With catch_workers_output
#                           the worker also logs "Hard memory limit of N bytes
#                           exhausted" (see oom-fatal-bursts.sh).
# Confirm patch status from the PHP version or package changelog, not exit codes.
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
code70=$(grab 'exited with code 70\b')
code137=$(grab 'exited with code 137\b')

if [ -n "$code70" ]; then
  echo "== $(printf '%s\n' "$code70" | wc -l | tr -d ' ') FPM 'exited with code 70' exit(s): request startup failed (patched or not)"
  printf '%s\n' "$code70" | tail -n 5
  echo
fi
if [ -n "$code137" ]; then
  echo "== $(printf '%s\n' "$code137" | wc -l | tr -d ' ') FPM 'exited with code 137' exit(s): hard memory limit (patched builds)"
  printf '%s\n' "$code137" | tail -n 5
  echo
fi
if [ -z "$deaths" ]; then
  echo "no signal deaths (SIGABRT/SIGSEGV) in ${#logs[@]} log file(s)"
  exit 0
fi
echo "== $(printf '%s\n' "$deaths" | wc -l | tr -d ' ') worker death(s) by signal"
printf '%s\n' "$deaths" | tail -n 30
exit 1
