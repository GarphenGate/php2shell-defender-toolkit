#!/usr/bin/env bash
# php-exposure-check.sh: where does this host sit for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619) and CVE-2026-115560?
#
# For each PHP binary it reports the version against the fixed floors
# (8.5.12, 8.4.27, 8.3.36, 8.2.35; 8.1 and older have no official release),
# whether Apache loads mod_php (the worst case), and the settings that decide
# triage order: session.upload_progress.enabled, memory_limit, post_max_size,
# session.serialize_handler and fatal_error_backtraces.
#
# It ranks; it does not clear anyone. A host that looks hard to reach is still
# unpatched, and the only complete fix is the upgrade plus a worker restart.
#
# usage: php-exposure-check.sh [PHP_BINARY ...]
#   default: php plus every php-fpm* binary on PATH and in /usr/sbin
# Read-only. exit: 0 all at or above their floor, 1 something below a floor
#            or without an official fix, 2 no PHP binary found
set -u

bins=("$@")
if [ ${#bins[@]} -eq 0 ]; then
  command -v php >/dev/null 2>&1 && bins+=("$(command -v php)")
  for b in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* $(compgen -c php-fpm 2>/dev/null | sort -u); do
    p=$(command -v "$b" 2>/dev/null) || continue
    case " ${bins[*]} " in *" $p "*) ;; *) bins+=("$p") ;; esac
  done
fi
[ ${#bins[@]} -gt 0 ] || { echo "no PHP binary found; pass one explicitly" >&2; exit 2; }

mod_php="no"
if ls /etc/apache2/mods-enabled/php*.load >/dev/null 2>&1 \
   || { command -v apache2ctl >/dev/null 2>&1 && apache2ctl -M 2>/dev/null | grep -qiE 'php[0-9_]*_module'; } \
   || { command -v httpd >/dev/null 2>&1 && httpd -M 2>/dev/null | grep -qiE 'php[0-9_]*_module'; }; then
  mod_php="yes"
fi
echo "Apache mod_php loaded: $mod_php"

worst=0
for bin in "${bins[@]}"; do
  ver=$("$bin" -v 2>/dev/null | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
  [ -n "$ver" ] || { echo; echo "== $bin: could not read a version"; continue; }
  info=$("$bin" -i 2>/dev/null)
  ini() { printf '%s\n' "$info" | awk -F' => ' -v k="$1" '$1 == k {print $2; exit}'; }
  IFS=. read -r maj min pat <<<"$ver"
  case "$maj.$min" in
    8.5) floor=12 ;; 8.4) floor=27 ;; 8.3) floor=36 ;; 8.2) floor=35 ;;
    *) floor="" ;;
  esac
  progress=$(ini session.upload_progress.enabled)
  echo
  echo "== $bin  (PHP $ver)"
  echo "   session.upload_progress.enabled = ${progress:-unknown}"
  echo "   memory_limit                    = $(ini memory_limit)"
  echo "   post_max_size                   = $(ini post_max_size)"
  echo "   session.serialize_handler       = $(ini session.serialize_handler)"
  fb=$(ini fatal_error_backtraces); [ -n "$fb" ] && echo "   fatal_error_backtraces          = $fb"

  if [ -z "$floor" ]; then
    if [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -le 1 ]; }; then
      echo "   VERDICT: no official fixed release for $maj.$min. Apply a vendor/LTS backport or migrate."
      worst=1
    else
      echo "   VERDICT: $maj.$min is not a branch this script knows; check the vendor advisory."
    fi
    continue
  fi
  if [ "$pat" -ge "$floor" ]; then
    echo "   VERDICT: at or above the floor $maj.$min.$floor for CVE-2026-109618/109619."
    echo "            Restart every worker if that has not happened since the upgrade."
  else
    worst=1
    if [ "$mod_php" = "yes" ] && [ "${progress:-On}" != "Off" ]; then
      echo "   VERDICT: below the floor $maj.$min.$floor, mod_php, upload progress on: patch first."
    elif [ "${progress:-On}" != "Off" ]; then
      echo "   VERDICT: below the floor $maj.$min.$floor with upload progress on: patch next."
    else
      echo "   VERDICT: below the floor $maj.$min.$floor. Upload progress is off, which blocks the"
      echo "            confirmed session paths only; patch."
    fi
    echo "            Distribution packages can carry the fix without a version bump: check the"
    echo "            package changelog (apt changelog / rpm -q --changelog) for CVE-2026-109618."
  fi
  case "$progress" in
    Off|off|0) ;;
    *) echo "   CVE-2026-115560: upload progress is on; run cve-2026-115560-audit.sh on the apps this binary serves." ;;
  esac
done
exit $worst
