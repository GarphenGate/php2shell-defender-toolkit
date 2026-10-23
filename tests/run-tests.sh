#!/usr/bin/env bash
# Self-test with synthetic logs and stub PHP binaries. Needs only bash, awk,
# grep and gzip; touches nothing outside a temporary directory.
#   bash tests/run-tests.sh
set -u
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail=0
expect() {  # expect NAME WANT_EXIT GREP_PATTERN -- command...
  local name="$1" want="$2" pat="$3"; shift 4
  local out rc; out=$("$@" 2>&1); rc=$?
  if [ "$rc" -ne "$want" ] || ! printf '%s\n' "$out" | grep -qE -- "$pat"; then
    echo "FAIL $name (exit $rc, want $want; pattern '$pat')"; printf '%s\n' "$out" | sed 's/^/     /'; fail=1
  else
    echo "ok   $name"
  fi
}

# --- logs
cat >"$tmp/php8.3-fpm.log" <<'EOF'
[23-Oct-2026 07:43:12] WARNING: [pool www] child 4242 said into stderr: "PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 2097160 bytes) in Unknown on line 0"
[23-Oct-2026 07:43:13] WARNING: [pool www] child 4243 said into stderr: "PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 2097160 bytes) in Unknown on line 0"
[23-Oct-2026 07:43:13] WARNING: [pool www] child 4243 exited with code 70 after 1.2 seconds from start
[23-Oct-2026 07:44:02] WARNING: [pool www] child 4250 exited on signal 11 (SIGSEGV) after 3.1 seconds from start
EOF
cat >"$tmp/error.log" <<'EOF'
[Fri Oct 23 07:43:12.123456 2026] [php:error] [pid 900] PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
[Fri Oct 23 07:43:14.000001 2026] [core:notice] [pid 100] AH00052: child pid 900 exit signal Segmentation fault (11)
EOF
gzip -c "$tmp/error.log" >"$tmp/error.log.1.gz"
printf '%s\n' '[23-Oct-2026 08:00:00] NOTICE: ready to handle connections' >"$tmp/clean.log"
cat >"$tmp/php2shell.log" <<'EOF'
203.0.113.5 [23/Oct/2026:07:43:12 +0000] "GET / HTTP/1.1" 200 "PHPSESSID=0123456789abcdefghijklmnopqrstuv; path=/"
203.0.113.5 [23/Oct/2026:07:43:13 +0000] "GET /index.php HTTP/1.1" 200 "PHPSESSID=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHH; path=/"
203.0.113.6 [23/Oct/2026:07:43:14 +0000] "GET /x HTTP/1.1" 200 "PHPSESSID=%01%02%03%04leaked%00bytes; path=/"
203.0.113.7 [23/Oct/2026:07:43:15 +0000] "GET /y HTTP/1.1" 200 "-"
EOF

expect "oom: finds bursts in FPM + Apache (+.gz)" 1 '07:43' -- bash "$here/hunt/oom-fatal-bursts.sh" "$tmp/php8.3-fpm.log" "$tmp/error.log.1.gz"
expect "oom: clean log is quiet" 0 'no OOM fatals' -- bash "$here/hunt/oom-fatal-bursts.sh" "$tmp/clean.log"
expect "crashes: signal deaths found" 1 'exit signal Segmentation fault' -- bash "$here/hunt/child-crashes.sh" "$tmp/error.log" "$tmp/php8.3-fpm.log"
expect "crashes: code-70 recycle reported as expected" 1 "exited with code 70" -- bash "$here/hunt/child-crashes.sh" "$tmp/php8.3-fpm.log"
expect "crashes: clean log is quiet" 0 'no signal deaths' -- bash "$here/hunt/child-crashes.sh" "$tmp/clean.log"
expect "sessid: flags the 31-byte marker" 1 'length 31' -- bash "$here/hunt/phpsessid-anomalies.sh" "$tmp/php2shell.log"
expect "sessid: flags percent-encoding" 1 'percent-encoded' -- bash "$here/hunt/phpsessid-anomalies.sh" "$tmp/php2shell.log"
expect "sessid: real 32-char ID not flagged" 0 'no anomalous' -- bash "$here/hunt/phpsessid-anomalies.sh" <(head -n 1 "$tmp/php2shell.log")
expect "sessid: custom baseline" 0 'no anomalous' -- bash "$here/hunt/phpsessid-anomalies.sh" -l 31,32 <(head -n 2 "$tmp/php2shell.log")

# --- stub PHP binaries
mkstub() {  # mkstub NAME VERSION HANDLER PROGRESS
  cat >"$tmp/$1" <<EOF
#!/usr/bin/env bash
case "\${1:-}" in
  -v) echo "PHP $2 (cli) (built: Oct 21 2026 14:00:00) (NTS)" ;;
  -i) printf '%s\n' "PHP Version => $2" "memory_limit => 128M => 128M" "post_max_size => 8M => 8M" \\
        "session.serialize_handler => $3 => $3" "session.upload_progress.enabled => $4 => $4" ;;
esac
EOF
  chmod +x "$tmp/$1"
}
mkstub php-old 8.3.35 php On
mkstub php-new 8.3.36 php On
mkstub php-81 8.1.31 php Off
mkstub php-binary 8.3.36 php_binary On
expect "exposure: 8.3.35 below the floor" 1 'below the floor 8.3.36' -- bash "$here/audit/php-exposure-check.sh" "$tmp/php-old"
expect "exposure: 8.3.36 at the floor" 0 'at or above the floor' -- bash "$here/audit/php-exposure-check.sh" "$tmp/php-new"
expect "exposure: 8.1 has no official release" 1 'no official fixed release' -- bash "$here/audit/php-exposure-check.sh" "$tmp/php-81"

mkdir -p "$tmp/app/src" "$tmp/app2"
cat >"$tmp/app/src/session.php" <<'EOF'
<?php
ini_set('session.serialize_handler', 'php');
session_start();
EOF
printf '%s\n' '<?php session_start();' >"$tmp/app2/index.php"
expect "115560: exposed pattern" 1 'EXPOSED: baseline php_binary' -- bash "$here/audit/cve-2026-115560-audit.sh" "$tmp/app" "$tmp/php-binary"
expect "115560: no runtime switch" 0 'NOT EXPOSED' -- bash "$here/audit/cve-2026-115560-audit.sh" "$tmp/app2" "$tmp/php-binary"
expect "115560: upload progress off" 0 'upload progress is off' -- bash "$here/audit/cve-2026-115560-audit.sh" "$tmp/app" "$tmp/php-81"
expect "115560: switch but default baseline -> review" 1 'REVIEW' -- bash "$here/audit/cve-2026-115560-audit.sh" "$tmp/app" "$tmp/php-new"

[ $fail -eq 0 ] && echo "all tests passed" || { echo "SOME TESTS FAILED"; exit 1; }
