# Interim hardening for PHP2Shell and CVE-2026-115560

PHP's own framing applies to every item below: interim measures reduce exposure to specific attack paths but do not make an installation safe. Upgrade to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or a vendor backport) and restart every worker. The full reasoning is in the [field guide](https://garphengate.com/blog/php2shell-defensive-guide).

## Do first

- [ ] **Turn off `session.upload_progress.enabled` where you don't use it.** Set it in `php.ini`, the FPM pool or the server configuration, not with `ini_set()` or `.user.ini`, then restart every worker. It blocks the confirmed session paths of CVE-2026-109618/109619 (not every variant) and fully covers CVE-2026-115560. PHP asks for it to stay off until its next regular release.
- [ ] **Restart workers after any change**, and again after patching, so OPcache and shared state are rebuilt.
- [ ] **On PHP 8.5, set `fatal_error_backtraces=0`** as an interim for one CVE-2026-109619 path.

## Shrink the multipart surface

- [ ] `post_max_size=8M` for applications without uploads, `32M` where uploads are required (PHP's guidance).
- [ ] At the proxy, limit decoded body size, part count, field count and nesting depth, including for requests without a usable `Content-Length` (chunked and HTTP/2 requests can hide their size).
- [ ] At the WAF, block or alert on multipart bodies that carry `PHP_SESSION_UPLOAD_PROGRESS` to endpoints that don't use upload progress, hundreds of same-name array fields, empty `filename=""` parts in bulk, or deeply nested field names. Start in log mode if you serve legitimate large multipart traffic, then switch to block.

## Memory limits

- [ ] Know each host's `memory_limit`. The public trigger is calibrated to a finite, reachable limit, which makes it a triage signal, not a shield.
- [ ] PHP's interim is `memory_limit=-1`, set so applications can't override it. An underlying allocation failure can still reach the vulnerable path.
- [ ] Do not substitute `RLIMIT_AS` or `RLIMIT_DATA`: they can force the allocation failures that trigger the bug.

## Workers

- [ ] PHP-FPM: a finite `pm.max_requests` shortens the window in which the same worker serves a fatal request and the follow-up the stale-state bugs need. It delays chaining; it does not prevent it.
- [ ] Prefork / mod_php: schedule graceful restarts until patched. mod_php is the highest-risk SAPI.

## CVE-2026-115560

- [ ] Run `audit/cve-2026-115560-audit.sh` on each application. Exposure needs all three: a `php_binary` or `php_serialize` baseline, code that switches to `php` with `ini_set()` before `session_start()`, and upload progress on.
- [ ] Don't switch serialize handlers at runtime. If legacy session data forces it, migrate the data instead.

## Telemetry while you patch

- [ ] Forward PHP/FPM/Apache error logs and alert on bursts of "Allowed memory size … exhausted".
- [ ] Alert on worker deaths by SIGABRT or SIGSEGV.
- [ ] Log `Set-Cookie` at the proxy for the hunt window only (`nginx/php2shell-setcookie-logging.conf`), then remove it.
- [ ] Hunt backwards at least two weeks: attacks were seen before the 21 October release.

Label everything here as temporary in your change record, except `session.upload_progress.enabled=0`, which PHP wants kept until its next regular release.
