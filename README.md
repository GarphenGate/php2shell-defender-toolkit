# PHP2Shell defender toolkit

Hunt queries, logging and audit scripts for **PHP2Shell** ([CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)) and the follow-up **CVE-2026-115560**, from GarphenGate Security Research.

The full write-up, with our lab evidence and the reasoning behind every check here, is on our blog:
**[PHP2Shell: A Defender's Field Guide](https://garphengate.com/blog/php2shell-defensive-guide)**.

> Patching is the only complete fix. Everything in this repository helps you find exposed hosts, sequence the work and spot attempts while you patch. None of it replaces the upgrade.

## Patch floors

| Branch | Fixed in | Note |
|---|---|---|
| 8.5 | **8.5.12** | `fatal_error_backtraces=0` is an interim for one CVE-2026-109619 path |
| 8.4 | **8.4.27** | the public one-click exploit targets 8.4.26 under mod_php |
| 8.3 | **8.3.36** | |
| 8.2 | **8.2.35** | the branch reaches end of life on 31 December 2026 |
| 8.1 and older | no official release | PHP published minimal source backports for 7.4, 8.0 and 8.1; otherwise vendor LTS or migrate |

Both CVEs are fixed in the same releases. Restart every PHP worker after upgrading: a patched binary on disk does not clear code or OPcache state that is already in memory. Distribution packages often carry the fix without changing the upstream version number, so check the package changelog for the CVE IDs.

CVE-2026-115560 (disclosed 23 October 2026) has no out-of-band release. It needs a specific session serialize-handler switch in application code; `session.upload_progress.enabled=0` in php.ini or the pool configuration fully covers it until PHP's next regular release.

## What is here

| Path | What it does | CVEs |
|---|---|---|
| [`audit/php-exposure-check.sh`](audit/php-exposure-check.sh) | Version against the floors, mod_php or FPM, and the settings that decide triage order | 109618, 109619, 115560 |
| [`audit/cve-2026-115560-audit.sh`](audit/cve-2026-115560-audit.sh) | Checks an application for the runtime serialize-handler switch, the configured baseline and upload progress | 115560 |
| [`hunt/oom-fatal-bursts.sh`](hunt/oom-fatal-bursts.sh) | Bursts of "Allowed memory size … exhausted" fatals, the trigger every attempt leaves | 109618, 109619 |
| [`hunt/child-crashes.sh`](hunt/child-crashes.sh) | Apache and PHP-FPM workers dying by SIGABRT or SIGSEGV; FPM "exited with code 70" recycles reported separately | 109618, 109619 |
| [`hunt/phpsessid-anomalies.sh`](hunt/phpsessid-anomalies.sh) | `PHPSESSID` response cookies that cannot be a real session ID: the memory-disclosure fingerprint | 109618, 109619 |
| [`nginx/php2shell-setcookie-logging.conf`](nginx/php2shell-setcookie-logging.conf) | Temporary nginx logging of the `Set-Cookie` response header, which default access logs leave out | 109618, 109619 |
| [`docs/hardening-checklist.md`](docs/hardening-checklist.md) | Interim hardening while patching waits | all three |

Every script is read-only, needs only bash, grep, awk and gzip, and prints what it found. Exit codes: `0` nothing found, `1` findings, `2` usage error.

## Quick start

```bash
git clone https://github.com/GarphenGate/php2shell-defender-toolkit.git
cd php2shell-defender-toolkit
bash tests/run-tests.sh                      # self-test on synthetic data

# 1. Where does this host sit?
bash audit/php-exposure-check.sh             # or pass binaries: php8.3 php-fpm8.3

# 2. Hunt backwards: attacks began before the 21 October release
bash hunt/oom-fatal-bursts.sh                # default log locations, rotated .gz included
bash hunt/child-crashes.sh

# 3. CVE-2026-115560: one hour per application
bash audit/cve-2026-115560-audit.sh /var/www/app php-fpm8.3
```

For the cookie hunt, add the temporary nginx format first (it writes session IDs to disk, so restrict the file and remove it afterwards), let traffic run, then:

```bash
bash hunt/phpsessid-anomalies.sh /var/log/nginx/php2shell.log
bash hunt/phpsessid-anomalies.sh -l 32 /var/log/nginx/php2shell.log   # your own baseline
```

Run each hunt on a known-clean period first. A real session ID is 32 characters with PHP's default settings and 26 on servers that kept the `php.ini-production` values shipped up to PHP 8.3; custom `session.sid_length` or `session.sid_bits_per_character=6` need their own baseline (`-l`).

## Reading the results

- **OOM fatal bursts** lined up with multipart POSTs are the trigger signature. One fatal on its own is ordinary.
- **Signal deaths** (SIGABRT, SIGSEGV) on POST-heavy endpoints are worth an investigation. On a patched PHP-FPM build, a fatal ends in a controlled `exited with code 70` recycle instead.
- **Anomalous `PHPSESSID` values** (wrong length, `%XX` encoding, unexpected bytes) are a strong unpatched-or-bypassed signal: on the patched hosts in our lab, the same requests produced clean, fresh session IDs every time.
- A quiet result on one host says that these signals are absent on that host, in those logs. It does not prove the host cannot be exploited; exploitability depends on version, SAPI, ini settings, loaded extensions and how the application handles requests.

## Sources

- PHP security advisory and release announcements, 21 October 2026: <https://www.php.net/archive/2026.php#2026-10-21-5>
- PHP informational advisory on CVE-2026-115560, 23 October 2026: <https://www.php.net/archive/2026.php#2026-10-23-1>
- NVD: [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/cve-2026-109618), [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/cve-2026-109619)
- CERT-EU advisory 2026-018: <https://cert.europa.eu/publications/security-advisories/2026-018>
- NCSC-NL inventory of affected products: <https://github.com/NCSC-NL/php2shell>

## Contributing and contact

Found a log format the hunts miss, or a false positive? Open an issue or a pull request with a redacted sample line. For an active incident, contact GarphenGate through <https://garphengate.com>.

## Licence

MIT, see [LICENSE](LICENSE). Provided as is, without warranty: test in a non-production environment first.
