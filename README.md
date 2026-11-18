# php2shell-check

A read-only shell script that tells you, on the server itself, whether a PHP host is still exposed to **PHP2Shell** (CVE-2026-109618, CVE-2026-109619), the two PHP core RCEs fixed on 21 October 2026 and listed in CISA's Known Exploited Vulnerabilities catalog on 26 October.

It automates the five-minute check from this guide: [PHP2Shell: how to tell in five minutes if your PHP site is still exposed](https://javiermorales.tech/blog/php2shell-check-in-five-minutes/) ([en español](https://javiermorales.tech/es/blog/php2shell-check-in-five-minutes/)).

## What it checks

1. **The PHP builds that serve the website**, not just the CLI: PHP-FPM, Apache mod_php, php-cgi, LiteSpeed `lsphp` and FrankenPHP. Each version is compared with the fixed releases (8.2.35, 8.3.36, 8.4.27, 8.5.12). Branches 8.1 and older are flagged as out of support.
2. **Distribution backports.** Debian, Ubuntu and RHEL-family packages often keep an old version number with the fix backported. For packaged PHP below the fixed release, the script looks for both CVEs in the package changelog (local file first, then `apt-get changelog` or `rpm -q --changelog`).
3. **The SAPI.** Whether Apache loads mod_php, the highest-risk case.
4. **`session.upload_progress.enabled`.** PHP's 23 October advisory (CVE-2026-115560) recommends keeping it at 0 even after updating. The script reads the value each SAPI actually loads (`php-fpm -i`, or the SAPI's own `php.ini` and `conf.d`) and lists pool or vhost overrides.

## What it does not do

It sends no requests, runs no exploit and changes nothing. It does not look for signs of intrusion: if a host was exposed after 17 October, follow the CISA and FBI guidance linked in the article.

## Usage

```bash
curl -fsSLO https://raw.githubusercontent.com/JAvito-GC/php2shell-check/main/php2shell-check.sh
less php2shell-check.sh          # read it first: it is short
sudo bash php2shell-check.sh     # root is optional; it only helps read configs
```

Needs bash 4+ and the usual base tools (`grep`, `awk`, `zcat`). Run it inside the container or VM that actually serves PHP.

Exit codes, for cron or CI:

| Code | Meaning |
|---|---|
| 0 | No exposed PHP build and nothing to act on |
| 1 | A PHP build is exposed or likely exposed |
| 2 | No exposed build, but an action is recommended (for example `session.upload_progress.enabled` is on) or something could not be checked |

A missing CVE in a changelog is reported as "likely exposed": not every changelog names every CVE, so confirm with your distribution's security tracker before concluding.

## Tested on

`tests/run-docker.sh` runs it in throwaway containers: upstream `php:8.2.34-fpm`, `php:8.2.35-apache`, `php:8.1-apache`, Ubuntu 24.04 and 22.04, Debian 12, Rocky Linux 9, an FPM pool override and a host with no PHP.

## Sources

- [php.net, 21 October 2026 release announcement](https://www.php.net/archive/2026.php#2026-10-21-5) and [23 October advisory](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [NVD CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618), [NVD CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)
- [CISA alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)

## License

MIT. Use at your own risk; it is a helper, not an audit.
