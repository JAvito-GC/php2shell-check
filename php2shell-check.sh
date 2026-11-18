#!/usr/bin/env bash
# php2shell-check.sh: read-only check for PHP2Shell (CVE-2026-109618, CVE-2026-109619)
# and the related upload-progress vector (CVE-2026-115560).
#
# It reads versions, packages and configuration. It never sends a request,
# never runs an exploit and never changes anything.
#
# Usage:  sudo bash php2shell-check.sh        (root is optional; it only helps read configs)
# Exit:   0 nothing found, 1 a PHP build is exposed or likely exposed,
#         2 no exposed build, but an action is recommended or something could not be checked
#
# Guide: https://javiermorales.tech/blog/php2shell-check-in-five-minutes/
# License: MIT

set -uo pipefail
((BASH_VERSINFO[0] >= 4)) || { echo "Needs bash 4 or newer" >&2; exit 2; }

VERSION="1.0.0"
CVES=(CVE-2026-109618 CVE-2026-109619)
# First fixed upstream release per branch (php.net, 21 October 2026).
declare -A FIXED=([8.2]=35 [8.3]=36 [8.4]=27 [8.5]=12)

if [[ -t 1 ]]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else R='' G='' Y='' B='' N=''; fi
WORST=0   # 0 ok, 2 unknown, 1 exposed (1 wins over 2)
mark() { if [[ $1 -eq 1 ]]; then WORST=1; elif [[ $1 -eq 2 && $WORST -eq 0 ]]; then WORST=2; fi; }
ok()   { printf '  %s[OK]%s      %s\n' "$G" "$N" "$*"; }
bad()  { printf '  %s[EXPOSED]%s %s\n' "$R" "$N" "$*"; mark 1; }
warn() { printf '  %s[CHECK]%s   %s\n' "$Y" "$N" "$*"; mark 2; }
act()  { printf '  %s[ACTION]%s  %s\n' "$Y" "$N" "$*"; mark 2; }
info() { printf '            %s\n' "$*"; }
hdr()  { printf '\n%s%s%s\n' "$B" "$*" "$N"; }

case "${1:-}" in
  -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  -V|--version) echo "php2shell-check $VERSION"; exit 0 ;;
esac

# ---------- helpers ----------

# Upstream version (x.y.z) printed by a PHP binary, or empty.
bin_version() {
  local out
  out=$("$1" -v 2>/dev/null | head -1) || true
  [[ $out =~ ([0-9]+\.[0-9]+\.[0-9]+) ]] && echo "${BASH_REMATCH[1]}"
}

# Owning package of a file: "deb <pkg>" / "rpm <pkg>" / empty.
owner_pkg() {
  local f p
  f=$(readlink -f "$1" 2>/dev/null || echo "$1")
  if command -v dpkg-query >/dev/null 2>&1; then
    p=$(dpkg-query -S "$f" 2>/dev/null | head -1 | cut -d: -f1)
    [[ -n $p ]] && { echo "deb $p"; return; }
  fi
  if command -v rpm >/dev/null 2>&1; then
    p=$(rpm -qf "$f" 2>/dev/null) && [[ $p != *"not owned"* ]] && { echo "rpm $p"; return; }
  fi
}

# Package version string (full, with distro suffix).
pkg_version() {
  case $1 in
    deb) dpkg-query -W -f='${Version}' "$2" 2>/dev/null ;;
    rpm) rpm -q --qf '%{VERSION}-%{RELEASE}' "$2" 2>/dev/null ;;
  esac
}

# Does the package changelog mention both CVEs? prints "yes", "no" or "unknown".
changelog_has_fix() {
  local kind=$1 pkg=$2 log="" src f
  case $kind in
    deb)
      src=$(dpkg-query -W -f='${source:Package}' "$pkg" 2>/dev/null)
      for f in /usr/share/doc/"$pkg"/changelog.Debian.gz /usr/share/doc/"$src"/changelog.Debian.gz \
               /usr/share/doc/"${src:-none}"*/changelog.Debian.gz; do
        [[ -r $f ]] && { log=$(zcat "$f" 2>/dev/null); break; }
      done
      # Fallback: apt downloads the changelog (read-only, needs network).
      [[ -z $log ]] && command -v apt-get >/dev/null 2>&1 && log=$(timeout 30 apt-get changelog "$pkg" 2>/dev/null)
      ;;
    rpm) log=$(rpm -q --changelog "$pkg" 2>/dev/null) ;;
  esac
  [[ -z $log ]] && { echo unknown; return; }
  local c
  for c in "${CVES[@]}"; do grep -q "$c" <<<"$log" || { echo no; return; }; done
  echo yes
}

# Verdict for one PHP build. Args: label, upstream version, binary path (optional).
judge() {
  local label=$1 ver=$2 path=${3:-} branch patch fixed pk kind pkg pver cl
  branch=${ver%.*}; patch=${ver##*.}
  fixed=${FIXED[$branch]:-}
  pk=$( [[ -n $path ]] && owner_pkg "$path" )
  if [[ -n $pk ]]; then
    read -r kind pkg <<<"$pk"; pver=$(pkg_version "$kind" "$pkg")
    info "package: $pkg $pver ($kind)"
  fi

  if [[ -n $fixed && $patch -ge $fixed ]]; then
    ok "$label $ver is at or above the fixed release $branch.$fixed"; return
  fi
  if [[ -z $fixed ]]; then
    local maj=${branch%%.*} min=${branch#*.}
    if (( maj > 8 || (maj == 8 && min > 5) )); then
      warn "$label $ver is a branch newer than this script knows; check php.net"; return
    fi
  fi
  # Below the fixed release (or out of support): only a distro backport can save it.
  if [[ -n $pk ]]; then
    cl=$(changelog_has_fix "$kind" "$pkg")
    case $cl in
      yes) ok "$label $ver: distro package carries the backported fix (both CVEs in its changelog)"; return ;;
      no)  bad "$label $ver: below the fixed release and the package changelog does not mention ${CVES[*]}"
           info "Confirm in your distribution's security tracker before concluding; then update."; return ;;
      *)   warn "$label $ver: below the fixed release; could not read the package changelog"
           info "Check your distribution's security tracker for ${CVES[*]}."; return ;;
    esac
  fi
  if [[ -z $fixed ]]; then
    bad "$label $ver: branch $branch gets no official fixes (only source backports on php-src)"
  else
    bad "$label $ver: below the fixed release $branch.$fixed"
  fi
}

# ---------- 1. find PHP builds that can serve web requests ----------

hdr "php2shell-check $VERSION on $(hostname 2>/dev/null) ($(date -u +%Y-%m-%dT%H:%MZ))"
[[ $EUID -ne 0 ]] && info "Not running as root: some configs may be unreadable."

shopt -s nullglob
SAPI_BINS=()
for f in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* /opt/remi/*/root/usr/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
         /usr/bin/php-cgi* /usr/local/bin/php-cgi* /usr/local/lsws/lsphp*/bin/lsphp /usr/local/bin/frankenphp /usr/bin/frankenphp; do
  [[ -x $f && ! -d $f ]] && SAPI_BINS+=("$(readlink -f "$f")")
done
mapfile -t SAPI_BINS < <(printf '%s\n' "${SAPI_BINS[@]}" | awk 'NF && !seen[$0]++')

MODS=()
for f in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so \
         /usr/local/apache2/modules/libphp*.so /etc/httpd/modules/libphp*.so; do
  [[ -f $f ]] && MODS+=("$(readlink -f "$f")")
done
mapfile -t MODS < <(printf '%s\n' "${MODS[@]}" | awk 'NF && !seen[$0]++')

hdr "1. PHP builds that can serve the website"
FOUND=0
for b in "${SAPI_BINS[@]}"; do
  if [[ $b == *frankenphp ]]; then
    out=$("$b" version 2>/dev/null); v=$(grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' <<<"$out" | cut -d' ' -f2)
  else
    v=$(bin_version "$b")
  fi
  [[ -z $v ]] && { warn "$b: could not read its version"; continue; }
  FOUND=1; printf '  %s\n' "$b"; judge "$(basename "$b")" "$v" "$b"
done

# mod_php: the module has no -v; use its package, or the CLI of the same install.
for m in "${MODS[@]}"; do
  FOUND=1; printf '  %s\n' "$m"
  pk=$(owner_pkg "$m"); v=""
  if [[ -n $pk ]]; then
    read -r kind pkg <<<"$pk"; pv=$(pkg_version "$kind" "$pkg")
    [[ $pv =~ ([0-9]+\.[0-9]+\.[0-9]+) ]] && v=${BASH_REMATCH[1]}
  else
    dir=$(dirname "$m"); for c in "$dir/../bin/php" /usr/local/bin/php; do [[ -x $c ]] && { v=$(bin_version "$c"); break; }; done
    [[ -n $v ]] && info "unpackaged module; version taken from the PHP CLI of the same install"
  fi
  if [[ -n $v ]]; then judge "mod_php" "$v" "$m"; else warn "mod_php at $m: could not determine its version"; fi
done

if [[ $FOUND -eq 0 ]]; then
  if command -v php >/dev/null 2>&1; then
    v=$(bin_version "$(command -v php)")
    warn "Only the PHP CLI was found ($v). The CLI alone is not exposed, but it may not match what the web server runs."
    judge "php (CLI)" "$v" "$(readlink -f "$(command -v php)")"
  else
    ok "No PHP found on this host. If the site runs in a container or on another server, run this there."
  fi
fi

# ---------- 2. SAPI in use (mod_php is the worst case) ----------

hdr "2. Which SAPI is loaded"
APACHECTL=""
for c in apache2ctl apachectl httpd; do command -v "$c" >/dev/null 2>&1 && { APACHECTL=$c; break; }; done
if [[ -n $APACHECTL ]]; then
  mods=$("$APACHECTL" -M 2>/dev/null | grep -iE 'php[0-9_]*_module' || true)
  if [[ -n $mods ]]; then
    printf '  %s[!]%s       Apache loads mod_php (%s): the highest-risk case; the exploit fires before app code runs\n' "$Y" "$N" "$(xargs <<<"$mods")"
  else
    ok "Apache is installed and does not load mod_php"
  fi
else
  info "No Apache control binary found."
fi
running=$(ps -eo comm= 2>/dev/null | grep -E '^(php-fpm|php-cgi|lsphp|frankenphp)' | sort -u | xargs || true)
[[ -n $running ]] && info "Running PHP processes: $running"
[[ -z $running && ${#SAPI_BINS[@]} -gt 0 ]] && info "No PHP worker processes running right now."

# ---------- 3. session.upload_progress (CVE-2026-115560 and interim mitigation) ----------

hdr "3. session.upload_progress.enabled (keep it 0 even after updating, per the 23 Oct advisory)"
is_on() { [[ $1 == 1 || ${1,,} == on || ${1,,} == true ]]; }
report_up() { # label, value, ini
  if [[ -z $2 ]]; then warn "$1: could not read session.upload_progress.enabled; check it by hand"
  elif is_on "$2"; then act "$1: session.upload_progress.enabled is on; set it to 0 (php.ini: ${3:-none})"
  else ok "$1: session.upload_progress.enabled is off (php.ini: ${3:-none})"; fi
}
CHECKED=0
# FPM reports its own effective config with -i (same php.ini and conf.d the pool workers load).
for b in "${SAPI_BINS[@]}"; do
  [[ $(basename "$b") == php-fpm* ]] || continue
  out=$("$b" -i 2>/dev/null) || true
  val=$(awk -F' => ' '/^session\.upload_progress\.enabled =>/{print $2; exit}' <<<"$out")
  ini=$(awk -F' => ' '/^Loaded Configuration File =>/{print $2; exit}' <<<"$out")
  CHECKED=1; report_up "$(basename "$b")" "$val" "$ini"
done
# mod_php and php-cgi on the Debian/Ubuntu layout: evaluate their php.ini with the CLI of the same branch.
for ini in /etc/php/*/apache2/php.ini /etc/php/*/cgi/php.ini; do
  sapi_dir=$(dirname "$ini"); br=$(basename "$(dirname "$sapi_dir")"); sapi=$(basename "$sapi_dir")
  cli=""; for c in "/usr/bin/php$br" /usr/bin/php; do [[ -x $c ]] && { cli=$c; break; }; done
  [[ -z $cli ]] && { warn "$ini: no PHP CLI to evaluate it; check session.upload_progress.enabled by hand"; continue; }
  val=$(PHP_INI_SCAN_DIR="$sapi_dir/conf.d" "$cli" -c "$ini" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)
  CHECKED=1; report_up "PHP $br $sapi" "$val" "$ini"
done
# Single-ini layouts (RHEL mod_php, official Docker images, source builds): the CLI shares php.ini.
DEB_APACHE_INI=(/etc/php/*/apache2/php.ini)
if [[ ${#MODS[@]} -gt 0 || $CHECKED -eq 0 ]] && [[ ${#DEB_APACHE_INI[@]} -eq 0 ]] && command -v php >/dev/null 2>&1; then
  val=$(php -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)
  ini=$(php --ini 2>/dev/null | awk -F': *' '/Loaded Configuration/{print $2}')
  CHECKED=1; report_up "php (CLI view)" "$val" "$ini"
  info "Read through the CLI; it applies to mod_php or CGI only if they share this php.ini."
fi
[[ $CHECKED -eq 0 && $FOUND -eq 1 ]] && warn "No way to evaluate php.ini here; check session.upload_progress.enabled by hand."

# Pool and vhost settings win over php.ini, so each one is judged on its own.
# (.ini files are left out: they were already evaluated above.)
over=$(grep -rIsE --exclude='*.ini' --exclude='*.ini-*' 'session\.upload_progress\.enabled' \
        /etc/php*/ /etc/php-fpm.d/ /etc/opt/remi/ /usr/local/etc/php-fpm.d/ /usr/local/etc/php-fpm.conf \
        /etc/apache2/ /etc/httpd/ /usr/local/apache2/conf/ 2>/dev/null | grep -vE '^[^:]+:[[:space:]]*[;#]' || true)
while IFS= read -r l; do
  [[ -z $l ]] && continue
  file=${l%%:*}; val=$(sed -E 's/.*session\.upload_progress\.enabled[^=[:space:]]*[][[:space:]="]*//; s/[[:space:]"].*//' <<<"${l#*:}")
  if is_on "$val"; then act "override in $file turns it back on: ${l#*:}"
  else ok "override in $file: ${l#*:}"; fi
done <<<"$over"
info "Ignore values set with ini_set() or .user.ini: they do not help here. Restart PHP after changing php.ini."

# ---------- summary ----------

hdr "Result"
case $WORST in
  0) ok "Nothing exposed found on this host." ;;
  1) printf '  %sExposed or likely exposed.%s Update PHP, restart every PHP process, then look for intrusions\n' "$R" "$N"
     info "(PHP processes spawning shells or downloading files). If you cannot update today, see the guide." ;;
  2) printf '  %sNo exposed PHP build found, but review the [ACTION] and [CHECK] lines above.%s\n' "$Y" "$N" ;;
esac
info "Guide: https://javiermorales.tech/blog/php2shell-check-in-five-minutes/"
exit "$WORST"
