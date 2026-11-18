#!/usr/bin/env bash
# Runs php2shell-check.sh in throwaway containers and prints the exit code of each.
# Usage: bash tests/run-docker.sh   (needs Docker; pulls public images)
set -uo pipefail
S="$(cd "$(dirname "$0")/.." && pwd)/php2shell-check.sh"
run() { # name image [setup]
  local name=$1 img=$2 setup=${3:-true}
  echo "################ $name ($img)"
  docker run --rm -v "$S:/p2s.sh:ro" "$img" bash -c "{ $setup; } >/dev/null 2>&1; bash /p2s.sh; echo EXIT=\$?"
}
run "upstream 8.2.34 fpm (vulnerable)"  php:8.2.34-fpm
run "upstream 8.2.35 apache + mitigation" php:8.2.35-apache "printf 'session.upload_progress.enabled=0\n' > /usr/local/etc/php/conf.d/zz.ini"
run "upstream 8.1 apache (EOL)"         php:8.1-apache
run "ubuntu 24.04 distro php"           ubuntu:24.04 "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y php8.3-fpm libapache2-mod-php8.3"
run "debian 12 distro php-fpm"          debian:12 "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y php8.2-fpm"
run "rocky 9 php-fpm (rpm)"             rockylinux:9 "dnf -y install php-fpm"
run "ubuntu 24.04 patched + mitigation" ubuntu:24.04 "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y php8.3-fpm libapache2-mod-php8.3 && for d in fpm apache2; do echo session.upload_progress.enabled=0 > /etc/php/8.3/\$d/conf.d/99-p2s.ini; done"
run "ubuntu 22.04 distro php 8.1"       ubuntu:22.04 "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y php8.1-fpm"
run "fpm pool override"                 debian:12 "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y php8.2-fpm && echo session.upload_progress.enabled=0 > /etc/php/8.2/fpm/conf.d/99-p2s.ini && echo 'php_admin_value[session.upload_progress.enabled] = 1' >> /etc/php/8.2/fpm/pool.d/www.conf"
run "apache vhost override"            php:8.2.35-apache "printf 'session.upload_progress.enabled=0\\n' > /usr/local/etc/php/conf.d/zz.ini && echo 'php_admin_flag session.upload_progress.enabled on' >> /etc/apache2/sites-enabled/000-default.conf"
run "no php"                            debian:12
