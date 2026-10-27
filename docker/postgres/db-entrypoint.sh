#!/bin/sh
# Wardstone's db bundle wrapper: two load-bearing acts, then the stock
# entrypoint.
# 1. Name the Wardstone image's fixed uid (10001) as the ws_setup peer
#    identity: peer auth resolves the CLIENT's uid through THIS
#    container's /etc/passwd, so the setup door's name must live here.
# 2. Point the image-default socket path at the pinned shared directory:
#    the official entrypoint's init-phase psql dials the default while the
#    pinned command's unix_socket_directories puts the temp server on the
#    shared socket — without this bridge the first-boot init aborts at
#    CREATE DATABASE (the CT 242 field bug).
set -e
grep -q '^ws_setup:' /etc/passwd || \
  echo 'ws_setup:x:10001:10001:ws_setup:/:/sbin/nologin' >> /etc/passwd
if [ -e /var/run/postgresql ] && [ ! -L /var/run/postgresql ]; then
  rm -rf /var/run/postgresql
fi
ln -sfn /run/wardstone/pg /var/run/postgresql
exec docker-entrypoint.sh "$@"
