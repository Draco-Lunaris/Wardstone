#!/bin/sh
# Wardstone's bundled bootstrap role: born LOGIN SUPERUSER, no password
# ever (peer-authenticated only through the hba's ws_setup line). Setup
# rotates the wardstone role through it and disarms it (NOLOGIN) at
# completion; the recovery runbook re-arms it.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'SQL'
    SELECT 'CREATE ROLE ws_setup LOGIN SUPERUSER' WHERE NOT EXISTS
        (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ws_setup')\gexec
SQL
