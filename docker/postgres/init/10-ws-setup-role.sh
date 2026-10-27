#!/bin/sh
# Wardstone's bundled bootstrap role: born LOGIN SUPERUSER, no password
# ever (peer-authenticated only through the hba's ws_setup line). Setup
# rotates the wardstone role through it and disarms it (NOLOGIN) at
# completion; the recovery runbook re-arms it.
#
# The dial rides the pinned hba's recovery line, not the app's SCRAM
# line: the initdb temp server runs with the compose command's FULL
# argument list (the pinned hba_file included), so the pinned hba
# governs the init phase too, and this script's psql dials as the
# container's postgres system user (the stock entrypoint re-execs
# itself as it) against the `postgres` database — first-match skips
# the db-qualified SCRAM line and lands on the recovery line, whose
# ident map renames the system user onto the wardstone role. CREATE
# ROLE is cluster-wide, so the database context carries no weight
# here; a dial against the wardstone database would first-match the
# SCRAM line and die passwordless.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<-'SQL'
    SELECT 'CREATE ROLE ws_setup LOGIN SUPERUSER' WHERE NOT EXISTS
        (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ws_setup')\gexec
SQL