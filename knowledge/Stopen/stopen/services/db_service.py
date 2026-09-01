"""SQLite 存储 —— 会话 + 任务 + C2"""
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from app_config.settings import DB_PATH


class Database:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # 每线程独立连接（WAL 模式），避免共享单连接的并发游标竞争
        self._local = threading.local()
        self._fernet = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    # ---- 敏感字段加密（与 config 共用 keyfile.key，密文落库，读取时透明解密）----
    def _get_fernet(self):
        if self._fernet is None:
            from cryptography.fernet import Fernet
            key_path = Path(os.environ.get("STOPEN_KEY_PATH", "") or (self.db_path.parent / "keyfile.key"))
            if key_path.exists():
                key = key_path.read_bytes()
            else:
                key = Fernet.generate_key()
                key_path.write_bytes(key)
            self._fernet = Fernet(key)
        return self._fernet

    def _encrypt(self, value: str) -> str:
        if not value:
            return value
        return self._get_fernet().encrypt(value.encode("utf-8")).decode("ascii")

    def _decrypt(self, value: str) -> str:
        """兼容历史明文：解密失败时原样返回"""
        if not value:
            return value
        try:
            return self._get_fernet().decrypt(value.encode("ascii")).decode("utf-8")
        except Exception:
            return value

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript("""
            PRAGMA foreign_keys=OFF;

            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                title TEXT DEFAULT '',
                model TEXT DEFAULT '',
                system_prompt TEXT DEFAULT '',
                task_type TEXT DEFAULT 'pentest',
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT DEFAULT '',
                created_at TEXT DEFAULT '',
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                task_type TEXT DEFAULT 'pentest',
                goal TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                model TEXT DEFAULT '',
                report_path TEXT DEFAULT '',
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS listeners (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                listener_type TEXT DEFAULT 'tcp',
                host TEXT DEFAULT '0.0.0.0',
                port INTEGER DEFAULT 4444,
                status TEXT DEFAULT 'stopped',
                secret TEXT DEFAULT '',
                created_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                listener_id TEXT NOT NULL,
                remote_addr TEXT DEFAULT '',
                hostname TEXT DEFAULT '',
                username TEXT DEFAULT '',
                os_info TEXT DEFAULT '',
                status TEXT DEFAULT 'active',
                last_seen TEXT DEFAULT '',
                created_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS c2_tasks (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                command TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                result TEXT DEFAULT '',
                created_at TEXT DEFAULT '',
                completed_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS webshells (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                password TEXT DEFAULT '',
                shell_type TEXT DEFAULT 'php',
                status TEXT DEFAULT 'active',
                created_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS mcp_servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                server_type TEXT DEFAULT 'mcp',
                base_url TEXT NOT NULL,
                api_key TEXT DEFAULT '',
                description TEXT DEFAULT '',
                enabled INTEGER DEFAULT 1,
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS roles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                role_type TEXT DEFAULT 'custom',
                system_prompt TEXT DEFAULT '',
                builtin INTEGER DEFAULT 0,
                skills TEXT DEFAULT '',
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                target TEXT DEFAULT '',
                title TEXT NOT NULL,
                vuln_type TEXT DEFAULT '',
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                description TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                source TEXT DEFAULT '',
                conversation_id TEXT DEFAULT '',
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS payload_templates (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                payload_type TEXT DEFAULT 'python',
                content TEXT DEFAULT '',
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS yaml_tools (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                category TEXT DEFAULT 'custom',
                tool_type TEXT DEFAULT 'subprocess',
                command TEXT DEFAULT '',
                parameters TEXT DEFAULT '{}',
                timeout INTEGER DEFAULT 60,
                enabled INTEGER DEFAULT 1,
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            );
            -- 迁移: 为旧表添加新字段 (单独处理以忽略已存在错误)
        """)
        try:
            conn.executescript("ALTER TABLE webshells ADD COLUMN protocol TEXT DEFAULT 'antsword';")
        except sqlite3.OperationalError:
            pass
        try:
            conn.executescript("""
            ALTER TABLE mcp_servers ADD COLUMN command TEXT DEFAULT '';
            """)
        except sqlite3.OperationalError:
            pass
        try:
            conn.executescript("""
            ALTER TABLE mcp_servers ADD COLUMN args TEXT DEFAULT '';
            """)
        except sqlite3.OperationalError:
            pass
        try:
            conn.executescript("""
            ALTER TABLE listeners ADD COLUMN encryption_type TEXT DEFAULT 'aes-256-ctr';
            """)
        except sqlite3.OperationalError:
            pass
        conn.commit()

    def _now(self):
        return datetime.now().isoformat(timespec="seconds")

    # ---- Conversations ----
    def create_conversation(self, title="", model="", system_prompt="", task_type="pentest"):
        import uuid
        cid = str(uuid.uuid4())[:8]
        now = self._now()
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO conversations (id,title,model,system_prompt,task_type,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
            (cid, title, model, system_prompt, task_type, now, now),
        )
        conn.commit()
        return {"id": cid, "title": title, "model": model, "system_prompt": system_prompt, "task_type": task_type}

    def list_conversations(self):
        cur = self._get_conn().execute("SELECT * FROM conversations ORDER BY updated_at DESC")
        return [dict(r) for r in cur.fetchall()]

    def get_conversation(self, cid: str):
        cur = self._get_conn().execute("SELECT * FROM conversations WHERE id=?", (cid,))
        r = cur.fetchone()
        return dict(r) if r else None

    def add_message(self, conv_id, role, content):
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO messages (conversation_id,role,content,created_at) VALUES (?,?,?,?)",
            (conv_id, role, content, now),
        )
        self._get_conn().execute("UPDATE conversations SET updated_at=? WHERE id=?", (now, conv_id))
        self._get_conn().commit()

    def get_messages(self, conv_id, limit=200):
        cur = self._get_conn().execute(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY id ASC LIMIT ?", (conv_id, limit))
        return [dict(r) for r in cur.fetchall()]

    # ---- Tasks ----
    def create_task(self, name, target, task_type="pentest", goal="", model=""):
        import uuid
        tid = str(uuid.uuid4())[:8]
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO tasks (id,name,target,task_type,goal,status,model,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (tid, name, target, task_type, goal, "pending", model, now, now),
        )
        self._get_conn().commit()
        return {"id": tid, "name": name, "target": target, "task_type": task_type, "goal": goal, "status": "pending"}

    def list_tasks(self):
        cur = self._get_conn().execute("SELECT * FROM tasks ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]

    def update_task(self, tid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        fields["updated_at"] = self._now()
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [tid]
        self._get_conn().execute(f"UPDATE tasks SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    # ---- Listeners ----
    def create_listener(self, name, listener_type="tcp", host="0.0.0.0", port=4444, encryption_type="aes-256-ctr"):
        import uuid
        lid = str(uuid.uuid4())[:8]
        now = self._now()
        import secrets
        secret = secrets.token_hex(32)  # 256-bit，匹配 aes-256-ctr
        self._get_conn().execute(
            "INSERT INTO listeners (id,name,listener_type,host,port,status,secret,encryption_type,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (lid, name, listener_type, host, port, "stopped", secret, encryption_type, now),
        )
        self._get_conn().commit()
        return {"id": lid, "name": name, "listener_type": listener_type, "host": host, "port": port, "status": "stopped", "secret": secret, "encryption_type": encryption_type}

    def list_listeners(self):
        cur = self._get_conn().execute("SELECT * FROM listeners ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]

    def update_listener(self, lid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [lid]
        self._get_conn().execute(f"UPDATE listeners SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    # ---- Sessions ----
    def create_session(self, listener_id, remote_addr="", hostname="", username="", os_info=""):
        import uuid
        sid = str(uuid.uuid4())[:8]
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO sessions (id,listener_id,remote_addr,hostname,username,os_info,status,last_seen,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, listener_id, remote_addr, hostname, username, os_info, "active", now, now),
        )
        self._get_conn().commit()
        return {"id": sid, "listener_id": listener_id, "remote_addr": remote_addr, "status": "active"}

    def list_sessions(self):
        cur = self._get_conn().execute("SELECT * FROM sessions ORDER BY last_seen DESC")
        return [dict(r) for r in cur.fetchall()]

    def update_session(self, sid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        fields["last_seen"] = self._now()
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [sid]
        self._get_conn().execute(f"UPDATE sessions SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    # ---- C2 Tasks ----
    def create_c2_task(self, session_id, command):
        import uuid
        tid = str(uuid.uuid4())[:8]
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO c2_tasks (id,session_id,command,status,created_at) VALUES (?,?,?,?,?)",
            (tid, session_id, command, "pending", now),
        )
        self._get_conn().commit()
        return {"id": tid, "session_id": session_id, "command": command, "status": "pending"}

    def list_c2_tasks(self, session_id):
        cur = self._get_conn().execute(
            "SELECT * FROM c2_tasks WHERE session_id=? ORDER BY created_at DESC", (session_id,))
        return [dict(r) for r in cur.fetchall()]

    def update_c2_task(self, tid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        if "result" in kw:
            fields["status"] = "done"
            fields["completed_at"] = self._now()
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [tid]
        self._get_conn().execute(f"UPDATE c2_tasks SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    # ---- WebShells ----
    def create_webshell(self, name, url, password="", shell_type="php", protocol="antsword"):
        import uuid
        wid = str(uuid.uuid4())[:8]
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO webshells (id,name,url,password,shell_type,status,protocol,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (wid, name, url, self._encrypt(password), shell_type, "active", protocol, now),
        )
        self._get_conn().commit()
        return {"id": wid, "name": name, "url": url, "shell_type": shell_type, "status": "active", "protocol": protocol}

    def list_webshells(self):
        cur = self._get_conn().execute("SELECT * FROM webshells WHERE status != 'deleted' ORDER BY created_at DESC")
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["password"] = self._decrypt(r.get("password", ""))
        return rows

    def update_webshell(self, wid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        if fields.get("password"):
            fields["password"] = self._encrypt(fields["password"])
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [wid]
        self._get_conn().execute(f"UPDATE webshells SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    # ---- MCP Servers ----
    def create_mcp_server(self, name, base_url, server_type="mcp", api_key="", description="", command="", args=""):
        import uuid
        mid = str(uuid.uuid4())[:8]
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO mcp_servers (id,name,server_type,base_url,api_key,description,command,args,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (mid, name, server_type, base_url, api_key, description, command, args, 1, now, now),
        )
        self._get_conn().commit()
        return {"id": mid, "name": name, "server_type": server_type, "base_url": base_url, "api_key": "****" if api_key else "", "enabled": 1}

    def list_mcp_servers(self):
        cur = self._get_conn().execute("SELECT * FROM mcp_servers ORDER BY created_at DESC")
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r.get("api_key"):
                r["api_key"] = "****"
        return rows

    def get_mcp_server(self, mid):
        cur = self._get_conn().execute("SELECT * FROM mcp_servers WHERE id=?", (mid,))
        r = cur.fetchone()
        return dict(r) if r else None

    def update_mcp_server(self, mid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        fields["updated_at"] = self._now()
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [mid]
        self._get_conn().execute(f"UPDATE mcp_servers SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    def delete_mcp_server(self, mid):
        self._get_conn().execute("DELETE FROM mcp_servers WHERE id=?", (mid,))
        self._get_conn().commit()

    # ---- Roles ----
    def create_role(self, name, description="", role_type="custom", system_prompt="", builtin=0, skills=""):
        import uuid
        rid = str(uuid.uuid4())[:8]
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO roles (id,name,description,role_type,system_prompt,builtin,skills,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (rid, name, description, role_type, system_prompt, builtin, skills, now, now),
        )
        self._get_conn().commit()
        return {"id": rid, "name": name, "description": description, "role_type": role_type, "builtin": builtin}

    def list_roles(self):
        cur = self._get_conn().execute("SELECT * FROM roles ORDER BY builtin DESC, created_at ASC")
        return [dict(r) for r in cur.fetchall()]

    def get_role(self, rid):
        cur = self._get_conn().execute("SELECT * FROM roles WHERE id=?", (rid,))
        r = cur.fetchone()
        return dict(r) if r else None

    def update_role(self, rid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        fields["updated_at"] = self._now()
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [rid]
        self._get_conn().execute(f"UPDATE roles SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    def delete_role(self, rid):
        self._get_conn().execute("DELETE FROM roles WHERE id=?", (rid,))
        self._get_conn().commit()

    # ---- Vulnerabilities ----
    def create_vulnerability(self, title, target="", vuln_type="", severity="medium",
                              status="open", description="", evidence="", source="",
                              conversation_id=""):
        import uuid
        vid = str(uuid.uuid4())[:8]
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO vulnerabilities (id,target,title,vuln_type,severity,status,description,evidence,source,conversation_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (vid, target, title, vuln_type, severity, status, description, evidence, source, conversation_id, now, now),
        )
        self._get_conn().commit()
        return {"id": vid, "title": title, "target": target, "severity": severity, "status": status}

    def list_vulnerabilities(self, severity="", status="", vuln_type=""):
        sql = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if status:
            sql += " AND status=?"
            params.append(status)
        if vuln_type:
            sql += " AND vuln_type=?"
            params.append(vuln_type)
        sql += " ORDER BY created_at DESC"
        cur = self._get_conn().execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def get_vulnerability(self, vid):
        cur = self._get_conn().execute("SELECT * FROM vulnerabilities WHERE id=?", (vid,))
        r = cur.fetchone()
        return dict(r) if r else None

    def update_vulnerability(self, vid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        fields["updated_at"] = self._now()
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [vid]
        self._get_conn().execute(f"UPDATE vulnerabilities SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    def delete_vulnerability(self, vid):
        self._get_conn().execute("DELETE FROM vulnerabilities WHERE id=?", (vid,))
        self._get_conn().commit()

    def vulnerability_stats(self):
        cur = self._get_conn().execute(
            "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity")
        by_severity = {r["severity"]: r["cnt"] for r in cur.fetchall()}
        cur = self._get_conn().execute(
            "SELECT status, COUNT(*) as cnt FROM vulnerabilities GROUP BY status")
        by_status = {r["status"]: r["cnt"] for r in cur.fetchall()}
        cur = self._get_conn().execute("SELECT COUNT(*) as total FROM vulnerabilities")
        total = cur.fetchone()["total"]
        return {"total": total, "by_severity": by_severity, "by_status": by_status}

    # ---- Payload Templates ----
    def create_payload_template(self, name, payload_type="python", content=""):
        import uuid
        tid = str(uuid.uuid4())[:8]
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO payload_templates (id,name,payload_type,content,created_at,updated_at) VALUES (?,?,?,?,?,?)",
            (tid, name, payload_type, content, now, now),
        )
        self._get_conn().commit()
        return {"id": tid, "name": name, "payload_type": payload_type}

    def list_payload_templates(self):
        cur = self._get_conn().execute("SELECT * FROM payload_templates ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]

    def get_payload_template(self, tid):
        cur = self._get_conn().execute("SELECT * FROM payload_templates WHERE id=?", (tid,))
        r = cur.fetchone()
        return dict(r) if r else None

    def update_payload_template(self, tid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        fields["updated_at"] = self._now()
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [tid]
        self._get_conn().execute(f"UPDATE payload_templates SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    def delete_payload_template(self, tid):
        self._get_conn().execute("DELETE FROM payload_templates WHERE id=?", (tid,))
        self._get_conn().commit()

    # ---- YAML Tools ----
    def create_yaml_tool(self, name, description="", category="custom", tool_type="subprocess",
                          command="", parameters="{}", timeout=60):
        import uuid
        yid = str(uuid.uuid4())[:8]
        now = self._now()
        self._get_conn().execute(
            "INSERT INTO yaml_tools (id,name,description,category,tool_type,command,parameters,timeout,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (yid, name, description, category, tool_type, command, parameters, timeout, 1, now, now),
        )
        self._get_conn().commit()
        return {"id": yid, "name": name, "tool_type": tool_type}

    def list_yaml_tools(self):
        cur = self._get_conn().execute("SELECT * FROM yaml_tools ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]

    def get_yaml_tool(self, yid):
        cur = self._get_conn().execute("SELECT * FROM yaml_tools WHERE id=?", (yid,))
        r = cur.fetchone()
        return dict(r) if r else None

    def update_yaml_tool(self, yid, **kw):
        fields = {k: v for k, v in kw.items() if v is not None}
        if not fields:
            return
        fields["updated_at"] = self._now()
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [yid]
        self._get_conn().execute(f"UPDATE yaml_tools SET {sets} WHERE id=?", vals)
        self._get_conn().commit()

    def delete_yaml_tool(self, yid):
        self._get_conn().execute("DELETE FROM yaml_tools WHERE id=?", (yid,))
        self._get_conn().commit()


db = Database()
