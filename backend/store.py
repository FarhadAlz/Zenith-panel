"""
store.py — local SQLite persistence for the panel: the server history
(add-once, one-click reconnect later), the encrypted LLM API key, and a
cached domain list per server (refreshable, not authoritative — the
authoritative read always happens live over SSH when the operator
actually opens a server).

Every column that can hold a credential (password, private key,
private key passphrase, the LLM API key) is stored pre-encrypted via
crypto_utils — this module never sees a plaintext secret's value, it
only shuttles ciphertext in and out of SQLite.
"""

import json
import os
import sqlite3
import threading
import time
import uuid

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "panel.db")

_lock = threading.RLock()


def _connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


_conn = _connect()


def init_db():
    with _lock:
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                username TEXT NOT NULL,
                auth_type TEXT NOT NULL,          -- 'password' | 'key'
                secret_enc TEXT NOT NULL,         -- encrypted password OR private key text
                passphrase_enc TEXT,              -- encrypted key passphrase (auth_type='key' only)
                created_at REAL NOT NULL,
                last_connected_at REAL,
                deployed INTEGER NOT NULL DEFAULT 0,
                domains_json TEXT,
                domains_fetched_at REAL
            )
            """
        )
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )
        _conn.commit()


def add_server(name, host, port, username, auth_type, secret_enc, passphrase_enc) -> str:
    server_id = uuid.uuid4().hex[:12]
    with _lock:
        _conn.execute(
            """INSERT INTO servers
               (id, name, host, port, username, auth_type, secret_enc, passphrase_enc, created_at, deployed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (server_id, name, host, port, username, auth_type, secret_enc, passphrase_enc, time.time()),
        )
        _conn.commit()
    return server_id


def list_servers():
    with _lock:
        rows = _conn.execute(
            "SELECT id, name, host, port, username, auth_type, created_at, last_connected_at, deployed, domains_json, domains_fetched_at FROM servers ORDER BY created_at DESC"
        ).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "name": r["name"],
            "host": r["host"],
            "port": r["port"],
            "username": r["username"],
            "auth_type": r["auth_type"],
            "created_at": r["created_at"],
            "last_connected_at": r["last_connected_at"],
            "deployed": bool(r["deployed"]),
            "domains": json.loads(r["domains_json"]) if r["domains_json"] else None,
            "domains_fetched_at": r["domains_fetched_at"],
        })
    return out


def get_server_full(server_id):
    """Includes the encrypted secret columns — for internal SSH-connect use only."""
    with _lock:
        row = _conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    return dict(row) if row else None


def touch_connected(server_id):
    with _lock:
        _conn.execute("UPDATE servers SET last_connected_at = ? WHERE id = ?", (time.time(), server_id))
        _conn.commit()


def set_deployed(server_id, deployed: bool):
    with _lock:
        _conn.execute("UPDATE servers SET deployed = ? WHERE id = ?", (1 if deployed else 0, server_id))
        _conn.commit()


def save_domains(server_id, domains: list):
    with _lock:
        _conn.execute(
            "UPDATE servers SET domains_json = ?, domains_fetched_at = ? WHERE id = ?",
            (json.dumps(domains, ensure_ascii=False), time.time(), server_id),
        )
        _conn.commit()


def delete_server(server_id):
    with _lock:
        _conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        _conn.commit()


def set_setting(key: str, value: str):
    with _lock:
        _conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        _conn.commit()


def get_setting(key: str):
    with _lock:
        row = _conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None
