"""
tools.py — Strictly typed, safe system interaction tools for Agent 500.

v2: extended with deep root-cause diagnostic tools so the agent is no longer
blind once nginx/httpd/php-fpm are all reported "active". These new tools
target the causes that most commonly survive a naive service-restart check:
permissions, broken sockets, exhausted FPM pools, PHP fatal errors, SELinux
denials, stale opcache after a deploy, and DB reachability.
"""

import subprocess
import socket
import shutil
import os
import re
import stat
import time

ALLOWED_SERVICES = {"nginx", "httpd", "php-fpm74", "php-fpm81", "php-fpm82", "php-fpm83"}

ALLOWED_LOG_PATHS = {
    "nginx_error": "/var/log/nginx/domains/farhad20.ir.error.log",
    "httpd_error": "/var/log/httpd/domains/farhad20.ir.error.log",
    "nginx_system": "/var/log/nginx/error_log",
    "httpd_system": "/var/log/httpd/error_log",
    "nginx_access": "/var/log/nginx/access.log",
    "php_fpm": "/var/log/httpd/domains/farhad20.ir.error.log",  # PHP-FPM errors in DA DirectAdmin route to Apache domain log
}

# TODO: set this to the real DirectAdmin webroot for the account being investigated.
# Used only by check_recent_file_changes to correlate errors with recent deploys.
DEFAULT_WEBROOT = "/home/CHANGE_ME/domains/farhad20.ir/public_html"

# Root-cause signatures used by analyze_log_patterns. Each entry is a read-only
# classification rule — it never triggers an action by itself, it only tells the
# agent (and the operator) which drill-down tool to run next.
LOG_PATTERNS = [
    {
        "category": "permission_denied",
        "pattern": r"[Pp]ermission denied",
        "severity": "high",
        "hint": "Ownership/permission problem. Extract the file path from the log line and call check_file_permissions(path) on it.",
    },
    {
        "category": "fpm_max_children",
        "pattern": r"server reached pm\.max_children",
        "severity": "high",
        "hint": "PHP-FPM worker pool exhausted. Call check_fpm_pool_status(pool) to confirm.",
    },
    {
        "category": "socket_missing",
        "pattern": r"connect\(\) to unix:.*failed",
        "severity": "high",
        "hint": "Upstream unix socket is broken or gone. Extract the socket path from the log line and call check_socket(path).",
    },
    {
        "category": "php_fatal_error",
        "pattern": r"PHP Fatal error:",
        "severity": "high",
        "hint": "Application-level fatal error (code bug). This is out of auto-fix scope — escalate to a developer with the exact stack line as evidence.",
    },
    {
        "category": "execution_timeout",
        "pattern": r"Maximum execution time|upstream timed out",
        "severity": "medium",
        "hint": "Script or upstream exceeded its time budget. Likely a slow external dependency or infinite loop — report, do not auto-fix.",
    },
    {
        "category": "htaccess_error",
        "pattern": r"\.htaccess:.*(Invalid command|not allowed here)",
        "severity": "medium",
        "hint": "Malformed .htaccess directive. Requires manual edit — out of auto-fix scope, report the exact line.",
    },
    {
        "category": "selinux_denial",
        "pattern": r"avc:\s+denied",
        "severity": "medium",
        "hint": "SELinux may be blocking access. Call check_selinux_denials() to confirm.",
    },
    {
        "category": "db_connection",
        "pattern": r"SQLSTATE|Connection refused|Too many connections",
        "severity": "high",
        "hint": "Database connectivity/exhaustion symptom. Call check_db_connectivity(host, port) for read-only confirmation — DB-side fixes are out of scope.",
    },
]


def _run(cmd: list[str], timeout: int = 10) -> dict:
    """Safe execution wrapper preventing shell injection using fixed argument lists."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "ok": p.returncode == 0,
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
        }
    except FileNotFoundError:
        return {"ok": False, "returncode": -1, "stdout": "", "stderr": "command not found"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "returncode": -1, "stdout": "", "stderr": "timeout"}


# ─────────────────────────── GREEN TOOLS (existing) ───────────────────────────

def http_check(url: str, timeout: int = 5) -> dict:
    import urllib.request
    import urllib.error

    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "agent500-healthcheck"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = round((time.time() - start) * 1000)
            return {"ok": True, "status_code": resp.status, "elapsed_ms": elapsed, "error": None}
    except urllib.error.HTTPError as e:
        elapsed = round((time.time() - start) * 1000)
        return {"ok": False, "status_code": e.code, "elapsed_ms": elapsed, "error": f"http_error_{e.code}"}
    except Exception as e:
        elapsed = round((time.time() - start) * 1000)
        return {"ok": False, "status_code": None, "elapsed_ms": elapsed, "error": str(e)}


def check_service(name: str) -> dict:
    if name not in ALLOWED_SERVICES:
        return {"ok": False, "error": f"service '{name}' not in allow-list"}
    r = _run(["systemctl", "is-active", name])
    state = r["stdout"] or "unknown"
    return {"ok": True, "service": name, "state": state, "active": state == "active"}


def check_port(port: int, host: str = "127.0.0.1") -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    listening = False
    try:
        result = sock.connect_ex((host, port))
        listening = result == 0
    finally:
        sock.close()

    owner = None
    ss = _run(["ss", "-ltnp"])
    if ss["ok"]:
        for line in ss["stdout"].splitlines():
            if f":{port} " in line or line.strip().endswith(f":{port}"):
                owner = line.strip()
                break
    return {"ok": True, "port": port, "listening": listening, "owner_line": owner}


def disk_usage(path: str = "/") -> dict:
    total, used, free = shutil.disk_usage(path)
    percent_used = round(used / total * 100, 1)

    log_dir_size = None
    du = _run(["du", "-sh", "/var/log"])
    if du["ok"]:
        log_dir_size = du["stdout"].split()[0] if du["stdout"] else None

    return {
        "ok": True,
        "path": path,
        "percent_used": percent_used,
        "total_gb": round(total / 1e9, 2),
        "free_gb": round(free / 1e9, 2),
        "var_log_size": log_dir_size,
    }


def read_log(log_key: str, lines: int = 50) -> dict:
    if log_key not in ALLOWED_LOG_PATHS:
        return {"ok": False, "error": f"log_key '{log_key}' not in allow-list", "content": None}

    path = ALLOWED_LOG_PATHS[log_key]

    # Fallback mechanism if specific domain log doesn't exist
    if not os.path.exists(path):
        if log_key in ("nginx_error", "nginx_access"):
            path = ALLOWED_LOG_PATHS["nginx_system"]
        elif log_key in ("httpd_error", "php_fpm"):
            path = ALLOWED_LOG_PATHS["httpd_system"]

    if not os.path.exists(path):
        return {"ok": False, "error": f"file not found at {path}", "content": None}

    r = _run(["tail", "-n", str(lines), path])
    return {"ok": r["ok"], "content": r["stdout"], "error": r["stderr"] or None}


def nginx_config_test() -> dict:
    r = _run(["nginx", "-t"])
    return {"ok": r["ok"], "valid": r["ok"], "detail": (r["stderr"] or r["stdout"])}


# ────────────────────── GREEN TOOLS (new — root-cause depth) ──────────────────

def analyze_log_patterns(log_key: str, lines: int = 200) -> dict:
    """Scans a log for known root-cause signatures. Never guesses — only reports
    matches with the exact evidence lines, so the agent can decide which
    drill-down tool to run next (or escalate if nothing matches)."""
    log_result = read_log(log_key, lines=lines)
    content = log_result.get("content") or ""
    if not content:
        return {"ok": log_result.get("ok", False), "log_key": log_key, "matches": [], "error": log_result.get("error")}

    matches = []
    for rule in LOG_PATTERNS:
        found = re.findall(rule["pattern"], content)
        if found:
            sample_lines = [ln for ln in content.splitlines() if re.search(rule["pattern"], ln)][-3:]
            matches.append(
                {
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "hint": rule["hint"],
                    "occurrences": len(found),
                    "sample_lines": sample_lines,
                }
            )
    return {"ok": True, "log_key": log_key, "matches": matches, "clean": len(matches) == 0}


def check_file_permissions(path: str) -> dict:
    """Reports owner, group, mode and access flags for a file/dir referenced in
    a 'Permission denied' log line."""
    if not os.path.exists(path):
        return {"ok": False, "error": f"path not found: {path}"}
    try:
        import pwd
        import grp

        st = os.stat(path)
        return {
            "ok": True,
            "path": path,
            "owner": pwd.getpwuid(st.st_uid).pw_name,
            "group": grp.getgrgid(st.st_gid).gr_name,
            "mode": oct(st.st_mode)[-3:],
            "readable": os.access(path, os.R_OK),
            "writable": os.access(path, os.W_OK),
            "executable": os.access(path, os.X_OK),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_socket(path: str) -> dict:
    """Confirms whether a unix socket file (e.g. php-fpm's) exists and is
    actually accepting connections — the exact failure mode behind
    'connect() to unix:... failed' in nginx logs."""
    if not os.path.exists(path):
        return {"ok": False, "exists": False, "error": f"socket file not found: {path}"}

    is_socket = stat.S_ISSOCK(os.stat(path).st_mode)
    listening = False
    if is_socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(path)
            listening = True
        except Exception:
            listening = False
        finally:
            s.close()

    return {
        "ok": True,
        "path": path,
        "exists": True,
        "is_socket": is_socket,
        "listening": listening,
        "permissions": check_file_permissions(path),
    }


def check_fpm_pool_status(pool: str) -> dict:
    """Counts live worker processes for a PHP-FPM pool and checks its error log
    for pm.max_children exhaustion — the usual cause of intermittent 502/504
    under load when systemctl still reports the service as 'active'."""
    if pool not in ALLOWED_SERVICES or "php-fpm" not in pool:
        return {"ok": False, "error": f"pool '{pool}' not in allow-list"}

    ps = _run(["pgrep", "-fc", pool])
    worker_count = int(ps["stdout"]) if ps["stdout"].isdigit() else None

    hits = []
    for candidate in (f"/var/log/php-fpm/{pool}/error.log", "/var/log/php-fpm/error.log", ALLOWED_LOG_PATHS.get("php_fpm")):
        if candidate and os.path.exists(candidate):
            g = _run(["grep", "-i", "max_children", candidate])
            if g["stdout"]:
                hits.append({"log": candidate, "recent_matches": g["stdout"].splitlines()[-3:]})
            break

    return {"ok": True, "pool": pool, "active_worker_count": worker_count, "max_children_hits": hits}


def check_selinux_denials() -> dict:
    """Checks whether SELinux is enforcing and, if so, pulls recent AVC denials.
    Returns applicable=False cleanly on hosts without SELinux tooling."""
    enforce = _run(["getenforce"])
    if enforce["stderr"] == "command not found":
        return {"ok": True, "applicable": False, "detail": "SELinux tooling not present on this host"}

    mode = enforce["stdout"].strip()
    if mode.lower() != "enforcing":
        return {"ok": True, "applicable": False, "mode": mode, "detail": "SELinux not enforcing — unlikely root cause"}

    r = _run(["ausearch", "-m", "avc", "-ts", "recent"])
    return {"ok": True, "applicable": True, "mode": mode, "denials": r["stdout"] or None, "detail": r["stderr"] or None}


def check_recent_file_changes(path: str = DEFAULT_WEBROOT, minutes: int = 30) -> dict:
    """Correlates the incident with a recent deploy by listing files modified
    in the last N minutes under the webroot — useful even when no log pattern
    matched anything (e.g. a bad deploy that only breaks specific routes)."""
    if not os.path.exists(path):
        return {"ok": False, "error": f"path not found: {path}"}
    r = _run(["find", path, "-type", "f", "-mmin", f"-{minutes}"])
    files = r["stdout"].splitlines() if r["ok"] else []
    return {"ok": True, "path": path, "window_minutes": minutes, "recently_changed_files": files[:50], "count": len(files)}


def check_db_connectivity(host: str, port: int = 3306, timeout: int = 3) -> dict:
    """Read-only TCP reachability check for the database host — confirms or
    rules out DB connectivity as the cause of SQLSTATE/'Connection refused'
    errors. Never touches credentials or runs queries; actual DB remediation
    is out of scope for this agent."""
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return {"ok": True, "host": host, "port": port, "reachable": True, "elapsed_ms": round((time.time() - start) * 1000)}
    except Exception as e:
        return {"ok": False, "host": host, "port": port, "reachable": False, "error": str(e), "elapsed_ms": round((time.time() - start) * 1000)}
    finally:
        s.close()


# ─────────────────────────── YELLOW TOOLS (existing) ───────────────────────────

def restart_service(name: str) -> dict:
    if name not in ALLOWED_SERVICES:
        return {"ok": False, "error": f"service '{name}' not in allow-list"}
    r = _run(["systemctl", "restart", name], timeout=20)
    return {"ok": r["ok"], "service": name, "stderr": r["stderr"]}


def reload_workers(name: str) -> dict:
    if name not in ALLOWED_SERVICES:
        return {"ok": False, "error": f"service '{name}' not in allow-list"}
    r = _run(["systemctl", "reload", name], timeout=20)
    return {"ok": r["ok"], "service": name, "stderr": r["stderr"]}


def safe_log_cleanup(log_key: str) -> dict:
    if log_key not in ALLOWED_LOG_PATHS:
        return {"ok": False, "error": f"log_key '{log_key}' not in allow-list"}
    path = ALLOWED_LOG_PATHS[log_key]
    if not os.path.exists(path):
        return {"ok": False, "error": "file not found"}
    archive_path = f"{path}.{int(time.time())}.gz"
    r = _run(["bash", "-c", f"gzip -c '{path}' > '{archive_path}' && truncate -s 0 '{path}'"])
    return {"ok": r["ok"], "archived_to": archive_path if r["ok"] else None, "error": r["stderr"] or None}


# ────────────────────── YELLOW TOOLS (new — root-cause depth) ──────────────────

def reset_opcache(pool: str) -> dict:
    """Clears PHP opcode cache for a pool by reloading its workers — fixes the
    common 'deployed a fix but the 500 keeps happening' case caused by stale
    cached bytecode. Implemented via systemctl reload for now; swap in a
    precise opcache_reset() call (e.g. via cachetool) later without changing
    the calling contract."""
    if pool not in ALLOWED_SERVICES or "php-fpm" not in pool:
        return {"ok": False, "error": f"pool '{pool}' not in allow-list"}
    r = _run(["systemctl", "reload", pool], timeout=20)
    return {"ok": r["ok"], "pool": pool, "stderr": r["stderr"]}


# ─────────────────────────── VERIFICATION TOOLS ───────────────────────────

def verify_http_check(url: str) -> dict:
    return http_check(url)


def verify_disk_usage(path: str = "/", threshold_percent: float = 85.0) -> dict:
    d = disk_usage(path)
    d["under_threshold"] = d["percent_used"] < threshold_percent
    return d