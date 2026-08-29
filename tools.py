"""
tools.py — Strictly typed, safe system interaction tools for Agent 500.
"""

import subprocess
import socket
import shutil
import os
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


# GREEN TOOLS
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


# YELLOW TOOLS
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


# VERIFICATION TOOLS
def verify_http_check(url: str) -> dict:
    return http_check(url)


def verify_disk_usage(path: str = "/", threshold_percent: float = 85.0) -> dict:
    d = disk_usage(path)
    d["under_threshold"] = d["percent_used"] < threshold_percent
    return d