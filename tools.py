"""
tools.py — Strictly typed, read-only diagnostic tools for Agent 500.

Purpose:
    Provide evidence-based HTTP 500 root-cause investigation for
    DirectAdmin-style nginx -> Apache -> PHP-FPM hosting stacks.

Design principles:
    - Diagnostic tools are read-only.
    - File inspection is restricted to webroot-like locations.
    - PHP source is inspected without executing the application.
    - PHP syntax is checked with `php -l`.
    - Recent file changes are correlated with the incident.
    - Logs are inspected with recency awareness.
    - Mutating operations remain explicitly separated.
"""

import datetime
import grp
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path

import domain_resolver


# ============================================================================
# CONFIGURATION
# ============================================================================

ALLOWED_SERVICES = {
    "nginx",
    "httpd",
    "php-fpm74",
    "php-fpm81",
    "php-fpm82",
    "php-fpm83",
}


# Database services are readable (status-check only) but intentionally kept
# OUT of ALLOWED_SERVICES itself, so restart_service / reload_workers /
# reset_opcache — which all gate on ALLOWED_SERVICES — can never target them.
# Database-side fixes are out of auto-fix scope; only detection is allowed.
DB_STATUS_SERVICES = {
    "mysql",
    "mysqld",
    "mariadb",
}

# Union used only by the read-only check_service() tool.
ALLOWED_STATUS_SERVICES = ALLOWED_SERVICES | DB_STATUS_SERVICES


# Multi-domain support.
#
# The webroot and per-domain log paths are NO LONGER hardcoded to a single
# domain. Every investigation must call resolve_domain(domain) first (see
# below); the resolved domain's webroot and log paths are then used
# automatically by every domain-aware tool in this module
# (check_recent_file_changes, read_log, analyze_log_patterns,
# safe_log_cleanup, check_fpm_pool_status).
#
# AGENT500_WEBROOT is kept ONLY as a legacy manual override for ad-hoc
# local testing outside the normal agent flow (i.e. when no domain has
# been resolved yet via resolve_domain()). Normal operation never needs it.
_LEGACY_WEBROOT_OVERRIDE = os.getenv("AGENT500_WEBROOT")


# Only files below these locations may be inspected by read-only file tools.
#
# This prevents an LLM tool call from arbitrarily reading sensitive files such
# as /etc/shadow or /root/.ssh/id_rsa. This boundary already covers every
# domain's home directory, so it needed no change to support multiple
# domains.
ALLOWED_FILE_ROOTS = [
    "/home/",
    "/usr/local/directadmin/data/users/",
]


# Log locations that are system-wide — i.e. NOT specific to any one
# domain — and therefore never change based on which domain is under
# investigation.
SYSTEM_LOG_PATHS = {
    "nginx_system": "/var/log/nginx/error_log",
    "httpd_system": "/var/log/httpd/error_log",
    "nginx_access": "/var/log/nginx/access.log",
}

# log_key values that are resolved dynamically, per the currently active
# domain (set by resolve_domain()), rather than from a fixed path.
PER_DOMAIN_LOG_KEYS = {"nginx_error", "httpd_error", "php_fpm"}

# Full allow-list of valid log_key values a tool call may use. Union of
# the system-wide keys and the per-domain keys. Kept under the original
# name ALLOWED_LOG_PATHS for membership checks (`log_key not in
# ALLOWED_LOG_PATHS`); actual path lookup for per-domain keys happens in
# _resolve_log_path(), not through this dict.
ALLOWED_LOG_PATHS = {
    **SYSTEM_LOG_PATHS,
    "nginx_error": None,
    "httpd_error": None,
    "php_fpm": None,
}


# ============================================================================
# ACTIVE DOMAIN CONTEXT — MULTI-DOMAIN SUPPORT
# ============================================================================
#
# resolve_domain() is the new tool that replaces the old single-domain
# hardcoding. It must be called first, before any other diagnostic tool,
# for every investigation (see llm_agent.py SYSTEM_PROMPT, Phase 0). On
# success it stores the resolved domain's webroot/log paths here; every
# other domain-aware tool below (check_recent_file_changes, read_log,
# analyze_log_patterns, safe_log_cleanup, check_fpm_pool_status) then
# automatically targets that domain — no other code needs to change per
# domain, and no domain is special-cased.

_active_domain_context = None


def resolve_domain(domain: str) -> dict:
    """
    Resolve a domain/subdomain given anywhere in the operator's request
    to the DirectAdmin account and webroot that hosts it on *this*
    server. Works for any domain hosted here, including subdomains.

    MUST be called first, before any other diagnostic tool, for every
    investigation. On success, every other domain-aware tool in this
    module automatically targets the resolved domain. On failure (the
    domain is not hosted on this server), no other tool should be
    called for this investigation — the error explains exactly what was
    checked.
    """

    global _active_domain_context

    result = domain_resolver.resolve_domain(domain)

    if result.get("ok"):
        _active_domain_context = result

    return result


def _require_domain_context():
    """
    Return (context, error_result) — exactly one of the two is not None.

    context is the dict last returned by a successful resolve_domain()
    call. error_result, when present, is a ready-to-return {"ok": False,
    "error": ...} dict explaining that resolve_domain() must be called
    first.
    """

    if _active_domain_context is not None:
        return _active_domain_context, None

    # Legacy manual-override path — only used for local/manual testing
    # outside the normal agent flow, when no domain has been resolved.
    if _LEGACY_WEBROOT_OVERRIDE:
        return {
            "domain": None,
            "webroot": _LEGACY_WEBROOT_OVERRIDE,
            "log_paths": {key: None for key in PER_DOMAIN_LOG_KEYS},
            "parent_log_paths": None,
        }, None

    return None, {
        "ok": False,
        "error": (
            "No domain has been resolved yet. Call resolve_domain(domain) "
            "before using this tool."
        ),
    }


def _resolve_log_path(log_key: str):
    """
    Resolve a log_key to an actual filesystem path.

    System-wide keys (nginx_system, httpd_system, nginx_access) resolve
    immediately, unchanged regardless of domain. Per-domain keys
    (nginx_error, httpd_error, php_fpm) resolve against whichever domain
    was last resolved via resolve_domain().

    Returns (path_or_None, error_message_or_None).
    """

    if log_key in SYSTEM_LOG_PATHS:
        return SYSTEM_LOG_PATHS[log_key], None

    if log_key not in PER_DOMAIN_LOG_KEYS:
        return None, f"log_key '{log_key}' not in allow-list"

    context, err = _require_domain_context()

    if err:
        return None, err["error"]

    return context["log_paths"].get(log_key), None


# ============================================================================
# KNOWN ROOT-CAUSE SIGNATURES
# ============================================================================

LOG_PATTERNS = [
    {
        "category": "permission_denied",
        "pattern": r"[Pp]ermission denied",
        "severity": "high",
        "hint": (
            "Permission/ownership problem. Extract the exact file path "
            "from the evidence and call check_file_permissions(path)."
        ),
    },
    {
        "category": "fpm_max_children",
        "pattern": r"server reached pm\.max_children",
        "severity": "high",
        "hint": (
            "PHP-FPM worker pool exhaustion. Call "
            "check_fpm_pool_status(pool) to confirm."
        ),
    },
    {
        "category": "socket_missing",
        "pattern": (
            r"connect\(\) to unix:.*failed|"
            r"AH02454.*attempt to connect to Unix domain socket|"
            r"AH01079: failed to make connection to backend"
        ),
        "severity": "high",
        "hint": (
            "Backend Unix socket failure. Extract the exact socket path "
            "and call check_socket(path)."
        ),
    },
    {
        "category": "php_fatal_error",
        "pattern": r"PHP Fatal error:",
        "severity": "high",
        "hint": (
            "PHP application fatal error. Quote the exact fatal error "
            "and source line if available."
        ),
    },
    {
        "category": "php_parse_error",
        "pattern": r"PHP Parse error:",
        "severity": "high",
        "hint": (
            "PHP syntax/parse error. Inspect the referenced source file "
            "and confirm with php_lint(path)."
        ),
    },
    {
        "category": "php_warning",
        "pattern": r"PHP Warning:",
        "severity": "medium",
        "hint": (
            "PHP warning detected. Do not automatically classify it as "
            "the root cause unless the evidence explicitly connects it "
            "to the HTTP 500."
        ),
    },
    {
        "category": "execution_timeout",
        "pattern": r"Maximum execution time|upstream timed out",
        "severity": "medium",
        "hint": (
            "Execution/upstream timeout. Report the exact evidence line."
        ),
    },
    {
        "category": "htaccess_error",
        "pattern": r"\.htaccess:.*(Invalid command|not allowed here)",
        "severity": "medium",
        "hint": (
            "Malformed .htaccess directive. Report exact evidence."
        ),
    },
    {
        "category": "selinux_denial",
        "pattern": r"avc:\s+denied",
        "severity": "medium",
        "hint": (
            "SELinux denial detected. Call check_selinux_denials()."
        ),
    },
    {
        "category": "db_connection",
        "pattern": (
            r"SQLSTATE|Connection refused|Too many connections|"
            r"mysqli.*connect|PDOException"
        ),
        "severity": "high",
        "hint": (
            "Database connectivity/exhaustion symptom. Call "
            "check_db_connectivity(host, port) when host/port are known."
        ),
    },
    {
        "category": "upstream_502",
        "pattern": r"upstream.*(failed|sent invalid|closed connection)",
        "severity": "high",
        "hint": (
            "Upstream/backend communication failure. Inspect the exact "
            "upstream evidence before drawing a conclusion."
        ),
    },
]


# ============================================================================
# LOW-LEVEL SAFE COMMAND EXECUTION
# ============================================================================

def _run(cmd: list[str], timeout: int = 10) -> dict:
    """
    Execute a fixed argv list without shell interpolation.

    This intentionally does NOT use shell=True.
    """

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return {
            "ok": p.returncode == 0,
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
        }

    except FileNotFoundError:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": "command not found",
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": "timeout",
        }

    except Exception as exc:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
        }


# ============================================================================
# PATH SAFETY
# ============================================================================

def _is_allowed_file_path(path: str) -> bool:
    """
    Verify that a path is inside one of the explicitly allowed roots.

    Uses realpath so symlinks cannot trivially bypass the boundary.
    """

    try:
        candidate = os.path.realpath(path)

        for root in ALLOWED_FILE_ROOTS:
            allowed_root = os.path.realpath(root)

            if candidate == allowed_root:
                return True

            if candidate.startswith(allowed_root.rstrip("/") + "/"):
                return True

        return False

    except Exception:
        return False


def _validate_readable_file(path: str) -> tuple[bool, str]:
    """
    Validate that a path is an existing regular file in an allowed area.
    """

    if not path:
        return False, "empty path"

    if not _is_allowed_file_path(path):
        return False, f"path outside allowed diagnostic roots: {path}"

    if not os.path.exists(path):
        return False, f"file not found: {path}"

    if not os.path.isfile(path):
        return False, f"path is not a regular file: {path}"

    return True, ""


# ============================================================================
# HTTP
# ============================================================================

def http_check(url: str, timeout: int = 5) -> dict:
    """
    Perform an HTTP health check.
    """

    import urllib.error
    import urllib.request

    start = time.time()

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "agent500-healthcheck",
                "Accept": "*/*",
            },
        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = round((time.time() - start) * 1000)
            body_snippet = resp.read(4000).decode("utf-8", errors="ignore")

            return {
                "ok": True,
                "status_code": resp.status,
                "elapsed_ms": elapsed,
                "error": None,
                "body_snippet": body_snippet,
            }

    except urllib.error.HTTPError as exc:
        elapsed = round((time.time() - start) * 1000)
        try:
            body_snippet = exc.read(4000).decode("utf-8", errors="ignore")
        except Exception:
            body_snippet = None

        return {
            "ok": False,
            "status_code": exc.code,
            "elapsed_ms": elapsed,
            "error": f"http_error_{exc.code}",
            "body_snippet": body_snippet,
        }

    except Exception as exc:
        elapsed = round((time.time() - start) * 1000)

        return {
            "ok": False,
            "status_code": None,
            "elapsed_ms": elapsed,
            "error": str(exc),
        }


# ============================================================================
# SERVICES
# ============================================================================

def check_service(name: str) -> dict:
    if name not in ALLOWED_STATUS_SERVICES:
        return {
            "ok": False,
            "error": f"service '{name}' not in allow-list",
        }

    r = _run(["systemctl", "is-active", name])

    state = r["stdout"] or "unknown"

    return {
        "ok": True,
        "service": name,
        "state": state,
        "active": state == "active",
    }


# ============================================================================
# PORTS
# ============================================================================

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

            if (
                f":{port} " in line
                or line.strip().endswith(f":{port}")
                or f":{port}\n" in line
            ):
                owner = line.strip()
                break

    return {
        "ok": True,
        "host": host,
        "port": port,
        "listening": listening,
        "owner_line": owner,
    }


# ============================================================================
# DISK
# ============================================================================

def disk_usage(path: str = "/") -> dict:
    try:
        total, used, free = shutil.disk_usage(path)
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }

    percent_used = round((used / total) * 100, 1)

    log_dir_size = None

    du = _run(["du", "-sh", "/var/log"])

    if du["ok"] and du["stdout"]:
        log_dir_size = du["stdout"].split()[0]

    return {
        "ok": True,
        "path": path,
        "percent_used": percent_used,
        "total_gb": round(total / 1e9, 2),
        "used_gb": round(used / 1e9, 2),
        "free_gb": round(free / 1e9, 2),
        "var_log_size": log_dir_size,
    }


# ============================================================================
# LOG READING
# ============================================================================

def read_log(log_key: str, lines: int = 100) -> dict:
    """
    Read an allow-listed log.

    The caller can request a larger tail, but it is capped to avoid
    accidentally returning enormous logs to the LLM.
    """

    if log_key not in SYSTEM_LOG_PATHS and log_key not in PER_DOMAIN_LOG_KEYS:
        return {
            "ok": False,
            "error": f"log_key '{log_key}' not in allow-list",
            "content": None,
        }

    try:
        lines = max(1, min(int(lines), 1000))
    except Exception:
        lines = 100

    path, err = _resolve_log_path(log_key)

    if err:
        return {
            "ok": False,
            "error": err,
            "content": None,
        }

    # Domain-specific log fallback.
    #
    # Step 1: for a subdomain that doesn't have its own dedicated log
    # file, try the parent domain's log — DirectAdmin subdomains
    # normally share the parent's vhost/log by default.
    if not os.path.exists(path) and log_key in PER_DOMAIN_LOG_KEYS:
        context, _ = _require_domain_context()

        parent_log_paths = (context or {}).get("parent_log_paths")

        if parent_log_paths:
            parent_path = parent_log_paths.get(log_key)

            if parent_path and os.path.exists(parent_path):
                path = parent_path

    # Step 2: fall back to the system-wide log of the same kind.
    if not os.path.exists(path):

        if log_key in ("nginx_error", "nginx_access"):
            path = SYSTEM_LOG_PATHS["nginx_system"]

        elif log_key in ("httpd_error", "php_fpm"):
            path = SYSTEM_LOG_PATHS["httpd_system"]

    if not os.path.exists(path):
        return {
            "ok": False,
            "error": f"file not found at {path}",
            "content": None,
        }

    r = _run(
        ["tail", "-n", str(lines), path],
        timeout=10,
    )

    return {
        "ok": r["ok"],
        "path": path,
        "content": r["stdout"],
        "error": r["stderr"] or None,
    }


# ============================================================================
# NGINX
# ============================================================================

def nginx_config_test() -> dict:
    r = _run(["nginx", "-t"], timeout=15)

    return {
        "ok": r["ok"],
        "valid": r["ok"],
        "detail": r["stderr"] or r["stdout"],
    }


# ============================================================================
# LOG TIMESTAMP PARSING
# ============================================================================

_APACHE_TS_RE = re.compile(
    r"\[(\w{3} \w{3} \d{1,2} "
    r"\d{2}:\d{2}:\d{2})(?:\.\d+)? "
    r"(\d{4})\]"
)

_NGINX_TS_RE = re.compile(
    r"(\d{4}/\d{2}/\d{2} "
    r"\d{2}:\d{2}:\d{2})"
)


def _parse_log_timestamp(line: str):
    """
    Best-effort timestamp parser.

    Returns None when timestamp format is unknown.
    """

    match = _APACHE_TS_RE.search(line)

    if match:
        try:
            return datetime.datetime.strptime(
                f"{match.group(1)} {match.group(2)}",
                "%a %b %d %H:%M:%S %Y",
            )
        except ValueError:
            return None

    match = _NGINX_TS_RE.search(line)

    if match:
        try:
            return datetime.datetime.strptime(
                match.group(1),
                "%Y/%m/%d %H:%M:%S",
            )
        except ValueError:
            return None

    return None


# ============================================================================
# LOG PATTERN ANALYSIS
# ============================================================================

def analyze_log_patterns(
    log_key: str,
    lines: int = 300,
    recent_minutes: int = 15,
) -> dict:
    """
    Scan logs for known root-cause signatures.

    IMPORTANT:
        A match is only considered current evidence if its timestamp is
        inside the requested recent window.

    Unknown/unparseable timestamps are retained because the tool cannot prove
    that they are stale.
    """

    log_result = read_log(log_key, lines=lines)

    content = log_result.get("content") or ""

    if not content:
        return {
            "ok": log_result.get("ok", False),
            "log_key": log_key,
            "matches": [],
            "clean": True,
            "error": log_result.get("error"),
        }

    now = datetime.datetime.now()

    matches = []

    for rule in LOG_PATTERNS:

        matched_lines = [
            line
            for line in content.splitlines()
            if re.search(rule["pattern"], line, re.IGNORECASE)
        ]

        if not matched_lines:
            continue

        recent_lines = []
        stale_lines = []

        for line in matched_lines:

            timestamp = _parse_log_timestamp(line)

            if timestamp is None:
                # We cannot prove that it is stale.
                recent_lines.append(line)
                continue

            age_seconds = (now - timestamp).total_seconds()

            if age_seconds <= recent_minutes * 60:
                recent_lines.append(line)
            else:
                stale_lines.append(line)

        if recent_lines:
            matches.append(
                {
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "hint": rule["hint"],
                    "occurrences": len(recent_lines),
                    "sample_lines": recent_lines[-5:],
                    "stale_occurrences_ignored": len(stale_lines),
                }
            )

    return {
        "ok": True,
        "log_key": log_key,
        "matches": matches,
        "clean": len(matches) == 0,
        "recent_window_minutes": recent_minutes,
        "lines_scanned": len(content.splitlines()),
    }


# ============================================================================
# FILE PERMISSIONS
# ============================================================================

def check_file_permissions(path: str) -> dict:
    """
    Inspect owner/group/mode/access for a file.

    This tool is diagnostic only.
    """

    if not os.path.exists(path):
        return {
            "ok": False,
            "error": f"path not found: {path}",
        }

    try:
        st = os.stat(path)

        return {
            "ok": True,
            "path": path,
            "owner": pwd.getpwuid(st.st_uid).pw_name,
            "group": grp.getgrgid(st.st_gid).gr_name,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "mode_numeric": stat.S_IMODE(st.st_mode),
            "is_file": stat.S_ISREG(st.st_mode),
            "is_directory": stat.S_ISDIR(st.st_mode),
            "readable": os.access(path, os.R_OK),
            "writable": os.access(path, os.W_OK),
            "executable": os.access(path, os.X_OK),
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }


# ============================================================================
# SOURCE FILE READING — IMPORTANT NEW TOOL
# ============================================================================

def read_file(
    path: str,
    max_lines: int = 250,
    max_bytes: int = 50000,
) -> dict:
    """
    Read source/configuration files for diagnostic inspection.

    SECURITY:
        Only files under ALLOWED_FILE_ROOTS can be read.

    SAFETY:
        This function NEVER executes the file.
    """

    valid, error = _validate_readable_file(path)

    if not valid:
        return {
            "ok": False,
            "path": path,
            "error": error,
        }

    try:
        max_lines = max(1, min(int(max_lines), 1000))
        max_bytes = max(1024, min(int(max_bytes), 200000))
    except Exception:
        max_lines = 250
        max_bytes = 50000

    try:
        file_size = os.path.getsize(path)

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as f:

            output_lines = []
            total_bytes = 0
            truncated = False

            for number, line in enumerate(f, start=1):

                encoded_size = len(line.encode("utf-8", errors="replace"))

                if number > max_lines:
                    truncated = True
                    break

                if total_bytes + encoded_size > max_bytes:
                    truncated = True
                    break

                output_lines.append(
                    f"{number}: {line.rstrip()}"
                )

                total_bytes += encoded_size

        return {
            "ok": True,
            "path": path,
            "file_size_bytes": file_size,
            "lines_returned": len(output_lines),
            "truncated": truncated,
            "content": "\n".join(output_lines),
        }

    except Exception as exc:
        return {
            "ok": False,
            "path": path,
            "error": str(exc),
        }


# ============================================================================
# PHP SYNTAX LINT — IMPORTANT NEW TOOL
# ============================================================================

def php_lint(path: str) -> dict:
    """
    Validate PHP syntax using:

        php -l <file>

    IMPORTANT:
        php -l parses the PHP file but does not run the web application.

    This is particularly important for:
        - parse errors
        - unexpected tokens
        - missing semicolons
        - malformed PHP syntax
        - certain compile-time/fatal problems
    """

    valid, error = _validate_readable_file(path)

    if not valid:
        return {
            "ok": False,
            "path": path,
            "valid": False,
            "error": error,
        }

    if not path.lower().endswith(".php"):
        return {
            "ok": False,
            "path": path,
            "valid": False,
            "error": "php_lint only accepts .php files",
        }

    r = _run(
        ["php", "-l", path],
        timeout=10,
    )

    return {
        "ok": True,
        "path": path,
        "valid": r["ok"],
        "returncode": r["returncode"],
        "stdout": r["stdout"],
        "stderr": r["stderr"],
    }


# ============================================================================
# PHP SOURCE INSPECTION
# ============================================================================

def inspect_php_file(
    path: str,
    max_lines: int = 300,
) -> dict:
    """
    Combined PHP diagnostic:

        1. read source
        2. PHP syntax lint
        3. identify obvious high-risk source constructs

    It does NOT execute the PHP file.
    """

    valid, error = _validate_readable_file(path)

    if not valid:
        return {
            "ok": False,
            "path": path,
            "error": error,
        }

    if not path.lower().endswith(".php"):
        return {
            "ok": False,
            "path": path,
            "error": "inspect_php_file requires a .php file",
        }

    source_result = read_file(
        path,
        max_lines=max_lines,
    )

    lint_result = php_lint(path)

    source = source_result.get("content") or ""

    suspicious_constructs = []

    # These are evidence flags, NOT automatic root-cause declarations.
    #
    # The LLM must correlate these with HTTP 500 and other evidence.
    patterns = [
        (
            r"\bundefined_function\b",
            "literal undefined_function identifier present",
        ),
        (
            r"\b(?:eval|assert)\s*\(",
            "dynamic code execution construct present",
        ),
        (
            r"\btrigger_error\s*\(",
            "trigger_error() call present",
        ),
        (
            r"\bexit\s*\(",
            "exit() call present",
        ),
        (
            r"\bdie\s*\(",
            "die() call present",
        ),
    ]

    for pattern, description in patterns:
        if re.search(pattern, source, re.IGNORECASE):
            suspicious_constructs.append(description)

    return {
        "ok": source_result.get("ok", False) and lint_result.get("ok", False),
        "path": path,
        "source": source,
        "source_read_ok": source_result.get("ok", False),
        "lint": lint_result,
        "suspicious_constructs": suspicious_constructs,
    }


# ============================================================================
# PHP.INI VALIDATION
# ============================================================================

def check_php_ini(pool: str = None) -> dict:
    """
    Validate the currently active php.ini for parse-level corruption.

    Rather than needing to know or read an arbitrary php.ini filesystem
    path (php.ini normally lives outside ALLOWED_FILE_ROOTS, e.g. under
    /usr/local/phpXX/lib or /etc), this asks PHP itself: it runs a short
    `php -r` snippet that calls php_ini_loaded_file() to find the active
    ini, then parse_ini_file() to confirm it is syntactically valid.

    IMPORTANT:
        Read-only. Never modifies php.ini. Does not run the web application.

    Args:
        pool: optional PHP-FPM pool name from ALLOWED_SERVICES
              (e.g. "php-fpm81"). When given, the matching versioned CLI
              binary is used if present, so the check reflects that
              pool's own php.ini rather than the system default `php`.
    """

    binary = "php"

    if pool:
        if pool not in ALLOWED_SERVICES or "php-fpm" not in pool:
            return {
                "ok": False,
                "error": f"pool '{pool}' not in allow-list",
            }

        version_suffix = pool.replace("php-fpm", "")
        candidate = f"/usr/local/php{version_suffix}/bin/php"

        if os.path.exists(candidate):
            binary = candidate

    php_snippet = (
        "$f = php_ini_loaded_file();"
        "if ($f === false) { echo json_encode(['loaded' => false]); exit; }"
        "$parsed = @parse_ini_file($f, false, INI_SCANNER_RAW);"
        "echo json_encode(["
        "'loaded' => true, 'path' => $f, 'valid' => $parsed !== false"
        "]);"
    )

    r = _run(
        [binary, "-d", "display_errors=0", "-r", php_snippet],
        timeout=10,
    )

    if not r["ok"]:
        return {
            "ok": False,
            "binary": binary,
            "error": r["stderr"] or "php execution failed",
        }

    try:
        payload = json.loads(r["stdout"])
    except Exception:
        return {
            "ok": False,
            "binary": binary,
            "error": "could not parse php.ini diagnostic output",
            "raw_stdout": r["stdout"],
        }

    return {
        "ok": True,
        "binary": binary,
        "ini_loaded": payload.get("loaded", False),
        "ini_path": payload.get("path"),
        "ini_valid": payload.get("valid"),
    }


# ============================================================================
# SOCKET
# ============================================================================

def check_socket(path: str) -> dict:
    """
    Check existence and connectivity of a Unix domain socket.
    """

    if not os.path.exists(path):
        return {
            "ok": False,
            "exists": False,
            "error": f"socket file not found: {path}",
        }

    try:
        file_stat = os.stat(path)
    except Exception as exc:
        return {
            "ok": False,
            "exists": True,
            "error": str(exc),
        }

    is_socket = stat.S_ISSOCK(file_stat.st_mode)

    listening = False

    if is_socket:

        sock = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        sock.settimeout(2)

        try:
            sock.connect(path)
            listening = True

        except Exception:
            listening = False

        finally:
            sock.close()

    return {
        "ok": True,
        "path": path,
        "exists": True,
        "is_socket": is_socket,
        "listening": listening,
        "permissions": check_file_permissions(path),
    }


# ============================================================================
# PHP-FPM
# ============================================================================

def check_fpm_pool_status(pool: str) -> dict:
    """
    Inspect PHP-FPM process count and recent max_children evidence.
    """

    if pool not in ALLOWED_SERVICES or "php-fpm" not in pool:
        return {
            "ok": False,
            "error": f"pool '{pool}' not in allow-list",
        }

    ps = _run(
        ["pgrep", "-fc", pool],
        timeout=5,
    )

    worker_count = None

    if ps["stdout"].isdigit():
        worker_count = int(ps["stdout"])

    hits = []

    php_fpm_log_path, _ = _resolve_log_path("php_fpm")

    candidates = [
        f"/var/log/php-fpm/{pool}/error.log",
        "/var/log/php-fpm/error.log",
        php_fpm_log_path,
    ]

    for candidate in candidates:

        if not candidate or not os.path.exists(candidate):
            continue

        grep = _run(
            [
                "grep",
                "-i",
                "-E",
                r"max_children|server reached pm\.max_children",
                candidate,
            ],
            timeout=5,
        )

        if grep["stdout"]:
            hits.append(
                {
                    "log": candidate,
                    "matches": grep["stdout"].splitlines()[-10:],
                }
            )

    return {
        "ok": True,
        "pool": pool,
        "active_worker_count": worker_count,
        "max_children_hits": hits,
    }


# ============================================================================
# SELINUX
# ============================================================================

def check_selinux_denials() -> dict:
    """
    Check SELinux state and recent AVC denials.
    """

    enforce = _run(["getenforce"])

    if enforce["stderr"] == "command not found":
        return {
            "ok": True,
            "applicable": False,
            "detail": "SELinux tooling not present on this host",
        }

    mode = enforce["stdout"].strip()

    if mode.lower() != "enforcing":
        return {
            "ok": True,
            "applicable": False,
            "mode": mode,
            "detail": "SELinux is not enforcing",
        }

    result = _run(
        ["ausearch", "-m", "avc", "-ts", "recent"],
        timeout=10,
    )

    return {
        "ok": True,
        "applicable": True,
        "mode": mode,
        "denials": result["stdout"] or None,
        "detail": result["stderr"] or None,
    }


# ============================================================================
# RECENT FILE CHANGES
# ============================================================================

def check_recent_file_changes(
    path: str = None,
    minutes: int = 30,
) -> dict:
    """
    Find files changed recently below the site's webroot.

    The returned list is sorted by modification time, newest first.

    If `path` is not given, the webroot of whichever domain was last
    resolved via resolve_domain() is used automatically — this is the
    normal way to call this tool (see llm_agent.py SYSTEM_PROMPT: never
    guess a path here).
    """

    if not path:
        context, err = _require_domain_context()

        if err:
            return err

        path = context["webroot"]

    if not path:
        return {
            "ok": False,
            "error": "webroot path is empty",
        }

    if not os.path.exists(path):
        return {
            "ok": False,
            "error": f"path not found: {path}",
        }

    if not os.path.isdir(path):
        return {
            "ok": False,
            "error": f"path is not a directory: {path}",
        }

    try:
        minutes = max(1, min(int(minutes), 1440))
    except Exception:
        minutes = 30

    # Use find only for discovery; no user-provided shell expression.
    r = _run(
        [
            "find",
            path,
            "-type",
            "f",
            "-mmin",
            f"-{minutes}",
            "-printf",
            "%T@ %p\n",
        ],
        timeout=15,
    )

    if not r["ok"]:
        return {
            "ok": False,
            "path": path,
            "error": r["stderr"] or "find failed",
        }

    files = []

    for line in r["stdout"].splitlines():

        try:
            timestamp_text, file_path = line.split(" ", 1)
            timestamp = float(timestamp_text)

            files.append(
                {
                    "path": file_path,
                    "mtime_epoch": timestamp,
                    "mtime": datetime.datetime.fromtimestamp(
                        timestamp
                    ).isoformat(
                        sep=" ",
                        timespec="seconds",
                    ),
                }
            )

        except ValueError:
            continue

    files.sort(
        key=lambda item: item["mtime_epoch"],
        reverse=True,
    )

    files = files[:100]

    php_files = [
        item["path"]
        for item in files
        if item["path"].lower().endswith(".php")
    ]

    return {
        "ok": True,
        "path": path,
        "window_minutes": minutes,
        "count": len(files),
        "recently_changed_files": files,
        "recent_php_files": php_files,
    }


# ============================================================================
# DATABASE CONNECTIVITY
# ============================================================================

def check_db_connectivity(
    host: str,
    port: int = 3306,
    timeout: int = 3,
) -> dict:
    """
    Read-only TCP connectivity test.
    """

    start = time.time()

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(timeout)

    try:
        sock.connect((host, port))

        return {
            "ok": True,
            "host": host,
            "port": port,
            "reachable": True,
            "elapsed_ms": round(
                (time.time() - start) * 1000
            ),
        }

    except Exception as exc:
        return {
            "ok": False,
            "host": host,
            "port": port,
            "reachable": False,
            "error": str(exc),
            "elapsed_ms": round(
                (time.time() - start) * 1000
            ),
        }

    finally:
        sock.close()


# ============================================================================
# MUTATING TOOLS
# ============================================================================

def restart_service(name: str) -> dict:

    if name not in ALLOWED_SERVICES:
        return {
            "ok": False,
            "error": f"service '{name}' not in allow-list",
        }

    r = _run(
        ["systemctl", "restart", name],
        timeout=20,
    )

    return {
        "ok": r["ok"],
        "service": name,
        "stderr": r["stderr"],
    }


def reload_workers(name: str) -> dict:

    if name not in ALLOWED_SERVICES:
        return {
            "ok": False,
            "error": f"service '{name}' not in allow-list",
        }

    r = _run(
        ["systemctl", "reload", name],
        timeout=20,
    )

    return {
        "ok": r["ok"],
        "service": name,
        "stderr": r["stderr"],
    }


def safe_log_cleanup(log_key: str) -> dict:

    if log_key not in SYSTEM_LOG_PATHS and log_key not in PER_DOMAIN_LOG_KEYS:
        return {
            "ok": False,
            "error": f"log_key '{log_key}' not in allow-list",
        }

    path, err = _resolve_log_path(log_key)

    if err:
        return {
            "ok": False,
            "error": err,
        }

    if not path or not os.path.exists(path):
        return {
            "ok": False,
            "error": "file not found",
        }

    archive_path = f"{path}.{int(time.time())}.gz"

    # Keep shell out of normal diagnostic operations.
    #
    # This operation is YELLOW and requires approval through safety.py.
    #
    # bash is retained here because gzip redirection + truncate need to
    # operate atomically enough for this existing tool contract.
    safe_path = path.replace("'", "'\\''")
    safe_archive = archive_path.replace("'", "'\\''")

    command = (
        f"gzip -c '{safe_path}' > '{safe_archive}' "
        f"&& truncate -s 0 '{safe_path}'"
    )

    r = _run(
        ["bash", "-c", command],
        timeout=30,
    )

    return {
        "ok": r["ok"],
        "archived_to": archive_path if r["ok"] else None,
        "error": r["stderr"] or None,
    }


def reset_opcache(pool: str) -> dict:
    """
    Reload the selected PHP-FPM pool.

    This remains a mutating/YELLOW operation.
    """

    if pool not in ALLOWED_SERVICES or "php-fpm" not in pool:
        return {
            "ok": False,
            "error": f"pool '{pool}' not in allow-list",
        }

    r = _run(
        ["systemctl", "reload", pool],
        timeout=20,
    )

    return {
        "ok": r["ok"],
        "pool": pool,
        "stderr": r["stderr"],
    }


# ============================================================================
# VERIFICATION TOOLS
# ============================================================================

def verify_http_check(url: str) -> dict:
    return http_check(url)


def verify_disk_usage(
    path: str = "/",
    threshold_percent: float = 85.0,
) -> dict:

    result = disk_usage(path)

    if not result.get("ok"):
        return result

    result["under_threshold"] = (
        result["percent_used"] < threshold_percent
    )

    return result