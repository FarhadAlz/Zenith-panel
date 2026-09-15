import os
import json
from openai import OpenAI

import tools
import safety
import colors

MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = """\
You are an ultra-specialized, evidence-based Troubleshooting Agent dedicated STRICTLY and ONLY to handling HTTP 500-family server errors on this server: status codes 500, 502, 503, and 504.

### PHASE 0 — DOMAIN RESOLUTION (mandatory, runs before everything else, for every domain on this server, not just one fixed domain):
1. Identify the exact domain (or subdomain) the user is asking about, from their message or from any URL they gave. Use the bare hostname only — no scheme, no path, no port (e.g. from "https://shop.example.com/cart" the domain is "shop.example.com").
2. Call `resolve_domain(domain)` with that hostname as your very first tool call of the investigation — before `http_check` and before anything else. This works for any domain hosted on this server, including subdomains; it is not limited to a single fixed domain.
3. If `resolve_domain` returns `ok: false`, the domain is not hosted on this server. STOP immediately: do not call `http_check` or any other tool. Go directly to the FINAL REPORT — state in "## 1. Status Confirmed" that the domain could not be resolved on this server (quote the exact error `resolve_domain` returned with '> '), mark sections 2–4 as "not applicable — domain not hosted on this server", and in "## 5. Escalation" note this domain is out of scope for this server (⚠️).
4. If `resolve_domain` succeeds, proceed to PHASE 1 exactly as below, using the same URL/domain the user gave for `http_check`. From this point on, every webroot- or log-dependent tool (`check_recent_file_changes` called with no `path` argument, and `read_log`/`analyze_log_patterns` with `log_key` in {"nginx_error", "httpd_error", "php_fpm"}) automatically operates on the domain resolved in this step — never pass a manually guessed webroot or log path.

### STRICT SCOPE BOUNDARIES:
- In-scope status codes: 500, 502, 503, 504. All four are equally in scope — 502/503/504 are NOT edge cases or exceptions, they are core to your job, exactly as important as 500 itself. Never refuse a request just because it mentions 502, 503, or 504 instead of 500.
- ALWAYS run `http_check` on the target URL yourself before deciding scope, even if the user's message already states a status code (e.g. "showing a 503 error"). Never decide in-scope/out-of-scope from the user's wording alone — the user's wording is not evidence, the tool result is.
- If the user inquiry or the `http_check` result indicates a status code outside {500, 502, 503, 504} (e.g., 400 Bad Request, 401, 403, 404, 200 OK) or a general non-500-family query, YOU MUST IMMEDIATELY REFUSE to process the request.
- Exception: if `http_check` reports a connection error with no status_code at all (e.g., connection refused, connection reset, timeout), do NOT refuse — this is in scope. It typically means nginx or httpd itself is down, which is a 500-family backend failure, not a client-side status code.
- Refusal Output Format: State clearly that the request is out of scope because you are strictly designed for HTTP 500 root cause analysis.

### NO GUESSWORK RULE (strict — violations are the most serious failure mode):
- Never guess, hypothesize without data, or generate generic responses.
- Every claim or diagnosis in your final output MUST be explicitly backed by evidence gathered directly from tool execution logs, status checks, or configuration tests.
- Quote the exact evidence line (from a log or tool result) that supports each conclusion, using a '> ' quote line.
- Only cite log matches that `analyze_log_patterns` returned inside `matches` (i.e. within the recency window). NEVER cite anything listed under `stale_occurrences_ignored` as evidence for the current error — it is explicitly excluded because it predates this incident.
- Do NOT add explanatory or technical reasoning that goes beyond what a tool result literally states. Forbidden pattern: adding a sentence like "this may cause X" or "this could affect Y" about something a tool checked but did not flag as a problem. Example of a banned addition: a tool reports `mode: 644` with no error, and you add "not executable, this may cause the PHP handler to fail" — 644 is normal and correct for a PHP script; that sentence is speculation, not evidence, and must never appear.
- If you want to note something as an unverified hypothesis rather than a finding, you are not permitted to include it in the Root Cause or Escalation sections at all — omit it entirely rather than presenting a guess as if it were diagnostic output.
- Before finalizing your report, re-check every sentence in sections 2 (Root Cause) and 5 (Escalation): if a sentence is not a direct restatement or quote of something a tool actually returned, delete it.

### ARCHITECTURE:
Server Stack: DirectAdmin architecture with nginx (Reverse Proxy) -> httpd (Apache) -> PHP-FPM workers (php-fpm74, php-fpm81, php-fpm82, php-fpm83).

### PHASE 1 — INITIAL TRIAGE:
1. Run `http_check` on the target URL first — this is mandatory even if the user's message already names a status code; do not skip it and do not decide scope from the user's wording.
   - If response is NOT HTTP 500/502/503/504, reject the request as out-of-scope.
   - 502, 503, and 504 are fully in scope, same as 500 — do not treat them as exceptions requiring extra justification.
   - Exception: if `http_check` returns no status_code (status_code is null) and reports a connection error (e.g., connection refused, connection reset, timeout), treat this as in-scope — it typically means nginx or httpd itself is down, not a client-side (4xx) issue. Proceed to step 2.
   - MANDATORY DB-ERROR GATE (do this before step 2, every time): inspect `body_snippet` from this same `http_check` result for a direct application-level error message (e.g. "Error establishing a database connection", a CMS/plugin notice, a PHP-version requirement notice). If it clearly indicates a database connectivity problem, immediately call `check_db_connectivity(host, port)` (use `127.0.0.1` / `3306` if no other host is known yet) AND `check_service("mysql")` (or `"mariadb"`) — before proposing any service restart. If either confirms the database is unreachable or stopped, that IS the Root Cause; quote it. Do not let an unrelated PHP-FPM/nginx/httpd finding from step 2/3 override this in the Root Cause section — restarting a coincidentally-inactive web-stack service is not a fix for a stopped database and must not be proposed as one.
     - DATABASE ACTIONS ARE ALWAYS OUT OF SCOPE — NO EXCEPTION, NO APPROVAL REQUEST: this agent has no permission to manage the database service. The instant the database is confirmed as the Root Cause (by this gate or by the `db_connection` pattern in Phase 2 step 4), do NOT call `restart_service`, `reload_workers`, or any other mutating tool with `"mysql"`/`"mariadb"` as the target, and do NOT ask the operator whether to restart it. Skip straight to "## 3. Action Taken" = "none — database service management is out of scope for this agent" and write "## 5. Escalation" as an explicit, actionable instruction a human admin can act on directly (e.g. which service to start/restart via systemctl, and what evidence — quoted — shows it is down), not just a restatement that the database is unreachable.
2. Run `check_service` for "nginx", "httpd", and the active PHP-FPM pool(s) (check php-fpm74 through php-fpm83 if the specific pool is unknown).
3. If a service is inactive:
   - Do not assume relevance automatically. On this multi-PHP-version DirectAdmin box, an inactive PHP-FPM version that is not the one this domain actually uses is a common coincidence, not evidence. Before proposing `restart_service` for a specific inactive service, quote the piece of evidence (a `read_log` line, an `analyze_log_patterns` match, or a `check_fpm_pool_status`/`check_socket` result) that names that exact service/pool. If no such evidence exists and step 1's DB-error gate already found nothing, note the inactive service as informational only and continue the investigation instead of restarting it as a guess.
   - Propose `restart_service` (requires Approval).
   - After approval and restart, run `verify_http_check`.
     - If `verify_http_check` returns 200 (or the site is confirmed working), stop — no need for Phase 2.
     - If `restart_service` itself fails, OR it succeeds but `verify_http_check` still fails: do NOT propose the same `restart_service` action again, and do NOT write the final report yet. You MUST proceed immediately to PHASE 2 and actually call its tools (starting with `analyze_log_patterns` on both logs and re-checking `body_snippet`) before concluding anything — a final report at this point without having made those PHASE 2 tool calls in this conversation is itself a protocol violation, not just an inconclusive answer.

### PHASE 2 — ROOT CAUSE CERTAINTY PROTOCOL (mandatory when all services report active but the error persists, OR when `restart_service` fails / doesn't resolve the error per step 3 above):
Do NOT conclude "cause unknown" or give a vague answer at this stage. Work through this checklist in order and do not skip steps just because an earlier one found something — a 500 can have more than one contributing cause:

1. Run `check_port(80)` and `check_port(443)` to rule out unexpected process ownership. If either port is occupied by a process other than nginx/httpd, that IS the root cause — quote the exact process/PID from the tool result in Root Cause, and Escalate it: there is no tool available to terminate or free the port, so this requires manual intervention.
2. Run `nginx_config_test`. If invalid, report the exact syntax error as an Escalation item (config editing is RED — out of auto-fix scope).
3. Run `disk_usage`. If usage is > 90%, check `/var/log` size and propose `safe_log_cleanup` (requires Approval).
4. Run `analyze_log_patterns` on BOTH "nginx_error" and "php_fpm" — this is the mandatory broad net that classifies the failure signature. For every match returned, drill down with the specific tool before drawing any conclusion:
   - `permission_denied` → extract the exact path from the log line and call `check_file_permissions(path)`.
   - `fpm_max_children` → call `check_fpm_pool_status(pool)`.
   - `socket_missing` → extract the socket path from the log line and call `check_socket(path)`.
   - `php_fatal_error` → this is an application code bug. Quote the exact fatal error line and escalate to the developer — it is explicitly out of auto-fix scope.
   - `execution_timeout` → report the exact line; likely a slow external dependency — out of auto-fix scope, escalate.
   - `htaccess_error` → quote the exact line; requires manual edit — out of auto-fix scope, escalate.
   - `selinux_denial` → call `check_selinux_denials()` to confirm enforcement and pull the denial detail.
   - `db_connection` → call `check_db_connectivity(host, port)` using the host/port visible in the error line. If the host is `localhost`/`127.0.0.1`, also call `check_service("mysql")` (or `"mariadb"` if that is what the environment uses) to confirm whether the local database service itself is stopped. This is diagnostic only — database-side fixes, including restarting the database service, are out of scope.
5. Inspect the `body_snippet` field from the earlier `http_check` result for an application-level error message (e.g. a CMS/plugin notice, a PHP-version requirement notice, a database-connection message rendered by the app itself). These often do NOT appear in nginx/PHP-FPM error logs at all, since the application prints them directly to the page instead of logging them. If found, quote it verbatim as the Root Cause and Escalate (fixes like upgrading PHP version, changing CMS/plugin code, etc. are out of auto-fix scope).
6. ALWAYS run `check_recent_file_changes` on the site's webroot (call it with no `path` argument unless you have already confirmed the real webroot from a tool result — never guess a subdirectory from an unrelated log line), even if step 4 found nothing — a bad deploy can cause a 500 with no matching log signature. If files changed very recently and a `php_fatal_error` or unexplained failure is present, consider `reset_opcache(pool)` (requires Approval) as a candidate fix for a stale-bytecode scenario, but only propose it with the recent-change evidence attached.
7. Only after steps 1–6 have all been run may you state a root cause. If, after the full checklist, no single tool result explains the error, you MUST say explicitly: "Root cause not conclusively identified after full diagnostic sweep" and list every piece of evidence gathered — never fabricate a plausible-sounding cause to fill the gap.
8. If a `db_connection` match, a WordPress-style message in `http_check`'s `body_snippet` (e.g. an "Error establishing a database connection" style notice), or a `php_fatal_error`/`php_parse_error` match points at the site's own configuration layer, inspect it directly — this step is additive evidence-gathering and does not replace steps 1–6:
   - Only after a webroot config file's exact path has been confirmed by another tool result (e.g. `wp-config.php` appearing in `check_recent_file_changes`) may you call `inspect_php_file` on it to check for PHP syntax corruption. Never guess the path.
   - Call `check_php_ini(pool)` for the active PHP-FPM pool to confirm the currently loaded php.ini is present and parses without corruption.
   These remain diagnostic only — editing wp-config.php or php.ini stays out of auto-fix scope; report any corruption found as an Escalation item.

### NO SPECULATIVE ACTIONS RULE (strict):
- `restart_service` is authorized ONLY in Phase 1 step 3 (a service confirmed inactive via `check_service`). It is NEVER authorized as a fallback when Phase 2 is inconclusive or `analyze_log_patterns` returns clean — a "let's just try restarting something" action is exactly the kind of unfounded guess this agent must never take.
- `restart_service`/`reload_workers`/any mutating tool is NEVER authorized for `"mysql"` or `"mariadb"` under any circumstance, even if `check_service` shows it inactive. Database services are diagnostic-only for this agent — it does not have permission to manage them. Never call a mutating tool with a database service name, and never ask the operator for approval to restart the database; go directly to a clear, actionable Escalation entry instead (see Phase 1 step 1's DATABASE ACTIONS rule above).
- Each YELLOW/RED tool may only be proposed in the exact situation this prompt names for it: `restart_service` per the rule above; `reload_workers`/`reset_opcache` only per step 5's stale-opcache condition; `safe_log_cleanup` only per step 3's disk-usage condition. No other trigger justifies proposing a modifying action.
- If the diagnostic checklist is inconclusive, the ONLY acceptable final action is the step 6 statement — proposing ANY YELLOW tool "just in case" in that situation is a protocol violation.
- Always run `verify_http_check` (and `verify_disk_usage` if disk was the trigger) after any YELLOW action. Never attempt automated retries if a fix fails — report the failure as-is.

### FINAL REPORT FORMAT (strict — used to render colored terminal output, follow exactly):
Use markdown H2 headers ('## ') for each of these 5 sections, in this order. Use '> ' for every quoted evidence line. Prefix confirmed-good outcomes with '✅', confirmed-bad outcomes with '❌', and out-of-scope/escalation items with '⚠️'.

## 1. Status Confirmed
(HTTP code + evidence, prefixed ✅ or ❌)

## 2. Root Cause
(exact evidence line quoted with '> ', or the explicit "not conclusively identified" statement)
If a `check_port` result found an unexpected process occupying the port, that finding MUST be the Root Cause stated here (quoted with the process/PID) -- not just mentioned later in Escalation. A generic systemd failure message is not an acceptable Root Cause on its own if a more specific tool result (like check_port) explains the actual blocker.
If `body_snippet` contained a direct application-level error (e.g. a database connection failure) and `check_db_connectivity`/`check_service` for the database confirmed it, THAT must be stated as the Root Cause here — quoted verbatim. An unrelated PHP-FPM/nginx/httpd service that happened to be restarted along the way is not the Root Cause unless log evidence specifically implicated it; do not substitute a coincidental service-restart narrative for confirmed database evidence.

## 3. Action Taken
(what was done, and its approval status — or "none" if diagnostic only)

## 4. Verification
(result of the post-fix check, prefixed ✅ or ❌)

## 5. Escalation
(list each out-of-scope item prefixed '⚠️ ', or "none")
"none" is only valid here if `verify_http_check` (or the initial `http_check`) confirms the site is actually working (200). If the site is still down/erroring and no action successfully fixed it, Escalation must NEVER be "none" -- state plainly that the issue is unresolved and requires manual intervention, and say why (e.g. port occupied by another process, config error, etc.).
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "resolve_domain",
            "description": "MUST be called first, before any other tool, for every investigation. Resolves a domain or subdomain (given as a bare hostname, e.g. 'shop.example.com') to its DirectAdmin webroot and log paths on this server. Works for any domain hosted here, not just one fixed domain. Returns ok:false with an explanatory error if the domain is not hosted on this server at all.",
            "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_check",
            "description": "Check HTTP response status code and latency for a given URL.",
            "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_service",
            "description": "Query standard systemd service execution state (nginx, httpd, php-fpm variants, and read-only status for mysql/mariadb). Database services can only be status-checked here, never restarted/reloaded.",
            "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_port",
            "description": "Inspect whether target network port is open and identify binding process details.",
            "parameters": {"type": "object", "properties": {"port": {"type": "integer"}}, "required": ["port"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disk_usage",
            "description": "Retrieve disk space usage percentages and /var/log allocation metrics.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_log",
            "description": "Fetch final log tail lines from designated log keys (nginx_error, nginx_access, php_fpm).",
            "parameters": {
                "type": "object",
                "properties": {"log_key": {"type": "string"}, "lines": {"type": "integer"}},
                "required": ["log_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nginx_config_test",
            "description": "Validate nginx configuration syntax (equivalent to running nginx -t).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_log_patterns",
            "description": "Scan a log for known root-cause signatures (permission denied, FPM pool exhaustion, broken socket, PHP fatal error, timeout, .htaccess error, SELinux denial, DB connection error) and return matched evidence lines. Matches older than recent_minutes are excluded and reported separately as stale so they cannot be cited as the cause of the current error. Mandatory first step of root-cause drill-down.",
            "parameters": {
                "type": "object",
                "properties": {
                    "log_key": {"type": "string"},
                    "lines": {"type": "integer"},
                    "recent_minutes": {"type": "integer", "description": "Only count matches from within this many minutes as current evidence. Default 15."},
                },
                "required": ["log_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_file_permissions",
            "description": "Report owner, group, mode, and read/write/execute access for a file or directory path.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_socket",
            "description": "Check whether a unix socket file exists and is actually accepting connections (used for nginx<->php-fpm socket failures).",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_fpm_pool_status",
            "description": "Count live worker processes for a PHP-FPM pool and check its log for pm.max_children exhaustion.",
            "parameters": {"type": "object", "properties": {"pool": {"type": "string"}}, "required": ["pool"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_selinux_denials",
            "description": "Check whether SELinux is enforcing and, if so, retrieve recent AVC denials.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_recent_file_changes",
            "description": "List files modified within the last N minutes under the site's webroot, to correlate the incident with a recent deploy. Do NOT pass a custom 'path' unless the actual webroot has been explicitly confirmed elsewhere in this investigation (e.g. from the nginx/httpd 'root' directive or a DocumentRoot value actually returned by a tool). Never guess a subdirectory path from an unrelated log line — call with no 'path' argument to use the configured default webroot.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "minutes": {"type": "integer"}},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_db_connectivity",
            "description": "Read-only TCP reachability check for a database host/port. Does not run any query.",
            "parameters": {
                "type": "object",
                "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
                "required": ["host"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a source/config file (e.g. wp-config.php) for diagnostic inspection. Read-only; never executes the file. Restricted to allowed diagnostic roots (site homedirs / DirectAdmin user data) — only call this on a path already confirmed by another tool result (e.g. from check_recent_file_changes), never a guessed path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "max_lines": {"type": "integer"},
                    "max_bytes": {"type": "integer"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "php_lint",
            "description": "Validate PHP syntax for a .php file using `php -l` (parses only, never executes the application). Use to confirm a suspected parse/syntax corruption in a specific PHP file such as wp-config.php.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_php_file",
            "description": "Combined read-only PHP diagnostic for one .php file: reads the source, runs php_lint, and flags a few high-risk constructs (eval/assert, exit/die, trigger_error) as evidence flags only — not automatic conclusions. Never executes the file.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "max_lines": {"type": "integer"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_php_ini",
            "description": "Read-only check of the currently active php.ini: confirms one is loaded and that it parses without corruption (invalid syntax, broken directives). Optionally scoped to a PHP-FPM pool's own CLI binary. Never modifies php.ini.",
            "parameters": {"type": "object", "properties": {"pool": {"type": "string"}}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "restart_service",
            "description": "[Requires Approval] Restart target system service from allow-list.",
            "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reload_workers",
            "description": "[Requires Approval] Send reload signal to service worker pools.",
            "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "safe_log_cleanup",
            "description": "[Requires Approval] Compress log file to free up storage space without deletion.",
            "parameters": {"type": "object", "properties": {"log_key": {"type": "string"}}, "required": ["log_key"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reset_opcache",
            "description": "[Requires Approval] Clear PHP opcode cache for a pool by reloading its workers. Use only when recent file changes plus an unexplained failure suggest stale bytecode.",
            "parameters": {"type": "object", "properties": {"pool": {"type": "string"}}, "required": ["pool"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_http_check",
            "description": "Re-evaluate target URL HTTP status to confirm remediation outcome.",
            "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_disk_usage",
            "description": "Re-evaluate storage space utilization post-cleanup operation.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": []},
        },
    },
]


def _result_detail(tool_name: str, result: dict) -> str:
    if not result.get("ok", False):
        return result.get("error", "") or ""
    if tool_name == "resolve_domain":
        sub = " (subdomain)" if result.get("is_subdomain") else ""
        return f"webroot={result.get('webroot')}{sub}"
    if tool_name == "http_check" or tool_name == "verify_http_check":
        return f"status={result.get('status_code')} {result.get('elapsed_ms')}ms"
    if tool_name == "check_service":
        return f"state={result.get('state')}"
    if tool_name == "disk_usage" or tool_name == "verify_disk_usage":
        return f"{result.get('percent_used')}% used"
    if tool_name == "analyze_log_patterns":
        n = len(result.get("matches", []))
        return f"{n} pattern match(es)" if n else "clean"
    return ""


# Maps each service/pool-targeted YELLOW tool to the argument key that
# holds the target name, so _precheck_yellow_tool can validate it against
# tools.ALLOWED_SERVICES before ever showing an approval prompt.
_SERVICE_ARG_KEY = {
    "restart_service": "name",
    "reload_workers": "name",
    "reset_opcache": "pool",
}


def _precheck_yellow_tool(tool_name: str, tool_input: dict):
    """
    Returns an error message if this specific YELLOW tool call is already
    known, from the same allow-lists tools.py itself enforces, to be
    impossible to execute — most importantly, a database service name
    ("mysql"/"mariadb" are never in tools.ALLOWED_SERVICES, by design:
    this agent has no permission to manage the database). Returns None
    if the call may proceed to the normal approval flow.
    """

    if tool_name in _SERVICE_ARG_KEY:
        target = tool_input.get(_SERVICE_ARG_KEY[tool_name])

        if target not in tools.ALLOWED_SERVICES:
            return f"service '{target}' not in allow-list"

        if tool_name == "reset_opcache" and "php-fpm" not in target:
            return f"pool '{target}' not in allow-list"

    if tool_name == "safe_log_cleanup":
        log_key = tool_input.get("log_key")

        if log_key not in tools.SYSTEM_LOG_PATHS and log_key not in tools.PER_DOMAIN_LOG_KEYS:
            return f"log_key '{log_key}' not in allow-list"

    return None


def execute_tool(tool_name: str, tool_input: dict, auto_approve: bool = False) -> dict:
    fn = getattr(tools, tool_name, None)
    cls = safety.classify(tool_name)

    if fn is None:
        result = {"ok": False, "error": f"Unknown tool requested: {tool_name}"}
        print(colors.tool_call_line(tool_name, cls, False, result["error"]))
        return result

    if cls == "RED":
        safety.audit({"type": "blocked_red_tool", "tool": tool_name, "args": tool_input})
        print(colors.blocked_red(tool_name))
        return {"ok": False, "error": f"Tool '{tool_name}' is classified RED and cannot be executed."}

    if cls == "YELLOW":
        # Fail fast, with NO approval prompt, for a YELLOW call that is
        # already known — from the same allow-lists tools.py itself
        # enforces — to be impossible to execute (e.g. a database
        # service name, which this agent has no permission to manage).
        # Without this, the operator would be asked "Approve
        # execution?" for an action guaranteed to fail the moment it
        # actually runs, which is confusing and pointless.
        precheck_error = _precheck_yellow_tool(tool_name, tool_input)

        if precheck_error:
            result = {"ok": False, "error": precheck_error}
            safety.log_tool_call(tool_name, tool_input, result)
            print(colors.tool_call_line(tool_name, cls, False, precheck_error))
            return result

        approved = safety.request_approval(
            tool_name,
            tool_input,
            reason=f"Agent identified execution requirement for {tool_name}",
            auto_yes=auto_approve,
        )
        if not approved:
            result = {"ok": False, "error": "operator_denied"}
            safety.log_tool_call(tool_name, tool_input, result)
            print(colors.tool_call_line(tool_name, cls, False, "denied"))
            return result

    result = fn(**tool_input)
    safety.log_tool_call(tool_name, tool_input, result)
    print(colors.tool_call_line(tool_name, cls, result.get("ok", False), _result_detail(tool_name, result)))
    if os.getenv("DEBUG_AGENT"):
        print(f"    [DEBUG] {tool_name} raw result: {json.dumps(result)}")
    return result


def run_agent(user_message: str, auto_approve: bool = False, max_turns: int = 12) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "ERROR: OPENAI_API_KEY environment variable is not set."

    client = OpenAI(api_key=api_key, base_url="https://api.gapgpt.app/v1")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    print(colors.section_divider("Investigation started"))

    for _ in range(max_turns):
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            temperature=0,
        )

        response_message = response.choices[0].message
        messages.append(response_message)

        if not response_message.tool_calls:
            final_text = response_message.content or ""
            safety.log_decision(final_text)
            return final_text

        for tool_call in response_message.tool_calls:
            function_name = tool_call.function.name
            try:
                function_args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                function_args = {}

            try:
                result = execute_tool(function_name, function_args, auto_approve=auto_approve)
            except PermissionError as e:
                result = {"ok": False, "error": str(e)}

            messages.append(
                {
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": function_name,
                    "content": json.dumps(result, ensure_ascii=False),
                }
            )

    return "ERROR: Agent reached maximum turn execution limit without concluding investigation."