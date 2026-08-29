"""
llm_agent.py — Main Agent loop using OpenAI client configured for GapGPT endpoint.

v2: adds a mandatory "Root Cause Certainty Protocol" so the agent can no longer
stop at "services are active, can't explain it". Once nginx/httpd/php-fpm all
report active, the agent is now required to run analyze_log_patterns first,
then drill into whichever candidate root causes it surfaces (permissions,
broken socket, exhausted FPM pool, PHP fatal error, timeout, .htaccess error,
SELinux denial, DB connectivity, or a stale-opcache-after-deploy signature),
citing the exact evidence line for each conclusion. If nothing conclusive is
found after running the full drill-down set, the agent must say so explicitly
instead of guessing.
"""

import os
import json
from openai import OpenAI

import tools
import safety

# Select model available in GapGPT (e.g., gpt-4o-mini or gpt-4o for high precision tool calling)
MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = """\
You are an ultra-specialized, evidence-based Troubleshooting Agent dedicated STRICTLY and ONLY to handling HTTP 500 Internal Server Error issues on this server.

### STRICT SCOPE BOUNDARIES:
- You ONLY handle HTTP 500 Internal Server Errors (or 502/504 proxy/gateway errors strictly tied to 500-family backend failures).
- If the user inquiry or initial URL check indicates any other status code (e.g., 400 Bad Request, 401, 403, 404, 200 OK) or a general non-500 query, YOU MUST IMMEDIATELY REFUSE to process the request.
- Refusal Output Format: State clearly that the request is out of scope because you are strictly designed for HTTP 500 root cause analysis.

### NO GUESSWORK RULE:
- Never guess, hypothesize without data, or generate generic responses.
- Every claim or diagnosis in your final output MUST be explicitly backed by evidence gathered directly from tool execution logs, status checks, or configuration tests.
- Quote the exact evidence line (from a log or tool result) that supports each conclusion.

### ARCHITECTURE:
Server Stack: DirectAdmin architecture with nginx (Reverse Proxy) -> httpd (Apache) -> PHP-FPM workers (php-fpm74, php-fpm81, php-fpm82, php-fpm83).

### PHASE 1 — INITIAL TRIAGE:
1. Run `http_check` on the target URL first.
   - If response is NOT HTTP 500/502/504, reject the request as out-of-scope.
2. If HTTP 500 is confirmed, run `check_service` for "nginx", "httpd", and the active PHP-FPM pool(s) (check php-fpm74 through php-fpm83 if the specific pool is unknown).
3. If a service is inactive:
   - Confirm root cause using `read_log`.
   - Propose `restart_service` (requires Approval).
   - After approval and restart, run `verify_http_check` and stop — no need for Phase 2.

### PHASE 2 — ROOT CAUSE CERTAINTY PROTOCOL (mandatory when all services report active but the error persists):
Do NOT conclude "cause unknown" or give a vague answer at this stage. Work through this checklist in order and do not skip steps just because an earlier one found something — a 500 can have more than one contributing cause:

1. Run `check_port(80)` and `check_port(443)` to rule out unexpected process ownership.
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
   - `db_connection` → call `check_db_connectivity(host, port)` using the host/port visible in the error line. This is diagnostic only — database-side fixes are out of scope.
5. ALWAYS run `check_recent_file_changes` on the site's webroot, even if step 4 found nothing — a bad deploy can cause a 500 with no matching log signature. If files changed very recently and a `php_fatal_error` or unexplained failure is present, consider `reset_opcache(pool)` (requires Approval) as a candidate fix for a stale-bytecode scenario, but only propose it with the recent-change evidence attached.
6. Only after steps 1–5 have all been run may you state a root cause. If, after the full checklist, no single tool result explains the error, you MUST say explicitly: "Root cause not conclusively identified after full diagnostic sweep" and list every piece of evidence gathered — never fabricate a plausible-sounding cause to fill the gap.

### POST-FIX VERIFICATION:
- Always run `verify_http_check` (and `verify_disk_usage` if disk was the trigger) after any YELLOW action. Never attempt automated retries if a fix fails — report the failure as-is.

### FINAL REPORT FORMAT:
Structure your final answer as:
1. Status confirmed (HTTP code + evidence)
2. Root cause (with the exact evidence line quoted) — or the explicit "not conclusively identified" statement from step 6
3. Action taken (if any) and its approval status
4. Verification result
5. Escalation items, if any (with reason each is out of scope)
"""

# OpenAI Function Schema Definitions
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "http_check",
            "description": "Check HTTP response status code and latency for a given URL.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_service",
            "description": "Query standard systemd service execution state (nginx, httpd, php-fpm variants).",
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_port",
            "description": "Inspect whether target network port is open and identify binding process details.",
            "parameters": {
                "type": "object",
                "properties": {"port": {"type": "integer"}},
                "required": ["port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disk_usage",
            "description": "Retrieve disk space usage percentages and /var/log allocation metrics.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": [],
            },
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
            "description": "Scan a log for known root-cause signatures (permission denied, FPM pool exhaustion, broken socket, PHP fatal error, timeout, .htaccess error, SELinux denial, DB connection error) and return matched evidence lines. Mandatory first step of root-cause drill-down.",
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
            "name": "check_file_permissions",
            "description": "Report owner, group, mode, and read/write/execute access for a file or directory path.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_socket",
            "description": "Check whether a unix socket file exists and is actually accepting connections (used for nginx<->php-fpm socket failures).",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_fpm_pool_status",
            "description": "Count live worker processes for a PHP-FPM pool and check its log for pm.max_children exhaustion.",
            "parameters": {
                "type": "object",
                "properties": {"pool": {"type": "string"}},
                "required": ["pool"],
            },
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
            "description": "List files modified within the last N minutes under a given webroot path, to correlate the incident with a recent deploy.",
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
            "name": "restart_service",
            "description": "[Requires Approval] Restart target system service from allow-list.",
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reload_workers",
            "description": "[Requires Approval] Send reload signal to service worker pools.",
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "safe_log_cleanup",
            "description": "[Requires Approval] Compress log file to free up storage space without deletion.",
            "parameters": {
                "type": "object",
                "properties": {"log_key": {"type": "string"}},
                "required": ["log_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reset_opcache",
            "description": "[Requires Approval] Clear PHP opcode cache for a pool by reloading its workers. Use only when recent file changes plus an unexplained failure suggest stale bytecode.",
            "parameters": {
                "type": "object",
                "properties": {"pool": {"type": "string"}},
                "required": ["pool"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_http_check",
            "description": "Re-evaluate target URL HTTP status to confirm remediation outcome.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_disk_usage",
            "description": "Re-evaluate storage space utilization post-cleanup operation.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": [],
            },
        },
    },
]


def execute_tool(tool_name: str, tool_input: dict, auto_approve: bool = False) -> dict:
    """Execute target tool with safety classification check and approval layer handling."""
    fn = getattr(tools, tool_name, None)
    if fn is None:
        return {"ok": False, "error": f"Unknown tool requested: {tool_name}"}

    cls = safety.classify(tool_name)
    if cls == "YELLOW":
        approved = safety.request_approval(
            tool_name,
            tool_input,
            reason=f"Agent identified execution requirement for {tool_name}",
            auto_yes=auto_approve,
        )
        if not approved:
            result = {"ok": False, "error": "operator_denied"}
            safety.log_tool_call(tool_name, tool_input, result)
            return result

    result = fn(**tool_input)
    safety.log_tool_call(tool_name, tool_input, result)
    return result


def run_agent(user_message: str, auto_approve: bool = False, max_turns: int = 12) -> str:
    """Execution cycle management using GapGPT custom base_url endpoint."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "ERROR: OPENAI_API_KEY environment variable is not set."

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.gapgpt.app/v1",
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    for _ in range(max_turns):
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
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

            result = execute_tool(function_name, function_args, auto_approve=auto_approve)

            messages.append(
                {
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": function_name,
                    "content": json.dumps(result, ensure_ascii=False),
                }
            )

    return "ERROR: Agent reached maximum turn execution limit without concluding investigation."