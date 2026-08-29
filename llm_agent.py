"""
llm_agent.py — Main Agent loop using OpenAI client configured for GapGPT endpoint.
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

### ARCHITECTURE & DIAGNOSTIC PROCEDURE:
Server Stack: DirectAdmin architecture with nginx (Reverse Proxy) -> httpd (Apache) -> PHP-FPM workers (php-fpm74, php-fpm81, php-fpm82, php-fpm83).

Diagnostic Workflow:
1. Perform `http_check` on the target URL first.
   - If response is NOT HTTP 500/502/504, reject the request as out-of-scope.
2. If HTTP 500 is confirmed:
   - Run `check_service` for "nginx", "httpd", and active PHP-FPM pools (check php-fpm74 through php-fpm83 if specific pool is unknown).
3. If a service is inactive:
   - Confirm root cause using `read_log`.
   - Propose `restart_service` (requires Approval).
4. If services are active:
   - Run `check_port(80)` and `check_port(443)` to identify unexpected process ownership.
   - Run `nginx_config_test`. If invalid, report configuration error as an Escalation item (Configuration editing is strictly RED out of scope).
   - Run `disk_usage`. If usage is > 90%, check `/var/log` and suggest `safe_log_cleanup` (requires Approval).
   - Run `read_log("nginx_error")` and `read_log("php_fpm")` to fetch exact stack traces, worker timeouts, or fatal errors.
5. Post-Fix Verification:
   - Always run `verify_http_check` or `verify_disk_usage` after any action. Never attempt automated retries if a fix fails.
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