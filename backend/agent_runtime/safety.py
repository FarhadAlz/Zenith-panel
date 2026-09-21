"""
safety.py — Audit logging and authorization layer for Agent 500.

v3: approval prompts and RED-block messages now render through colors.py
for readable SSH-terminal output. No change to classification logic,
audit log format, or the RED-defaults-to-blocked guarantee.
"""

import json
import time
import os

import colors

LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "audit.jsonl")

# When a Dashboard (dashboard.py) is active, approval prompts render as a
# panel inside the live view instead of raw colors.py prints. Defaults to
# None so existing callers (tests, non-interactive use) are unaffected.
_ui = None


def set_ui(ui):
    """Register the active Dashboard instance. Pass None to go back to
    plain colors.py/stdin prompts (e.g. when no dashboard is running)."""
    global _ui
    _ui = ui


TOOL_CLASSIFICATION = {
    # domain resolution — must run first, every investigation (read-only)
    "resolve_domain": "GREEN",
    # existing diagnostics
    "http_check": "GREEN",
    "check_service": "GREEN",
    "check_port": "GREEN",
    "disk_usage": "GREEN",
    "read_log": "GREEN",
    "nginx_config_test": "GREEN",
    "verify_http_check": "GREEN",
    "verify_disk_usage": "GREEN",
    # root-cause diagnostics (all read-only)
    "analyze_log_patterns": "GREEN",
    "check_file_permissions": "GREEN",
    "check_socket": "GREEN",
    "check_fpm_pool_status": "GREEN",
    "check_selinux_denials": "GREEN",
    "check_recent_file_changes": "GREEN",
    "check_db_connectivity": "GREEN",
    # config/source inspection (read-only; never executes/modifies the file)
    "read_file": "GREEN",
    "php_lint": "GREEN",
    "inspect_php_file": "GREEN",
    "check_php_ini": "GREEN",
    # mutating actions — require operator approval
    "restart_service": "YELLOW",
    "reload_workers": "YELLOW",
    "safe_log_cleanup": "YELLOW",
    "reset_opcache": "YELLOW",
}


def audit(event: dict):
    event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def classify(tool_name: str) -> str:
    return TOOL_CLASSIFICATION.get(tool_name, "RED")


def request_approval(tool_name: str, args: dict, reason: str, auto_yes: bool = False) -> bool:
    cls = classify(tool_name)
    if cls == "RED":
        audit({"type": "blocked_red_tool", "tool": tool_name, "args": args})
        print(colors.blocked_red(tool_name))
        raise PermissionError(f"Tool '{tool_name}' is classified as RED and cannot be executed.")

    if cls == "GREEN":
        return True

    if _ui is not None:
        approved = _ui.ask_approval(tool_name, args, reason, auto_yes=auto_yes)
    else:
        print("\n" + colors.approval_box(tool_name, args, reason))

        if auto_yes:
            approved = True
        else:
            answer = input(colors.c("Approve execution? [y/N]: ", colors.Fg.YELLOW, bold=True)).strip().lower()
            approved = answer == "y"

        print(colors.approval_result(approved))

    audit(
        {
            "type": "approval_request",
            "tool": tool_name,
            "args": args,
            "reason": reason,
            "approved": approved,
        }
    )
    return approved


def log_tool_call(tool_name: str, args: dict, result: dict):
    audit({"type": "tool_call", "tool": tool_name, "args": args, "result": result})


def log_decision(text: str):
    audit({"type": "decision", "text": text})