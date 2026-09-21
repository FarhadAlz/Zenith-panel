#!/usr/bin/env python3
"""
remote_runner.py — runs ON the target server, over SSH, invoked by the
Zenith panel. It is the only new "glue" code in this whole agent runtime
folder: every diagnostic/remediation decision is still made by the exact
same tools.py / safety.py / llm_agent.py / domain_resolver.py that the
original CLI agent (main.py) used. This file never re-implements any of
that logic — it only adapts the existing set_ui()-shaped hook (the same
interface dashboard.py already defined) so its events go out as JSON
lines on stdout instead of a rich terminal UI, and reads approval
answers back as JSON lines on stdin instead of a terminal prompt.

Protocol (line-delimited JSON, UTF-8):

  stdin, first line  -> control message:
      {"command": "list_domains"} |
      {"command": "check_domain", "domain": "..."} |
      {"command": "investigate", "domain": "...", "api_key": "...",
       "auto_approve": false}

  stdin, subsequent lines (investigate only) -> approval answers, one
  per "approval_request" event this script emits:
      {"approved": true}

  stdout -> one JSON object per line, always with a "type" field:
      {"type": "result", ...}                (list_domains / check_domain)
      {"type": "agent_status", "status": "..."}
      {"type": "site_status", "ok": true|false|null, "detail": "..."}
      {"type": "turn"}
      {"type": "tool_log", "tool": "...", "level": "...", "ok": ..., "detail": "..."}
      {"type": "blocked_red", "tool": "..."}
      {"type": "approval_request", "tool": "...", "args": {...}, "reason": "..."}
      {"type": "report", "text": "..."}
      {"type": "error", "message": "..."}

The panel never sends the SSH password/username/IP into this process —
it only ever sees whatever tools.py itself already exposes to the LLM
(tool names + JSON args/results). Credentials stay entirely on the
panel side of the SSH transport.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _emit(obj: dict):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _read_control_line():
    line = sys.stdin.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    return json.loads(line)


class StreamUI:
    """Same public surface as dashboard.Dashboard (set_agent_status,
    set_site_status, new_turn, log_tool, blocked_red, ask_approval,
    show_report) — llm_agent.py / safety.py call these exact methods
    without knowing or caring that a network stream, not a terminal,
    is on the other end."""

    def set_agent_status(self, status: str):
        _emit({"type": "agent_status", "status": status})

    def set_site_status(self, ok, detail: str):
        _emit({"type": "site_status", "ok": ok, "detail": detail})

    def new_turn(self):
        _emit({"type": "turn"})

    def log_tool(self, tool_name: str, level: str, ok: bool, detail: str = ""):
        _emit({"type": "tool_log", "tool": tool_name, "level": level, "ok": ok, "detail": detail})

    def blocked_red(self, tool_name: str):
        _emit({"type": "blocked_red", "tool": tool_name})

    def ask_approval(self, tool_name: str, args: dict, reason: str, auto_yes: bool = False) -> bool:
        _emit({
            "type": "approval_request",
            "tool": tool_name,
            "args": args,
            "reason": reason,
            "auto_yes": auto_yes,
        })

        if auto_yes:
            return True

        answer = _read_control_line()
        if not answer:
            return False
        return bool(answer.get("approved", False))

    def show_report(self, report_text: str, wait_for_key: bool = False):
        _emit({"type": "report", "text": report_text})


def cmd_list_domains():
    import domain_resolver
    try:
        result = domain_resolver.list_domains()
    except Exception as exc:
        _emit({"type": "result", "ok": False, "error": f"list_domains failed: {exc}"})
        return
    _emit({"type": "result", **result})


def cmd_check_domain(domain: str):
    import tools

    resolve_result = tools.resolve_domain(domain)

    http_result = None
    checked_url = None
    if resolve_result.get("ok"):
        for scheme in ("https://", "http://"):
            checked_url = f"{scheme}{domain}"
            http_result = tools.http_check(checked_url)
            if http_result.get("ok") or http_result.get("status_code"):
                break

    _emit({
        "type": "result",
        "ok": True,
        "domain": domain,
        "resolve": resolve_result,
        "checked_url": checked_url,
        "http_check": http_result,
    })


def cmd_investigate(domain: str, api_key: str, auto_approve: bool):
    import llm_agent
    import safety

    if api_key:
        os.environ["OPENAI_API_KEY"] = api_key

    ui = StreamUI()
    llm_agent.set_ui(ui)
    safety.set_ui(ui)

    try:
        result = llm_agent.run_agent(domain, auto_approve=auto_approve)
    except Exception as exc:
        _emit({"type": "error", "message": f"investigate failed: {exc}"})
        return
    finally:
        llm_agent.set_ui(None)
        safety.set_ui(None)

    ui.show_report(result)


def main():
    control = _read_control_line()

    if control is None:
        _emit({"type": "error", "message": "no control message received on stdin"})
        sys.exit(1)

    command = control.get("command")

    try:
        if command == "list_domains":
            cmd_list_domains()
        elif command == "check_domain":
            cmd_check_domain(control.get("domain", ""))
        elif command == "investigate":
            cmd_investigate(
                control.get("domain", ""),
                control.get("api_key", ""),
                bool(control.get("auto_approve", False)),
            )
        else:
            _emit({"type": "error", "message": f"unknown command: {command}"})
            sys.exit(1)
    except Exception as exc:
        _emit({"type": "error", "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
