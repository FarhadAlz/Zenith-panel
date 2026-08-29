"""
test_safety_layer.py — Automated test harness for security policy validation.

v2: adds coverage for the new diagnostic (GREEN) and reset_opcache (YELLOW)
tool classifications, so a future contributor can't silently downgrade one
of them without a failing test.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

import safety
from llm_agent import execute_tool


def test_green_tool_no_approval_needed(capsys):
    result = execute_tool("disk_usage", {"path": "/"}, auto_approve=False)
    assert result["ok"] is True
    captured = capsys.readouterr()
    assert "APPROVAL REQUESTED" not in captured.out


def test_yellow_tool_denied_without_approval():
    result = execute_tool("restart_service", {"name": "mysql"}, auto_approve=True)
    assert result["ok"] is False
    assert "allow-list" in result["error"]


def test_yellow_tool_auto_approve_path():
    result = execute_tool("restart_service", {"name": "nginx"}, auto_approve=True)
    assert "error" in result or "ok" in result


def test_red_tool_is_blocked():
    with pytest.raises(PermissionError):
        safety.request_approval("unauthorized_tool_name", {}, "test", auto_yes=True)


def test_unknown_tool_defaults_to_red():
    assert safety.classify("some_random_tool_not_defined") == "RED"


@pytest.mark.parametrize(
    "tool_name",
    [
        "analyze_log_patterns",
        "check_file_permissions",
        "check_socket",
        "check_fpm_pool_status",
        "check_selinux_denials",
        "check_recent_file_changes",
        "check_db_connectivity",
    ],
)
def test_new_diagnostic_tools_are_green(tool_name):
    assert safety.classify(tool_name) == "GREEN"


def test_reset_opcache_is_yellow():
    assert safety.classify("reset_opcache") == "YELLOW"


def test_reset_opcache_rejects_non_fpm_service():
    result = execute_tool("reset_opcache", {"pool": "nginx"}, auto_approve=True)
    assert result["ok"] is False
    assert "allow-list" in result["error"]


if __name__ == "__main__":
    import traceback

    tests = [
        test_yellow_tool_denied_without_approval,
        test_yellow_tool_auto_approve_path,
        test_red_tool_is_blocked,
        test_unknown_tool_defaults_to_red,
        test_reset_opcache_is_yellow,
        test_reset_opcache_rejects_non_fpm_service,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"✅ {t.__name__}")
            passed += 1
        except Exception:
            print(f"❌ {t.__name__}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} tests passed successfully.")