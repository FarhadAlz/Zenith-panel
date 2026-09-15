"""
main.py — CLI interface for triggering HTTP 500 Troubleshooting Agent.

v2: colored banners for start/end, and the final report is now run through
colors.format_report() so the model's '## ' headers, '> ' evidence quotes,
and ✅/❌/⚠️ markers render as a readable colored panel in the terminal.
"""

import sys
import colors
from llm_agent import run_agent


def main():
    if len(sys.argv) < 2:
        print('Usage: python3 main.py "Target URL or error issue description"')
        sys.exit(1)

    user_message = " ".join(sys.argv[1:])
    print(colors.banner("🔎 AGENT 500 — Investigation Initiated"))
    print(colors.c(f"Input: {user_message}\n", colors.Fg.GRAY))

    result = run_agent(user_message, auto_approve=False)

    print("\n" + colors.banner("📋 FINAL INVESTIGATION REPORT", color=colors.Fg.CYAN))
    print(colors.format_report(result))
    print()


if __name__ == "__main__":
    main()