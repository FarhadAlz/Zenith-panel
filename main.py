"""
main.py — CLI interface for triggering HTTP 500 Troubleshooting Agent.
"""

import sys
from llm_agent import run_agent


def main():
    if len(sys.argv) < 2:
        print('Usage: python3 main.py "Target URL or error issue description"')
        sys.exit(1)

    user_message = " ".join(sys.argv[1:])
    print(f"🔎 Initiating investigation for input: {user_message}\n")
    result = run_agent(user_message, auto_approve=False)
    print("\n" + "─" * 60)
    print("📋 Final Agent Investigation Report:\n")
    print(result)


if __name__ == "__main__":
    main()