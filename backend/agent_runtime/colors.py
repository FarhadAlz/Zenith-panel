"""
colors.py — Terminal color/formatting utilities for Agent 500 CLI output.

Pure ANSI escape codes, zero external dependencies (works on any standard
Linux terminal via SSH). Central place for all color decisions so tool-call
level (GREEN/YELLOW/RED), approval prompts, and the final report all look
consistent.
"""

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"


class Fg:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[95m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"


LEVEL_COLOR = {"GREEN": Fg.GREEN, "YELLOW": Fg.YELLOW, "RED": Fg.RED}


def c(text: str, color: str, bold: bool = False, dim: bool = False) -> str:
    prefix = (BOLD if bold else "") + (DIM if dim else "")
    return f"{prefix}{color}{text}{RESET}"


def banner(title: str, color: str = Fg.CYAN) -> str:
    line = "─" * max(20, len(title) + 4)
    return f"{c(line, color, bold=True)}\n{c(title, color, bold=True)}\n{c(line, color, bold=True)}"


def tool_call_line(name: str, level: str, ok: bool, detail: str = "") -> str:
    """One line printed live as each tool executes, e.g.:
    [GREEN] check_service(nginx)              ✓ active
    """
    level_color = LEVEL_COLOR.get(level, Fg.WHITE)
    tag = c(f"[{level:^6}]", level_color, bold=True)
    status = c("✓", Fg.GREEN, bold=True) if ok else c("✗", Fg.RED, bold=True)
    detail_txt = c(f"  {detail}", Fg.GRAY) if detail else ""
    return f"  {tag} {name:<32} {status}{detail_txt}"


def approval_box(tool_name: str, args: dict, reason: str) -> str:
    border = c("═" * 60, Fg.YELLOW, bold=True)
    title = c("  ⚠  APPROVAL REQUIRED — modifying action ", Fg.YELLOW, bold=True)
    lines = [
        border,
        title,
        border,
        f"  {c('Tool   :', Fg.GRAY)} {c(tool_name, Fg.YELLOW, bold=True)}",
        f"  {c('Args   :', Fg.GRAY)} {args}",
        f"  {c('Reason :', Fg.GRAY)} {reason}",
        border,
    ]
    return "\n".join(lines)


def approval_result(approved: bool) -> str:
    if approved:
        return c("  ✓ Approved — executing.", Fg.GREEN, bold=True)
    return c("  ✗ Denied — action skipped.", Fg.RED, bold=True)


def blocked_red(tool_name: str) -> str:
    return c(f"  🔒 BLOCKED — '{tool_name}' is classified RED and cannot run.", Fg.RED, bold=True)


def section_divider(label: str, color: str = Fg.BLUE) -> str:
    return f"\n{c('▶', color, bold=True)} {c(label, color, bold=True)}"


def format_report(text: str) -> str:
    """Post-process the model's final markdown-ish report into a colorized
    terminal view. Expects '## ' section headers, '> ' evidence quotes, and
    optional ✅ / ❌ / ⚠️ status markers, as instructed in the system prompt.
    Falls back gracefully on plain text — nothing breaks if the model
    doesn't follow the convention exactly."""
    out_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            title = stripped[3:].strip()
            out_lines.append("")
            out_lines.append(c(f"── {title} ", Fg.CYAN, bold=True) + c("─" * max(0, 50 - len(title)), Fg.CYAN))
        elif stripped.startswith("> "):
            out_lines.append("  " + c(stripped[2:], Fg.MAGENTA))
        elif stripped.startswith("✅"):
            out_lines.append(c(line, Fg.GREEN, bold=True))
        elif stripped.startswith("❌"):
            out_lines.append(c(line, Fg.RED, bold=True))
        elif stripped.startswith("⚠️") or stripped.startswith("⚠"):
            out_lines.append(c(line, Fg.YELLOW, bold=True))
        else:
            out_lines.append(line)
    return "\n".join(out_lines)