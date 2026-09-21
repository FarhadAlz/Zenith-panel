# ⚡ Zenith Panel

**An agent-less, self-hosted control panel that finds and fixes HTTP 500/502/503 errors across all your DirectAdmin servers — automatically, safely, and with a human always in the loop.**

Zenith Panel wraps a purpose-built LLM diagnostic agent (**Agent 500**) in a clean local dashboard. Point it at any server over SSH, browse its domains, and click **Investigate & Fix** — the agent runs the full triage-to-root-cause pipeline live in your browser, asking for your explicit approval before it ever touches anything.

---

## ✨ Highlights

- 🖥️ **One dashboard, many servers** — add a server once, reconnect with a single click afterward.
- 🕵️ **Automated root-cause diagnosis** — service checks, log pattern analysis, permissions, disk, PHP-FPM pools, SELinux, DB connectivity, and more, chained together by an LLM agent that only reasons from tool evidence — never guesses.
- 🚦 **Three-tier safety model** — every tool the agent can call is classified `GREEN` (read-only, runs freely), `YELLOW` (mutating, requires your explicit approval), or `RED` (never executed, always escalated to a human).
- 🔌 **Agent-less by design** — nothing is permanently installed on your servers. The panel ships a lightweight runtime over SFTP for the duration of a session and can be wiped anytime.
- 🔐 **Zero-knowledge credential vault** — server credentials and the LLM API key are encrypted at rest with a key derived from a master password that is never stored anywhere, and never lives outside the panel's own process.
- 🌗 **Dark / light mode**, live WebSocket investigation stream, and a color-coded tool-call log — the same clarity you'd get from a terminal, in a real UI.

---

## 🏗️ Architecture

Your Browser <── HTTP / WebSocket ──> Zenith Panel (FastAPI, runs locally) <── SSH ──> Target Server(s)


The panel is the **only** place that ever holds server credentials or the model's API key. The LLM itself never sees an IP, a password, or a private key — it only ever sees tool names and their JSON results (e.g. the output of `check_service("nginx")`). That boundary is enforced entirely in code, not by prompting.

zenith-panel/
├── backend/
│ ├── main.py # FastAPI app — REST routes + live WebSocket investigation stream
│ ├── ssh_manager.py # SSH connection handling, runtime upload, remote execution
│ ├── crypto_utils.py # At-rest encryption derived from the master password
│ ├── store.py # SQLite persistence — servers, cached domains, settings
│ └── agent_runtime/ # The diagnostic agent itself, executed on the remote server
│ ├── tools.py # All diagnostic & remediation tools
│ ├── safety.py # GREEN / YELLOW / RED classification + approval + audit log
│ ├── llm_agent.py # The agent loop and system prompt
│ ├── domain_resolver.py
│ └── remote_runner.py # Bridges the agent runtime to a remote SSH session
└── frontend/ # Vanilla HTML/CSS/JS dashboard (dark/light, live log view)


---

## 🚀 Getting Started

### Requirements

**On the machine running the panel** (Windows / macOS / Linux):
- Python 3.10+

**On each target server:**
- SSH access (password or private key)
- `python3` available (present by default on virtually every DirectAdmin / CentOS / AlmaLinux box)
- For automated remediation to actually take effect, the SSH user needs permission to run `systemctl restart/reload` on `nginx`, `httpd`, and the relevant `php-fpm` pool(s)

### Installation

```bash
git clone https://github.com/FarhadAlz/zenith-panel.git
cd zenith-panel
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run

```bash
cd backend
uvicorn main:app --host 127.0.0.1 --port 8787
```

Then open **http://127.0.0.1:8787** in your browser. The panel listens on `127.0.0.1` only by design — it's meant to run on your own machine, not be exposed to the network.

---

## 🔑 First-Run Setup

1. On first launch, you'll be asked to set a **master password**. It is never written to disk — it only exists in memory, for the current session, and is used to derive the key that encrypts everything sensitive. Losing it means losing access to stored credentials (there's no recovery path by design).
2. Add your LLM API key from the settings panel. It's encrypted at rest and only ever passed to the remote runtime through the SSH control channel — never as an environment variable or CLI argument, so it never shows up in a process list on the target server.

---

## ➕ Adding a Server

1. Click **Add Server** in the sidebar.
2. Enter a display name, host/IP, SSH port, and username.
3. Authenticate with either a password or a private key (+ passphrase if needed).
4. Hit **Test & Save** — the panel connects, uploads the runtime, and caches the server's domain list.
5. From then on, reconnect with one click — no need to re-enter credentials.

## 🩺 Daily Use

1. Pick a server → browse its domains as cards.
2. Click a domain — the panel checks its live HTTP status instantly.
3. If it's unhealthy (500/502/503/504, or a connection error), an **Investigate & Fix** button appears.
4. The agent runs its full diagnostic pipeline live, streamed to the dashboard as a color-coded tool-call log.
5. Any `YELLOW` (mutating) action pauses for your explicit approval before executing. `RED` actions are never run.
6. You get a structured final report — root cause, actions taken, and current status — all backed by quoted tool evidence.

---

## 🛡️ Security Notes

- The encryption key never touches disk — it's derived from your master password at unlock time and lives only in memory.
- The LLM has no direct SSH access and never sees a server's credentials, in a prompt or in any tool result.
- Every mutating action requires a manual approval click; nothing destructive runs unattended.
- Intended for local/personal use — avoid exposing the panel's port beyond your own machine.

---

## 🧰 Troubleshooting

| Issue | Fix |
|---|---|
| "Authentication failed" when adding a server | Double-check username/password/key — some servers disable direct root+password login; try a different user or a key. |
| Domain list comes back empty | The server likely doesn't follow the `/home/*/domains/*` DirectAdmin layout, or the SSH user can't read that path. |
| "No response from server" | Confirm `python3` is on `PATH` on the target server. |
| A `YELLOW` action fails with `operator_denied` | The SSH user lacks permission for `systemctl restart/reload` on that service. |
| Final report looks empty or off | Re-check the API key in settings — it must be a valid OpenAI-compatible key. |
