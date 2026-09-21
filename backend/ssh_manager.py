"""
ssh_manager.py — every place the panel actually touches a remote
server's IP/username/password/key lives HERE and only here. The rest
of the backend (routes in main.py) only ever calls into this module
with a server_id; it never sees or forwards raw credentials again
after connect-time.

Responsibilities:
    1. Open/hold/close a paramiko SSH connection per server_id.
    2. One-time (per session) upload of agent_runtime/* to the remote
       host — this is the "agentless" part: nothing is permanently
       installed; we drop a small, disposable copy of the exact same
       tools.py / safety.py / llm_agent.py / domain_resolver.py /
       remote_runner.py the original CLI agent used, under a dotfolder
       in the connecting user's home directory, and only ever invoke it
       for the duration of one SSH session.
    3. Run the three remote_runner.py commands:
         - list_domains / check_domain: short-lived, blocking, run in a
           thread pool (see main.py's use of asyncio.to_thread).
         - investigate: long-lived and interactive (it can pause mid-
           way to ask for YELLOW-tool approval), so it's driven from a
           background thread that streams JSON events out and reads
           approval answers back in via a plain thread-safe queue.Queue
           pair — see InvestigationSession below.
"""

import io
import json
import os
import queue
import threading
import time

import paramiko

REMOTE_RUNTIME_DIR = ".zenith_runtime"
AGENT_RUNTIME_FILES = [
    "colors.py",
    "domain_resolver.py",
    "tools.py",
    "safety.py",
    "llm_agent.py",
    "remote_runner.py",
]

_LOCAL_RUNTIME_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_runtime")

# server_id -> paramiko.SSHClient
_clients: dict[str, paramiko.SSHClient] = {}
_lock = threading.RLock()


class SSHError(Exception):
    pass


def _load_private_key(key_text: str, passphrase: str | None):
    key_classes = [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey]
    last_exc = None
    for cls in key_classes:
        try:
            return cls.from_private_key(io.StringIO(key_text), password=passphrase or None)
        except Exception as exc:  # noqa: BLE001 - trying multiple key types on purpose
            last_exc = exc
            continue
    raise SSHError(f"private key could not be parsed by any supported key type ({last_exc})")


def connect(server_id: str, host: str, port: int, username: str,
            auth_type: str, secret: str, passphrase: str | None,
            timeout: int = 12) -> None:
    """Open (or replace) the SSH connection for server_id. Raises
    SSHError with a human-readable reason on failure."""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if auth_type == "password":
            client.connect(
                hostname=host, port=port, username=username,
                password=secret, timeout=timeout, banner_timeout=timeout,
                auth_timeout=timeout,
            )
        elif auth_type == "key":
            pkey = _load_private_key(secret, passphrase)
            client.connect(
                hostname=host, port=port, username=username,
                pkey=pkey, timeout=timeout, banner_timeout=timeout,
                auth_timeout=timeout,
            )
        else:
            raise SSHError(f"unknown auth_type: {auth_type}")
    except paramiko.AuthenticationException as exc:
        raise SSHError("احراز هویت ناموفق بود — نام کاربری/رمز یا کلید را بررسی کنید") from exc
    except Exception as exc:  # noqa: BLE001
        raise SSHError(f"اتصال برقرار نشد: {exc}") from exc

    with _lock:
        old = _clients.get(server_id)
        if old is not None:
            try:
                old.close()
            except Exception:
                pass
        _clients[server_id] = client


def is_connected(server_id: str) -> bool:
    with _lock:
        client = _clients.get(server_id)
    if client is None:
        return False
    transport = client.get_transport()
    return bool(transport and transport.is_active())


def disconnect(server_id: str):
    with _lock:
        client = _clients.pop(server_id, None)
    if client:
        try:
            client.close()
        except Exception:
            pass


def _get_client(server_id: str) -> paramiko.SSHClient:
    with _lock:
        client = _clients.get(server_id)
    if client is None or not is_connected(server_id):
        raise SSHError("این سرور متصل نیست — دوباره وصل شوید")
    return client


def deploy_runtime(server_id: str):
    """Upload agent_runtime/* into ~/.zenith_runtime/ on the remote
    host. Idempotent — safe to call every time before running a
    command, which keeps the remote copy always in sync with whatever
    logic ships in this panel (no stale/forked copies drifting on a
    server the operator hasn't opened in months)."""

    client = _get_client(server_id)
    sftp = client.open_sftp()
    try:
        remote_home = sftp.normalize(".")
        remote_dir = f"{remote_home}/{REMOTE_RUNTIME_DIR}"

        try:
            sftp.mkdir(remote_dir)
        except IOError:
            pass  # already exists

        for filename in AGENT_RUNTIME_FILES:
            local_path = os.path.join(_LOCAL_RUNTIME_DIR, filename)
            sftp.put(local_path, f"{remote_dir}/{filename}")
        sftp.chmod(remote_dir, 0o700)
    finally:
        sftp.close()


def _remote_runtime_path(server_id: str) -> str:
    client = _get_client(server_id)
    sftp = client.open_sftp()
    try:
        remote_home = sftp.normalize(".")
    finally:
        sftp.close()
    return f"{remote_home}/{REMOTE_RUNTIME_DIR}"


def run_blocking_command(server_id: str, control: dict, timeout: int = 30) -> dict:
    """For short commands (list_domains, check_domain). Sends the
    control message, reads every stdout line, returns the last
    well-formed JSON object of type 'result' or 'error'."""

    client = _get_client(server_id)
    runtime_dir = _remote_runtime_path(server_id)

    stdin, stdout, stderr = client.exec_command(
        f"cd '{runtime_dir}' && python3 remote_runner.py", timeout=timeout
    )
    stdin.write(json.dumps(control, ensure_ascii=False) + "\n")
    stdin.flush()
    stdin.channel.shutdown_write()

    last_event = None
    for raw_line in stdout:
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") in ("result", "error"):
            last_event = event

    err_text = stderr.read().decode("utf-8", errors="ignore").strip()

    if last_event is None:
        return {"ok": False, "error": err_text or "پاسخی از سرور دریافت نشد"}

    return last_event


class InvestigationSession:
    """Drives one `investigate` run in a background thread so it can
    stream tool-call events out and pause mid-flight for a YELLOW-tool
    approval without blocking the FastAPI event loop.

    Usage (from an async WebSocket handler):
        session = InvestigationSession(server_id, domain, api_key)
        session.start()
        while True:
            event = await asyncio.to_thread(session.events.get)
            if event is None:            # sentinel: finished
                break
            ... send event to browser ...
            if event["type"] == "approval_request":
                approved = await wait_for_browser_click()
                session.answer_approval(approved)
    """

    def __init__(self, server_id: str, domain: str, api_key: str, auto_approve: bool = False):
        self.server_id = server_id
        self.domain = domain
        self.api_key = api_key
        self.auto_approve = auto_approve
        self.events: queue.Queue = queue.Queue()
        self._approval_answers: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def answer_approval(self, approved: bool):
        self._approval_answers.put(approved)

    def _run(self):
        try:
            client = _get_client(self.server_id)
            runtime_dir = _remote_runtime_path(self.server_id)
            channel = client.get_transport().open_session()
            channel.exec_command(f"cd '{runtime_dir}' && python3 remote_runner.py")

            control = {
                "command": "investigate",
                "domain": self.domain,
                "api_key": self.api_key,
                "auto_approve": self.auto_approve,
            }
            channel.send((json.dumps(control, ensure_ascii=False) + "\n").encode("utf-8"))

            buf = ""
            while True:
                if channel.exit_status_ready() and not channel.recv_ready():
                    break
                chunk = channel.recv(4096)
                if not chunk:
                    break
                buf += chunk.decode("utf-8", errors="ignore")

                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    self.events.put(event)

                    if event.get("type") == "approval_request":
                        approved = self._approval_answers.get()  # blocks this thread only
                        channel.send((json.dumps({"approved": approved}) + "\n").encode("utf-8"))

                    if event.get("type") in ("report", "error"):
                        channel.close()
                        self.events.put(None)
                        return

            self.events.put(None)
        except Exception as exc:  # noqa: BLE001
            self.events.put({"type": "error", "message": str(exc)})
            self.events.put(None)
