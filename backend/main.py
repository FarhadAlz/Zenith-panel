"""
main.py — Zenith Panel backend entry point.

Run with:
    uvicorn main:app --host 127.0.0.1 --port 8787

See ../README.md for the full setup and usage guide (in Persian).
"""

import asyncio
import os

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import crypto_utils
import ssh_manager
import store

store.init_db()

app = FastAPI(title="Zenith Panel")

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")


def require_unlocked():
    if not crypto_utils.is_unlocked():
        raise HTTPException(status_code=401, detail="پنل قفل است — ابتدا رمز اصلی را وارد کنید")


# ---------------------------------------------------------------------------
# Auth / vault
# ---------------------------------------------------------------------------

class PasswordBody(BaseModel):
    password: str


@app.get("/api/auth/status")
def auth_status():
    return {"initialized": crypto_utils.is_initialized(), "unlocked": crypto_utils.is_unlocked()}


@app.post("/api/auth/setup")
def auth_setup(body: PasswordBody):
    if crypto_utils.is_initialized():
        raise HTTPException(status_code=400, detail="پنل قبلاً راه‌اندازی شده — از گزینه ورود استفاده کنید")
    try:
        crypto_utils.initialize(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True}


@app.post("/api/auth/unlock")
def auth_unlock(body: PasswordBody):
    if not crypto_utils.is_initialized():
        raise HTTPException(status_code=400, detail="پنل هنوز راه‌اندازی نشده است")
    ok = crypto_utils.unlock(body.password)
    if not ok:
        raise HTTPException(status_code=401, detail="رمز اصلی نادرست است")
    return {"ok": True}


@app.post("/api/auth/lock")
def auth_lock():
    crypto_utils.lock()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Settings — LLM API key
# ---------------------------------------------------------------------------

class ApiKeyBody(BaseModel):
    api_key: str


@app.get("/api/settings/api-key")
def get_api_key_status():
    require_unlocked()
    enc = store.get_setting("openai_api_key_enc")
    return {"is_set": bool(enc)}


@app.post("/api/settings/api-key")
def set_api_key(body: ApiKeyBody):
    require_unlocked()
    enc = crypto_utils.encrypt_str(body.api_key)
    store.set_setting("openai_api_key_enc", enc)
    return {"ok": True}


def _get_decrypted_api_key() -> str:
    enc = store.get_setting("openai_api_key_enc")
    if not enc:
        raise HTTPException(status_code=400, detail="ابتدا کلید API را در تنظیمات وارد کنید")
    return crypto_utils.decrypt_str(enc)


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------

class AddServerBody(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str
    auth_type: str  # "password" | "key"
    secret: str      # password OR private key text
    passphrase: str | None = None


@app.get("/api/servers")
def api_list_servers():
    require_unlocked()
    servers = store.list_servers()
    for s in servers:
        s["connected"] = ssh_manager.is_connected(s["id"])
    return servers


@app.post("/api/servers")
def api_add_server(body: AddServerBody):
    require_unlocked()

    try:
        ssh_manager.connect(
            server_id="__pending__",
            host=body.host, port=body.port, username=body.username,
            auth_type=body.auth_type, secret=body.secret, passphrase=body.passphrase,
        )
    except ssh_manager.SSHError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    secret_enc = crypto_utils.encrypt_str(body.secret)
    passphrase_enc = crypto_utils.encrypt_str(body.passphrase) if body.passphrase else None

    server_id = store.add_server(
        body.name, body.host, body.port, body.username, body.auth_type,
        secret_enc, passphrase_enc,
    )

    # Move the just-tested connection from the temporary key to the real id.
    ssh_manager.disconnect("__pending__")
    try:
        ssh_manager.connect(
            server_id=server_id,
            host=body.host, port=body.port, username=body.username,
            auth_type=body.auth_type, secret=body.secret, passphrase=body.passphrase,
        )
        ssh_manager.deploy_runtime(server_id)
        store.set_deployed(server_id, True)
        store.touch_connected(server_id)
        result = ssh_manager.run_blocking_command(server_id, {"command": "list_domains"})
        if result.get("ok"):
            store.save_domains(server_id, result.get("domains", []))
    except ssh_manager.SSHError as exc:
        # Server row is saved either way (it's now in history) — surface
        # the deploy/list error but don't lose the saved credentials.
        return {"id": server_id, "ok": True, "warning": str(exc)}

    return {"id": server_id, "ok": True}


@app.post("/api/servers/{server_id}/reconnect")
def api_reconnect(server_id: str):
    require_unlocked()
    row = store.get_server_full(server_id)
    if not row:
        raise HTTPException(status_code=404, detail="سرور یافت نشد")

    secret = crypto_utils.decrypt_str(row["secret_enc"])
    passphrase = crypto_utils.decrypt_str(row["passphrase_enc"]) if row["passphrase_enc"] else None

    try:
        ssh_manager.connect(
            server_id=server_id,
            host=row["host"], port=row["port"], username=row["username"],
            auth_type=row["auth_type"], secret=secret, passphrase=passphrase,
        )
        ssh_manager.deploy_runtime(server_id)
        store.set_deployed(server_id, True)
        store.touch_connected(server_id)
    except ssh_manager.SSHError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"ok": True}


@app.delete("/api/servers/{server_id}")
def api_delete_server(server_id: str):
    require_unlocked()
    ssh_manager.disconnect(server_id)
    store.delete_server(server_id)
    return {"ok": True}


@app.post("/api/servers/{server_id}/domains/refresh")
def api_refresh_domains(server_id: str):
    require_unlocked()
    result = ssh_manager.run_blocking_command(server_id, {"command": "list_domains"})
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "خطای نامشخص"))
    store.save_domains(server_id, result.get("domains", []))
    return result


class CheckDomainBody(BaseModel):
    domain: str


@app.post("/api/servers/{server_id}/check")
def api_check_domain(server_id: str, body: CheckDomainBody):
    require_unlocked()
    result = ssh_manager.run_blocking_command(
        server_id, {"command": "check_domain", "domain": body.domain}
    )
    return result


# ---------------------------------------------------------------------------
# Investigate — live WebSocket bridge to remote_runner.py's "investigate"
# ---------------------------------------------------------------------------

@app.websocket("/ws/investigate")
async def ws_investigate(websocket: WebSocket):
    await websocket.accept()

    try:
        init_msg = await websocket.receive_json()
    except WebSocketDisconnect:
        return

    if not crypto_utils.is_unlocked():
        await websocket.send_json({"type": "error", "message": "پنل قفل است"})
        await websocket.close()
        return

    server_id = init_msg.get("server_id")
    domain = init_msg.get("domain")
    auto_approve = bool(init_msg.get("auto_approve", False))

    try:
        api_key = _get_decrypted_api_key()
    except HTTPException as exc:
        await websocket.send_json({"type": "error", "message": exc.detail})
        await websocket.close()
        return

    session = ssh_manager.InvestigationSession(server_id, domain, api_key, auto_approve)
    session.start()

    try:
        while True:
            event = await asyncio.to_thread(session.events.get)
            if event is None:
                break
            await websocket.send_json(event)
            if event.get("type") == "approval_request":
                answer = await websocket.receive_json()
                session.answer_approval(bool(answer.get("approved", False)))
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Frontend (static)
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
