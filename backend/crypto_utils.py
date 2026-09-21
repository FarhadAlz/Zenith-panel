"""
crypto_utils.py — at-rest encryption for everything sensitive the panel
stores (server SSH credentials, the LLM API key).

Design:
    - Nothing sensitive is EVER stored in plaintext on disk.
    - The encryption key is never stored on disk either. It is derived
      (PBKDF2-HMAC-SHA256, 390k iterations) from a master password the
      operator chooses on first run, combined with a random per-install
      salt (the salt IS stored — it's not a secret, it just needs to be
      the same salt every time to re-derive the same key).
    - The derived key only ever lives in this process's memory, and only
      after the operator "unlocks" the panel by typing the master
      password. Restarting the panel forgets the key; it must be
      unlocked again.
    - The LLM (the model behind the agent) is architecturally
      incapable of reaching any of this: it only ever sees tool names
      and JSON tool results (see agent_runtime/remote_runner.py) — the
      master password, the derived key, and every decrypted credential
      stay entirely inside this backend process and are never placed in
      any prompt, tool schema, or tool result.
"""

import base64
import json
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CONFIG_PATH = os.path.join(DATA_DIR, "vault_config.json")

_CANARY = "zenith-panel-unlocked"
_PBKDF2_ITERATIONS = 390_000

# In-memory only. Never written to disk, never logged.
_fernet: Fernet | None = None


def is_initialized() -> bool:
    return os.path.exists(CONFIG_PATH)


def is_unlocked() -> bool:
    return _fernet is not None


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def initialize(master_password: str):
    """First-run only: choose a master password, generate a fresh salt,
    derive the key, and store a canary ciphertext so future unlocks can
    verify the password without ever storing the password itself."""

    global _fernet

    if is_initialized():
        raise RuntimeError("vault already initialized")

    if not master_password or len(master_password) < 6:
        raise ValueError("master password must be at least 6 characters")

    os.makedirs(DATA_DIR, exist_ok=True)

    salt = secrets.token_bytes(16)
    key = _derive_key(master_password, salt)
    fernet = Fernet(key)
    canary = fernet.encrypt(_CANARY.encode("utf-8")).decode("utf-8")

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump({"salt": base64.urlsafe_b64encode(salt).decode("ascii"), "canary": canary}, f)
    os.chmod(CONFIG_PATH, 0o600)

    _fernet = fernet


def unlock(master_password: str) -> bool:
    """Try to unlock the vault for this process. Returns True/False;
    never raises on a wrong password."""

    global _fernet

    if not is_initialized():
        raise RuntimeError("vault not initialized yet")

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    salt = base64.urlsafe_b64decode(cfg["salt"])
    key = _derive_key(master_password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(cfg["canary"].encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return False

    if decrypted != _CANARY:
        return False

    _fernet = fernet
    return True


def lock():
    global _fernet
    _fernet = None


def _require_unlocked() -> Fernet:
    if _fernet is None:
        raise RuntimeError("vault is locked — call /api/auth/unlock first")
    return _fernet


def encrypt_str(plaintext: str) -> str:
    if plaintext is None:
        return ""
    return _require_unlocked().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_str(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    return _require_unlocked().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
