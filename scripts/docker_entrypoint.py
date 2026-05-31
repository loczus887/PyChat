from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pcs import hash_password_for_user
from pcs.logging_config import setup_logging
from pcs.security import generate_self_signed_cert
from db.users import UserDB


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def main() -> None:
    data_dir = Path(_env("PYCHAT_DATA_DIR", "/app/data"))
    cert_dir = data_dir / "certs"
    log_dir = data_dir / "logs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    generate_self_signed_cert(
        cert_dir / "server.crt",
        cert_dir / "server.key",
        cn="localhost",
    )

    db_path = _env("PYCHAT_DB", str(data_dir / "pychat.db"))
    demo_user = _env("PYCHAT_DEMO_USER", "alice")
    demo_password = _env("PYCHAT_DEMO_PASSWORD", "secret")

    db = UserDB(db_path)
    db.init()

    demo_users = [
        (demo_user, demo_password),
        ("bob", demo_password),
    ]
    for username, password in demo_users:
        if not db.user_exists(username):
            hashed = hash_password_for_user(password, username)
            db.create_user(username, hashed, role="user")
            print(f"Utworzono użytkownika demo: {username}")

    db.close()

    log_level = _env("PYCHAT_LOG_LEVEL", "INFO")
    log_file = _env("PYCHAT_LOG_FILE", str(log_dir / "pychat.log"))
    setup_logging(log_level, log_file)

    host = _env("PYCHAT_HOST", "0.0.0.0")
    port = _env("PYCHAT_PORT", "9000")
    certfile = _env("PYCHAT_CERTFILE", str(cert_dir / "server.crt"))
    keyfile = _env("PYCHAT_KEYFILE", str(cert_dir / "server.key"))
    hmac_secret = _env("PYCHAT_HMAC_SECRET", "pychat-default-secret")

    cmd = [
        sys.executable, "-m", "server.main",
        "--host", host,
        "--port", port,
        "--db", db_path,
        "--certfile", certfile,
        "--keyfile", keyfile,
        "--hmac-secret", hmac_secret,
        "--log-level", log_level,
    ]
    if log_file:
        cmd.extend(["--log-file", log_file])
    os.execv(sys.executable, cmd)


if __name__ == "__main__":
    main()
