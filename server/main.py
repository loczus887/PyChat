from __future__ import annotations

import argparse
import asyncio
import logging
import os
import secrets
from pathlib import Path

from pcs import derive_hmac_key, create_server_tls_context, generate_self_signed_cert
from pcs.logging_config import setup_logging
from db.users import UserDB
from server.server import PCSServer

logger = logging.getLogger(__name__)


def make_verify_credentials(db: UserDB):
    async def verify_credentials(username: str, password_hash: str) -> bool:
        stored = db.get_password_hash(username)
        if stored is None:
            return False
        return secrets.compare_digest(password_hash, stored)
    return verify_credentials


def main() -> None:
    parser = argparse.ArgumentParser(description="PyChat PCS Server")
    parser.add_argument("--host",        default="0.0.0.0")
    parser.add_argument("--port",        type=int, default=9000)
    parser.add_argument("--db",          default="pychat.db")
    parser.add_argument("--certfile",    required=True, help="Certyfikat TLS 1.3 (wymagany)")
    parser.add_argument("--keyfile",     required=True, help="Klucz prywatny TLS (wymagany)")
    parser.add_argument("--hmac-secret", default="pychat-default-secret",
                        help="Sekret HKDF dla HMAC (musi byc identyczny na kliencie i serwerze)")
    parser.add_argument("--hmac-from-tls", action="store_true",
                        help="Klucz HMAC z eksportu TLS zamiast --hmac-secret")
    parser.add_argument("--log-level",   default=os.environ.get("PYCHAT_LOG_LEVEL", "INFO"),
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--log-file",    default=os.environ.get("PYCHAT_LOG_FILE"),
                        help="Opcjonalny plik logów (rotacja ręczna)")
    args = parser.parse_args()

    setup_logging(args.log_level, args.log_file)

    cert_path = Path(args.certfile)
    key_path = Path(args.keyfile)
    if not cert_path.exists() or not key_path.exists():
        logger.warning(
            "Brak certyfikatu TLS (%s) - generuję self-signed (dev only)",
            cert_path,
        )
        generate_self_signed_cert(cert_path, key_path)

    db = UserDB(args.db)
    db.init()

    ssl_context = create_server_tls_context(args.certfile, args.keyfile)
    hmac_key = derive_hmac_key(args.hmac_secret.encode())
    server = PCSServer(
        args.host, args.port, hmac_key, make_verify_credentials(db), ssl_context,
        hmac_from_tls=args.hmac_from_tls,
    )

    logger.info(
        "start host=%s port=%d db=%s tls=1.3 log_level=%s",
        args.host, args.port, args.db, args.log_level,
    )

    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        logger.info("shutdown signal received")
    finally:
        db.close()
        logger.info("server stopped active_sessions=0")


if __name__ == "__main__":
    main()
