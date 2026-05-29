from __future__ import annotations

import argparse
import asyncio
import logging

from pcs import derive_hmac_key, verify_password, create_server_tls_context
from db.users import UserDB
from server.server import PCSServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


def make_verify_credentials(db: UserDB):
    async def verify_credentials(username: str, password_hash: str) -> bool:
        stored = db.get_password_hash(username)
        if stored is None:
            return False
        return verify_password(password_hash, stored)
    return verify_credentials


def main() -> None:
    parser = argparse.ArgumentParser(description="PyChat PCS Server")
    parser.add_argument("--host",        default="0.0.0.0")
    parser.add_argument("--port",        type=int, default=9000)
    parser.add_argument("--db",          default="pychat.db")
    parser.add_argument("--certfile",    default=None)
    parser.add_argument("--keyfile",     default=None)
    parser.add_argument("--hmac-secret", default="pychat-default-secret",
                        help="Sekret do wyprowadzenia klucza HMAC przez HKDF")
    args = parser.parse_args()

    db = UserDB(args.db)
    db.init()

    ssl_context = None
    if args.certfile and args.keyfile:
        ssl_context = create_server_tls_context(args.certfile, args.keyfile)

    hmac_key = derive_hmac_key(args.hmac_secret.encode())
    server = PCSServer(args.host, args.port, hmac_key, make_verify_credentials(db), ssl_context)

    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        pass
    finally:
        db.close()


if __name__ == "__main__":
    main()
