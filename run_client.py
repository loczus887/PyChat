from __future__ import annotations

import argparse
import getpass
import os

from pcs import derive_hmac_key
from pcs.logging_config import setup_logging
from client.auth import AuthError, RateLimitError
from client.cli import ChatCLI


def main() -> None:
    parser = argparse.ArgumentParser(description="PyChat klient")
    parser.add_argument("--host",        default="127.0.0.1")
    parser.add_argument("--port",        type=int, default=9000)
    parser.add_argument("--cafile",      default=None)
    parser.add_argument("--no-verify",   action="store_true")
    parser.add_argument("--hmac-secret", default="pychat-default-secret")
    parser.add_argument("--hmac-from-tls", action="store_true",
                        help="Klucz HMAC z eksportu TLS (wymaga zgodności klient/serwer)")
    parser.add_argument("--log-level",   default=os.environ.get("PYCHAT_LOG_LEVEL", "WARNING"),
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--no-keepalive", action="store_true",
                        help="Wyłącz PING/PONG (do demo timeoutu sesji 60 s)")
    args = parser.parse_args()

    setup_logging(args.log_level)

    hmac_key = derive_hmac_key(args.hmac_secret.encode())

    username = input("Login: ")
    password = getpass.getpass("Hasło: ")

    try:
        print(f"Łączenie z {args.host}:{args.port}...")
        cli = ChatCLI(
            host=args.host,
            port=args.port,
            username=username,
            password=password,
            hmac_fallback=hmac_key,
            cafile=args.cafile,
            verify_cert=not args.no_verify,
            keepalive=not args.no_keepalive,
            hmac_from_tls=args.hmac_from_tls,
        )
        cli.run()
    except AuthError as exc:
        print(f"[błąd logowania] {exc}")
    except RateLimitError as exc:
        print(f"[rate limit] {exc}")
    except ConnectionError as exc:
        print(f"[błąd połączenia] {exc}")


if __name__ == "__main__":
    main()