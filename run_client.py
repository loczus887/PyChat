from __future__ import annotations

import argparse
import getpass
import logging

from pcs import derive_hmac_key
from client.auth import AuthError, RateLimitError
from client.cli import ChatCLI

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="PyChat klient")
    parser.add_argument("--host",        default="127.0.0.1")
    parser.add_argument("--port",        type=int, default=9000)
    parser.add_argument("--cafile",      default=None)
    parser.add_argument("--no-verify",   action="store_true")
    parser.add_argument("--hmac-secret", default="pychat-default-secret")
    args = parser.parse_args()

    hmac_key = derive_hmac_key(args.hmac_secret.encode())

    username = input("Login: ")
    password = getpass.getpass("Hasło: ")

    try:
        cli = ChatCLI(
            host=args.host,
            port=args.port,
            username=username,
            password=password,
            hmac_key=hmac_key,
            cafile=args.cafile,
            verify_cert=not args.no_verify,
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