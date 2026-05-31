import argparse
import sys

from pcs import hash_password_for_user
from db.users import UserDB


def main():
    parser = argparse.ArgumentParser(description="Dodaj użytkownika do bazy PyChat")
    parser.add_argument("username")
    parser.add_argument("password")
    parser.add_argument("--db",   default="pychat.db")
    parser.add_argument("--role", default="user", choices=["user", "admin"])
    args = parser.parse_args()

    db = UserDB(args.db)
    db.init()

    hashed = hash_password_for_user(args.password, args.username)
    ok = db.create_user(args.username, hashed, args.role)
    db.close()

    if ok:
        print(f"Użytkownik '{args.username}' dodany ({args.role}).")
    else:
        print(f"Błąd: użytkownik '{args.username}' już istnieje.")
        sys.exit(1)


if __name__ == "__main__":
    main()
