"""Rotate only the existing shared analyst password during release preparation.

Run manually against the final release database after browser testing. This
module has no database side effects on import and never initializes accounts.
"""

import argparse
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from werkzeug.security import generate_password_hash

from config import Config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database", type=Path, default=Path(Config.DATABASE_PATH),
        help="Existing final release database (defaults to Config.DATABASE_PATH).",
    )
    args = parser.parse_args()
    db_path = args.database.resolve()
    if not db_path.is_file():
        raise SystemExit("Database not found. Initialize Black Falcon first.")

    print("BLACK FALCON - RELEASE ACCOUNT SECURITY")
    print("---------------------------------------")
    print(f"Database: {db_path}")
    try:
        # mode=rw prevents SQLite from creating a database if it disappears
        # between the path check and connection. Do not invoke the app factory.
        with closing(sqlite3.connect(db_path.as_uri() + "?mode=rw", uri=True)) as db:
            if db.execute("SELECT 1 FROM users WHERE username = ?", ("analyst",)).fetchone() is None:
                raise SystemExit("The analyst account does not exist. No changes made.")
            confirmation = input("Rotate the existing analyst password? [yes/NO]: ").strip()
            if confirmation != "yes":
                print("No changes made.")
                return
            new_password = secrets.token_urlsafe(32)
            password_hash = generate_password_hash(new_password)
            with db:
                cursor = db.execute(
                    "UPDATE users SET password = ? WHERE username = ?",
                    (password_hash, "analyst"),
                )
                if cursor.rowcount != 1:
                    raise SystemExit("The analyst account changed during preparation. No changes made.")
    except sqlite3.Error as error:
        raise SystemExit(f"Account preparation failed: {error}") from error

    # Reveal the random credential only after the update has committed. It is
    # never saved to a report, source file or application log by this utility.
    print("The analyst password has been rotated. Other accounts and progress are unchanged.")
    print("Store this credential privately; it is shown only for this rotation:")
    print(f"Username: analyst\nPassword: {new_password}")


if __name__ == "__main__":
    main()
