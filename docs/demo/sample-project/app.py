"""A tiny notes service for the Kestrix demo. Every security problem in this file is planted on purpose."""

import hashlib
import sqlite3
import subprocess


def find_notes(db: sqlite3.Connection, author: str) -> list[tuple[str]]:
    return db.execute(f"SELECT body FROM notes WHERE author = '{author}'").fetchall()


def archive(folder: str) -> None:
    subprocess.run(f"tar czf notes.tgz {folder}", shell=True, check=True)


def password_digest(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
