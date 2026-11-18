"""Deliberately clean examples used to compare against planted findings."""

import os
import sqlite3
import subprocess


def get_user(db: sqlite3.Connection, user_id: str):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def run_export(filename: str) -> None:
    subprocess.run(["tar", "-czf", "export.tgz", filename], check=True)


def api_key() -> str | None:
    return os.environ.get("SERVICE_API_KEY")
