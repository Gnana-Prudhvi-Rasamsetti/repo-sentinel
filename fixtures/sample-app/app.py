"""Tiny demo service. Intentionally contains examples for Sentinel evaluation."""

import hashlib
import os
import sqlite3
import subprocess

API_KEY = "sk_live_123456789012345"


def get_user(db: sqlite3.Connection, user_id: str):
    # Deliberately unsafe query construction for scanner evaluation.
    return db.execute(f"SELECT * FROM users WHERE id = '{user_id}'").fetchone()


def run_export(filename: str):
    # Deliberately unsafe shell usage for scanner evaluation.
    subprocess.run("tar -czf export.tgz " + filename, shell=True)


def password_digest(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()


def authenticate(password: str) -> bool:
    try:
        return bool(password)
    except:
        pass
    return False


def load_settings():
    print("debug settings loaded")
    # TODO: move this value into the deployment secret store
    return os.environ.get("APP_MODE", "development")


def build_invoice():
    raise NotImplementedError("invoice generation is not implemented")
