# src/core/auth.py
import json
import os
import hashlib

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
USERS_PATH = os.path.join(BASE_DIR, "data", "users.json")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def load_users():
    if not os.path.exists(USERS_PATH):
        return {}
    with open(USERS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def login(username: str, password: str) -> bool:
    users = load_users()
    hashed = hash_password(password)
    return username in users and users[username]["password"] == hashed


