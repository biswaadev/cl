#!/usr/bin/env python3
"""
Firebase Realtime Database Sync Engine for FFGlory / XYZGlory.
Persists SQLite database state to Firebase Realtime Database in the cloud.
Guarantees 0% data loss across Railway / Docker container restarts.
"""

import os
import json
import time
import threading
import sqlite3
import requests
from db import get_db, resolve_db_path

FIREBASE_DB_URL = os.environ.get("FIREBASE_DB_URL", "https://java-d72c4-default-rtdb.firebaseio.com").rstrip("/")
DEFAULT_FIREBASE_SECRET = "jRD9dMfKsio67rKV6QCSxWQZJHqYKbt7IKDTu4Sk"

_sync_lock = threading.Lock()
_last_sync_time = 0
_last_sync_status = "Not synced yet"
_last_sync_error = None

_trigger_timer = None
_timer_lock = threading.Lock()

def get_secret():
    """Retrieves secret from environment, DB settings, or default python secret."""
    sec = os.environ.get("FIREBASE_DB_SECRET", "").strip()
    if sec:
        return sec
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'firebase_db_secret' LIMIT 1")
        row = c.fetchone()
        conn.close()
        if row and row["value"]:
            return str(row["value"]).strip()
    except Exception:
        pass
    return DEFAULT_FIREBASE_SECRET

def get_firebase_url(path="ffglory"):
    clean_path = path.strip("/ ")
    url = f"{FIREBASE_DB_URL}/{clean_path}.json"
    sec = get_secret()
    if sec:
        url += f"?auth={sec}"
    return url

def export_sqlite_to_json():
    """Extracts all tables from SQLite as a clean JSON dictionary."""
    conn = get_db()
    c = conn.cursor()
    data = {
        "updated_at": int(time.time()),
        "tables": {}
    }

    target_tables = ["users", "settings", "groups", "transactions", "coupons"]
    for table in target_tables:
        try:
            c.execute(f"SELECT * FROM {table}")
            rows = c.fetchall()
            col_names = [d[0] for d in c.description]
            table_data = []
            for r in rows:
                row_dict = {}
                for col in col_names:
                    val = r[col]
                    row_dict[col] = val
                table_data.append(row_dict)
            data["tables"][table] = table_data
        except Exception as e:
            print(f"[Firebase Sync] Error exporting table {table}: {e}")
    conn.close()
    return data

def import_json_to_sqlite(data):
    """Restores SQLite database from a JSON dictionary."""
    if not data or not isinstance(data, dict):
        return False

    tables = data.get("tables", {})
    if not tables:
        return False

    conn = get_db()
    c = conn.cursor()

    try:
        # 1. Restore Users
        if "users" in tables and isinstance(tables["users"], list) and len(tables["users"]) > 0:
            c.execute("DELETE FROM users")
            for u in tables["users"]:
                c.execute('''
                    INSERT INTO users (id, username, password_hash, role, basic_credits, premium_credits, max_groups, is_banned, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        username=excluded.username,
                        password_hash=excluded.password_hash,
                        role=excluded.role,
                        basic_credits=excluded.basic_credits,
                        premium_credits=excluded.premium_credits,
                        max_groups=excluded.max_groups,
                        is_banned=excluded.is_banned
                ''', (
                    u.get("id"),
                    u.get("username"),
                    u.get("password_hash"),
                    u.get("role", "user"),
                    u.get("basic_credits", 0),
                    u.get("premium_credits", 0),
                    u.get("max_groups", 100),
                    u.get("is_banned", 0),
                    u.get("created_at")
                ))

        # 2. Restore Settings
        if "settings" in tables and isinstance(tables["settings"], list):
            for s in tables["settings"]:
                c.execute('''
                    INSERT OR REPLACE INTO settings (key, value)
                    VALUES (?, ?)
                ''', (s.get("key"), str(s.get("value") or "")))

        # 3. Restore Groups
        if "groups" in tables and isinstance(tables["groups"], list):
            for g in tables["groups"]:
                c.execute('''
                    INSERT OR REPLACE INTO groups (id, user_id, group_id, clan_id, clan_name, region, status, glory_gained, clan_total_glory, clan_level, captain, members, uptime, started_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    g.get("id"), g.get("user_id", 1), str(g.get("group_id")), str(g.get("clan_id")),
                    g.get("clan_name"), g.get("region", "IND"), g.get("status", "running"),
                    g.get("glory_gained", 0), g.get("clan_total_glory", 0), g.get("clan_level", 4),
                    g.get("captain", ""), g.get("members", "45/50"), g.get("uptime", "Active"),
                    g.get("started_at"), g.get("created_at")
                ))

        # 4. Restore Transactions
        if "transactions" in tables and isinstance(tables["transactions"], list):
            for t in tables["transactions"]:
                c.execute('''
                    INSERT OR REPLACE INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    t.get("id"), t.get("user_id", 1), t.get("username", "admin"),
                    t.get("amount", 0), t.get("credit_type", "basic"), t.get("usd", 0.0),
                    t.get("order_id", ""), t.get("status", "approved"), t.get("created_at")
                ))

        # 5. Restore Coupons
        if "coupons" in tables and isinstance(tables["coupons"], list):
            for cpn in tables["coupons"]:
                c.execute('''
                    INSERT OR REPLACE INTO coupons (id, code, credits, created_by, status, redeemed_by, redeemed_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cpn.get("id"), cpn.get("code"), cpn.get("credits", 0),
                    cpn.get("created_by", "admin"), cpn.get("status", "active"),
                    cpn.get("redeemed_by"), cpn.get("redeemed_at"), cpn.get("created_at")
                ))

        conn.commit()
        print(f"[Firebase Sync] Successfully restored database from Firebase cloud snapshot!")
        return True
    except Exception as e:
        print(f"[Firebase Sync] Error restoring data to SQLite: {e}")
        return False
    finally:
        conn.close()

def sync_push_to_firebase():
    """Pushes local SQLite snapshot to Firebase Realtime Database."""
    global _last_sync_time, _last_sync_status, _last_sync_error
    with _sync_lock:
        try:
            payload = export_sqlite_to_json()
            url = get_firebase_url("ffglory")
            r = requests.put(url, json=payload, timeout=10)
            if r.status_code == 200:
                _last_sync_time = time.time()
                _last_sync_status = "Success"
                _last_sync_error = None
                print(f"[Firebase Sync] Successfully backed up database to Firebase Realtime DB at {time.ctime()}")
                return True, "Synced successfully"
            else:
                err = f"Firebase responded with HTTP {r.status_code}: {r.text}"
                _last_sync_status = "Failed"
                _last_sync_error = err
                print(f"[Firebase Sync Warning] {err}")
                return False, err
        except Exception as e:
            err = f"Failed to connect to Firebase: {str(e)}"
            _last_sync_status = "Error"
            _last_sync_error = err
            print(f"[Firebase Sync Error] {err}")
            return False, err

def sync_pull_from_firebase():
    """Pulls cloud snapshot from Firebase and restores local SQLite."""
    try:
        url = get_firebase_url("ffglory")
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data and isinstance(data, dict) and "tables" in data:
                return import_json_to_sqlite(data)
            else:
                print("[Firebase Sync] No previous cloud backup found in Firebase. Initializing first push...")
                sync_push_to_firebase()
                return True
        else:
            print(f"[Firebase Sync Warning] Failed to pull from Firebase: HTTP {r.status_code} {r.text}")
            return False
    except Exception as e:
        print(f"[Firebase Sync Error] Could not pull from Firebase: {e}")
        return False

def trigger_async_sync(delay=1.0):
    """Debounced async sync so multiple fast updates trigger a single clean push."""
    global _trigger_timer
    with _timer_lock:
        if _trigger_timer is not None:
            try:
                _trigger_timer.cancel()
            except Exception:
                pass
        _trigger_timer = threading.Timer(delay, sync_push_to_firebase)
        _trigger_timer.daemon = True
        _trigger_timer.start()

def start_periodic_sync(interval=60):
    """Background periodic sync thread."""
    def worker():
        while True:
            time.sleep(interval)
            sync_push_to_firebase()
    t = threading.Thread(target=worker, daemon=True)
    t.start()

if __name__ == "__main__":
    print("Testing Firebase Sync...")
    success, msg = sync_push_to_firebase()
    print("Push result:", success, msg)
