import sqlite3
import os
import hashlib
import time
import shutil

LOCAL_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.db")

def resolve_db_path():
    # 1. Custom env var if set by user or host
    custom_path = os.environ.get("DATABASE_PATH")
    if custom_path:
        os.makedirs(os.path.dirname(os.path.abspath(custom_path)), exist_ok=True)
        return custom_path

    # 2. Railway volume mount path from env
    railway_vol = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
    if railway_vol and os.path.isdir(railway_vol):
        vol_db = os.path.join(railway_vol, "panel.db")
        if not os.path.exists(vol_db) and os.path.exists(LOCAL_DB_PATH):
            try:
                shutil.copy2(LOCAL_DB_PATH, vol_db)
                print(f"[DB] Initialized persistent database in Railway Volume: {vol_db}")
            except Exception as e:
                print(f"[DB] Error copying to Railway Volume: {e}")
        return vol_db

    # 3. Standard persistent /data volume (Railway / Docker mount)
    if os.path.isdir("/data"):
        data_db = "/data/panel.db"
        if not os.path.exists(data_db) and os.path.exists(LOCAL_DB_PATH):
            try:
                shutil.copy2(LOCAL_DB_PATH, data_db)
                print(f"[DB] Initialized persistent database in /data: {data_db}")
            except Exception as e:
                print(f"[DB] Error copying to /data: {e}")
        return data_db

    # 4. Fallback to local file in project directory
    return LOCAL_DB_PATH

DB_PATH = resolve_db_path()

def get_db():
    current_path = resolve_db_path()
    conn = sqlite3.connect(current_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    salt = "ffglory_salt_2026"
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def init_db():
    current_path = resolve_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(current_path)), exist_ok=True)
    conn = get_db()
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            basic_credits INTEGER DEFAULT 0,
            premium_credits INTEGER DEFAULT 0,
            max_groups INTEGER DEFAULT 100,
            is_banned INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Groups table
    c.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            group_id TEXT NOT NULL,
            clan_id TEXT NOT NULL,
            clan_name TEXT,
            region TEXT NOT NULL,
            status TEXT DEFAULT 'running',
            glory_gained INTEGER DEFAULT 0,
            clan_total_glory INTEGER DEFAULT 0,
            clan_level INTEGER DEFAULT 4,
            captain TEXT,
            members TEXT DEFAULT '45/50',
            uptime TEXT DEFAULT '1m',
            started_at INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Transactions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            amount INTEGER NOT NULL,
            credit_type TEXT DEFAULT 'basic',
            usd REAL NOT NULL,
            order_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Coupons table
    c.execute('''
        CREATE TABLE IF NOT EXISTS coupons (
            id TEXT PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            credits INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            redeemed_by TEXT,
            redeemed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Settings table
    c.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    # Seed default settings
    default_settings = {
        "reseller_binance_pay_id": "759228054",
        "reseller_upi_id": "ffglory@upi",
        "credit_price_usd": "1.50",
        "upstream_api_key": "ak_84b879661bf49d33cb43fef87c101ba720dabbfdf0fc3a5f885f78d05256ef02",
        "upstream_master_key": "22e15fc938aef0cf08bff1a4dd7a4aaa",
        "broadcast_active": "0",
        "broadcast_title": "Welcome to FFGlory Reseller Network",
        "broadcast_message": "Automated Free Fire Glory Boosting is active across all regions."
    }

    for k, v in default_settings.items():
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

    # Seed Admin account (admin / admin123)
    admin_pw = hash_password("admin123")
    c.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, role, basic_credits, premium_credits, max_groups)
        VALUES ('admin', ?, 'admin', 99999, 9999, 500)
    ''', (admin_pw,))

    # Seed konikhabikela account with starter credits
    user_pw = hash_password("password123")
    c.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, role, basic_credits, premium_credits, max_groups)
        VALUES ('konikhabikela', ?, 'user', 25, 2, 100)
    ''', (user_pw,))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at", DB_PATH)
